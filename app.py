"""
模块名称：app
功能描述：ProxyCat 面板的 Web 入口与进程骨架：用 Flask 承载面板页面与 /api/* 接口，并在本进程内创建、启停与热更新出口代理服务和代理池。
职责边界：负责：路由注册与 token 鉴权、config.ini 的读取与持久化、出口服务与代理池的进程内启停及配置推送、退出资源收尾。
          不负责：代理转发与代理池内部业务（见 modules.proxyserver、modules.proxypool_service）；
          日志装配与配置取值校验见 modules.logging_setup、modules.config_validation、modules.pool_config_ini。
关键依赖：modules.modules、modules.logging_setup、modules.proxyserver、modules.proxypool_service、
          modules.proxypool_api、modules.pool_config_ini、modules.config_validation、
          modules.domain_stats、modules.version_check、modules.access_records、
          modules.access_log，Flask 与 waitress。
已知限制：
  1. 配置迁移只在 __name__ 为 __main__ 时执行且必须早于模块级装配；配置在导入期即被读取，web_port 等启动参数改动需重启进程。
  2. 鉴权只比对查询串中的单一 token，无 CSRF 防护；/api/version 与三个广告端点有意免鉴权，不要给它们补 require_token。
  3. 鉴权失败为 401；400 仅出自 POST /api/config 的校验失败，其余端点的参数校验失败均为 200 且 status=error，调用方须同时检查两者。
  4. 代理列表、IP 黑白名单与 bypass 名单全量写盘：名单由面板按秒轮询，代理列表仅 POST 后重载。
  5. Windows 上文件被占用时 os.replace 抛 PermissionError，相关 POST 偶发失败。
  6. 导入即注册 atexit 与信号处理器（SIGINT 恒有、SIGTERM 仅非 Windows、SIGBREAK 仅 Windows）；3 秒硬超时（os._exit(1)）仅在信号路径。
  7. watch_server_config 线程按秒同步手改的 config.ini；面板保存后的重复推送由 _note_config_written 记的 mtime 挡住，避免重置切换节奏。
  8. 比较配置变更时两侧须各自归一（strip/lower）；跨来源直接比较会把未变更误判为已变更，无谓清空出口名册重建。
"""

from flask import Flask, render_template, jsonify, request, redirect, send_from_directory, Response
import sys
import os
import csv
import io
import logging
import json
import threading
from datetime import datetime, timedelta
from configparser import ConfigParser
from itertools import cycle
import werkzeug.serving
from functools import wraps
import signal
import atexit

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(BASE_DIR)

from modules.modules import load_config, check_proxies, get_message, load_ip_list, load_bypass_whitelist, CURRENT_VERSION, port_in_use, strip_deprecated_server_keys, migrate_pool_proxy_count, migrate_getip_url, update_ini_keys, write_ini_section, read_config_text, write_text_atomic, ini_parser, enable_safe_console_output
from modules.logging_setup import (
    ALL_CATEGORIES, apply_log_level, clear_log_ring, current_log_filenames,
    flush_log_queue, iter_log_files, log_file_path, log_ring_stats, query_log_ring,
    read_log_file, setup_logging, shutdown_logging, truncate_log_file,
)
from modules import access_records
from modules.access_log import sanitize_proxy
from modules.access_records import TIME_FORMAT as _RECORD_TIME_FORMAT, RecordFilter
from modules.domain_stats import UPSTREAM_DIRECT, UPSTREAM_UNKNOWN
from modules.proxyserver import AsyncProxyServer, run_server
from modules import pool_config_ini
from modules.config_validation import display_server_values, validate_server_updates
from modules.modules import normalize_rotation_mode, list_files_snapshot, reload_ip_lists_if_changed
from modules.proxypool_service import ProxyPoolService
from modules.proxypool_api import create_pool_blueprint
from modules.version_check import VersionChecker
import asyncio
import time

CONFIG_INI_PATH = os.path.join(BASE_DIR, 'config', 'config.ini')
LEGACY_POOL_YAML_PATH = os.path.join(BASE_DIR, 'modules', 'proxypool', 'config.yaml')

app = Flask(__name__,
           template_folder=os.path.join(BASE_DIR, 'web', 'templates'),
           static_folder=os.path.join(BASE_DIR, 'web', 'static'))

werkzeug.serving.WSGIRequestHandler.log = lambda self, type, message, *args: None
logging.getLogger('werkzeug').setLevel(logging.ERROR)
logging.getLogger('waitress.task').setLevel(logging.ERROR)

_config_sections: dict = {}
_config_sections_mtime: float = 0.0


def config_sections() -> dict:
    global _config_sections, _config_sections_mtime
    try:
        mtime = os.path.getmtime(CONFIG_INI_PATH)
    except OSError:
        return _config_sections

    if mtime != _config_sections_mtime:
        _config_sections = pool_config_ini.read_ini_sections(CONFIG_INI_PATH)
        _config_sections_mtime = mtime
    return _config_sections


if __name__ == '__main__':
    pool_config_ini.ensure_pool_section(CONFIG_INI_PATH, LEGACY_POOL_YAML_PATH)
    migrate_pool_proxy_count(CONFIG_INI_PATH)
    migrate_getip_url(CONFIG_INI_PATH)
    strip_deprecated_server_keys(CONFIG_INI_PATH)

_sections = config_sections()

config = load_config(CONFIG_INI_PATH)
pool_service = ProxyPoolService(
    config=pool_config_ini.build_pool_config(
        _sections.get('Server', {}),
        _sections.get(pool_config_ini.POOL_SECTION, {}),
        strict=False,
    ),
    config_ini_path=CONFIG_INI_PATH,
    language_provider=lambda: server.language,
)
server = AsyncProxyServer(config, pool_service=pool_service)

def get_config_path(filename):
    return os.path.join(BASE_DIR, 'config', filename)

_config_lock = threading.Lock()

_ad_dismissed = False

def verify_token():
    config_token = server.config.get('token', '')
    if not config_token:
        return None
    if request.args.get('token') == config_token:
        return None
    return jsonify({
        'status': 'error',
        'message': get_message('invalid_token', server.language)
    }), 401


def require_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        failure = verify_token()
        if failure is not None:
            return failure
        return f(*args, **kwargs)
    return decorated_function


_pool_blueprint = create_pool_blueprint(pool_service)


@_pool_blueprint.before_request
def _authorize_pool_request():
    return verify_token()


app.register_blueprint(_pool_blueprint)

@app.route('/')
def root():
    token = request.args.get('token')
    if token:
        return redirect(f'/web?token={token}')
    return redirect('/web')

_WEB_STATIC_DIR = os.path.join(BASE_DIR, 'web', 'static')


def asset_version():
    latest = 0.0
    for root, _dirs, names in os.walk(_WEB_STATIC_DIR):
        for name in names:
            try:
                latest = max(latest, os.path.getmtime(os.path.join(root, name)))
            except OSError:
                continue
    return str(int(latest)) if latest else CURRENT_VERSION


@app.route('/web')
@require_token
def web():
    return render_template('index.html', app_version=CURRENT_VERSION, asset_version=asset_version())

@app.route('/api/status')
@require_token
def get_status():
    server_config = config_sections().get('Server', {})

    current_proxy = sanitize_proxy(server.current_proxy)
    if not current_proxy and server.proxy_source_mode == 'local':
        if hasattr(server, 'proxies') and server.proxies:
            current_proxy = sanitize_proxy(server.proxies[0])
        else:
            current_proxy = get_message('no_proxy', server.language)

    time_left = server.time_until_next_switch()
    if time_left == float('inf'):
        time_left = -1

    return jsonify({
        'current_proxy': current_proxy,
        'mode': server.mode,
        'port': _bound_server_port() or int(server_config.get('port', '1080')),
        'interval': server.interval,
        'time_left': time_left,
        'switch_countdown_mode': server.switch_countdown_mode(),
        'total_proxies': len(server.proxies) if hasattr(server, 'proxies') else 0,
        'active_proxies': server.active_workers() if hasattr(server, 'active_workers') else [],
        'proxy_source_mode': server.proxy_source_mode,
        'exit_count': server.exit_count if hasattr(server, 'exit_count') else 0,
        'elastic_active': bool(getattr(server, 'elastic_active', False)),
        'auth_required': server.auth_required,
        'display_level': int(server_config.get('display_level', '1')),
        'service_status': 'running' if server.running else 'stopped',
        'language': server.language,
        'request_interval': server.request_interval,
        'pool_running': pool_service.is_running,
        'source_error': server.last_source_error(),
    })


@app.route('/api/config', methods=['GET'])
@require_token
def get_config():
    sections = pool_config_ini.read_ini_sections(CONFIG_INI_PATH)
    server_section = dict(sections.get('Server', {}))
    server_section.pop('token', None)

    return jsonify({
        'status': 'success',
        'server': display_server_values(server_section),
        'pool': dict(sections.get(pool_config_ini.POOL_SECTION, {})),
    })

def _config_error(message, status=400, details=None):
    payload = {'status': 'error', 'message': message}
    if details is not None:
        payload['details'] = details
    return jsonify(payload), status


def _error_details(error):
    key = getattr(error, 'key', None)
    reason_key = getattr(error, 'reason_key', None)
    if key is None or reason_key is None:
        return None
    return {
        'key': key,
        'reason': get_message(reason_key, server.language,
                              *getattr(error, 'reason_args', ())),
    }


def _localized_error_text(exc) -> str:
    localized = getattr(exc, 'localized', None)
    if callable(localized):
        return localized(server.language)
    return str(exc)


@app.route('/api/config', methods=['POST'])
@require_token
def save_config():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _config_error(get_message('config_body_must_be_json', server.language))

    server_updates = payload.get('server') or {}
    pool_updates = payload.get('pool') or {}
    if not isinstance(server_updates, dict) or not isinstance(pool_updates, dict):
        return _config_error(
            get_message('config_sections_must_be_json', server.language))

    try:
        normalized_server = validate_server_updates(server_updates)
        normalized_pool = pool_config_ini.normalize_pool_updates(pool_updates)
    except ValueError as e:
        logging.warning(f"配置校验未通过: {e}")
        return _config_error(_localized_error_text(e), details=_error_details(e))

    if not normalized_server and not normalized_pool:
        return _config_error(get_message('config_nothing_to_save', server.language))

    try:
        current_config = load_config(CONFIG_INI_PATH)
        port_changed = str(normalized_server.get('port', current_config.get('port'))) != str(current_config.get('port'))
        web_port_changed = (
            str(normalized_server.get('web_port', current_config.get('web_port', '5001')))
            != str(current_config.get('web_port', '5001'))
        )
        new_source_mode = str(normalized_server.get(
            'proxy_source_mode', current_config.get('proxy_source_mode', 'local'))).strip().lower()
        old_source_mode = str(current_config.get('proxy_source_mode', 'local')).strip().lower()
        mode_changed = (
            normalize_rotation_mode(normalized_server.get('mode', current_config.get('mode')), new_source_mode)
            != normalize_rotation_mode(current_config.get('mode'), old_source_mode)
        )
        source_mode_changed = new_source_mode != old_source_mode

        updated_config = _persist_config(normalized_server, normalized_pool)
    except Exception as e:
        logging.error(f"保存配置失败: {e}")
        return _config_error(str(e), 500)

    if web_port_changed:
        logging.warning(
            "web_port 已保存为 %s：面板端口需重启整个应用后生效，当前面板仍运行在旧端口",
            updated_config.get('web_port'),
        )

    if 'log_level' in normalized_server:
        applied_level = apply_log_level(normalized_server['log_level'])
        logging.getLogger(__name__).info(
            "日志级别已切换为 %s", logging.getLevelName(applied_level)
        )

    applied = {
        'proxy': _apply_proxy_config(updated_config, mode_changed, source_mode_changed),
        'pool': _apply_pool_config(updated_config, source_mode_changed),
    }

    return jsonify({
        'status': 'success',
        'port_changed': port_changed,
        'web_port_changed': web_port_changed,
        'service_status': 'running' if server.running else 'stopped',
        'applied': applied,
    })


def _persist_config(normalized_server, normalized_pool):
    with _config_lock:
        update_ini_keys(CONFIG_INI_PATH, 'Server', normalized_server)

        if normalized_pool:
            pool_config_ini.sync_pool_section_text(CONFIG_INI_PATH, normalized_pool)

        sections = pool_config_ini.read_ini_sections(CONFIG_INI_PATH)
        updated_config = dict(sections.get('Server', {}))
        if 'Users' in sections:
            updated_config['Users'] = dict(sections['Users'])

    _note_config_written()
    reload_config_sections()
    return updated_config


def reload_config_sections() -> None:
    global _config_sections_mtime
    _config_sections_mtime = 0.0
    config_sections()


_config_watch_mtime: float = 0.0


def _note_config_written() -> None:
    global _config_watch_mtime
    try:
        _config_watch_mtime = os.path.getmtime(CONFIG_INI_PATH)
    except OSError:
        _config_watch_mtime = 0.0


def _hot_reload_once() -> bool:
    global _config_watch_mtime
    try:
        mtime = os.path.getmtime(CONFIG_INI_PATH)
    except OSError:
        return False
    if mtime == _config_watch_mtime:
        return False
    _config_watch_mtime = mtime

    try:
        new_config = load_config(CONFIG_INI_PATH)
    except Exception as e:
        logging.warning(f"配置热重载：读取失败，沿用当前配置: {e}")
        return False

    try:
        new_source_mode = new_config.get('proxy_source_mode', 'local').lower()
        server.apply_config_sync(
            new_config,
            mode_changed=(
                server.mode
                != normalize_rotation_mode(new_config.get('mode', 'cycle'), new_source_mode)),
            source_mode_changed=(server.proxy_source_mode != new_source_mode),
            reset_switch_timers=True,
            timeout=10,
        )
        logging.info(get_message('config_file_changed', server.language))
    except Exception as e:
        logging.error(f"配置热重载：应用失败，沿用当前配置: {e}")
        return False
    return True


def watch_server_config(interval: float = 1.0) -> None:
    _note_config_written()
    list_snapshot = list_files_snapshot(server)
    while True:
        time.sleep(interval)
        _hot_reload_once()
        try:
            list_snapshot = reload_ip_lists_if_changed(server, list_snapshot)
        except Exception as e:
            logging.warning(f"访问名单热重载失败（沿用当前名单）: {e}")


def _apply_proxy_config(updated_config, mode_changed, source_mode_changed) -> bool:
    try:
        server.apply_config_sync(
            updated_config, mode_changed, source_mode_changed,
            reset_switch_timers=bool(
                mode_changed and updated_config.get('mode') == 'loadbalance'),
            timeout=10,
        )
        return True
    except Exception as e:
        logging.error(f"代理服务应用新配置失败: {e}")
        return False


def _apply_pool_config(updated_config=None, source_mode_changed: bool = False) -> bool:
    try:
        if pool_service.is_running:
            pool_service.reload_config_from_file()
        elif updated_config is not None and pool_config_ini.should_autostart_pool(updated_config):
            if pool_service.start():
                reason_key = 'pool_autostart_source_switched' if source_mode_changed else 'pool_autostart_required'
                logging.info(get_message(reason_key, server.language))
            else:
                logging.error(get_message('pool_start_failed', server.language, pool_service.last_error))
                pool_service.note_config_saved()
                return False
        pool_service.note_config_saved()
        return True
    except Exception as e:
        logging.error(f"代理池应用新配置失败: {e}")
        return False


@app.route('/api/proxies', methods=['GET', 'POST'])
@require_token
def handle_proxies():
    if request.method == 'POST':
        try:
            proxies = request.json.get('proxies', [])
            if not isinstance(proxies, list):
                return jsonify({
                    'status': 'error',
                    'message': get_message('proxies_must_be_list', server.language)
                })
            proxy_file = get_config_path(os.path.basename(server.proxy_file))
            write_text_atomic(proxy_file, '\n'.join(str(line) for line in proxies))
            server.reload_local_proxies(run_check=False)
            return jsonify({
                'status': 'success',
                'message': get_message('proxy_save_success', server.language)
            })
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': get_message('proxy_save_failed', server.language, str(e))
            })
    else:
        try:
            proxy_file = get_config_path(os.path.basename(server.proxy_file))
            proxies = read_config_text(proxy_file).splitlines()
            return jsonify({'proxies': proxies})
        except Exception as e:
            logging.error(f"读取本地代理列表失败: {e}")
            return jsonify({
                'status': 'error',
                'message': get_message('load_proxy_file_error', server.language, str(e))
            })

@app.route('/api/check_proxies')
@require_token
def check_proxies_api():
    try:
        test_url = request.args.get('test_url', 'https://www.baidu.com')
        candidates = server.source_proxies()
        valid_proxies = _run_async_safe(
            check_proxies, candidates, test_url, server.check_concurrency
        )
        total_valid = len(valid_proxies)
        return jsonify({
            'status': 'success',
            'valid_proxies': valid_proxies,
            'checked': len(candidates),
            'total': total_valid,
            'message': get_message('proxy_check_result', server.language, total_valid)
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': get_message('proxy_check_failed', server.language, str(e))
        })

@app.route('/api/ip_lists', methods=['GET', 'POST'])
@require_token
def handle_ip_lists():
    if request.method == 'POST':
        try:
            list_type = request.json.get('type', '')
            if list_type not in ('whitelist', 'blacklist'):
                return jsonify({
                    'status': 'error',
                    'message': get_message('ip_list_type_invalid', server.language),
                })
            ip_list = request.json.get('list', [])
            base_filename = os.path.basename(server.whitelist_file if list_type == 'whitelist' else server.blacklist_file)
            filename = get_config_path(base_filename)

            write_text_atomic(filename, '\n'.join(ip_list))

            if list_type == 'whitelist':
                server.whitelist = load_ip_list(filename)
            else:
                server.blacklist = load_ip_list(filename)

            return jsonify({
                'status': 'success',
                'message': get_message('ip_list_save_success', server.language)
            })
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': get_message('ip_list_save_failed', server.language, str(e))
            })
    else:
        whitelist_file = get_config_path(os.path.basename(server.whitelist_file))
        blacklist_file = get_config_path(os.path.basename(server.blacklist_file))
        return jsonify({
            'whitelist': list(load_ip_list(whitelist_file)),
            'blacklist': list(load_ip_list(blacklist_file))
        })

@app.route('/api/bypass_whitelist', methods=['GET', 'POST'])
@require_token
def handle_bypass_whitelist():
    if request.method == 'POST':
        try:
            bypass_list = request.json.get('list', [])
            filename = os.path.join(BASE_DIR, 'config', os.path.basename(server.bypass_whitelist_file))
            write_text_atomic(filename, '\n'.join(bypass_list))
            server.bypass_whitelist = load_bypass_whitelist(filename)
            return jsonify({
                'status': 'success',
                'message': get_message('ip_list_save_success', server.language)
            })
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': str(e)
            })
    else:
        filename = os.path.join(BASE_DIR, 'config', os.path.basename(server.bypass_whitelist_file))
        return jsonify({'list': list(load_bypass_whitelist(filename))})

def _requested_category():
    category = request.args.get('category', 'all')
    if category == 'all' or category in ALL_CATEGORIES:
        return category
    return None


@app.route('/api/logs')
@require_token
def get_logs():
    try:
        category = _requested_category()
        if category is None:
            return jsonify({
                'status': 'error',
                'message': get_message('log_category_unknown', server.language),
            })

        start = max(0, int(request.args.get('start', 0)))
        limit = max(1, min(int(request.args.get('limit', 200)), 2000))
        level = request.args.get('level', 'ALL')
        search = request.args.get('search', '').strip()

        filtered = query_log_ring(category, level, search)

        end = len(filtered) - start
        begin = max(0, end - limit)
        page = filtered[begin:end] if end > 0 else []

        return jsonify({'logs': page, 'total': len(filtered), 'status': 'success'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/logs/stats')
@require_token
def get_logs_stats():
    try:
        return jsonify({'status': 'success', 'stats': log_ring_stats()})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/logs/files')
@require_token
def get_log_files():
    try:
        return jsonify({'status': 'success', 'files': iter_log_files(BASE_DIR)})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/logs/file')
@require_token
def get_log_file():
    try:
        filename = request.args.get('name', '')
        lines = max(1, min(int(request.args.get('lines', 500)), 5000))
        entries, truncated = read_log_file(filename, BASE_DIR, lines)
        return jsonify({
            'status': 'success', 'name': filename,
            'lines': entries, 'truncated': truncated,
        })
    except ValueError as e:
        return jsonify({'status': 'error', 'message': _localized_error_text(e)})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/logs/export')
@require_token
def export_logs():
    try:
        filename = request.args.get('file', '')
        if filename:
            path = log_file_path(filename, BASE_DIR)
            if path is None or not os.path.exists(path):
                return jsonify({
                    'status': 'error',
                    'message': get_message('log_file_missing', server.language),
                })
            flush_log_queue()
            return send_from_directory(
                os.path.join(BASE_DIR, 'logs'), filename,
                mimetype='text/plain', as_attachment=True,
            )

        category = _requested_category()
        if category is None:
            return jsonify({'status': 'error',
                            'message': get_message('log_category_unknown', server.language)})
        logs = query_log_ring(category, request.args.get('level', 'ALL'),
                              request.args.get('search', '').strip())
        content = '\n'.join(
            f"{entry['time']} - {entry['level']} - {entry['message']}" for entry in logs
        )
        return Response(content, mimetype='text/plain',
                        headers={'Content-Disposition': 'attachment;filename=proxycat_export.log'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/logs/clear', methods=['POST'])
@require_token
def clear_logs():
    try:
        payload = request.get_json(silent=True) or {}
        category = payload.get('category', 'all')
        if category != 'all' and category not in ALL_CATEGORIES:
            return jsonify({'status': 'error',
                            'message': get_message('log_category_unknown', server.language)})

        clear_log_ring(category)
        failed = [
            name for name in current_log_filenames(category)
            if not truncate_log_file(name, BASE_DIR)
        ]
        if failed:
            return jsonify({
                'status': 'error',
                'message': get_message('clear_logs_failed', server.language, ', '.join(failed)),
            })

        return jsonify({
            'status': 'success',
            'message': get_message('logs_cleared', server.language),
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': get_message('clear_logs_failed', server.language, str(e)),
        })


def _upstream_label(key: str) -> str:
    if key == UPSTREAM_DIRECT:
        return get_message('access_direct', server.language)
    if key == UPSTREAM_UNKNOWN:
        return get_message('access_unknown', server.language)
    return key


_RECORD_OUTCOMES = ('success', 'failure', 'aborted')


def _int_arg(name: str, default: int) -> int:
    raw = (request.args.get(name) or '').strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default

_RECORD_CSV_HEADER_KEYS = (
    'csv_col_time', 'csv_col_kind', 'csv_col_method', 'csv_col_client_ip',
    'csv_col_client_user', 'csv_col_host', 'csv_col_port', 'csv_col_upstream',
    'csv_col_real_ip', 'csv_col_outcome', 'csv_col_status_code', 'csv_col_elapsed',
    'csv_col_reason',
)


def _normalize_record_time(raw: str | None, *, end: bool) -> str | None:
    text = (raw or '').strip()
    if not text:
        return None

    normalized = text.replace('T', ' ')
    for pattern in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M'):
        try:
            moment = datetime.strptime(normalized, pattern)
        except ValueError:
            continue
        if end and moment.second == 0 and pattern == '%Y-%m-%d %H:%M':
            moment = moment.replace(second=59)
        return moment.strftime(_RECORD_TIME_FORMAT)

    try:
        day = datetime.strptime(normalized, '%Y-%m-%d')
    except ValueError:
        return None
    if end:
        day = day.replace(hour=23, minute=59, second=59)
    return day.strftime(_RECORD_TIME_FORMAT)


_CSV_FORMULA_PREFIXES = ('=', '+', '-', '@')


def _csv_safe(value) -> str:
    text = '' if value is None else str(value)
    if text[:1] in _CSV_FORMULA_PREFIXES:
        return "'" + text
    return text


def _render_records_csv(rows: list[dict]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    _message = lambda key: get_message(key, server.language)
    writer.writerow([_message(key) for key in _RECORD_CSV_HEADER_KEYS])

    outcome_labels = {
        'success': get_message('access_outcome_success', server.language),
        'failure': get_message('access_outcome_failure', server.language),
        'aborted': get_message('access_outcome_aborted', server.language),
    }
    for row in rows:
        writer.writerow([_csv_safe(cell) for cell in (
            row['ts'],
            row['kind'],
            row['method'],
            row['client_ip'],
            row['client_user'],
            row['host'],
            row['port'],
            _upstream_label(row['upstream']),
            row['real_ip'],
            outcome_labels.get(row['outcome'], row['outcome']),
            '' if row['status_code'] is None else row['status_code'],
            row['elapsed_ms'],
            row['reason'],
        )])
    return buffer.getvalue()


@app.route('/api/logs/domains')
@require_token
def get_domain_stats():
    try:
        sort = request.args.get('sort', 'last_seen')
        order = request.args.get('order', 'desc')
        search = request.args.get('search', '').strip()
        limit = max(1, min(int(request.args.get('limit', 100)), 1000))
        offset = max(0, int(request.args.get('offset', 0)))
        upstream = request.args.get('upstream', '')

        store = server.domain_stats
        payload = {
            'status': 'success',
            'enabled': store.enabled,
            'summary': store.summary(),
        }

        if upstream:
            rows, total = store.query_domains(upstream, search, sort, order, limit, offset)
            payload.update({
                'mode': 'domains',
                'upstream': upstream,
                'upstream_label': _upstream_label(upstream),
                'domains': rows,
                'total': total,
            })
        else:
            rows, total = store.query_proxies(search, sort, order, limit, offset)
            for row in rows:
                row['upstream_label'] = _upstream_label(row['upstream'])
            payload.update({'mode': 'proxies', 'proxies': rows, 'total': total})

        return jsonify(payload)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/logs/domains/clear', methods=['POST'])
@require_token
def clear_domain_stats():
    try:
        removed = server.domain_stats.clear()
        return jsonify({
            'status': 'success',
            'removed': removed,
            'message': get_message('domain_stats_cleared', server.language, removed),
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/logs/records')
@require_token
def get_access_records():
    store = server.access_records
    try:
        since = _normalize_record_time(request.args.get('since'), end=False)
        until = _normalize_record_time(request.args.get('until'), end=True)
        if since is None:
            since = (datetime.now() - timedelta(hours=1)).strftime(_RECORD_TIME_FORMAT)

        outcome = request.args.get('outcome', '').strip()
        if outcome and outcome not in _RECORD_OUTCOMES:
            return jsonify({
                'status': 'error',
                'message': get_message('access_records_bad_outcome', server.language, outcome),
            })

        flt = RecordFilter(
            since=since,
            until=until,
            upstream=request.args.get('upstream', '').strip() or None,
            host=request.args.get('host', '').strip() or None,
            outcome=outcome or None,
            search=request.args.get('search', '').strip(),
        )
        limit = max(1, min(_int_arg('limit', 100), 500))
        offset = max(0, _int_arg('offset', 0))

        rows, total, counts = store.query(
            flt, limit=limit, offset=offset, order=request.args.get('order', 'desc')
        )
        for row in rows:
            row['upstream_label'] = _upstream_label(row['upstream'])

        return jsonify({
            'status': 'success',
            'enabled': store.enabled,
            'range': {'since': since, 'until': until or ''},
            'outcome_counts': counts,
            'total': total,
            'export_limit': access_records.EXPORT_LIMIT,
            'records': rows,
            **store.stats(),
        })
    except ValueError as e:
        return jsonify({'status': 'error', 'message': str(e)})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/logs/records/export')
@require_token
def export_access_records():
    store = server.access_records
    try:
        since = _normalize_record_time(request.args.get('since'), end=False)
        until = _normalize_record_time(request.args.get('until'), end=True)
        if since is None:
            since = (datetime.now() - timedelta(hours=1)).strftime(_RECORD_TIME_FORMAT)

        outcome = request.args.get('outcome', '').strip()
        if outcome and outcome not in _RECORD_OUTCOMES:
            return jsonify({
                'status': 'error',
                'message': get_message('access_records_bad_outcome', server.language, outcome),
            })

        export_format = (request.args.get('format') or 'csv').strip().lower()
        if export_format not in ('csv', 'json'):
            return jsonify({
                'status': 'error',
                'message': get_message('access_records_bad_format', server.language, export_format),
            })

        flt = RecordFilter(
            since=since,
            until=until,
            upstream=request.args.get('upstream', '').strip() or None,
            host=request.args.get('host', '').strip() or None,
            outcome=outcome or None,
            search=request.args.get('search', '').strip(),
        )
        rows = store.export_rows(flt)
        stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"access_records_{stamp}.{export_format}"

        if export_format == 'json':
            body = json.dumps(
                {
                    'exported_at': datetime.now().strftime(_RECORD_TIME_FORMAT),
                    'range': {'since': since, 'until': until or ''},
                    'upstream': flt.upstream or '',
                    'host': flt.host or '',
                    'outcome': flt.outcome or '',
                    'count': len(rows),
                    'truncated': len(rows) >= access_records.EXPORT_LIMIT,
                    'records': rows,
                },
                ensure_ascii=False,
                indent=2,
            )
            return Response(
                body,
                content_type='application/json; charset=utf-8',
                headers={'Content-Disposition': f'attachment; filename={filename}'},
            )

        return Response(
            '﻿' + _render_records_csv(rows),
            content_type='text/csv; charset=utf-8',
            headers={'Content-Disposition': f'attachment; filename={filename}'},
        )
    except ValueError as e:
        return jsonify({'status': 'error', 'message': str(e)})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/logs/records/options')
@require_token
def get_access_record_options():
    try:
        options = server.access_records.distinct_options()
        for item in options['upstreams']:
            item['label'] = _upstream_label(item['value'])
        return jsonify({'status': 'success', **options})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/logs/records/clear', methods=['POST'])
@require_token
def clear_access_records():
    try:
        removed = server.access_records.clear()
        return jsonify({
            'status': 'success',
            'removed': removed,
            'message': get_message('access_records_cleared', server.language, removed),
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/switch_proxy')
@require_token
def switch_proxy():
    try:
        result = _run_async_safe(server.switch_proxy)
        if result is True:
            return jsonify({
                'status': 'success',
                'current_proxy': sanitize_proxy(server.current_proxy),
                'active_proxies': server.active_workers() if hasattr(server, 'active_workers') else [],
                'total_proxies': len(server.proxies) if hasattr(server, 'proxies') else 0,
                'message': get_message('switch_success', server.language)
            })
        elif isinstance(result, dict) and 'cooldown' in result:
            remaining = result['cooldown']
            return jsonify({
                'status': 'error',
                'cooldown': True,
                'cooldown_remaining': remaining,
                'message': get_message('switch_cooldown_msg', server.language).replace('{}', str(remaining))
            })
        elif isinstance(result, dict) and 'switching' in result:
            return jsonify({
                'status': 'error',
                'switching': True,
                'message': get_message('switch_in_progress', server.language)
            })
        else:
            current = sanitize_proxy(server.current_proxy) or get_message('no_current_proxy', server.language)
            return jsonify({
                'status': 'error',
                'current_proxy': current,
                'message': get_message('switch_failed', server.language, current)
            })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': get_message('switch_failed', server.language, str(e))
        })

def _close_server_instance():
    server.close_listener()


def _wait_proxy_thread_exit(timeout: float = 10.0) -> bool:
    proxy_thread = getattr(server, 'proxy_thread', None)
    if proxy_thread is None or not proxy_thread.is_alive():
        return True
    proxy_thread.join(timeout=timeout)
    return not proxy_thread.is_alive()


def _wait_server_running(timeout: float = 5.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if server.running:
            return True
        time.sleep(0.5)
    return server.running


def _start_server_thread():
    def _runner():
        try:
            if server.proxy_source_mode == 'local':
                server.run_startup_check_blocking()
            _run_async_safe(run_server, server)
        except Exception as e:
            logging.error(f"代理服务线程异常退出: {e}")

    server.stop_server = False
    server.proxy_thread = threading.Thread(target=_runner, daemon=True)
    server.proxy_thread.start()


@app.route('/api/service', methods=['POST'])
@require_token
def control_service():
    try:
        action = request.json.get('action')
        if action == 'start':
            if server.running:
                return jsonify({
                    'status': 'success',
                    'message': get_message('service_already_running', server.language),
                    'service_status': 'running'
                })
            if port_in_use(server.port):
                return jsonify({
                    'status': 'error',
                    'message': get_message('port_in_use', server.language, server.port),
                    'service_status': 'stopped'
                })
            if not _wait_proxy_thread_exit():
                return jsonify({
                    'status': 'error',
                    'message': get_message(
                        'operation_failed', server.language,
                        get_message('service_thread_still_running', server.language),
                    ),
                    'service_status': 'stopped'
                })
            _start_server_thread()

            if _wait_server_running():
                return jsonify({
                    'status': 'success',
                    'message': get_message('service_start_success', server.language),
                    'service_status': 'running'
                })
            reason = f"：{server.last_start_error}" if server.last_start_error else ""
            return jsonify({
                'status': 'error',
                'message': get_message('service_start_failed', server.language) + reason,
                'service_status': 'stopped'
            })

        elif action == 'stop':
            if not server.running:
                return jsonify({
                    'status': 'success',
                    'message': get_message('service_not_running', server.language),
                    'service_status': 'stopped'
                })
            server.stop_server = True
            _close_server_instance()

            if not _wait_proxy_thread_exit():
                return jsonify({
                    'status': 'error',
                    'message': get_message(
                        'operation_failed', server.language,
                        get_message('service_stop_timeout', server.language),
                    ),
                    'service_status': 'stopped'
                })
            return jsonify({
                'status': 'success',
                'message': get_message('service_stop_success', server.language),
                'service_status': 'stopped'
            })

        elif action == 'restart':
            if server.running:
                server.stop_server = True
                _close_server_instance()

            if not _wait_proxy_thread_exit():
                return jsonify({
                    'status': 'error',
                    'message': get_message('service_thread_still_running', server.language),
                    'service_status': 'stopped'
                })

            if port_in_use(server.port):
                return jsonify({
                    'status': 'error',
                    'message': get_message('port_in_use', server.language, server.port),
                    'service_status': 'stopped'
                })

            _start_server_thread()

            if _wait_server_running():
                return jsonify({
                    'status': 'success',
                    'message': get_message('service_restart_success', server.language)
                })
            return jsonify({
                'status': 'error',
                'message': get_message('service_restart_failed', server.language, server.last_start_error or ''),
                'service_status': 'stopped'
            })

        return jsonify({
            'status': 'error',
            'message': get_message('invalid_action', server.language)
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': get_message('operation_failed', server.language, str(e))
        })

@app.route('/api/language', methods=['POST'])
@require_token
def change_language():
    try:
        new_language = request.json.get('language', 'cn')
        if new_language not in ['cn', 'en']:
            return jsonify({
                'status': 'error',
                'message': get_message('unsupported_language', server.language)
            })

        with _config_lock:
            update_ini_keys(CONFIG_INI_PATH, 'Server', {'language': new_language})

        _note_config_written()
        reload_config_sections()

        server.language = new_language

        return jsonify({
            'status': 'success',
            'language': new_language
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': get_message('operation_failed', server.language, str(e))
        })

version_checker = VersionChecker(
    os.path.join(BASE_DIR, 'logs', 'version_check.json'),
    language_provider=lambda: server.language,
    url_provider=lambda: server.config.get('version_check_url', ''),
)


@app.route('/api/version')
def check_version():
    return jsonify(version_checker.result_payload())

@app.route('/api/version/check', methods=['POST'])
@require_token
def check_version_now():
    return jsonify(version_checker.check_now())

@app.route('/api/users', methods=['GET', 'POST'])
@require_token
def handle_users():
    if request.method == 'POST':
        try:
            users = request.json.get('users', {})
            with _config_lock:
                write_ini_section(CONFIG_INI_PATH, 'Users', users)

            _note_config_written()
            reload_config_sections()

            server.users = users
            server.auth_required = bool(users)

            return jsonify({
                'status': 'success',
                'message': get_message('users_save_success', server.language)
            })
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': get_message('users_save_failed', server.language, str(e))
            })
    else:
        try:
            config = ini_parser()
            config.read_string(read_config_text(CONFIG_INI_PATH))
            users = {}
            if config.has_section('Users'):
                users = dict(config.items('Users'))
            return jsonify({'status': 'success', 'users': users})
        except Exception as e:
            logging.error(f"Error getting users: {e}")
            return jsonify({
                'status': 'error',
                'users': None,
                'message': get_message('users_load_failed', server.language, str(e))
            })

@app.route('/api/api_credentials', methods=['GET', 'POST'])
@require_token
def handle_api_credentials():
    if request.method == 'POST':
        try:
            action = request.json.get('action', 'save')
            config = ini_parser()
            config.read_string(read_config_text(CONFIG_INI_PATH))

            if not config.has_section('api_credentials'):
                config.add_section('api_credentials')

            if action == 'save':
                cred_name = request.json.get('name', '').strip()
                if not cred_name:
                    return jsonify({
                        'status': 'error',
                        'message': get_message('credential_name_required', server.language),
                    })

                cred_url = request.json.get('url', '')
                cred_user = request.json.get('username', '')
                cred_pass = request.json.get('password', '')

                stored = config.get('api_credentials', 'credential_sets', fallback='[]')
                try:
                    sets = json.loads(stored)
                except Exception:
                    sets = []

                existing = next((s for s in sets if s.get('name') == cred_name), None)
                if existing:
                    existing['url'] = cred_url
                    existing['username'] = cred_user
                    existing['password'] = cred_pass
                else:
                    sets.append({
                        'name': cred_name,
                        'url': cred_url,
                        'username': cred_user,
                        'password': cred_pass
                    })

                updates = {'credential_sets': json.dumps(sets, ensure_ascii=False)}

                active = config.get('api_credentials', 'active_credential', fallback='')
                if not active or active == cred_name:
                    active = cred_name
                    updates['active_credential'] = active

                with _config_lock:
                    update_ini_keys(CONFIG_INI_PATH, 'api_credentials', updates)

                _note_config_written()
                reload_config_sections()

                return jsonify({
                    'status': 'success',
                    'message': get_message('credential_saved', server.language),
                    'sets': sets,
                    'active_credential': active
                })

            elif action == 'delete':
                cred_name = request.json.get('name', '').strip()
                if not cred_name:
                    return jsonify({'status': 'error',
                                    'message': get_message('credential_name_required', server.language)})

                stored = config.get('api_credentials', 'credential_sets', fallback='[]')
                try:
                    sets = json.loads(stored)
                except Exception:
                    sets = []

                sets = [s for s in sets if s.get('name') != cred_name]
                updates = {'credential_sets': json.dumps(sets, ensure_ascii=False)}

                active = config.get('api_credentials', 'active_credential', fallback='')
                server_updates = None
                if active == cred_name:
                    active = sets[0]['name'] if sets else ''
                    updates['active_credential'] = active
                    replacement = next(
                        (s for s in sets if s.get('name') == active), None) or {}
                    server_updates = {
                        'api_proxy_url': replacement.get('url', ''),
                        'proxy_username': replacement.get('username', ''),
                        'proxy_password': replacement.get('password', ''),
                    }

                with _config_lock:
                    update_ini_keys(CONFIG_INI_PATH, 'api_credentials', updates)
                    if server_updates:
                        update_ini_keys(CONFIG_INI_PATH, 'Server', server_updates)

                _note_config_written()
                reload_config_sections()

                return jsonify({
                    'status': 'success',
                    'message': get_message('credential_deleted', server.language),
                    'sets': sets,
                    'active_credential': active
                })

            elif action == 'set_active':
                cred_name = request.json.get('name', '').strip()
                if not cred_name:
                    return jsonify({'status': 'error',
                                    'message': get_message('credential_name_required', server.language)})
                cred_updates = {'active_credential': cred_name}

                stored = config.get('api_credentials', 'credential_sets', fallback='[]')
                try:
                    sets = json.loads(stored)
                except Exception:
                    sets = []

                target = next((s for s in sets if s.get('name') == cred_name), None)
                if target is None:
                    return jsonify({
                        'status': 'error',
                        'message': get_message('credential_not_found', server.language, cred_name)
                    })

                server_updates = {
                    'api_proxy_url': target.get('url', ''),
                    'proxy_username': target.get('username', ''),
                    'proxy_password': target.get('password', ''),
                }

                with _config_lock:
                    update_ini_keys(CONFIG_INI_PATH, 'api_credentials', cred_updates)
                    update_ini_keys(CONFIG_INI_PATH, 'Server', server_updates)

                _note_config_written()
                reload_config_sections()

                return jsonify({
                    'status': 'success',
                    'message': get_message('credential_switched', server.language),
                    'active_credential': cred_name,
                    'credential': target
                })

            else:
                return jsonify({
                    'status': 'error',
                    'message': get_message('unknown_action', server.language),
                })

        except Exception as e:
            logging.error(f"Error handling API credentials: {e}")
            return jsonify({'status': 'error', 'message': str(e)})

    else:
        try:
            config = ini_parser()
            config.read_string(read_config_text(CONFIG_INI_PATH))

            stored = config.get('api_credentials', 'credential_sets', fallback='[]')
            try:
                sets = json.loads(stored)
            except Exception:
                sets = []

            active = config.get('api_credentials', 'active_credential', fallback='')

            return jsonify({
                'status': 'success',
                'sets': sets,
                'active_credential': active
            })
        except Exception as e:
            logging.error(f"Error getting API credentials: {e}")
            return jsonify({'status': 'error', 'sets': [], 'active_credential': ''})

_AD_URL_SCHEMES = ('http://', 'https://')


def _safe_ad_url(value) -> str:
    text = str(value or '').strip()
    if not text:
        return ''
    lowered = text.lower()
    if lowered.startswith(_AD_URL_SCHEMES) or text.startswith('//') or text.startswith('/'):
        return text
    logging.warning("广告地址协议不受支持，已忽略: %s", text[:80])
    return ''


@app.route('/api/ads')
def get_ads():
    try:
        ads_dir = os.path.join(BASE_DIR, 'config', 'ads')
        ads = []
        if not os.path.isdir(ads_dir):
            return jsonify({'status': 'success', 'ads': [], 'total': 0, 'dismissed': _ad_dismissed})
        for filename in sorted(os.listdir(ads_dir)):
            if not filename.endswith('.json'):
                continue
            filepath = os.path.join(ads_dir, filename)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    ad = json.load(f)
                if not isinstance(ad, dict) or not ad.get('enabled', True):
                    continue
                ads.append({
                    'id': ad.get('id', filename.replace('.json', '')),
                    'title': ad.get('title', ''),
                    'body': ad.get('body', ''),
                    'image_url': _safe_ad_url(ad.get('image_url')),
                    'link_url': _safe_ad_url(ad.get('link_url')),
                    'link_text': ad.get('link_text', ''),
                    'display_time': int(ad.get('display_time', 15))
                })
            except Exception as e:
                logging.warning("跳过无法解析的广告文件 %s: %s", filename, e)
                continue
        return jsonify({'status': 'success', 'ads': ads, 'total': len(ads), 'dismissed': _ad_dismissed})
    except Exception as e:
        logging.error(f"获取广告数据失败: {e}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/ads/dismiss', methods=['POST'])
def dismiss_ads():
    global _ad_dismissed
    _ad_dismissed = True
    return jsonify({'status': 'success', 'dismissed': True})

@app.route('/api/ads/reopen', methods=['POST'])
def reopen_ads():
    global _ad_dismissed
    _ad_dismissed = False
    return jsonify({'status': 'success', 'dismissed': False})

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory(os.path.join(BASE_DIR, 'web', 'static'), path)


@app.after_request
def _revalidate_static(response):
    if request.path.startswith('/static/'):
        if request.args.get('v'):
            response.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
        else:
            response.headers['Cache-Control'] = 'no-cache'
    return response

def _run_async_safe(async_func, *args):
    return server.run_coroutine_sync(lambda: async_func(*args), timeout=30)


def _bound_server_port():
    listen_sock = getattr(server, '_listen_sock', None)
    try:
        if listen_sock is not None:
            return listen_sock.getsockname()[1]
    except Exception:
        pass
    return None

def shutdown_pool_service():
    try:
        if not pool_service.has_live_thread:
            return
        if not pool_service.stop():
            logging.warning("代理池未能在超时时间内停止")
    except Exception as e:
        logging.error(f"停止代理池失败: {e}")


atexit.register(shutdown_pool_service)


def shutdown_access_stores():
    for name, store in (('域名统计', getattr(server, 'domain_stats', None)),
                        ('访问记录', getattr(server, 'access_records', None))):
        if store is None:
            continue
        try:
            store.stop()
        except Exception as e:
            logging.error(f"停止{name}失败: {e}")


atexit.register(shutdown_access_stores)

atexit.register(version_checker.stop)


def _signal_handler(signum, frame):
    logging.info("收到终止信号，正在清理...")

    version_checker.stop()
    shutdown_pool_service()
    shutdown_access_stores()

    shutdown_logging(timeout=2.0)

    for handler in logging.getLogger().handlers:
        try:
            handler.flush()
        except Exception:
            pass

    def _force_exit():
        time.sleep(3)
        os._exit(1)

    threading.Thread(target=_force_exit, daemon=True).start()

    sys.exit(0)

signal.signal(signal.SIGINT, _signal_handler)
if os.name != 'nt':
    signal.signal(signal.SIGTERM, _signal_handler)
if hasattr(signal, 'SIGBREAK'):
    signal.signal(signal.SIGBREAK, _signal_handler)

def run_proxy_server():
    try:
        asyncio.run(run_server(server))
    except KeyboardInterrupt:
        logging.info(get_message('user_interrupt', server.language))
    except Exception as e:
        logging.error(f"Proxy server error: {e}")

if __name__ == '__main__':
    enable_safe_console_output()

    setup_logging(config, BASE_DIR)
    web_port = int(config.get('web_port', '5001'))

    if port_in_use(web_port):
        logging.error(get_message('web_port_in_use', server.language, web_port))
        sys.exit(1)

    proxy_port = int(config.get('port', '1080'))
    proxy_port_occupied = port_in_use(proxy_port)
    if proxy_port_occupied:
        logging.error(get_message('port_in_use', server.language, proxy_port))
        logging.error("代理服务跳过启动：修改配置中的 port 后可通过面板重新启动")

    version_checker.start()

    if pool_config_ini.should_autostart_pool(config):
        logging.info(get_message('pool_starting', server.language))
        if pool_service.start():
            logging.info(get_message('pool_start_success', server.language))
        else:
            logging.error(get_message('pool_start_failed', server.language, pool_service.last_error))
    else:
        logging.info(get_message('pool_autostart_skipped', server.language))

    web_url = f"http://127.0.0.1:{web_port}"
    if config.get('token'):
        web_url += f"/web?token={config.get('token')}"
    logging.info(get_message('web_panel_url', server.language, web_url))
    logging.info(get_message('web_panel_notice', server.language))

    if not proxy_port_occupied:
        server.proxy_thread = threading.Thread(target=run_proxy_server, daemon=True)
        server.proxy_thread.start()

    threading.Thread(target=watch_server_config, daemon=True).start()

    from waitress import serve
    try:
        serve(app, host='0.0.0.0', port=web_port, threads=16)
    finally:
        shutdown_pool_service()