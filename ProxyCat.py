"""
模块名称：ProxyCat
功能描述：代理轮换服务的命令行入口，解析 -c/--config 配置，装配日志与信号处理，创建池服务与出口代理服务并管理其启停，常驻热重载配置与代理文件并刷新控制台状态。
职责边界：负责：命令行参数解析、日志与信号装配、池与出口服务的创建启停、热重载与状态显示；
          不负责：代理切换与转发（见 modules/proxyserver.py）、池抓取与验证（见 proxypool 包）；
          配置项定义与校验由 modules.modules、modules.config_validation 与 pool_config_ini 负责。
关键依赖：modules.modules、modules.logging_setup、modules.proxyserver、modules.proxypool_service、
          modules.pool_config_ini、modules.version_check；第三方 colorama、tqdm。
已知限制：
1. 热重载的代理文件监控与启动预检都只覆盖 local 来源，API 与池模式只能靠运行期反馈判断代理可用性。
2. 控制台日志级别固定为 WARNING；关键状态与版本检查结果直接写终端（print / tqdm.write），不依赖日志流展示。
3. 端口被占用时进程以退出码 1 退出；运行期改 port 只记日志、不重绑监听，热重载时该变更在 main 与 proxy 两个日志类别各记一条，换端口须重启进程。
4. 倒计时进度条只在按时间切换模式下绘制，其余模式仅在出口名册变化时打印一次出口清单。
5. 状态监控线程为守护线程，单轮异常被捕获后循环继续，线程卡死时无外部机制能发现。
6. SIGTERM 只在非 Windows 平台注册，Windows 仅依赖 SIGINT 触发收尾。
7. 判断轮换模式是否变化时，须把配置中的 mode 按来源归一后再与 server.mode 比较，直接比较原始配置值会把归一后相同的模式误判为已切换。
"""

from modules.modules import load_config, get_message, print_banner, port_in_use, strip_deprecated_server_keys, migrate_pool_proxy_count, migrate_getip_url, enable_safe_console_output, normalize_rotation_mode, list_files_snapshot, reload_ip_lists_if_changed
from modules.logging_setup import setup_logging, shutdown_logging
import threading, argparse, logging, asyncio, time, os, signal, sys
from modules.proxyserver import AsyncProxyServer, run_server
from modules import pool_config_ini
from modules.proxypool_service import ProxyPoolService
from modules.version_check import VersionChecker
from colorama import init, Fore, Style
from tqdm import tqdm

init(autoreset=True)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def reload_server_config(server, new_config, ip_file, last_ip_modified_time):
    old_source_mode = server.proxy_source_mode
    old_mode = server.mode
    old_port = int(server.config.get('port', '1080'))
    old_revision = server.roster_revision()

    new_source_mode = new_config.get('proxy_source_mode', 'local').lower()
    server.apply_config_sync(
        new_config,
        mode_changed=(
            old_mode
            != normalize_rotation_mode(new_config.get('mode', 'cycle'), new_source_mode)),
        source_mode_changed=old_source_mode != new_source_mode,
        reset_switch_timers=True,
    )

    mode_changed = old_source_mode != server.proxy_source_mode or old_mode != server.mode
    if mode_changed:
        last_ip_modified_time = (
            os.path.getmtime(server.proxy_file) if os.path.exists(server.proxy_file) else 0
        )
    elif server.proxy_file != ip_file:
        last_ip_modified_time = 0

    if old_port != server.port:
        logging.info(get_message('port_changed', server.language, old_port, server.port))

    if server.roster_revision() != old_revision:
        logging.info(get_message('proxy_workers_ready', server.language, len(server.proxies)))

    return server.proxy_file, last_ip_modified_time, int(server.config.get('display_level', '1'))


def print_version_result(payload, language='cn'):
    if not payload or payload.get('status') != 'success':
        return
    if payload.get('is_latest'):
        line = get_message('latest_version', language)
    else:
        line = get_message(
            'new_version_available', language,
            payload.get('latest_version', ''), payload.get('current_version', ''),
        )
    tqdm.write(f"{Fore.CYAN}{line}{Style.RESET_ALL}")


def _exit_remaining(exit_info, mode, language):
    parts = []
    if mode == 'time' and exit_info['expires_in'] is not None:
        parts.append(f"{int(round(exit_info['expires_in']))}{get_message('seconds', language)}")
    if mode in ('time', 'request_count') and exit_info['requests_left'] is not None:
        parts.append(get_message('exit_left_requests', language, exit_info['requests_left']))
    if not parts:
        return get_message('exit_left_none', language)
    return ' · '.join(parts)


def format_exit_status(server):
    language = server.language
    mode = server.switch_countdown_mode()
    exits = server.active_workers()
    summary_key = ('exits_summary_expanded' if server.elastic_active
                   else 'exits_summary')
    lines = [get_message(summary_key, language, len(exits), server.exit_count)]
    for exit_info in exits:
        capacity = exit_info['capacity']
        load = (f"{exit_info['active']}/{capacity}" if capacity
                else get_message('exit_load_no_cap', language, exit_info['active']))
        lines.append(get_message(
            'exit_line', language, exit_info['url'], load,
            _exit_remaining(exit_info, mode, language),
        ))
    return lines


def update_status(server, config_file):
    def print_proxy_info():
        for line in format_exit_status(server):
            logging.info(line)
            print(line)

    def roster_changed():
        revision = server.roster_revision()
        if getattr(server, 'last_roster_revision', None) == revision:
            return False
        server.last_roster_revision = revision
        return True

    ip_file = server.proxy_file
    last_config_modified_time = os.path.getmtime(config_file) if os.path.exists(config_file) else 0
    last_ip_modified_time = os.path.getmtime(ip_file) if os.path.exists(ip_file) else 0
    display_level = int(server.config.get('display_level', '1'))
    is_docker = os.path.exists('/.dockerenv')
    list_snapshot = list_files_snapshot(server)

    while True:
        try:
            list_snapshot = reload_ip_lists_if_changed(server, list_snapshot)

            if os.path.exists(config_file):
                current_config_modified_time = os.path.getmtime(config_file)
                if current_config_modified_time > last_config_modified_time:
                    logging.info(get_message('config_file_changed', server.language))
                    new_config = load_config(config_file)
                    ip_file, last_ip_modified_time, display_level = reload_server_config(
                        server, new_config, ip_file, last_ip_modified_time
                    )
                    last_config_modified_time = current_config_modified_time
                    continue

            if os.path.exists(ip_file) and server.proxy_source_mode == 'local':
                current_ip_modified_time = os.path.getmtime(ip_file)
                if current_ip_modified_time > last_ip_modified_time:
                    logging.info(get_message('proxy_file_changed', server.language))
                    server.reload_local_proxies(run_check=True)
                    last_ip_modified_time = current_ip_modified_time
                    continue

            if display_level == 0:
                if roster_changed():
                    print_proxy_info()
                time.sleep(1)
                continue

            if server.mode == 'loadbalance':
                if display_level >= 1 and roster_changed():
                    print_proxy_info()
                time.sleep(5)
                continue

            if server.switch_countdown_mode() != 'time':
                if display_level >= 1 and roster_changed():
                    print_proxy_info()
                time.sleep(5)
                continue

            time_left = server.time_until_next_switch()
            if roster_changed():
                print_proxy_info()

            total_time = int(server.interval)
            elapsed_time = total_time - int(time_left)

            if display_level >= 1:
                if elapsed_time > total_time:
                    if hasattr(server, 'progress_bar'):
                        if not is_docker:
                            server.progress_bar.n = total_time
                            server.progress_bar.refresh()
                            server.progress_bar.close()
                        delattr(server, 'progress_bar')
                    if hasattr(server, 'last_update_time'):
                        delattr(server, 'last_update_time')
                    time.sleep(0.5)
                    continue

                if is_docker:
                    if not hasattr(server, 'last_update_time') or \
                       (time.time() - server.last_update_time >= (5 if display_level == 1 else 1) and elapsed_time <= total_time):
                        if display_level >= 2:
                            logging.info(f"{get_message('next_switch', server.language)}: {time_left:.0f} {get_message('seconds', server.language)} ({elapsed_time}/{total_time})")
                        else:
                            logging.info(f"{get_message('next_switch', server.language)}: {time_left:.0f} {get_message('seconds', server.language)}")
                        server.last_update_time = time.time()
                else:
                    if not hasattr(server, 'progress_bar'):
                        server.progress_bar = tqdm(
                            total=total_time,
                            desc=f"{Fore.YELLOW}{get_message('next_switch', server.language)}{Style.RESET_ALL}",
                            bar_format='{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} ' + get_message('seconds', server.language),
                            colour='green'
                        )

                    server.progress_bar.n = min(elapsed_time, total_time)
                    server.progress_bar.refresh()

        except Exception as e:
            if display_level >= 2:
                logging.error(f"Status update error: {e}")
            elif display_level >= 1:
                logging.error(get_message('status_update_error', server.language))
        time.sleep(1)


if __name__ == '__main__':
    enable_safe_console_output()

    parser = argparse.ArgumentParser(description='ProxyCat - 代理轮换工具')
    parser.add_argument('-c', '--config', default=os.path.join(BASE_DIR, 'config', 'config.ini'), help='配置文件路径')
    args = parser.parse_args()
    config = load_config(args.config)

    setup_logging(config, BASE_DIR, console_level=logging.WARNING)

    migrate_pool_proxy_count(args.config)
    migrate_getip_url(args.config)
    strip_deprecated_server_keys(args.config)
    pool_config_ini.ensure_pool_section(
        args.config,
        os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            'modules', 'proxypool', 'config.yaml',
        ),
    )
    sections = pool_config_ini.read_ini_sections(args.config)
    pool_config = pool_config_ini.build_pool_config(
        sections.get('Server', {}),
        sections.get(pool_config_ini.POOL_SECTION, {}),
        strict=False,
    )
    pool_service = ProxyPoolService(
        pool_config,
        config_ini_path=args.config,
        language_provider=lambda: server.language,
    )

    server = AsyncProxyServer(config, pool_service=pool_service)
    print_banner(config)

    version_language = config.get('language', 'cn')
    version_checker = VersionChecker(
        os.path.join(BASE_DIR, 'logs', 'version_check.json'),
        language_provider=lambda: version_language,
        on_result=lambda payload: print_version_result(payload, version_language),
    )
    if not version_checker.start():
        print_version_result(version_checker.result_payload(), version_language)

    def _handle_signal(sig, frame):
        server.stop_server = True
        logging.info(get_message('server_closing', config.get('language', 'cn')))
        raise KeyboardInterrupt
    signal.signal(signal.SIGINT, _handle_signal)
    if os.name != 'nt':
        signal.signal(signal.SIGTERM, _handle_signal)

    async def main():
        proxy_port = int(config.get('port', '1080'))
        if port_in_use(proxy_port):
            logging.error(get_message('port_in_use', config.get('language', 'cn'), proxy_port))
            sys.exit(1)

        if pool_config_ini.should_autostart_pool(config):
            logging.info(get_message('pool_starting', server.language))
            if pool_service.start():
                logging.info(get_message('pool_start_success', server.language))
            else:
                logging.error(get_message('pool_start_failed', server.language,
                                          pool_service.last_error))
        else:
            logging.info(get_message('pool_autostart_skipped', server.language))
        proxy_mode = config.get('proxy_source_mode', 'local').lower()
        if proxy_mode == 'local':
            await server.run_startup_check()
        else:
            notice = 'api_mode_notice' if proxy_mode == 'api' else 'pool_mode_notice'
            logging.info(get_message(notice, server.language))
        await run_server(server)

    status_thread = threading.Thread(
        target=update_status, args=(server, args.config), daemon=True
    )
    status_thread.start()

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info(get_message('user_interrupt', server.language))
    finally:
        pool_service.stop()
        version_checker.stop()
        shutdown_logging()
