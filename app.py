from flask import Flask, render_template, jsonify, request, redirect, url_for, send_from_directory
import sys
import os
import logging
from datetime import datetime
import json
from configparser import ConfigParser
from itertools import cycle
import werkzeug.serving
from functools import wraps

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ProxyCat import run_server
from modules.modules import load_config, check_proxies, get_message, load_ip_list
from modules.proxyserver import AsyncProxyServer
import asyncio
import threading
import time

app = Flask(__name__, 
           template_folder='web/templates',
           static_folder='web/static') 

werkzeug.serving.WSGIRequestHandler.log = lambda self, type, message, *args: None
logging.getLogger('werkzeug').setLevel(logging.ERROR)

config = load_config('config/config.ini')
server = AsyncProxyServer(config)

def get_config_path(filename):
    return os.path.join('config', filename)

log_file = 'logs/proxycat.log'
os.makedirs('logs', exist_ok=True)
log_messages = []
max_log_messages = 10000

class CustomFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        return datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S')

def setup_logging():
    file_formatter = CustomFormatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setFormatter(file_formatter)

    console_handler = logging.StreamHandler()
    console_formatter = CustomFormatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)

    memory_handler = MemoryHandler()
    memory_handler.setFormatter(CustomFormatter('%(message)s'))

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    root_logger.addHandler(memory_handler)

class MemoryHandler(logging.Handler):
    def emit(self, record):
        global log_messages
        log_messages.append({
            'time': datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S'),
            'level': record.levelname,
            'message': self.format(record)
        })
        if len(log_messages) > max_log_messages:
            log_messages = log_messages[-max_log_messages:]

def require_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.args.get('token')
        config_token = server.config.get('token', '')
        
        if not config_token:
            return f(*args, **kwargs)
            
        if not token or token != config_token:
            return jsonify({
                'status': 'error',
                'message': get_message('invalid_token', server.language)
            }), 401
            
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def root():
    token = request.args.get('token')
    if token:
        return redirect(f'/web?token={token}')
    return redirect('/web')

@app.route('/web')
@require_token
def web():
    return render_template('index.html')

@app.route('/api/status')
@require_token
def get_status():
    with open('config/config.ini', 'r', encoding='utf-8') as f:
        config_content = f.read()
        
    config = ConfigParser()
    config.read('config/config.ini', encoding='utf-8')
    
    server_config = dict(config.items('Server')) if config.has_section('Server') else {}
    
    current_proxy = server.current_proxy
    if not current_proxy and not server.use_getip:
        if hasattr(server, 'proxies') and server.proxies:
            current_proxy = server.proxies[0]
        else:
            current_proxy = get_message('no_proxy', server.language)
    
    return jsonify({
        'current_proxy': current_proxy,
        'mode': server.mode,
        'port': int(server_config.get('port', '1080')),
        'interval': server.interval,
        'time_left': server.time_until_next_switch(),
        'total_proxies': len(server.proxies) if hasattr(server, 'proxies') else 0,
        'use_getip': server.use_getip,
        'getip_url': getattr(server, 'getip_url', '') if getattr(server, 'use_getip', False) else '',
        'auth_required': server.auth_required,
        'display_level': int(config.get('DEFAULT', 'display_level', fallback='1')),
        'service_status': 'running' if server.running else 'stopped',
        'config': {
            'port': server_config.get('port', ''),
            'mode': server_config.get('mode', 'cycle'),
            'interval': server_config.get('interval', ''),
            'username': server_config.get('username', ''),
            'password': server_config.get('password', ''),
            'use_getip': server_config.get('use_getip', 'False'),
            'getip_url': server_config.get('getip_url', ''),
            'proxy_username': server_config.get('proxy_username', ''),
            'proxy_password': server_config.get('proxy_password', ''),
            'proxy_file': server_config.get('proxy_file', ''),
            'check_proxies': server_config.get('check_proxies', 'False'),
            'language': server_config.get('language', 'cn'),
            'whitelist_file': server_config.get('whitelist_file', ''),
            'blacklist_file': server_config.get('blacklist_file', ''),
            'ip_auth_priority': server_config.get('ip_auth_priority', 'whitelist'),
            'display_level': config.get('DEFAULT', 'display_level', fallback='1'),
            'raw_content': config_content 
        }
    })

@app.route('/api/config', methods=['POST'])
def save_config():
    try:
        new_config = request.get_json()
        current_config = load_config('config/config.ini')
        port_changed = str(new_config.get('port', '')) != str(current_config.get('port', ''))
        
        config_parser = ConfigParser()
        config_parser.read('config/config.ini', encoding='utf-8')
        
        if not config_parser.has_section('Server'):
            config_parser.add_section('Server')
            
        for key, value in new_config.items():
            if key != 'users':
                config_parser.set('Server', key, str(value))
        
        with open('config/config.ini', 'w', encoding='utf-8') as f:
            config_parser.write(f)
            
        server.config = load_config('config/config.ini')
        server._init_config_values(server.config)
        
        return jsonify({
            'status': 'success',
            'port_changed': port_changed
        })
        
    except Exception as e:
        logging.error(f"Error saving config: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        })

@app.route('/api/proxies', methods=['GET', 'POST'])
def handle_proxies():
    if request.method == 'POST':
        try:
            proxies = request.json.get('proxies', [])
            proxy_file = get_config_path(os.path.basename(server.proxy_file))
            with open(proxy_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(proxies))
            server.proxies = server._load_file_proxies()
            if server.proxies:
                server.proxy_cycle = cycle(server.proxies)
                server.current_proxy = next(server.proxy_cycle)
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
            with open(proxy_file, 'r', encoding='utf-8') as f:
                proxies = f.read().splitlines()
            return jsonify({'proxies': proxies})
        except Exception:
            return jsonify({'proxies': []})

@app.route('/api/check_proxies')
def check_proxies_api():
    try:
        test_url = request.args.get('test_url', 'https://www.baidu.com')
        valid_proxies = asyncio.run(check_proxies(server.proxies, test_url))
        total_valid = len(valid_proxies)
        return jsonify({
            'status': 'success',
            'valid_proxies': valid_proxies,
            'total': total_valid,
            'message': get_message('proxy_check_result', server.language, total_valid)
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': get_message('proxy_check_failed', server.language, str(e))
        })

@app.route('/api/ip_lists', methods=['GET', 'POST'])
def handle_ip_lists():
    if request.method == 'POST':
        try:
            list_type = request.json.get('type')
            ip_list = request.json.get('list', [])
            base_filename = os.path.basename(server.whitelist_file if list_type == 'whitelist' else server.blacklist_file)
            filename = get_config_path(base_filename)
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write('\n'.join(ip_list))
            
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

@app.route('/api/logs')
def get_logs():
    try:
        start = int(request.args.get('start', 0))
        limit = int(request.args.get('limit', 100))
        level = request.args.get('level', 'ALL')
        search = request.args.get('search', '').lower()
        
        filtered_logs = log_messages
        
        if level != 'ALL':
            filtered_logs = [log for log in log_messages if log['level'] == level]
        
        if search:
            filtered_logs = [
                log for log in filtered_logs 
                if search in log['message'].lower() or 
                   search in log['level'].lower() or 
                   search in log['time'].lower()
            ]
        
        return jsonify({
            'logs': filtered_logs[start:start+limit],
            'total': len(filtered_logs),
            'status': 'success'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        })

@app.route('/api/logs/clear', methods=['POST'])
def clear_logs():
    try:
        global log_messages
        log_messages = []
        
        with open(log_file, 'w', encoding='utf-8') as f:
            f.write('')
            
        return jsonify({
            'status': 'success',
            'message': get_message('logs_cleared', server.language)
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': get_message('clear_logs_failed', server.language, str(e))
        })

@app.route('/api/switch_proxy')
@require_token
def switch_proxy():
    try:
        if server.use_getip:
            from config.getip import newip
            try:
                old_proxy = server.current_proxy
                new_proxy = newip()
                server.current_proxy = new_proxy
                server.last_switch_time = time.time()
                server._log_proxy_switch(old_proxy, new_proxy)
                return jsonify({
                    'status': 'success',
                    'current_proxy': server.current_proxy,
                    'message': get_message('switch_success', server.language)
                })
            except Exception as e:
                return jsonify({
                    'status': 'error',
                    'message': get_message('get_proxy_failed', server.language, str(e))
                })
        else:
            if not server.proxies:
                server.proxies = server._load_file_proxies()
                if server.proxies:
                    server.proxy_cycle = cycle(server.proxies)
                    
            if server.proxy_cycle:
                old_proxy = server.current_proxy
                server.current_proxy = next(server.proxy_cycle)
                server.last_switch_time = time.time()
                server._log_proxy_switch(old_proxy, server.current_proxy)
                return jsonify({
                    'status': 'success',
                    'current_proxy': server.current_proxy,
                    'message': get_message('switch_success', server.language)
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': get_message('no_proxies_available', server.language)
                })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': get_message('switch_failed', server.language, str(e))
        })

@app.route('/api/service', methods=['POST'])
@require_token
def control_service():
    try:
        action = request.json.get('action')
        if action == 'start':
            if not server.running:
                server.stop_server = False
                if hasattr(server, 'proxy_thread') and server.proxy_thread and server.proxy_thread.is_alive():
                    server.proxy_thread.join(timeout=5)
                server.proxy_thread = threading.Thread(target=lambda: asyncio.run(run_server(server)), daemon=True)
                server.proxy_thread.start()
                
                for _ in range(10):
                    if server.running:
                        break
                    time.sleep(0.5)
                    
                if server.running:
                    return jsonify({
                        'status': 'success',
                        'message': get_message('service_start_success', server.language),
                        'service_status': 'running'
                    })
                else:
                    return jsonify({
                        'status': 'error',
                        'message': get_message('service_start_failed', server.language),
                        'service_status': 'stopped'
                    })
            return jsonify({
                'status': 'success',
                'message': get_message('service_already_running', server.language),
                'service_status': 'running'
            })
            
        elif action == 'stop':
            if server.running:
                server.stop_server = True
                server.running = False
                
                if server.server_instance:
                    server.server_instance.close()
                
                if hasattr(server, 'proxy_thread') and server.proxy_thread:
                    server.proxy_thread = None
                
                for _ in range(5):
                    if server.server_instance is None:
                        break
                    time.sleep(0.2)
                
                return jsonify({
                    'status': 'success',
                    'message': get_message('service_stop_success', server.language),
                    'service_status': 'stopped'
                })
            return jsonify({
                'status': 'success',
                'message': get_message('service_not_running', server.language),
                'service_status': 'stopped'
            })
            
        elif action == 'restart':
            if server.running:
                server.stop_server = True
                if server.server_instance:
                    server.server_instance.close()
                
                for _ in range(10):
                    if not server.running:
                        break
                    time.sleep(0.5)
                
                if server.running:
                    if hasattr(server, 'proxy_thread') and server.proxy_thread:
                        server.proxy_thread = None
                    server.running = False
            
            server.stop_server = False
            server.proxy_thread = threading.Thread(target=lambda: asyncio.run(run_server(server)), daemon=True)
            server.proxy_thread.start()
            
            for _ in range(10):
                if server.running:
                    break
                time.sleep(0.5)
            
            if server.running:
                return jsonify({
                    'status': 'success',
                    'message': get_message('service_restart_success', server.language)
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': get_message('service_restart_failed', server.language)
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
def change_language():
    try:
        new_language = request.json.get('language', 'cn')
        if new_language not in ['cn', 'en']:
            return jsonify({
                'status': 'error',
                'message': get_message('unsupported_language', server.language)
            })
        
        config = ConfigParser()
        config.read('config/config.ini', encoding='utf-8')
        
        if 'Server' not in config:
            config.add_section('Server')
        
        config.set('Server', 'language', new_language)
        
        with open('config/config.ini', 'w', encoding='utf-8') as f:
            config.write(f)
            
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

@app.route('/api/version')
def check_version():
    try:
        import re
        import httpx
        from packaging import version
        import logging
        
        httpx_logger = logging.getLogger('httpx')
        original_level = httpx_logger.level
        httpx_logger.setLevel(logging.WARNING)
        
        CURRENT_VERSION = "ProxyCat-V2.0.1"
        
        try:
            client = httpx.Client(transport=httpx.HTTPTransport(retries=3))
            response = client.get("https://y.shironekosan.cn/1.html", timeout=10)
            response.raise_for_status()
            content = response.text
            
            match = re.search(r'<p>(ProxyCat-V\d+\.\d+\.\d+)</p>', content)
            if match:
                latest_version = match.group(1)
                is_latest = version.parse(latest_version.split('-V')[1]) <= version.parse(CURRENT_VERSION.split('-V')[1])
                
                return jsonify({
                    'status': 'success',
                    'is_latest': is_latest,
                    'current_version': CURRENT_VERSION,
                    'latest_version': latest_version
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': get_message('version_info_not_found', server.language)
                })
        finally:
            httpx_logger.setLevel(original_level)
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': get_message('update_check_error', server.language, str(e))
        })

@app.route('/api/users', methods=['GET', 'POST'])
@require_token
def handle_users():
    if request.method == 'POST':
        try:
            users = request.json.get('users', {})
            config = ConfigParser()
            config.read('config/config.ini', encoding='utf-8')
            
            sections_to_preserve = {}
            for section in config.sections():
                if section != 'Users':
                    sections_to_preserve[section] = dict(config.items(section))

            config = ConfigParser()
            
            for section, options in sections_to_preserve.items():
                config.add_section(section)
                for key, value in options.items():
                    config.set(section, key, value)
            
            if users:
                config.add_section('Users')
                for username, password in users.items():
                    config.set('Users', username, password)
            
            with open('config/config.ini', 'w', encoding='utf-8') as f:
                config.write(f)
            
            server.users = users
            server.auth_required = bool(users)
            
            if hasattr(server, 'proxy_server') and server.proxy_server:
                server.proxy_server.users = users
                server.proxy_server.auth_required = bool(users)
            
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
            config = ConfigParser()
            config.read('config/config.ini', encoding='utf-8')
            users = {}
            if config.has_section('Users'):
                users = dict(config.items('Users'))
            return jsonify({'users': users})
        except Exception as e:
            logging.error(f"Error getting users: {e}")
            return jsonify({'users': {}})

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('web/static', path)

def run_proxy_server():
    try:
        asyncio.run(run_server(server))
    except KeyboardInterrupt:
        logging.info(get_message('user_interrupt', server.language))
    except Exception as e:
        logging.error(f"Proxy server error: {e}")

if __name__ == '__main__':
    setup_logging()
    web_port = int(config.get('web_port', '5000'))
    web_url = f"http://127.0.0.1:{web_port}"
    if config.get('token'):
        web_url += f"?token={config.get('token')}"
    
    logging.info(get_message('web_panel_url', server.language, web_url))
    logging.info(get_message('web_panel_notice', server.language))

    proxy_thread = threading.Thread(target=run_proxy_server, daemon=True)
    proxy_thread.start()
    
    app.run(host='0.0.0.0', port=web_port)