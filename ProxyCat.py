from wsgiref import headers
from modules.modules import ColoredFormatter, load_config, DEFAULT_CONFIG, check_proxies, check_for_updates, get_message, load_ip_list, print_banner, logos
import threading, argparse, logging, asyncio, time, socket, signal, sys, os
from concurrent.futures import ThreadPoolExecutor
from modules.proxyserver import AsyncProxyServer
from colorama import init, Fore, Style
from itertools import cycle
from tqdm import tqdm
import base64
from configparser import ConfigParser

init(autoreset=True)

log_format = '%(asctime)s - %(levelname)s - %(message)s'
formatter = ColoredFormatter(log_format)

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)

logging.basicConfig(level=logging.INFO, handlers=[console_handler])

def update_status(server):
    def print_proxy_info():
        status = f"{get_message('current_proxy', server.language)}: {server.current_proxy}"
        logging.info(status)

    def reload_server_config(new_config):
        old_use_getip = server.use_getip
        old_mode = server.mode
        old_port = int(server.config.get('port', '1080'))
        
        server.config.update(new_config)
        
        server.port = int(new_config.get('port', '1080'))
        server.mode = new_config.get('mode', 'cycle')
        server.interval = int(new_config.get('interval', '300'))
        server.language = new_config.get('language', 'cn')
        server.use_getip = new_config.get('use_getip', 'False').lower() == 'true'
        server.check_proxies = new_config.get('check_proxies', 'True').lower() == 'true'
        
        server.username = new_config.get('username', '')
        server.password = new_config.get('password', '')
        server.proxy_username = new_config.get('proxy_username', '')
        server.proxy_password = new_config.get('proxy_password', '')
        server.auth_required = bool(server.username and server.password)
        
        server.proxy_file = new_config.get('proxy_file', 'ip.txt')
        server.whitelist_file = new_config.get('whitelist_file', '')
        server.blacklist_file = new_config.get('blacklist_file', '')
        server.ip_auth_priority = new_config.get('ip_auth_priority', 'whitelist')
        
        server.whitelist = load_ip_list(new_config.get('whitelist_file', ''))
        server.blacklist = load_ip_list(new_config.get('blacklist_file', ''))
        
        if old_use_getip != server.use_getip or old_mode != server.mode:
            if server.use_getip:
                server.proxies = []
                server.proxy_cycle = None
                server.current_proxy = None
                logging.info(get_message('api_mode_notice', server.language))
            else:
                server.proxies = server._load_file_proxies()
                if server.proxies:
                    server.proxy_cycle = cycle(server.proxies)
                    server.current_proxy = next(server.proxy_cycle)
                    if server.check_proxies:
                        asyncio.run(run_proxy_check(server))
        
        if server.use_getip:
            server.getip_url = new_config.get('getip_url', '')
        
        server.last_switch_time = time.time()
        
        nonlocal display_level
        display_level = int(new_config.get('display_level', '1'))
        
        if hasattr(server, 'progress_bar'):
            if not is_docker:
                server.progress_bar.close()
            delattr(server, 'progress_bar')
        if hasattr(server, 'last_update_time'):
            delattr(server, 'last_update_time')
        
        if old_port != server.port:
            logging.info(get_message('port_changed', server.language, old_port, server.port))
        
        logging.info(get_message('config_updated', server.language))

    display_level = int(server.config.get('display_level', '1'))
    is_docker = os.path.exists('/.dockerenv')
    
    config_file = 'config/config.ini'
    ip_file = server.proxy_file
    last_config_modified_time = os.path.getmtime(config_file) if os.path.exists(config_file) else 0
    last_ip_modified_time = os.path.getmtime(ip_file) if os.path.exists(ip_file) else 0
    
    while True:
        try:
            if os.path.exists(config_file):
                current_config_modified_time = os.path.getmtime(config_file)
                if current_config_modified_time > last_config_modified_time:
                    logging.info(get_message('config_file_changed', server.language))
                    new_config = load_config(config_file)
                    reload_server_config(new_config)
                    last_config_modified_time = current_config_modified_time
                    continue
            
            if os.path.exists(ip_file) and not server.use_getip:
                current_ip_modified_time = os.path.getmtime(ip_file)
                if current_ip_modified_time > last_ip_modified_time:
                    logging.info(get_message('proxy_file_changed', server.language))
                    server.proxies = server._load_file_proxies()
                    if server.proxies:
                        server.proxy_cycle = cycle(server.proxies)
                        server.current_proxy = next(server.proxy_cycle)
                        if server.check_proxies:
                            asyncio.run(run_proxy_check(server))
                    last_ip_modified_time = current_ip_modified_time
                    continue

            if display_level == 0:
                if not hasattr(server, 'last_proxy') or server.last_proxy != server.current_proxy:
                    print_proxy_info()
                    server.last_proxy = server.current_proxy
                time.sleep(1)
                continue

            if server.mode == 'load_balance':
                if display_level >= 1:
                    print_proxy_info()
                time.sleep(5)
                continue

            time_left = server.time_until_next_switch()
            if time_left == float('inf'):
                if display_level >= 1:
                    print_proxy_info()
                time.sleep(5)
                continue
            
            if not hasattr(server, 'last_proxy') or server.last_proxy != server.current_proxy:
                print_proxy_info()
                server.last_proxy = server.current_proxy
                if display_level >= 2:
                    logging.info(get_message('proxy_switch_detail', server.language, 
                                          getattr(server, 'previous_proxy', 'None'), 
                                          server.current_proxy))
                server.previous_proxy = server.current_proxy

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

async def handle_client_wrapper(server, reader, writer, clients):
    task = asyncio.create_task(server.handle_client(reader, writer))
    clients.add(task)
    try:
        await task
    except Exception as e:
        logging.error(get_message('client_handle_error', server.language, e))
    finally:
        clients.remove(task)

async def run_server(server):
    try:
        await server.start()
    except asyncio.CancelledError:
        logging.info(get_message('server_closing', server.language))
    except Exception as e:
        if not server.stop_server:
            logging.error(f"Server error: {e}")
    finally:
        await server.stop()

async def run_proxy_check(server):
    if server.config.get('check_proxies', 'False').lower() == 'true':
        logging.info(get_message('proxy_check_start', server.language))
        valid_proxies = await check_proxies(server.proxies)
        if valid_proxies:
            server.proxies = valid_proxies
            server.proxy_cycle = cycle(valid_proxies)
            server.current_proxy = next(server.proxy_cycle)
            logging.info(get_message('valid_proxies', server.language, valid_proxies))
        else:
            logging.error(get_message('no_valid_proxies', server.language))
    else:
        logging.info(get_message('proxy_check_disabled', server.language))

class ProxyCat:
    def __init__(self):
        self.executor = ThreadPoolExecutor(
            max_workers=min(32, (os.cpu_count() or 1) * 4),
            thread_name_prefix="proxy_worker"
        )

        loop = asyncio.get_event_loop()
        loop.set_default_executor(self.executor)
        
        if hasattr(asyncio, 'WindowsSelectorEventLoopPolicy'):
            if os.name == 'nt':
                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

        socket.setdefaulttimeout(30)
        if hasattr(socket, 'TCP_NODELAY'):
            socket.TCP_NODELAY = True
        
        self.running = True

        signal.signal(signal.SIGINT, self.handle_shutdown)
        signal.signal(signal.SIGTERM, self.handle_shutdown)
        self.config = load_config('config/config.ini')
        self.language = self.config.get('language', 'cn').lower()
        
        self.users = {}
        config = ConfigParser()
        config.read('config/config.ini', encoding='utf-8')
        if config.has_section('Users'):
            self.users = dict(config.items('Users'))
        self.auth_required = bool(self.users)

    async def start_server(self):
        try:
            server = await asyncio.start_server(
                self.handle_client,
                self.config.get('SERVER', 'host'),
                self.config.get('SERVER', 'port')
            )
            logging.info(get_message('server_running', self.language,
                self.config.get('SERVER', 'host'),
                self.config.get('SERVER', 'port')))
            
            async with server:
                await server.serve_forever()
        except Exception as e:
            logging.error(get_message('server_start_error', self.language, e))
            sys.exit(1)

    def handle_shutdown(self, signum, frame):
        logging.info(get_message('server_shutting_down', self.language))
        self.running = False
        self.executor.shutdown(wait=True)
        sys.exit(0)

    async def handle_client(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        try:
            if self.auth_required:
                auth_header = headers.get('proxy-authorization')
                if not auth_header or not self._authenticate(auth_header):
                    writer.write(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Proxy"\r\n\r\n')
                    await writer.drain()
                    return
            
            await asyncio.get_event_loop().run_in_executor(
                self.executor, 
                self.process_client_request,
                reader, 
                writer
            )
        except Exception as e:
            logging.error(get_message('client_process_error', self.language, e))
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass

    def _authenticate(self, auth_header):
        if not self.users:
            return True
        
        try:
            scheme, credentials = auth_header.split()
            if scheme.lower() != 'basic':
                return False
            
            decoded_auth = base64.b64decode(credentials).decode()
            username, password = decoded_auth.split(':')
            
            return username in self.users and self.users[username] == password
        except:
            return False

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=logos())
    parser.add_argument('-c', '--config', default='config/config.ini', help='配置文件路径')
    args = parser.parse_args()
    config = load_config(args.config)
    server = AsyncProxyServer(config)
    print_banner(config)
    asyncio.run(check_for_updates(config.get('language', 'cn').lower()))
    if not config.get('use_getip', 'False').lower() == 'true':
        asyncio.run(run_proxy_check(server))
    else:
        logging.info(get_message('api_mode_notice', server.language))
    
    status_thread = threading.Thread(target=update_status, args=(server,), daemon=True)
    status_thread.start()
    
    try:
        asyncio.run(run_server(server))
    except KeyboardInterrupt:
        logging.info(get_message('user_interrupt', server.language))
