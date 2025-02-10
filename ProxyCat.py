from modules.modules import load_config, DEFAULT_CONFIG, check_proxies, check_for_updates, get_message, print_banner, logos
import threading, argparse, logging, asyncio, time, socket, signal, sys, os
from concurrent.futures import ThreadPoolExecutor
from modules.proxyserver import AsyncProxyServer
from colorama import init, Fore, Style
from itertools import cycle

init(autoreset=True)

class ColoredFormatter(logging.Formatter):
    COLORS = {
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT,
    }

    def format(self, record):
        log_color = self.COLORS.get(record.levelno, Fore.WHITE)
        record.msg = f"{log_color}{record.msg}{Style.RESET_ALL}"
        return super().format(record)

log_format = '%(asctime)s - %(levelname)s - %(message)s'
formatter = ColoredFormatter(log_format)

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)

logging.basicConfig(level=logging.INFO, handlers=[console_handler])

def update_status(server):
    while True:
        try:
            if server.mode == 'load_balance':
                status = f"\r{Fore.YELLOW}{get_message('current_proxy', server.language)}: {Fore.GREEN}{server.current_proxy}"
            else:
                time_left = server.time_until_next_switch()
                if time_left == float('inf'):
                    status = f"\r{Fore.YELLOW}{get_message('current_proxy', server.language)}: {Fore.GREEN}{server.current_proxy}"
                else:
                    status = f"\r{Fore.YELLOW}{get_message('current_proxy', server.language)}: {Fore.GREEN}{server.current_proxy} | {Fore.YELLOW}{get_message('next_switch', server.language)}: {Fore.GREEN}{time_left:.1f}{get_message('seconds', server.language)}"

            if os.path.exists('/.dockerenv'):
                logging.info(status)
            else:
                print(status, end='', flush=True)
                
        except Exception as e:
            logging.error(f"Status update error: {e}")
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
    clients = set()
    server_instance = None
    try:
        server_instance = await asyncio.start_server(
            lambda r, w: handle_client_wrapper(server, r, w, clients),
            '0.0.0.0', 
            int(server.config['port']),
            limit=256 * 1024
        )
        async with server_instance:
            await server_instance.serve_forever()
    except asyncio.CancelledError:
        logging.info(get_message('server_closing', server.language))
    finally:
        if server_instance:
            server_instance.close()
            await server_instance.wait_closed()
        for client in clients:
            client.cancel()
        await asyncio.gather(*clients, return_exceptions=True)

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
        self.language = config.get('language', 'cn').lower()

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
        try:
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
