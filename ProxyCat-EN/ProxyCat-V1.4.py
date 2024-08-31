from httpx import AsyncClient, TimeoutException
from colorama import init, Fore
from packaging import version
from itertools import cycle
import configparser
import threading
import logoprint
import argparse
import logging
import asyncio
import socket
import base64
import getip
import httpx
import time
import re

init(autoreset=True)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_config(config_file='config.ini'):
    config = configparser.ConfigParser()
    config.read(config_file, encoding='utf-8')
    return config['SETTINGS']

def load_proxies(file_path='ip.txt'):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file if '://' in line]

class AsyncProxyServer:
    def __init__(self, config):
        self.config = config
        self.username = config.get('username', '').strip()
        self.password = config.get('password', '').strip()
        self.auth_required = bool(self.username and self.password)
        self.mode = config.get('mode', 'cycle')
        self.interval = config.getint('interval', 300)
        self.use_getip = config.getboolean('use_getip', False)
        self.proxy_file = config.get('proxy_file', 'ip.txt')
        self.proxies = self.load_proxies()
        self.initial_proxy = self.proxies[0] if self.proxies else "No proxy available"
        self.proxy_cycle = cycle(self.proxies)
        self.current_proxy = self.initial_proxy
        self.last_switch_time = time.time()
        self.rate_limiter = asyncio.Queue(maxsize=3000)

    def load_proxies(self):
        if self.use_getip:
            return [getip.newip()]
        else:
            return load_proxies(self.proxy_file)

    async def get_next_proxy(self):
        current_time = time.time()
        if current_time - self.last_switch_time >= self.interval:
            if self.use_getip:
                self.current_proxy = getip.newip()
            else:
                self.current_proxy = next(self.proxy_cycle)
            self.last_switch_time = current_time
            logging.info(f"Switch to a new proxy: {self.current_proxy}")
        return self.current_proxy

    def time_until_next_switch(self):
        return max(0, self.interval - (time.time() - self.last_switch_time))

    async def acquire(self):
        await self.rate_limiter.put(None)
        await asyncio.sleep(0.001)
        self.rate_limiter.get_nowait()

    async def handle_client(self, reader, writer):
        try:
            await asyncio.shield(self._handle_client_impl(reader, writer))
        except asyncio.CancelledError:
            logging.info("Client process canceled")
        except Exception as e:
            logging.error(f"Client processing error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def _handle_client_impl(self, reader, writer):
        try:
            await self.acquire()
            request_line = await reader.readline()
            if not request_line:
                return

            try:
                method, path, _ = request_line.decode('utf-8', errors='ignore').split()
            except ValueError:
                logging.error(f"Invalid request line: {request_line}")
                return

            headers = {}
            while True:
                line = await reader.readline()
                if line == b'\r\n':
                    break
                if line == b'':
                    return
                try:
                    name, value = line.decode('utf-8', errors='ignore').strip().split(': ', 1)
                    headers[name.lower()] = value
                except ValueError:
                    logging.error(f"Invalid request line: {line}")
                    continue

            if self.auth_required and not self._authenticate(headers):
                writer.write(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Proxy"\r\n\r\n')
                await writer.drain()
                return

            if method == 'CONNECT':
                await self._handle_connect(path, reader, writer)
            else:
                await self._handle_request(method, path, headers, reader, writer)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logging.error(f"An error occurred while processing the client request: {e}")

    def _authenticate(self, headers):
        if not self.auth_required:
            return True
        
        auth = headers.get('proxy-authorization')
        if not auth:
            return False
        try:
            scheme, credentials = auth.split()
            if scheme.lower() != 'basic':
                return False
            username, password = base64.b64decode(credentials).decode().split(':')
            return username == self.username and password == self.password
        except:
            return False

    async def _handle_connect(self, path, reader, writer):
        try:
            host, port = path.split(':')
            port = int(port)
        except ValueError:
            logging.error(f"Invalid CONNECT path: {path}")
            writer.write(b'HTTP/1.1 400 Bad Request\r\n\r\n')
            await writer.drain()
            return

        proxy = await self.get_next_proxy()
        proxy_type, proxy_addr = proxy.split('://')
        proxy_auth, proxy_host_port = self._split_proxy_auth(proxy_addr)
        proxy_host, proxy_port = proxy_host_port.split(':')
        proxy_port = int(proxy_port)

        try:
            async with asyncio.timeout(10):
                remote_reader, remote_writer = await asyncio.open_connection(proxy_host, proxy_port)

            if proxy_type == 'http':
                connect_headers = [f'CONNECT {host}:{port} HTTP/1.1', f'Host: {host}:{port}']
                if proxy_auth:
                    auth_header = f'Proxy-Authorization: Basic {base64.b64encode(proxy_auth.encode()).decode()}'
                    connect_headers.append(auth_header)
                connect_request = '\r\n'.join(connect_headers) + '\r\n\r\n'
                remote_writer.write(connect_request.encode())
                await remote_writer.drain()
                response = await remote_reader.readline()
                if not response.startswith(b'HTTP/1.1 200'):
                    raise Exception("Bad Gateway")
                while (await remote_reader.readline()) != b'\r\n':
                    pass
            elif proxy_type in ['socks4', 'socks5']:
                if proxy_type == 'socks4':
                    remote_writer.write(b'\x04\x01' + port.to_bytes(2, 'big') + socket.inet_aton(host) + b'\x00')
                else:
                    remote_writer.write(b'\x05\x01\x00')
                    await remote_writer.drain()
                    if (await remote_reader.read(2))[1] == 0:
                        remote_writer.write(b'\x05\x01\x00\x03' + len(host).to_bytes(1, 'big') + host.encode() + port.to_bytes(2, 'big'))
                await remote_writer.drain()
                if (await remote_reader.read(10))[1] != 0:
                    raise Exception("Bad Gateway")
            else:
                raise Exception("Unsupported proxy type")

            writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            await writer.drain()

            await asyncio.gather(
                self._pipe(reader, remote_writer),
                self._pipe(remote_reader, writer)
            )
        except asyncio.TimeoutError:
            logging.error("Connection timeout")
            writer.write(b'HTTP/1.1 504 Gateway Timeout\r\n\r\n')
            await writer.drain()
        except Exception as e:
            logging.error(f"Error in CONNECT: {e}")
            writer.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
            await writer.drain()

    def _split_proxy_auth(self, proxy_addr):
        match = re.match(r'((?P<username>.+?):(?P<password>.+?)@)?(?P<host>.+)', proxy_addr)
        if match:
            username = match.group('username')
            password = match.group('password')
            host = match.group('host')
            if username and password:
                return f"{username}:{password}", host
        return None, proxy_addr

    async def _pipe(self, reader, writer):
        try:
            while True:
                try:
                    data = await reader.read(8192)
                    if not data:
                        break
                    writer.write(data)
                    await writer.drain()
                except asyncio.CancelledError:
                    break
        finally:
            writer.close()
            await writer.wait_closed()

    async def _handle_request(self, method, path, headers, reader, writer):
        body = await reader.read()
        proxy = await self.get_next_proxy()
        proxy_type, proxy_addr = proxy.split('://')
        proxy_auth, proxy_host_port = self._split_proxy_auth(proxy_addr)
        
        async with httpx.AsyncClient(
            limits=httpx.Limits(max_keepalive_connections=500, max_connections=3000),
            timeout=30
        ) as client:
            try:
                if proxy_auth:
                    proxy = f"{proxy_type}://{proxy_host_port}"
                    headers['Proxy-Authorization'] = f'Basic {base64.b64encode(proxy_auth.encode()).decode()}'
                
                async with client.stream(method, path, headers=headers, content=body, proxies=proxy) as response:
                    await self._write_response(writer, response)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logging.error(f"Request processing error: {e}")
                writer.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                await writer.drain()

    async def _write_response(self, writer, response):
        try:
            writer.write(f'HTTP/1.1 {response.status_code} {response.reason_phrase}\r\n'.encode('utf-8', errors='ignore'))
            writer.write(b'Transfer-Encoding: chunked\r\n')
            for name, value in response.headers.items():
                if name.lower() != 'transfer-encoding':
                    writer.write(f'{name}: {value}\r\n'.encode('utf-8', errors='ignore'))
            writer.write(b'\r\n')
            await writer.drain()

            async for chunk in response.aiter_bytes(chunk_size=8192):
                if asyncio.current_task().cancelled():
                    raise asyncio.CancelledError()
                writer.write(f'{len(chunk):X}\r\n'.encode('utf-8', errors='ignore'))
                writer.write(chunk)
                writer.write(b'\r\n')
                await writer.drain()
            writer.write(b'0\r\n\r\n')
            await writer.drain()
        except asyncio.CancelledError:
            logging.info("Response write canceled")
            raise

def print_banner(config):
    auth_info = f"{config.get('username')}:{config.get('password')}" if config.get('username') and config.get('password') else "Not set (no authentication required)"
    banner_info = [
        ('公众号', '樱花庄的本间白猫'),
        ('Blog', 'https://y.shironekosan.cn'),
        ('Github', 'https://github.com/honmashironeko/ProxyCat'),
        ('Local listening port', config.get('port')),
        ('Proxy rotation mode', 'cycle' if config.get('mode') == 'cycle' else 'once'),
        ('Agent change time', f"{config.get('interval')}Second"),
        ('Default account password', auth_info),
    ]
    print(f"{Fore.MAGENTA}{'=' * 55}")
    for key, value in banner_info:
        print(f"{Fore.YELLOW}{key}: {Fore.GREEN}{value}")
    print(f"{Fore.MAGENTA}{'=' * 55}\n")

def update_status(server):
    while True:
        time_left = server.time_until_next_switch()
        status = f"\r{Fore.YELLOW}Current Proxy: {Fore.GREEN}{server.current_proxy} | {Fore.YELLOW}Next switch: {Fore.GREEN}{time_left:.1f}Second"
        print(status, end='', flush=True)
        time.sleep(1)

async def handle_client_wrapper(server, reader, writer, clients):
    task = asyncio.create_task(server.handle_client(reader, writer))
    clients.add(task)
    try:
        await task
    except Exception as e:
        logging.error(f"Client processing error: {e}")
    finally:
        clients.remove(task)

async def run_server(server):
    clients = set()
    server_instance = None
    try:
        server_instance = await asyncio.start_server(
            lambda r, w: handle_client_wrapper(server, r, w, clients),
            '0.0.0.0', 
            server.config.getint('port', 1080)
        )
        async with server_instance:
            await server_instance.serve_forever()
    except asyncio.CancelledError:
        logging.info("The server is shutting down...")
    finally:
        if server_instance:
            server_instance.close()
            await server_instance.wait_closed()
        for client in clients:
            client.cancel()
        await asyncio.gather(*[client for client in clients], return_exceptions=True)

async def check_for_updates():
    current_version = "ProxyCat-V1.4"
    timeout = 10
    try:
        async with AsyncClient() as client:
            try:
                response = await asyncio.wait_for(
                    client.get("https://y.shironekosan.cn/1.html"),
                    timeout=timeout
                )
                response.raise_for_status()
                content = response.text
                match = re.search(r'<p>(ProxyCat-V\d+\.\d+)</p>', content)
                if match:
                    latest_version = match.group(1)
                    if version.parse(latest_version.split('-V')[1]) > version.parse(current_version.split('-V')[1]):
                        print(f"{Fore.YELLOW}New version found! Current version: {current_version}, Latest version: {latest_version}")
                        print(f"{Fore.YELLOW}Please visit https://pan.quark.cn/s/39b4b5674570 to get the latest version")
                        print(f"{Fore.YELLOW}Please visit https://github.com/honmashironeko/ProxyCat to get the latest version")
                        print(f"{Fore.YELLOW}Please visit https://pan.baidu.com/s/1C9LVC9aiaQeYFSj_2mWH1w?pwd=13r5 to get the latest version")
                    else:
                        print(f"{Fore.GREEN}The current version is the latest ({current_version})")
                else:
                    print(f"{Fore.RED}Unable to find version information in the response")
            except TimeoutException:
                print(f"{Fore.RED}Checking for updates has timed out, please check your network connection")
            except Exception as e:
                print(f"{Fore.RED}An error occurred while checking for updates: {e}")
    except Exception as e:
        print(f"{Fore.RED}An error occurred while creating the HTTP client: {e}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=logoprint.logos())
    parser.add_argument('-c', '--config', default='config.ini', help='Configuration file path')
    args = parser.parse_args()
    config = load_config(args.config)
    server = AsyncProxyServer(config)
    print_banner(config)
    asyncio.run(check_for_updates())
    status_thread = threading.Thread(target=update_status, args=(server,), daemon=True)
    status_thread.start()
    try:
        asyncio.run(run_server(server))
    except KeyboardInterrupt:
        logging.info("The program was interrupted by the user")
