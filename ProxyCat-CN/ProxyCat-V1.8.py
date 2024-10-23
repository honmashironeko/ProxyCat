from typing import List, Optional
from colorama import init, Fore, Style
from packaging import version
from itertools import cycle
import configparser
import logoprint
import argparse
import logging
import asyncio
import struct
import random
import socket
import base64
import getip
import httpx
import time
import sys
import re

init(autoreset=True)

LOG_COLORS = {
    'DEBUG': Fore.CYAN,
    'INFO': Fore.GREEN,
    'WARNING': Fore.YELLOW,
    'ERROR': Fore.RED,
    'CRITICAL': Fore.MAGENTA
}

class ColoredFormatter(logging.Formatter):
    def format(self, record):
        log_color = LOG_COLORS.get(record.levelname, Fore.WHITE)
        reset = Style.RESET_ALL
        record.msg = f"{log_color}{record.msg}{reset}"
        return super().format(record)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

handler = logging.StreamHandler()
formatter = ColoredFormatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.handlers = [handler]

DEFAULT_CONFIG = {
    'port': 1080,
    'mode': 'cycle',
    'interval': 300,
    'username': '',
    'password': '',
    'use_getip': False,
    'proxy_file': 'ip.txt',
    'check_proxies': True,
}

def load_config(config_file: str = 'config.ini') -> dict:
    config = configparser.ConfigParser()
    config.read(config_file, encoding='utf-8')
    return {**DEFAULT_CONFIG, **dict(config['SETTINGS'])}

def load_proxies(file_path: str = 'ip.txt') -> List[str]:
    try:
        with open(file_path, 'r') as file:
            return [line.strip() for line in file if '://' in line]
    except FileNotFoundError:
        logging.error(f"代理文件未找到: {file_path}")
        return []

def is_valid_proxy(proxy: str) -> bool:
    pattern = re.compile(
        r'^(http|https|socks5)://'
        r'('
            r'(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.'
            r'(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.'
            r'(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.'
            r'(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)'
            r'|'
            r'([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}'
        r')'
        r':'
        r'(6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}|[1-5]\d{4}|\d{1,4})$'
    )
    return bool(pattern.match(proxy))

class AsyncProxyServer:
    def __init__(self, config: dict):
        self.config = config
        self.username = self.config['username'].strip()
        self.password = self.config['password'].strip()
        self.auth_required = bool(self.username and self.password)
        self.mode = self.config['mode']
        self.interval = int(self.config['interval'])
        self.use_getip = self.config.get('use_getip', 'False').lower() == 'true'
        self.proxy_file = self.config['proxy_file']
        self.proxies = self.load_proxies()
        self.proxy_cycle = cycle(self.proxies) if self.proxies else cycle([])
        self.current_proxy = next(self.proxy_cycle, "没有可用的代理")
        self.last_switch_time = time.time()
        self.rate_limiter = asyncio.Semaphore(3000)

        self.proxy_selector = {
            'cycle': self.cycle_proxy,
            'load_balance': self.load_balance_proxy,
            'custom': self.custom_proxy
        }

    def load_proxies(self) -> List[str]:
        if self.use_getip:
            proxy = self.get_valid_proxy()
            return [proxy]
        else:
            return load_proxies(self.proxy_file)

    def get_valid_proxy(self, retries: int = 3) -> str:
        for attempt in range(1, retries + 1):
            proxy = getip.newip()
            if is_valid_proxy(proxy):
                return proxy
            else:
                logging.error(f"获取到的代理格式不正确: {proxy}，尝试重新获取 ({attempt}/{retries})")
                time.sleep(1)
        logging.error("多次获取代理失败，程序将于10秒后停止。")
        time.sleep(10)
        sys.exit(1) 

    async def get_next_proxy(self) -> str:
        selector = self.proxy_selector.get(self.mode, self.cycle_proxy)
        return await selector()

    async def cycle_proxy(self) -> str:
        if self.use_getip:
            proxy = self.get_valid_proxy()
            self.current_proxy = proxy
            logging.info(f"切换到新的代理: {self.current_proxy}")
        else:
            if time.time() - self.last_switch_time >= self.interval:
                self.current_proxy = next(self.proxy_cycle, "没有可用的代理")
                self.last_switch_time = time.time()
                logging.info(f"切换到新的代理: {self.current_proxy}")
        return self.current_proxy

    async def load_balance_proxy(self) -> str:
        if self.use_getip:
            proxy = self.get_valid_proxy()
            return proxy
        else:
            proxy = random.choice(self.proxies) if self.proxies else "没有可用的代理"
            return proxy

    async def custom_proxy(self) -> str:
        """
        自定义代理选择函数。
        用户可以在此函数中实现自定义的代理选择逻辑。
        示例：
            self.current_proxy = your_custom_proxy_function()
        """
        return self.current_proxy

    def time_until_next_switch(self) -> float:
        return float('inf') if self.mode == 'load_balance' else max(0, self.interval - (time.time() - self.last_switch_time))

    async def acquire_rate_limit(self):
        async with self.rate_limiter:
            pass

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            await self.acquire_rate_limit()
            first_byte = await reader.read(1)
            if not first_byte:
                return

            if first_byte == b'\x05':
                await self.handle_socks5_connection(reader, writer)
            else:
                await self.handle_http_connection(first_byte, reader, writer)
        except asyncio.CancelledError:
            logging.info("客户端处理取消")
        except Exception as e:
            logging.error(f"客户端处理出错: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def handle_socks5_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            nmethods = ord(await reader.readexactly(1))
            methods = await reader.readexactly(nmethods)

            if self.auth_required:
                writer.write(b'\x05\x02')
            else:
                writer.write(b'\x05\x00')
            await writer.drain()

            if self.auth_required:
                await self.authenticate_socks5(reader, writer)

            version, cmd, _, atyp = struct.unpack('!BBBB', await reader.readexactly(4))
            if cmd != 1:
                await self.send_socks5_response(writer, error_code=7)
                return

            dst_addr = await self.parse_dst_addr(reader, atyp)
            dst_port = struct.unpack('!H', await reader.readexactly(2))[0]

            await self.connect_to_target(reader, writer, dst_addr, dst_port, atyp)
        except Exception as e:
            logging.error(f"SOCKS5 连接错误: {e}")
            await self.send_socks5_response(writer, error_code=1)

    async def authenticate_socks5(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        auth_version = await reader.readexactly(1)
        if auth_version != b'\x01':
            writer.close()
            return

        ulen = ord(await reader.readexactly(1))
        username = await reader.readexactly(ulen)
        plen = ord(await reader.readexactly(1))
        password = await reader.readexactly(plen)

        if username.decode() != self.username or password.decode() != self.password:
            writer.write(b'\x01\x01')
            await writer.drain()
            writer.close()
            return

        writer.write(b'\x01\x00')
        await writer.drain()

    async def send_socks5_response(self, writer: asyncio.StreamWriter, error_code: int = 0):
        response = struct.pack('!BBBB', 5, error_code, 0, 1) + socket.inet_aton('0.0.0.0') + struct.pack('!H', 0)
        writer.write(response)
        await writer.drain()
        writer.close()

    async def parse_dst_addr(self, reader: asyncio.StreamReader, atyp: int) -> str:
        if atyp == 1:
            return socket.inet_ntoa(await reader.readexactly(4))
        elif atyp == 3:
            addr_len = ord(await reader.readexactly(1))
            return (await reader.readexactly(addr_len)).decode()
        elif atyp == 4:
            return socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
        else:
            raise ValueError("不支持的地址类型")

    async def connect_to_target(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, dst_addr: str, dst_port: int, atyp: int):
        try:
            proxy = await self.get_next_proxy()
            if proxy == "没有可用的代理":
                raise ValueError("没有可用的代理")
            proxy_type, proxy_addr = proxy.split('://')
            proxy_auth, proxy_host_port = self.split_proxy_auth(proxy_addr)
            proxy_host, proxy_port = proxy_host_port.split(':')
            proxy_port = int(proxy_port)

            remote_reader, remote_writer = await asyncio.open_connection(proxy_host, proxy_port)

            if proxy_type == 'socks5':
                await self.setup_socks5_proxy(remote_reader, remote_writer, dst_addr, dst_port)
            elif proxy_type in ['http', 'https']:
                await self.setup_http_proxy(remote_reader, remote_writer, dst_addr, dst_port, proxy_auth)
            else:
                raise ValueError("不支持的代理类型")

            writer.write(b'\x05\x00\x00\x01' + socket.inet_aton('0.0.0.0') + struct.pack('!H', 0))
            await writer.drain()

            await asyncio.gather(
                self.pipe_data(remote_reader, writer),
                self.pipe_data(reader, remote_writer)
            )
        except Exception as e:
            logging.error(f"连接目标失败: {e}")
            await self.send_socks5_response(writer, error_code=1)

    async def setup_socks5_proxy(self, remote_reader: asyncio.StreamReader, remote_writer: asyncio.StreamWriter, dst_addr: str, dst_port: int):
        remote_writer.write(b'\x05\x01\x00')
        await remote_writer.drain()
        response = await remote_reader.readexactly(2)
        if response[1] != 0:
            raise ConnectionError("SOCKS5代理认证失败")

        addr = dst_addr.encode() if isinstance(dst_addr, str) else socket.inet_aton(dst_addr)
        if isinstance(dst_addr, str):
            addr = b'\x03' + bytes([len(dst_addr)]) + dst_addr.encode()
        else:
            addr = b'\x01' + socket.inet_aton(dst_addr)

        remote_writer.write(b'\x05\x01\x00' + addr + struct.pack('!H', dst_port))
        await remote_writer.drain()
        response = await remote_reader.readexactly(10)
        if response[1] != 0:
            raise ConnectionError("无法连接到目标服务器")

    async def setup_http_proxy(self, remote_reader: asyncio.StreamReader, remote_writer: asyncio.StreamWriter, dst_addr: str, dst_port: int, proxy_auth: Optional[str]):
        connect_request = f'CONNECT {dst_addr}:{dst_port} HTTP/1.1\r\nHost: {dst_addr}:{dst_port}\r\n'
        if proxy_auth:
            connect_request += f'Proxy-Authorization: Basic {base64.b64encode(proxy_auth.encode()).decode()}\r\n'
        connect_request += '\r\n'
        remote_writer.write(connect_request.encode())
        await remote_writer.drain()

        while True:
            line = await remote_reader.readline()
            if line == b'\r\n':
                break
            if not line.startswith(b'HTTP/1.1 200'):
                raise ConnectionError("HTTP代理连接失败")

    async def handle_http_connection(self, first_byte: bytes, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            request_line = first_byte + await reader.readline()
            method, path, protocol = request_line.decode('utf-8', errors='ignore').split()
            headers = await self.parse_http_headers(reader)

            if self.auth_required and not self.authenticate_http(headers):
                await self.send_http_response(writer, status_code=407, reason='Proxy Authentication Required', headers={'Proxy-Authenticate': 'Basic realm="Proxy"'})
                return

            if method.upper() == 'CONNECT':
                await self.handle_http_connect(path, reader, writer)
            else:
                await self.handle_http_request(method, path, headers, reader, writer)
        except ValueError:
            logging.error(f"无效的请求行: {request_line}")
        except Exception as e:
            logging.error(f"处理HTTP连接时出错: {e}")

    async def parse_http_headers(self, reader: asyncio.StreamReader) -> dict:
        headers = {}
        while True:
            line = await reader.readline()
            if line in (b'\r\n', b''):
                break
            try:
                name, value = line.decode('utf-8').strip().split(': ', 1)
                headers[name.lower()] = value
            except ValueError:
                logging.error(f"无效的HTTP头部: {line}")
        return headers

    def authenticate_http(self, headers: dict) -> bool:
        auth = headers.get('proxy-authorization')
        if not auth:
            return False
        try:
            scheme, credentials = auth.split()
            if scheme.lower() != 'basic':
                return False
            username, password = base64.b64decode(credentials).decode().split(':')
            return username == self.username and password == self.password
        except Exception:
            return False

    async def send_http_response(self, writer: asyncio.StreamWriter, status_code: int, reason: str, headers: Optional[dict] = None, body: Optional[bytes] = None):
        response = f'HTTP/1.1 {status_code} {reason}\r\n'
        if headers:
            for key, value in headers.items():
                response += f'{key}: {value}\r\n'
        response += '\r\n'
        writer.write(response.encode())
        if body:
            writer.write(body)
        await writer.drain()

    async def handle_http_connect(self, path: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            host, port = path.split(':')
            port = int(port)
            proxy = await self.get_next_proxy()
            if proxy == "没有可用的代理":
                raise ValueError("没有可用的代理")
            proxy_type, proxy_addr = proxy.split('://')
            proxy_auth, proxy_host_port = self.split_proxy_auth(proxy_addr)
            proxy_host, proxy_port = proxy_host_port.split(':')
            proxy_port = int(proxy_port)

            remote_reader, remote_writer = await asyncio.open_connection(proxy_host, proxy_port)

            if proxy_type == 'http':
                connect_request = f'CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n'
                if proxy_auth:
                    connect_request += f'Proxy-Authorization: Basic {base64.b64encode(proxy_auth.encode()).decode()}\r\n'
                connect_request += '\r\n'
                remote_writer.write(connect_request.encode())
                await remote_writer.drain()

                response = await remote_reader.readline()
                if not response.startswith(b'HTTP/1.1 200'):
                    raise ConnectionError("HTTP代理连接失败")
                while await remote_reader.readline() != b'\r\n':
                    pass

            elif proxy_type == 'socks5':
                await self.setup_socks5_proxy(remote_reader, remote_writer, host, port)
            else:
                raise ValueError("不支持的代理类型")

            await self.send_http_response(writer, 200, 'Connection Established')
            await asyncio.gather(
                self.pipe_data(remote_reader, writer),
                self.pipe_data(reader, remote_writer)
            )
        except Exception as e:
            logging.error(f"CONNECT请求处理失败: {e}")
            await self.send_http_response(writer, 502, 'Bad Gateway')

    async def handle_http_request(self, method: str, path: str, headers: dict, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        body = await reader.read()
        proxy = await self.get_next_proxy()
        if proxy == "没有可用的代理":
            logging.error("没有可用的代理来处理HTTP请求")
            await self.send_http_response(writer, 502, 'Bad Gateway')
            return
        proxy_type, proxy_addr = proxy.split('://')
        proxy_auth, proxy_host_port = self.split_proxy_auth(proxy_addr)
        client_kwargs = {
            "limits": httpx.Limits(max_keepalive_connections=500, max_connections=3000),
            "timeout": 30.0,
        }

        if proxy_type in ['http', 'https']:
            client_kwargs["proxies"] = {proxy_type: f"{proxy_type}://{proxy_host_port}"}
        elif proxy_type == 'socks5':
            client_kwargs["transport"] = httpx.AsyncHTTPTransport(proxy=f"{proxy_type}://{proxy_host_port}")
        else:
            logging.error(f"不支持的代理类型: {proxy_type}")
            await self.send_http_response(writer, 502, 'Bad Gateway')
            return

        if proxy_auth:
            headers['Proxy-Authorization'] = f'Basic {base64.b64encode(proxy_auth.encode()).decode()}'

        async with httpx.AsyncClient(**client_kwargs) as client:
            try:
                response = await client.request(method, path, headers=headers, content=body)
                await self.write_http_response(writer, response)
            except Exception as e:
                logging.error(f"代理请求失败: {e}")
                await self.send_http_response(writer, 502, 'Bad Gateway')

    async def write_http_response(self, writer: asyncio.StreamWriter, response: httpx.Response):
        status_line = f'HTTP/1.1 {response.status_code} {response.reason_phrase}\r\n'
        writer.write(status_line.encode())
        for key, value in response.headers.items():
            if key.lower() != 'transfer-encoding':
                writer.write(f'{key}: {value}\r\n'.encode())
        writer.write(b'\r\n')
        await writer.drain()

        async for chunk in response.aiter_bytes(8192):
            writer.write(chunk)
            await writer.drain()
        writer.write(b'0\r\n\r\n')
        await writer.drain()

    async def pipe_data(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            while True:
                data = await reader.read(8192)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except asyncio.CancelledError:
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    def split_proxy_auth(self, proxy_addr: str) -> tuple:
        match = re.match(r'((?P<username>.+?):(?P<password>.+?)@)?(?P<host>.+)', proxy_addr)
        if match:
            username = match.group('username')
            password = match.group('password')
            host = match.group('host')
            if username and password:
                return f"{username}:{password}", host
        return None, proxy_addr

async def print_banner(config: dict):
    auth_info = f"{config.get('username')}:{config.get('password')}" if config.get('username') and config.get('password') else ""
    banner_info = [
        ('公众号', '樱花庄的本间白猫'),
        ('博客', 'https://y.shironekosan.cn'),
        ('代理轮换模式', '循环' if config.get('mode') == 'cycle' else '负载均衡' if config.get('mode') == 'load_balance' else '单轮'),
        ('代理更换时间', f"{config.get('interval')}秒"),
        ('本地监听地址 (HTTP)', f"http://{auth_info + '@' if auth_info else ''}127.0.0.1:{config.get('port')}"),
        ('本地监听地址 (SOCKS5)', f"socks5://{auth_info + '@' if auth_info else ''}127.0.0.1:{config.get('port')}"),
        ('开源项目求 Star', 'https://github.com/honmashironeko/ProxyCat'),
    ]
    print(f"{Fore.MAGENTA}{'=' * 60}")
    for key, value in banner_info:
        print(f"{Fore.YELLOW}{key}: {Fore.GREEN}{value}")
    print(f"{Fore.MAGENTA}{'=' * 60}\n")

async def update_status(server: AsyncProxyServer):
    while True:
        if server.mode == 'load_balance':
            status = f"当前代理: {Fore.GREEN}{server.current_proxy} "
        else:
            time_left = server.time_until_next_switch()
            status = (f"当前代理: {Fore.GREEN}{server.current_proxy} | "
                      f"下次切换: {Fore.GREEN}{time_left:.1f}秒")

        print(f"\r{Fore.YELLOW}{status}", end='', flush=True)
        await asyncio.sleep(1)

async def handle_client_wrapper(server: AsyncProxyServer, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, clients: set):
    task = asyncio.create_task(server.handle_client(reader, writer))
    clients.add(task)
    try:
        await task
    except Exception as e:
        logging.error(f"客户端处理出错: {e}")
    finally:
        clients.remove(task)

async def run_server(server: AsyncProxyServer):
    clients = set()
    server_instance = None
    try:
        server_instance = await asyncio.start_server(
            lambda r, w: handle_client_wrapper(server, r, w, clients),
            '0.0.0.0', 
            int(server.config['port'])
        )
        async with server_instance:
            await server_instance.serve_forever()
    except asyncio.CancelledError:
        logging.info("服务器正在关闭...")
    finally:
        if server_instance:
            server_instance.close()
            await server_instance.wait_closed()
        for client in clients:
            client.cancel()
        await asyncio.gather(*clients, return_exceptions=True)

async def check_proxy(proxy: str) -> bool:
    proxy_type = proxy.split('://')[0]
    check_funcs = {
        'http': check_http_proxy,
        'https': check_https_proxy,
        'socks5': check_socks_proxy
    }
    
    check_func = check_funcs.get(proxy_type)
    if not check_func:
        return False
    
    try:
        return await check_func(proxy)
    except Exception as e:
        logging.error(f"{proxy_type.upper()}代理 {proxy} 检测失败: {e}")
        return False

async def check_http_proxy(proxy: str) -> bool:
    async with httpx.AsyncClient(proxies={'http://': proxy}, timeout=10) as client:
        response = await client.get('http://www.baidu.com')
        return response.status_code == 200

async def check_https_proxy(proxy: str) -> bool:
    async with httpx.AsyncClient(proxies={'https://': proxy}, timeout=10) as client:
        response = await client.get('https://www.baidu.com')
        return response.status_code == 200

async def check_socks_proxy(proxy: str) -> bool:
    proxy_type, proxy_addr = proxy.split('://')
    proxy_host, proxy_port = proxy_addr.split(':')
    proxy_port = int(proxy_port)
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(proxy_host, proxy_port), timeout=5)
        if proxy_type == 'socks5':
            writer.write(b'\x05\x01\x00')
            await writer.drain()
            response = await asyncio.wait_for(reader.readexactly(2), timeout=5)
            valid = response == b'\x05\x00'
        else:
            valid = False
        writer.close()
        await writer.wait_closed()
        return valid
    except Exception:
        return False

async def check_proxies(proxies: List[str]) -> List[str]:
    tasks = [check_proxy(proxy) for proxy in proxies]
    results = await asyncio.gather(*tasks)
    return [proxy for proxy, valid in zip(proxies, results) if valid]

async def run_proxy_check(server: AsyncProxyServer):
    if server.config.get('check_proxies', 'false').lower() == 'true':
        logging.info("开始检测代理地址...")
        valid_proxies = await check_proxies(server.proxies)
        if valid_proxies:
            server.proxies = valid_proxies
            server.proxy_cycle = cycle(valid_proxies)
            server.current_proxy = next(server.proxy_cycle, "没有可用的代理")
            logging.info(f"有效代理地址: {valid_proxies}")
        else:
            logging.error("没有有效的代理地址")
            logging.info("程序将于10秒后停止。")
            time.sleep(10)
            sys.exit(1)
    else:
        logging.info("代理检测已禁用")

async def check_for_updates():
    try:
        async with httpx.AsyncClient() as client:
            response = await asyncio.wait_for(client.get("https://y.shironekosan.cn/1.html"), timeout=10)
            response.raise_for_status()
            content = response.text
            match = re.search(r'<p>(ProxyCat-V\d+\.\d+)</p>', content)
            if match:
                latest_version = match.group(1)
                CURRENT_VERSION = "ProxyCat-V1.8"
                if version.parse(latest_version.split('-V')[1]) > version.parse(CURRENT_VERSION.split('-V')[1]):
                    logging.warning(f"发现新版本！当前版本: {CURRENT_VERSION}, 最新版本: {latest_version}")
                    logging.warning("请访问以下地址获取最新版本：")
                    logging.warning("https://pan.quark.cn/s/39b4b5674570")
                    logging.warning("https://github.com/honmashironeko/ProxyCat")
                    logging.warning("https://pan.baidu.com/s/1C9LVC9aiaQeYFSj_2mWH1w?pwd=13r5")
                else:
                    logging.info(f"当前版本已是最新 ({CURRENT_VERSION})")
            else:
                logging.error("无法在响应中找到版本信息")
    except Exception as e:
        logging.error(f"检查更新时发生错误: {e}")

async def main():
    parser = argparse.ArgumentParser(description=logoprint.logos())
    parser.add_argument('-c', '--config', default='config.ini', help='配置文件路径')
    args = parser.parse_args()
    
    config = load_config(args.config)
    server = AsyncProxyServer(config)
    
    await check_for_updates()
    await run_proxy_check(server)
    
    await print_banner(config)
    await asyncio.gather(
        update_status(server),
        run_server(server)
    )

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("程序被用户中断")
