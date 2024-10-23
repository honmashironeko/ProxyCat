import threading, logoprint, argparse, logging, asyncio, socket, base64, getip, httpx, time, re, struct, random
from config import load_config, DEFAULT_CONFIG
from colorama import init, Fore, Style
from proxy_check import check_proxies
from update import check_for_updates
from banner import print_banner
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

def load_proxies(file_path='ip.txt'):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file if '://' in line]

def validate_proxy(proxy):
    pattern = re.compile(r'^(?P<scheme>socks5|http|https)://(?P<host>[^:]+):(?P<port>\d+)$')
    return pattern.match(proxy) is not None

class AsyncProxyServer:
    def __init__(self, config):
        self.config = {**DEFAULT_CONFIG, **config}
        self.username = self.config['username'].strip()
        self.password = self.config['password'].strip()
        self.auth_required = bool(self.username and self.password)
        self.mode = self.config['mode']
        self.interval = int(self.config['interval'])
        self.use_getip = self.config.get('use_getip', 'False').lower() == 'true'
        self.proxy_file = self.config['proxy_file']
        self.proxies = self.load_proxies()
        self.proxy_cycle = cycle(self.proxies)
        self.current_proxy = next(self.proxy_cycle) if self.proxies else "没有可用的代理"
        self.last_switch_time = time.time()
        self.rate_limiter = asyncio.Queue(maxsize=3000)
        self.proxy_failed = False

    def load_proxies(self):
        proxies = load_proxies(self.proxy_file)
        valid_proxies = [p for p in proxies if validate_proxy(p)]
        
        if self.use_getip:
            valid_proxies = []
            for _ in range(4):
                new_ip = getip.newip()
                if validate_proxy(new_ip):
                    valid_proxies.append(new_ip)
                    break
            else:
                logging.error("多次尝试获取有效代理失败，退出程序")
                exit(1)
        
        return valid_proxies

    async def get_next_proxy(self):
        if self.mode == 'load_balance':
            return random.choice(self.proxies)
        elif self.mode == 'custom':
            return await self.custom_proxy_switch()
        
        if time.time() - self.last_switch_time >= self.interval:
            await self.get_proxy()
        return self.current_proxy

    async def get_proxy(self):
        self.current_proxy = getip.newip() if self.use_getip else next(self.proxy_cycle)
        self.last_switch_time = time.time()
        logging.info(f"切换到新的代理: {self.current_proxy}")

    async def custom_proxy_switch(self):
        """ 自定义的代理切换逻辑 """
        return self.proxies[0] if self.proxies else "没有可用的代理"

    def time_until_next_switch(self):
        return float('inf') if self.mode == 'load_balance' else max(0, self.interval - (time.time() - self.last_switch_time))

    async def acquire(self):
        await self.rate_limiter.put(None)
        await asyncio.sleep(0.001)
        self.rate_limiter.get_nowait()

    async def handle_client(self, reader, writer):
        try:
            # await self.acquire()
            first_byte = await reader.read(1)
            if not first_byte:
                return
            
            if first_byte == b'\x05':
                await self.handle_socks5_connection(reader, writer)
            else: 
                await self._handle_client_impl(reader, writer, first_byte)
        except asyncio.CancelledError:
            logging.info("客户端处理取消")
        except Exception as e:
            logging.error(f"客户端处理出错: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def handle_socks5_connection(self, reader, writer):
        nmethods = ord(await reader.readexactly(1))
        await reader.readexactly(nmethods)

        writer.write(b'\x05\x02' if self.auth_required else b'\x05\x00')
        await writer.drain()

        if self.auth_required:
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

        version, cmd, _, atyp = struct.unpack('!BBBB', await reader.readexactly(4))
        if cmd != 1: 
            writer.write(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()
            writer.close()
            return

        if atyp == 1: 
            dst_addr = socket.inet_ntoa(await reader.readexactly(4))
        elif atyp == 3:
            addr_len = ord(await reader.readexactly(1))
            dst_addr = (await reader.readexactly(addr_len)).decode()
        elif atyp == 4: 
            dst_addr = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
        else:
            writer.write(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()
            writer.close()
            return

        dst_port = struct.unpack('!H', await reader.readexactly(2))[0]

        try:
            proxy = await self.get_next_proxy()
            proxy_type, proxy_addr = proxy.split('://')
            proxy_auth, proxy_host_port = self._split_proxy_auth(proxy_addr)
            proxy_host, proxy_port = proxy_host_port.split(':')
            proxy_port = int(proxy_port)

            remote_reader, remote_writer = await asyncio.open_connection(proxy_host, proxy_port)

            if proxy_type == 'socks5':
                remote_writer.write(b'\x05\x01\x00')
                await remote_writer.drain()
                await remote_reader.readexactly(2)
                
                remote_writer.write(b'\x05\x01\x00' + (b'\x03' + len(dst_addr).to_bytes(1, 'big') + dst_addr.encode() if isinstance(dst_addr, str) else b'\x01' + socket.inet_aton(dst_addr)) + struct.pack('!H', dst_port))
                await remote_writer.drain()
                
                await remote_reader.readexactly(10)
            elif proxy_type in ['http', 'https']:
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

            writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()

            await asyncio.gather(
                self._pipe(reader, remote_writer),
                self._pipe(remote_reader, writer)
            )
        except Exception as e:
            logging.error(f"SOCKS5 连接错误: {e}")
            writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()

    async def _handle_client_impl(self, reader, writer, first_byte):
        try:
            request_line = first_byte + await reader.readline()
            if not request_line:
                return

            try:
                method, path, _ = request_line.decode('utf-8', errors='ignore').split()
            except ValueError:
                #logging.error(f"无效的请求行: {request_line}")
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
                    #logging.error(f"无效的请求行: {line}")
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
            logging.error(f"处理客户端请求时出错: {e}")

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
            # logging.error(f"无效的连接路径: {path}")
            writer.write(b'HTTP/1.1 400 Bad Request\r\n\r\n')
            await writer.drain()
            return

        proxy = await self.get_next_proxy()
        proxy_type, proxy_addr = proxy.split('://')
        proxy_auth, proxy_host_port = self._split_proxy_auth(proxy_addr)
        proxy_host, proxy_port = proxy_host_port.split(':')
        proxy_port = int(proxy_port)

        try:
            remote_reader, remote_writer = await asyncio.wait_for(asyncio.open_connection(proxy_host, proxy_port),timeout=10)

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
            elif proxy_type == 'socks5':
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
            logging.error("连接超时")
            writer.write(b'HTTP/1.1 504 Gateway Timeout\r\n\r\n')
            await writer.drain()
        except Exception as e:
            logging.error(f"代理地址失效，切换代理地址")
            if not self.proxy_failed: 
                self.proxy_failed = True  
                await self.get_proxy() 
        else:
            self.proxy_failed = False

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
        
        client_kwargs = {
            "limits": httpx.Limits(max_keepalive_connections=500, max_connections=3000),
            "timeout": 30,
        }
        
        if proxy_type in ['http', 'https']:
            client_kwargs["proxies"] = {proxy_type: f"{proxy_type}://{proxy_host_port}"}
        elif proxy_type == 'socks5':
            client_kwargs["transport"] = httpx.AsyncHTTPTransport(proxy=f"{proxy_type}://{proxy_host_port}")
        
        if proxy_auth:
            headers['Proxy-Authorization'] = f'Basic {base64.b64encode(proxy_auth.encode()).decode()}'
        
        async with httpx.AsyncClient(**client_kwargs) as client:
            try:
                async with client.stream(method, path, headers=headers, content=body) as response:
                    await self._write_response(writer, response)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logging.error(f"请求处理出错: {e}")
                writer.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                await writer.drain()

    async def _write_response(self, writer, response):
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

def update_status(server):
    while True:
        if server.mode == 'load_balance':
            status = f"\r{Fore.YELLOW}当前代理: {Fore.GREEN}{server.current_proxy}"
        else:
            time_left = server.time_until_next_switch()
            status = f"\r{Fore.YELLOW}当前代理: {Fore.GREEN}{server.current_proxy} | {Fore.YELLOW}下次切换: {Fore.GREEN}{time_left:.1f}秒"
        print(status, end='', flush=True)
        time.sleep(1)

async def handle_client_wrapper(server, reader, writer, clients):
    task = asyncio.create_task(server.handle_client(reader, writer))
    clients.add(task)
    try:
        await task
    except Exception as e:
        logging.error(f"客户端处理出错: {e}")
    finally:
        clients.remove(task)

async def run_server(server):
    clients = set()
    server_instance = None
    try:
        server_instance = await asyncio.start_server(lambda r, w: handle_client_wrapper(server, r, w, clients),'0.0.0.0', int(server.config['port']))
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

async def run_proxy_check(server):
    if server.config.get('check_proxies', 'False').lower() == 'true':
        logging.info("开始检测代理地址...")
        valid_proxies = await check_proxies(server.proxies)
        if valid_proxies:
            server.proxies = valid_proxies
            server.proxy_cycle = cycle(valid_proxies)
            server.current_proxy = next(server.proxy_cycle)
            logging.info(f"有效代理地址: {valid_proxies}")
        else:
            logging.error("没有有效的代理地址")
    else:
        logging.info("代理检测已禁用")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=logoprint.logos())
    parser.add_argument('-c', '--config', default='config.ini', help='配置文件路径')
    args = parser.parse_args()
    
    config = load_config(args.config)
    server = AsyncProxyServer(config)
    print_banner(config)
    asyncio.run(check_for_updates())
    asyncio.run(run_proxy_check(server))
    
    status_thread = threading.Thread(target=update_status, args=(server,), daemon=True)
    status_thread.start()
    
    try:
        asyncio.run(run_server(server))
    except KeyboardInterrupt:
        logging.info("程序被用户中断")
