import asyncio, httpx, logging, re, socket, struct, time, socket, base64, random
from modules.modules import get_message, load_ip_list
from itertools import cycle
from config import getip

def load_proxies(file_path='ip.txt'):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file if '://' in line]

def validate_proxy(proxy):
    pattern = re.compile(r'^(?P<scheme>socks5|http|https)://(?P<host>[^:]+):(?P<port>\d+)$')
    return pattern.match(proxy) is not None

class AsyncProxyServer:
    def __init__(self, config):
        self.config = config
        self.username = self.config['username'].strip()
        self.password = self.config['password'].strip()
        self.auth_required = bool(self.username and self.password)
        self.mode = self.config['mode']
        self.interval = int(self.config['interval'])
        self.use_getip = self.config.get('use_getip', 'False').lower() == 'true'
        self.proxy_file = self.config['proxy_file']
        self.language = self.config.get('language', 'cn').lower()
        self.whitelist = load_ip_list(config.get('whitelist_file', ''))
        self.blacklist = load_ip_list(config.get('blacklist_file', ''))
        self.ip_auth_priority = config.get('ip_auth_priority', 'whitelist')
        
        if not self.use_getip:
            self.proxies = self._load_file_proxies()
            self.proxy_cycle = cycle(self.proxies)
            self.current_proxy = next(self.proxy_cycle) if self.proxies else "No proxies available"
        else:
            self.proxies = []
            self.proxy_cycle = None
            self.current_proxy = None
        
        self.last_switch_time = time.time()
        self.rate_limiter = asyncio.Queue(maxsize=3000)
        self.proxy_failed = False
        self.proxy_fail_count = 0
        self.max_fail_count = 2
        self.semaphore = asyncio.Semaphore(10000)

    async def get_next_proxy(self):
        if self.mode == 'load_balance':
            return random.choice(self.proxies)
        elif self.mode == 'custom':
            return await self.custom_proxy_switch()
        
        if time.time() - self.last_switch_time >= self.interval:
            await self.get_proxy()
        
        if self.use_getip and not self.current_proxy:
            self.current_proxy = await self._load_getip_proxy()
        
        return self.current_proxy

    async def _load_getip_proxy(self):
        valid_proxies = []
        for _ in range(4):
            new_ip = getip.newip()
            if validate_proxy(new_ip):
                valid_proxies.append(new_ip)
                break
        else:
            logging.error(get_message('multiple_proxy_fail', self.language))
            exit(1)
        return valid_proxies[0]

    def _load_file_proxies(self):
        try:
            with open(self.proxy_file, 'r') as file:
                proxies = [line.strip() for line in file if '://' in line]
            valid_proxies = [p for p in proxies if validate_proxy(p)]
            if not valid_proxies:
                logging.error(get_message('no_valid_proxies', self.language))
                exit(1)
            return valid_proxies
        except FileNotFoundError:
            logging.error(get_message('proxy_file_not_found', self.language, self.proxy_file))
            exit(1)

    async def get_proxy(self):
        if self.use_getip:
            self.current_proxy = getip.newip()
        else:
            self.current_proxy = next(self.proxy_cycle)
        self.last_switch_time = time.time()
        logging.info(get_message('proxy_switch', self.language, self.current_proxy))

    async def custom_proxy_switch(self):
        return self.proxies[0] if self.proxies else "No proxies available"

    def time_until_next_switch(self):
        return float('inf') if self.mode == 'load_balance' else max(0, self.interval - (time.time() - self.last_switch_time))

    async def acquire(self):
        await self.rate_limiter.put(None)
        await asyncio.sleep(0.001)
        self.rate_limiter.get_nowait()

    def check_ip_auth(self, ip):
        if self.ip_auth_priority == 'whitelist':
            if self.whitelist and ip in self.whitelist:
                return True
            if self.blacklist and ip in self.blacklist:
                return False
            return not self.whitelist
        else:
            if self.blacklist and ip in self.blacklist:
                return False
            if self.whitelist and ip in self.whitelist:
                return True
            return not self.blacklist

    async def handle_client(self, reader, writer):
        async with self.semaphore:
            try:
                client_ip = writer.get_extra_info('peername')[0]
                if not self.check_ip_auth(client_ip):
                    logging.warning(get_message('unauthorized_ip', self.language, client_ip))
                    writer.close()
                    await writer.wait_closed()
                    return

                first_byte = await reader.read(1)
                if not first_byte:
                    return
                
                if (first_byte == b'\x05'):
                    await self.handle_socks5_connection(reader, writer)
                else: 
                    await self._handle_client_impl(reader, writer, first_byte)
            except asyncio.CancelledError:
                logging.info(get_message('client_cancelled', self.language))
            except Exception as e:
                logging.error(get_message('client_error', self.language, e))
            finally:
                writer.close()
                await writer.wait_closed()

    async def handle_socks5_connection(self, reader, writer):
        try:
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

            proxy = await self.get_next_proxy()
            proxy_type, proxy_addr = proxy.split('://')
            proxy_auth, proxy_host_port = self._split_proxy_auth(proxy_addr)
            proxy_host, proxy_port = proxy_host_port.split(':')
            proxy_port = int(proxy_port)

            remote_reader, remote_writer = await asyncio.open_connection(proxy_host, proxy_port)

            if proxy_type == 'socks5':
                await self._initiate_socks5(remote_reader, remote_writer, dst_addr, dst_port)
            elif proxy_type in ['http', 'https']:
                await self._initiate_http(remote_reader, remote_writer, dst_addr, dst_port, proxy_auth)

            writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()

            await asyncio.gather(
                self._pipe(reader, remote_writer),
                self._pipe(remote_reader, writer)
            )
        except Exception as e:
            logging.error(get_message('socks5_connection_error', self.language, e))
            writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()

    async def _initiate_socks5(self, remote_reader, remote_writer, dst_addr, dst_port):
        remote_writer.write(b'\x05\x01\x00')
        await remote_writer.drain()
        await remote_reader.readexactly(2)
        
        remote_writer.write(b'\x05\x01\x00' + (b'\x03' + len(dst_addr).to_bytes(1, 'big') + dst_addr.encode() if isinstance(dst_addr, str) else b'\x01' + socket.inet_aton(dst_addr)) + struct.pack('!H', dst_port))
        await remote_writer.drain()
        
        await remote_reader.readexactly(10)

    async def _initiate_http(self, remote_reader, remote_writer, dst_addr, dst_port, proxy_auth):
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

    async def _pipe(self, reader, writer):
        try:
            buffer_size = 65536 
            while True:
                try:
                    data = await asyncio.wait_for(reader.read(buffer_size), timeout=30)
                    if not data:
                        break
                    writer.write(data)
                    await writer.drain()
                except asyncio.TimeoutError:
                    logging.warning(get_message('data_transfer_timeout', self.language))
                    continue
                except ConnectionResetError:
                    logging.error(get_message('connection_reset', self.language))
                    break
        except asyncio.CancelledError:
            logging.info(get_message('transfer_cancelled', self.language))
        except Exception as e:
            logging.error(get_message('data_transfer_error', self.language, e))
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass

    async def _handle_client_impl(self, reader, writer, first_byte):
        try:
            request_line = first_byte + await reader.readline()
            if not request_line:
                return

            try:
                method, path, _ = request_line.decode('utf-8', errors='ignore').split()
            except ValueError:
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
            logging.error(get_message('client_request_error', self.language, e))

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
            writer.write(b'HTTP/1.1 400 Bad Request\r\n\r\n')
            await writer.drain()
            return

        proxy = await self.get_next_proxy()
        proxy_type, proxy_addr = proxy.split('://')
        proxy_auth, proxy_host_port = self._split_proxy_auth(proxy_addr)
        proxy_host, proxy_port = proxy_host_port.split(':')
        proxy_port = int(proxy_port)

        try:
            remote_reader, remote_writer = await asyncio.wait_for(asyncio.open_connection(proxy_host, proxy_port), timeout=10)

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
            logging.error(get_message('connect_timeout', self.language))
            writer.write(b'HTTP/1.1 504 Gateway Timeout\r\n\r\n')
            await writer.drain()
        except Exception as e:
            logging.error(get_message('proxy_invalid_switch', self.language))
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

    async def _handle_request(self, method, path, headers, reader, writer):
        if not path.startswith(('http://', 'https://')):
            logging.warning(get_message('unsupported_protocol', self.language, path))
            writer.write(b'HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n')
            await writer.drain()
            return

        body = await reader.read()
        retry_count = 2
        
        while retry_count > 0:
            try:
                proxy = await self.get_next_proxy()
                proxy_type, proxy_addr = proxy.split('://')
                proxy_auth, proxy_host_port = self._split_proxy_auth(proxy_addr)
                
                client_kwargs = {
                    "limits": httpx.Limits(
                        max_keepalive_connections=100,
                        max_connections=1000,
                        keepalive_expiry=30
                    ),
                    "timeout": httpx.Timeout(30.0),
                    "follow_redirects": True
                }
                
                if proxy_type in ['http', 'https']:
                    client_kwargs["proxies"] = {
                        "http://": f"{proxy_type}://{proxy_host_port}",
                        "https://": f"{proxy_type}://{proxy_host_port}"
                    }
                elif proxy_type == 'socks5':
                    client_kwargs["transport"] = httpx.AsyncHTTPTransport(
                        proxy=f"{proxy_type}://{proxy_host_port}",
                        verify=False
                    )
                
                if proxy_auth:
                    headers['Proxy-Authorization'] = f'Basic {base64.b64encode(proxy_auth.encode()).decode()}'
                
                async with httpx.AsyncClient(**client_kwargs) as client:
                    async with client.stream(
                        method, 
                        path, 
                        headers=headers,
                        content=body,
                        timeout=30.0
                    ) as response:
                        await self._write_response(writer, response)
                        self.proxy_fail_count = 0
                        return
                        
            except (httpx.TimeoutException, httpx.ConnectTimeout, httpx.ConnectError):
                logging.warning(get_message('request_retry', self.language, retry_count-1))
                await self.handle_proxy_failure()
                retry_count -= 1
                if retry_count > 0:
                    await asyncio.sleep(1)
                continue
            except Exception as e:
                logging.error(get_message('request_error', self.language, e))
                await self.handle_proxy_failure()
                break
        
        writer.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
        await writer.drain()

    async def _write_response(self, writer, response):
        try:
            status_line = f'HTTP/1.1 {response.status_code} {response.reason_phrase}\r\n'
            writer.write(status_line.encode('utf-8', errors='ignore'))
            writer.write(b'Transfer-Encoding: chunked\r\n')
            
            for name, value in response.headers.items():
                if name.lower() not in ('transfer-encoding', 'connection'):
                    writer.write(f'{name}: {value}\r\n'.encode('utf-8', errors='ignore'))
            
            writer.write(b'\r\n')
            await writer.drain()

            async for chunk in response.aiter_bytes(chunk_size=65536):
                if asyncio.current_task().cancelled():
                    raise asyncio.CancelledError
                writer.write(f'{len(chunk):X}\r\n'.encode('utf-8', errors='ignore'))
                writer.write(chunk)
                writer.write(b'\r\n')
                await writer.drain()
                
            writer.write(b'0\r\n\r\n')
            await writer.drain()
        except Exception as e:
            logging.error(get_message('response_write_error', self.language, e))
            raise

    async def check_current_proxy(self):
        try:
            proxy = self.current_proxy
            proxy_type = proxy.split('://')[0]
            async with httpx.AsyncClient(
                proxies={f"{proxy_type}://": proxy},
                timeout=10,
                verify=False
            ) as client:
                response = await client.get('https://www.baidu.com')
                return response.status_code == 200
        except Exception:
            return False

    async def handle_proxy_failure(self):
        if await self.check_current_proxy():
            self.proxy_fail_count += 1
            if self.proxy_fail_count >= self.max_fail_count:
                logging.warning(get_message('consecutive_failures', self.language, self.current_proxy))
                await self.force_switch_proxy()
        else:
            logging.error(get_message('invalid_proxy', self.language, self.current_proxy))
            await self.force_switch_proxy()

    async def force_switch_proxy(self):
        self.proxy_failed = True
        self.proxy_fail_count = 0
        old_proxy = self.current_proxy
        await self.get_proxy()
        self.last_switch_time = time.time()
        logging.info(get_message('proxy_switched', self.language, old_proxy, self.current_proxy))
