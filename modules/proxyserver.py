import asyncio, httpx, logging, re, socket, struct, time, base64, random, os
from modules.modules import get_message, load_ip_list
from asyncio import TimeoutError
from itertools import cycle
from config import getip
from configparser import ConfigParser


def load_proxies(file_path='ip.txt'):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file if '://' in line]

def validate_proxy(proxy):
    pattern = re.compile(r'^(?P<scheme>socks5|http|https)://(?:(?P<auth>[^@]+)@)?(?P<host>[^:]+):(?P<port>\d+)$')
    match = pattern.match(proxy)
    if not match:
        return False
    
    port = int(match.group('port'))
    return 0 < port < 65536

class AsyncProxyServer:
    def __init__(self, config):
        self.config = config
        self._init_config_values(config)
        self._init_server_state()
        self._init_connection_settings()

    def _init_config_values(self, config):
        self.port = int(config.get('port', '1080'))
        self.mode = config.get('mode', 'cycle')
        self.interval = int(config.get('interval', '300'))
        self.language = config.get('language', 'cn')
        self.use_getip = config.get('use_getip', 'False').lower() == 'true'
        self.check_proxies = config.get('check_proxies', 'True').lower() == 'true'
        
        self.username = config.get('username', '')
        self.password = config.get('password', '')
        self.proxy_username = config.get('proxy_username', '')
        self.proxy_password = config.get('proxy_password', '')
        
        self.users = {}
        if 'Users' in config:
            self.users = dict(config['Users'].items())
        self.auth_required = bool(self.users)
        
        self.proxy_file = os.path.join('config', os.path.basename(config.get('proxy_file', 'ip.txt')))
        self.whitelist_file = os.path.join('config', os.path.basename(config.get('whitelist_file', 'whitelist.txt')))
        self.blacklist_file = os.path.join('config', os.path.basename(config.get('blacklist_file', 'blacklist.txt')))
        self.ip_auth_priority = config.get('ip_auth_priority', 'whitelist')
        
        self.test_url = config.get('test_url', 'https://www.baidu.com')
        self.whitelist = load_ip_list(self.whitelist_file)
        self.blacklist = load_ip_list(self.blacklist_file)
        
        if self.use_getip:
            self.getip_url = config.get('getip_url', '')
            
        self.switching_proxy = False
        self.last_switch_attempt = 0
        self.switch_cooldown = 5
        self.proxy_check_cache = {}
        self.last_check_time = {}
        self.proxy_check_ttl = 300
        self.check_cooldown = 10
        self.max_fail_count = 3
        self.proxy_fail_count = 0
        self.connected_clients = set()

    def _init_server_state(self):
        self.running = False
        self.stop_server = False
        self.server_instance = None
        self.tasks = set()
        self.last_switch_time = time.time()
        self.proxy_failed = False
        self.proxy_cycle = None
        self.current_proxy = None
        self.proxies = []
        self.known_clients = set()
        
        if not self.use_getip:
            self.proxies = self._load_file_proxies()
            if self.proxies:
                self.proxy_cycle = cycle(self.proxies)
                self.current_proxy = next(self.proxy_cycle)

    def _init_connection_settings(self):
        self.buffer_size = 8192
        self.connection_timeout = 30
        self.read_timeout = 60
        self.max_concurrent_requests = 50
        self.request_semaphore = asyncio.Semaphore(self.max_concurrent_requests)
        self.connection_pool = {}
        self.max_pool_size = 100

    def _update_config_values(self, new_config):
        self._init_config_values(new_config)
        self.last_switch_time = time.time()

    def _handle_mode_change(self):
        if self.use_getip:
            self.proxies = []
            self.proxy_cycle = None
            self.current_proxy = None
            logging.info(get_message('api_mode_notice', self.language))
        else:
            self.proxies = self._load_file_proxies()
            if self.proxies:
                self.proxy_cycle = cycle(self.proxies)
                self.current_proxy = next(self.proxy_cycle)
                if self.check_proxies:
                    asyncio.run(self._check_proxies())

    def _reload_proxies(self):
        self.proxies = self._load_file_proxies()
        if self.proxies:
            self.proxy_cycle = cycle(self.proxies)
            self.current_proxy = next(self.proxy_cycle)
            if self.check_proxies:
                asyncio.run(self._check_proxies())

    async def _check_proxies(self):
        from modules.modules import check_proxies
        valid_proxies = await check_proxies(self.proxies, test_url=self.test_url)
        if valid_proxies:
            self.proxies = valid_proxies
            self.proxy_cycle = cycle(valid_proxies)
            self.current_proxy = next(self.proxy_cycle)

    def _load_file_proxies(self):
        try:
            proxy_file = os.path.join('config', os.path.basename(self.proxy_file))
            if os.path.exists(proxy_file):
                with open(proxy_file, 'r', encoding='utf-8') as f:
                    proxies = [line.strip() for line in f if line.strip()]
                return proxies
            else:
                logging.error(get_message('proxy_file_not_found', self.language, proxy_file))
                return []
        except Exception as e:
            logging.error(get_message('load_proxy_file_error', self.language, str(e)))
            return []

    async def start(self):
        if not self.running:
            self.stop_server = False
            self.running = True
            
            try:
                self.server_instance = await asyncio.start_server(
                    self.handle_client,
                    '0.0.0.0',
                    self.port
                )
                logging.info(get_message('server_running', self.language, '0.0.0.0', self.port))
                
                async with self.server_instance:
                    await self.server_instance.serve_forever()
            except Exception as e:
                if not self.stop_server:
                    logging.error(get_message('server_start_error', self.language, str(e)))
            finally:
                self.running = False
                self.server_instance = None

    async def stop(self):
        if self.running:
            self.stop_server = True
            if self.server_instance:
                self.server_instance.close()
                await self.server_instance.wait_closed()
                self.server_instance = None
            
            for task in self.tasks:
                task.cancel()
            if self.tasks:
                await asyncio.gather(*self.tasks, return_exceptions=True)
            self.tasks.clear()
            
            self.running = False
            logging.info(get_message('server_shutting_down', self.language))

    async def get_next_proxy(self):
        try:
            current_time = time.time()
            
            if self.switching_proxy or (current_time - self.last_switch_attempt < self.switch_cooldown):
                return self.current_proxy
                
            if (self.use_getip and (not self.current_proxy or 
                current_time - self.last_switch_time >= self.interval)):
                try:
                    self.switching_proxy = True
                    self.last_switch_attempt = current_time
                    old_proxy = self.current_proxy
                    
                    await self.get_proxy()
                        
                finally:
                    self.switching_proxy = False
            
            return self.current_proxy
                    
        except Exception as e:
            logging.error(get_message('proxy_switch_error', self.language, str(e)))
            self.switching_proxy = False
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

    def time_until_next_switch(self):
        return float('inf') if self.mode == 'load_balance' else max(0, self.interval - (time.time() - self.last_switch_time))

    def check_ip_auth(self, ip):
        try:
            if not self.whitelist and not self.blacklist:
                return True

            if self.ip_auth_priority == 'whitelist':
                if self.whitelist:
                    if ip in self.whitelist:
                        return True
                    return False
                if self.blacklist:
                    return ip not in self.blacklist
                return True
            else:
                if ip in self.blacklist:
                    return False
                if self.whitelist:
                    return ip in self.whitelist
                return True
        except Exception as e:
            logging.error(get_message('whitelist_error', self.language, str(e)))
            return False

    def _authenticate(self, headers):
        if not self.auth_required:
            return True
            
        auth_header = headers.get('proxy-authorization', '')
        if not auth_header:
            return False
            
        try:
            scheme, credentials = auth_header.split()
            if scheme.lower() != 'basic':
                return False
                
            decoded = base64.b64decode(credentials).decode()
            username, password = decoded.split(':')
            
            if username in self.users and self.users[username] == password:
                return username, password
                
        except Exception:
            pass
            
        return False

    async def handle_client(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        try:
            peername = writer.get_extra_info('peername')
            if peername:
                client_ip = peername[0]
                if not self.check_ip_auth(client_ip):
                    logging.warning(get_message('unauthorized_ip', self.language, client_ip))
                    writer.write(b'HTTP/1.1 403 Forbidden\r\n\r\n')
                    await writer.drain()
                    return
                
            first_byte = await reader.read(1)
            if not first_byte:
                return
                
            if first_byte == b'\x05':
                await self.handle_socks5_connection(reader, writer)
            else:
                await self._handle_client_impl(reader, writer, first_byte)
                
        except Exception as e:
            logging.error(get_message('client_handle_error', self.language, e))
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
            self.tasks.remove(task)

    async def _pipe(self, reader, writer):
        try:
            while True:
                data = await reader.read(self.buffer_size)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logging.error(get_message('data_transfer_error', self.language, e))

    def _split_proxy_auth(self, proxy_addr):
        match = re.match(r'((?P<username>.+?):(?P<password>.+?)@)?(?P<host>.+)', proxy_addr)
        if match:
            username = match.group('username')
            password = match.group('password')
            host = match.group('host')
            if username and password:
                return f"{username}:{password}", host
        return None, proxy_addr

    async def _create_client(self, proxy):
        proxy_type, proxy_addr = proxy.split('://')
        proxy_auth = None
        
        if '@' in proxy_addr:
            auth, proxy_addr = proxy_addr.split('@')
            proxy_auth = auth
        
        if proxy_auth:
            proxy_url = f"{proxy_type}://{proxy_auth}@{proxy_addr}"
        else:
            proxy_url = f"{proxy_type}://{proxy_addr}"
            
        return httpx.AsyncClient(
            proxies={"all://": proxy_url},
            limits=httpx.Limits(
                max_keepalive_connections=100,
                max_connections=1000,
                keepalive_expiry=30
            ),
            timeout=30.0,
            http2=True,
            verify=False 
        )

    async def _cleanup_connections(self):
        current_time = time.time()
        expired_keys = [
            key for key, client in self.connection_pool.items()
            if current_time - client._last_used > 30
        ]
        for key in expired_keys:
            client = self.connection_pool.pop(key)
            await client.aclose()

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

                username = username.decode()
                password = password.decode()
                
                if username in self.users and self.users[username] == password:
                    peername = writer.get_extra_info('peername')
                    if peername:
                        client_ip = peername[0]
                        client_key = (client_ip, username)
                        if client_key not in self.known_clients:
                            self.known_clients.add(client_key)
                            logging.info(get_message('new_client_connect', self.language, client_ip, f"{username}:{password}"))
                else:
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

            max_retries = 3
            retry_count = 0
            last_error = None

            while retry_count < max_retries:
                try:
                    proxy = await self.get_next_proxy()
                    if not proxy:
                        raise Exception("No proxy available")

                    proxy_type, proxy_addr = proxy.split('://')
                    proxy_auth, proxy_host_port = self._split_proxy_auth(proxy_addr)
                    proxy_host, proxy_port = proxy_host_port.split(':')
                    proxy_port = int(proxy_port)

                    remote_reader, remote_writer = await asyncio.wait_for(
                        asyncio.open_connection(proxy_host, proxy_port),
                        timeout=10
                    )

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
                    
                    self.proxy_failed = False
                    return

                except (asyncio.TimeoutError, ConnectionRefusedError, ConnectionResetError) as e:
                    last_error = e
                    logging.warning(get_message('request_retry', self.language, max_retries - retry_count - 1))
                    await self.handle_proxy_failure()
                    retry_count += 1
                    if retry_count < max_retries:
                        await asyncio.sleep(1)
                    continue
                    
                except Exception as e:
                    last_error = e
                    logging.error(get_message('socks5_connection_error', self.language, str(e)))
                    await self.handle_proxy_failure()
                    retry_count += 1
                    if retry_count < max_retries:
                        await asyncio.sleep(1)
                    continue

            if last_error:
                logging.error(get_message('all_retries_failed', self.language, str(last_error)))
            writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()

        except Exception as e:
            logging.error(get_message('socks5_connection_error', self.language, str(e)))
            writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()

    async def _initiate_socks5(self, remote_reader, remote_writer, dst_addr, dst_port):
        try:
            auth = None
            proxy_type, proxy_addr = self.current_proxy.split('://')
            if '@' in proxy_addr:
                auth, _ = proxy_addr.split('@')

            if auth:
                remote_writer.write(b'\x05\x02\x00\x02')
            else:
                remote_writer.write(b'\x05\x01\x00')
                
            await remote_writer.drain()
            
            try:
                auth_method = await asyncio.wait_for(
                    remote_reader.readexactly(2),
                    timeout=10
                )
                if auth_method[0] != 0x05:
                    raise Exception("Invalid SOCKS5 proxy response")
                    
                if auth_method[1] == 0x02 and auth:
                    username, password = auth.split(':')
                    auth_packet = bytes([0x01, len(username)]) + username.encode() + bytes([len(password)]) + password.encode()
                    remote_writer.write(auth_packet)
                    await remote_writer.drain()
                    
                    auth_response = await asyncio.wait_for(
                        remote_reader.readexactly(2),
                        timeout=10
                    )
                    if auth_response[1] != 0x00:
                        raise Exception("Authentication failed")

                if isinstance(dst_addr, str):
                    remote_writer.write(b'\x05\x01\x00\x03' + len(dst_addr).to_bytes(1, 'big') + 
                                      dst_addr.encode() + dst_port.to_bytes(2, 'big'))
                else:
                    remote_writer.write(b'\x05\x01\x00\x01' + socket.inet_aton(dst_addr) + 
                                      dst_port.to_bytes(2, 'big'))
                
                await remote_writer.drain()
                
                response = await asyncio.wait_for(
                    remote_reader.readexactly(4),
                    timeout=10
                )
                if response[1] != 0x00:
                    error_codes = {
                        0x01: "General failure",
                        0x02: "Connection not allowed",
                        0x03: "Network unreachable",
                        0x04: "Host unreachable",
                        0x05: "Connection refused",
                        0x06: "TTL expired",
                        0x07: "Command not supported",
                        0x08: "Address type not supported"
                    }
                    error_msg = error_codes.get(response[1], f"Unknown error code {response[1]}")
                    raise Exception(f"Connection failed: {error_msg}")

                if response[3] == 0x01:
                    await asyncio.wait_for(
                        remote_reader.readexactly(6),
                        timeout=10
                    )
                elif response[3] == 0x03:  
                    domain_len = (await asyncio.wait_for(
                        remote_reader.readexactly(1),
                        timeout=10
                    ))[0]
                    await asyncio.wait_for(
                        remote_reader.readexactly(domain_len + 2),
                        timeout=10
                    )
                elif response[3] == 0x04: 
                    await asyncio.wait_for(
                        remote_reader.readexactly(18),
                        timeout=10
                    )
                else:
                    raise Exception(f"Unsupported address type: {response[3]}")
                    
            except asyncio.TimeoutError:
                raise Exception("SOCKS5 proxy response timeout")
            except Exception as e:
                raise Exception(f"SOCKS5 protocol error: {str(e)}")
                
        except Exception as e:
            if isinstance(e, asyncio.TimeoutError):
                raise Exception("SOCKS5 connection timeout")
            elif "Connection refused" in str(e):
                raise Exception("SOCKS5 connection refused")
            else:
                raise Exception(f"SOCKS5 initialization failed: {str(e)}")

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

    async def _handle_client_impl(self, reader, writer, first_byte):
        try:
            peername = writer.get_extra_info('peername')
            if peername:
                client_ip = peername[0]
                if not self.check_ip_auth(client_ip):
                    logging.warning(get_message('unauthorized_ip', self.language, client_ip))
                    writer.write(b'HTTP/1.1 403 Forbidden\r\n\r\n')
                    await writer.drain()
                    return

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

            if self.auth_required:
                auth_result = self._authenticate(headers)
                if not auth_result:
                    writer.write(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Proxy"\r\n\r\n')
                    await writer.drain()
                    return
                elif isinstance(auth_result, tuple):
                    username, password = auth_result
                    peername = writer.get_extra_info('peername')
                    if peername:
                        client_ip = peername[0]
                        client_key = (client_ip, username)
                        if client_key not in self.known_clients:
                            self.known_clients.add(client_key)
                            logging.info(get_message('new_client_connect', self.language, client_ip, f"{username}:{password}"))

            if method == 'CONNECT':
                await self._handle_connect(path, reader, writer)
            else:
                await self._handle_request(method, path, headers, reader, writer)

        except asyncio.CancelledError:
            raise
        except Exception as e:
            logging.error(get_message('client_request_error', self.language, e))

    async def _handle_connect(self, path, reader, writer):
        try:
            host, port = path.split(':')
            port = int(port)
        except ValueError:
            writer.write(b'HTTP/1.1 400 Bad Request\r\n\r\n')
            await writer.drain()
            return

        proxy = await self.get_next_proxy()
        if not proxy:
            writer.write(b'HTTP/1.1 503 Service Unavailable\r\n\r\n')
            await writer.drain()
            return

        try:
            proxy_type, proxy_addr = proxy.split('://')
            proxy_auth, proxy_host_port = self._split_proxy_auth(proxy_addr)
            proxy_host, proxy_port = proxy_host_port.split(':')
            proxy_port = int(proxy_port)

            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(proxy_host, proxy_port), 
                timeout=10
            )

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
            writer.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
            await writer.drain()
            if not self.proxy_failed: 
                self.proxy_failed = True  
                await self.get_proxy() 
        else:
            self.proxy_failed = False

    async def _handle_request(self, method, path, headers, reader, writer):
        async with self.request_semaphore:
            try:
                proxy = await self.get_next_proxy()
                if not proxy:
                    writer.write(b'HTTP/1.1 503 Service Unavailable\r\n\r\n')
                    await writer.drain()
                    return

                key = f"{proxy}:{path}"
                
                proxy_headers = headers.copy()
                proxy_type, proxy_addr = proxy.split('://')
                if '@' in proxy_addr:
                    auth, _ = proxy_addr.split('@')
                    auth_header = f'Basic {base64.b64encode(auth.encode()).decode()}'
                    proxy_headers['Proxy-Authorization'] = auth_header
                
                if key in self.connection_pool:
                    client = self.connection_pool[key]
                else:
                    client = await self._create_client(proxy)
                    self.connection_pool[key] = client

                async with client.stream(
                    method,
                    path,
                    headers=proxy_headers, 
                    content=reader,
                ) as response:
                    writer.write(f'HTTP/1.1 {response.status_code} {response.reason_phrase}\r\n'.encode())
                    
                    for header_name, header_value in response.headers.items():
                        if header_name.lower() != 'transfer-encoding': 
                            writer.write(f'{header_name}: {header_value}\r\n'.encode())
                    writer.write(b'\r\n')
                    
                    async for chunk in response.aiter_bytes(chunk_size=self.buffer_size):
                        writer.write(chunk)
                        if len(chunk) >= self.buffer_size:
                            await writer.drain()
                    
                    await writer.drain()
                    
            except Exception as e:
                logging.error(get_message('request_handling_error', self.language, str(e)))
                writer.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                await writer.drain()
            finally:
                await self._cleanup_connections()

    async def handle_proxy_failure(self):
        try:
            current_time = time.time()
            
            if self.switching_proxy or (current_time - self.last_switch_attempt < self.switch_cooldown):
                return
                
            self.proxy_fail_count += 1
            
            if self.proxy_fail_count >= self.max_fail_count:
                current_proxy = self.current_proxy if self.current_proxy else get_message('no_proxy', self.language)
                logging.warning(get_message('proxy_consecutive_fails', self.language, 
                                         current_proxy, self.proxy_fail_count))
                try:
                    self.switching_proxy = True
                    self.last_switch_attempt = current_time
                    old_proxy = current_proxy
                    
                    await self.get_proxy()
                    
                    self.proxy_fail_count = 0
                    self.proxy_failed = False
                        
                finally:
                    self.switching_proxy = False
            else:
                current_proxy = self.current_proxy if self.current_proxy else get_message('no_proxy', self.language)
                logging.warning(get_message('request_retry', self.language, 
                                         self.max_fail_count - self.proxy_fail_count))
                
        except Exception as e:
            current_proxy = self.current_proxy if self.current_proxy else get_message('no_proxy', self.language)
            logging.error(get_message('proxy_invalid', self.language, current_proxy))
            self.switching_proxy = False

    async def check_current_proxy(self):
        try:
            proxy = self.current_proxy
            current_time = time.time()

            if proxy in self.last_check_time:
                if current_time - self.last_check_time[proxy] < self.check_cooldown:
                    return self.proxy_check_cache.get(proxy, (current_time, True))[1]

            if proxy in self.proxy_check_cache:
                cache_time, is_valid = self.proxy_check_cache[proxy]
                if current_time - cache_time < self.proxy_check_ttl:
                    return is_valid

            self.last_check_time[proxy] = current_time

            test_url = self.config.get('test_url', 'https://www.baidu.com')
            
            proxy_type = proxy.split('://')[0]
            async with httpx.AsyncClient(
                proxies={f"{proxy_type}://": proxy},
                timeout=10,
                verify=False
            ) as client:
                response = await client.get(test_url)
                is_valid = response.status_code == 200
                self.proxy_check_cache[proxy] = (current_time, is_valid)
                return is_valid

        except Exception:
            self.proxy_check_cache[proxy] = (current_time, False)
            return False

    def _clean_proxy_cache(self):
        current_time = time.time()
        self.proxy_check_cache = {
            proxy: (cache_time, is_valid)
            for proxy, (cache_time, is_valid) in self.proxy_check_cache.items()
            if current_time - cache_time < self.proxy_check_ttl
        }
        self.last_check_time = {
            proxy: check_time
            for proxy, check_time in self.last_check_time.items()
            if current_time - check_time < self.proxy_check_ttl
        }

    def initialize_proxies(self):
        if self.mode == 'cycle':
            if hasattr(self, 'proxies') and self.proxies:
                self.proxy_cycle = cycle(self.proxies)
            elif self.use_getip:
                pass
            else:
                try:
                    with open(self.proxy_file, 'r') as f:
                        self.proxies = [line.strip() for line in f if line.strip()]
                    if self.proxies:
                        self.proxy_cycle = cycle(self.proxies)
                except Exception as e:
                    logging.error(get_message('load_proxy_file_error', self.language, str(e)))

    async def cleanup_disconnected_ips(self):
        while True:
            try:
                active_ips = set()
                for client_info in self.get_active_connections():
                    active_ips.add(client_info[0])
                
                self.connected_clients = active_ips
                
            except Exception as e:
                logging.error(get_message('cleanup_error', self.language, str(e)))
            
            await asyncio.sleep(30)

    def is_docker():
        return os.path.exists('/.dockerenv')

    async def get_proxy_status(self):
        if self.mode == 'load_balance':
            return f"{get_message('current_proxy', self.language)}: {self.current_proxy}"
        else:
            time_left = self.time_until_next_switch()
            if time_left == float('inf'):
                return f"{get_message('current_proxy', self.language)}: {self.current_proxy}"
            else:
                return f"{get_message('current_proxy', self.language)}: {self.current_proxy} | {get_message('next_switch', self.language)}: {time_left:.1f}{get_message('seconds', self.language)}"


    async def _get_proxy_connection(self, proxy):
        if proxy in self.proxy_pool:
            conn = self.proxy_pool[proxy]
            if not conn.is_closed:
                return conn
                
        proxy_type, proxy_addr = proxy.split('://')
        if '@' in proxy_addr:
            auth, addr = proxy_addr.split('@')
            username, password = auth.split(':')
        else:
            username = self.username
            password = self.password
            addr = proxy_addr
            
        host, port = addr.split(':')
        port = int(port)
        
        if proxy_type in ('socks5', 'socks4'):
            conn = await self._create_socks_connection(
                host, port, username, password, 
                proxy_type == 'socks5'
            )
        else:
            conn = await self._create_http_connection(
                host, port, username, password
            )
            
        if len(self.proxy_pool) < self.max_pool_size:
            self.proxy_pool[proxy] = conn
            
        return conn
        
    async def _create_socks_connection(self, host, port, username, password, is_socks5):
        reader, writer = await asyncio.open_connection(
            host, port, 
            limit=self.buffer_size
        )
        
        if is_socks5:
            writer.write(b'\x05\x02\x00\x02' if username else b'\x05\x01\x00')
            await writer.drain()
            
            version, method = await reader.readexactly(2)
            if version != 5:
                raise Exception('Invalid SOCKS version')
                
            if method == 2 and username:
                auth = bytes([1, len(username)]) + username.encode() + \
                       bytes([len(password)]) + password.encode()
                writer.write(auth)
                await writer.drain()
                
                auth_version, status = await reader.readexactly(2)
                if status != 0:
                    raise Exception('Authentication failed')
                    
        return reader, writer
        
    async def _create_http_connection(self, host, port, username, password):
        reader, writer = await asyncio.open_connection(
            host, port,
            limit=self.buffer_size
        )
        
        if username:
            auth = base64.b64encode(f'{username}:{password}'.encode()).decode()
            writer.write(f'Proxy-Authorization: Basic {auth}\r\n'.encode())
            await writer.drain()
            
        return reader, writer
        
    async def _cleanup_pool(self):
        while True:
            try:
                for proxy, conn in list(self.proxy_pool.items()):
                    if conn.is_closed:
                        del self.proxy_pool[proxy]
            except Exception as e:
                logging.error(f'连接池清理错误: {e}')
            await asyncio.sleep(60)

    def _log_proxy_switch(self, old_proxy, new_proxy):
        if old_proxy != new_proxy:
            old_proxy = old_proxy if old_proxy else get_message('no_proxy', self.language)
            new_proxy = new_proxy if new_proxy else get_message('no_proxy', self.language)
            logging.info(get_message('proxy_switch', self.language, old_proxy, new_proxy))

    async def _validate_proxy(self, proxy):
        if not proxy:
            return False
            
        try:
            if not validate_proxy(proxy):
                logging.warning(get_message('proxy_invalid', self.language, proxy))
                return False
                
            proxy_type, proxy_addr = proxy.split('://')
            proxy_auth, proxy_host_port = self._split_proxy_auth(proxy_addr)
            proxy_host, proxy_port = proxy_host_port.split(':')
            proxy_port = int(proxy_port)
            
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(proxy_host, proxy_port),
                    timeout=5
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except:
                    pass
                return True
            except:
                return False
                
        except Exception as e:
            logging.error(get_message('proxy_check_failed', self.language, proxy, str(e)))
            return False

    async def get_proxy(self):
        try:
            old_proxy = self.current_proxy
            
            if not self.use_getip and self.proxies:
                if not self.proxy_cycle:
                    self.proxy_cycle = cycle(self.proxies)
                    
                for _ in range(3):
                    new_proxy = next(self.proxy_cycle)
                    if await self._validate_proxy(new_proxy):
                        self.current_proxy = new_proxy
                        self.last_switch_time = time.time()
                        self._log_proxy_switch(old_proxy, self.current_proxy)
                        return self.current_proxy
                        
                logging.error(get_message('no_valid_proxies', self.language))
                return self.current_proxy
            
            if self.use_getip:
                try:
                    new_proxy = await self._load_getip_proxy()
                    if new_proxy and await self._validate_proxy(new_proxy):
                        self.current_proxy = new_proxy
                        self.last_switch_time = time.time()
                        self._log_proxy_switch(old_proxy, self.current_proxy)
                        return self.current_proxy
                    else:
                        logging.error(get_message('proxy_get_failed', self.language))
                except Exception as e:
                    logging.error(get_message('proxy_get_error', self.language, str(e)))
            
            return self.current_proxy
            
        except Exception as e:
            logging.error(get_message('proxy_get_error', self.language, str(e)))
            return self.current_proxy
