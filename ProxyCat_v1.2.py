from http.server import BaseHTTPRequestHandler, HTTPServer
from concurrent.futures import ThreadPoolExecutor
from httpx import AsyncClient
import multiprocessing
import logoprint
import threading
import argparse
import asyncio
import logging
import socket
import select
import base64
import httpx
import getip
import socks
import time

logging.basicConfig(level=logging.INFO)
proxy_index, rotate_mode, rotate_interval = 0, 'cycle', 60
proxy_fail_count = {}

def load_proxies(file_path='ip.txt'):
    with open(file_path, 'r') as file:
        proxies = [line.strip().split('://') for line in file]
        return [(p[0], *p[1].split(':')) for p in proxies if len(p) == 2]

def rotate_proxies(proxies, interval):
    global proxy_index
    while True:
        time.sleep(interval)
        if args.k:
            proxies.clear()
            proxies.extend(get_proxy_from_getip())
            proxy_index = (proxy_index + 1) % len(proxies)
        else:
            if rotate_mode == 'cycle':
                proxy_index = (proxy_index + 1) % len(proxies)
            elif rotate_mode == 'once' and proxy_index < len(proxies) - 1:
                proxy_index += 1
        logging.info(f"切换到代理地址: {proxies[proxy_index]}")

def get_proxy_from_getip():
    proxy = getip.newip()
    protocol, host_port = proxy.split('://')
    host, port = host_port.split(':')
    return [(protocol, host, port)]

proxies = []

class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.client = AsyncClient(http2=True, timeout=httpx.Timeout(10.0, read=30.0))
        super().__init__(*args, **kwargs)

    def _update_proxy(self):
        global proxy_index, proxy_fail_count
        if rotate_interval == 0:
            if args.k:
                proxies.clear()
                proxies.extend(get_proxy_from_getip())
            proxy_index = (proxy_index + 1) % len(proxies)
            logging.info(f"切换到代理地址: {proxies[proxy_index]}")
        protocol, host, port = proxies[proxy_index]
        self.proxy_dict = {"http://": f"{protocol}://{host}:{port}", "https://": f"{protocol}://{host}:{port}"}

    def _authenticate(self):
        auth = self.headers.get('Proxy-Authorization')
        if not auth:
            self.send_response(407)
            self.send_header('Proxy-Authenticate', 'Basic realm="Proxy"')
            self.end_headers()
            return False
        auth = auth.split()
        if len(auth) != 2:
            self.send_error(400, message="Invalid authentication format")
            return False
        if auth[0].lower() != 'basic':
            self.send_error(400, message="Unsupported authentication method")
            return False
        auth = auth[1].encode('utf-8')
        auth = base64.b64decode(auth).decode('utf-8')
        username, password = auth.split(':', 1)
        if username != self.server.username or password != self.server.password:
            self.send_error(403, message="Invalid credentials")
            return False
        return True

    def do_GET(self):
        if self._authenticate():
            self._proxy_request()

    def do_POST(self):
        if self._authenticate():
            self._proxy_request()

    def do_CONNECT(self):
        if self._authenticate():
            self._tunnel_request()

    def _proxy_request(self):
        self._update_proxy()
        data = self.rfile.read(int(self.headers['Content-Length'])) if 'Content-Length' in self.headers else None
        headers = {key: val for key, val in self.headers.items()}
        headers['Connection'] = 'keep-alive'

        async def handle():
            for attempt in range(3):
                try:
                    logging.info(f"处理请求: {self.command} {self.path}")
                    response = await self.client.request(self.command, self.path, headers=headers, data=data, 
                                                         proxies=self.proxy_dict, stream=True)
                    self.send_response(response.status_code)
                    self.send_headers(response)
                    await self.forward_content(response)
                    break
                except (httpx.RequestError, socket.timeout, OSError) as e:
                    logging.error(f"请求失败: {e}")
                    self._handle_proxy_failure()
                    if attempt == 2:
                        self.send_error(500, message=str(e))

        asyncio.run(handle())

    def _handle_proxy_failure(self):
        global proxy_index, proxy_fail_count
        current_proxy = proxies[proxy_index]
        if current_proxy in proxy_fail_count:
            proxy_fail_count[current_proxy] += 1
        else:
            proxy_fail_count[current_proxy] = 1

        if proxy_fail_count[current_proxy] >= 3:
            logging.info(f"代理地址 {current_proxy} 失败次数达到3次，尝试切换到下一个代理")
            original_proxy_index = proxy_index
            if args.k:
                new_proxies = get_proxy_from_getip()
                if new_proxies:
                    proxies.clear()
                    proxies.extend(new_proxies)
                    proxy_index = (proxy_index + 1) % len(proxies)
                    logging.info(f"切换到新代理地址: {proxies[proxy_index]}")
                else:
                    logging.warning("无法获取新代理，继续使用原代理")
                    proxy_index = original_proxy_index 
            else:
                if rotate_mode == 'cycle':
                    proxy_index = (proxy_index + 1) % len(proxies)
                elif rotate_mode == 'once' and proxy_index < len(proxies) - 1:
                    proxy_index += 1
                logging.info(f"切换到代理地址: {proxies[proxy_index]}")
            proxy_fail_count[current_proxy] = 0 

    def send_headers(self, response):
        for key, value in response.headers.items():
            if key.lower() != 'connection':
                self.send_header(key, value)
        self.send_header('Connection', 'keep-alive')
        self.end_headers()

    async def forward_content(self, response):
        async for chunk in response.aiter_bytes(chunk_size=4096):
            if chunk:
                self.wfile.write(chunk)
                self.wfile.flush()

    def _tunnel_request(self):
        self._update_proxy()
        host, port = self.path.split(':')
        try:
            remote_socket = self._connect_via_proxy(host, int(port))
            self.send_response(200, 'Connection Established')
            self.send_header('Connection', 'keep-alive')
            self.end_headers()
            self._forward_data(self.connection, remote_socket)
        except (socket.error, Exception) as e:
            logging.error(f"隧道请求失败: {e}")
            self._handle_proxy_failure()
            self.send_error(502, message=str(e))

    def _connect_via_proxy(self, host, port):
        protocol = proxies[proxy_index][0]
        if protocol == 'http':
            return self._connect_via_http_proxy(host, port)
        elif protocol == 'socks5':
            return self._connect_via_socks5_proxy(host, port)
        else:
            raise Exception("不支持的代理类型")

    def _connect_via_http_proxy(self, host, port):
        proxy_connect = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: keep-alive\r\n\r\n"
        remote_socket = socket.create_connection((proxies[proxy_index][1], int(proxies[proxy_index][2])))
        remote_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 4096)
        remote_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 4096)
        remote_socket.sendall(proxy_connect.encode())
        response = remote_socket.recv(4096).decode('utf-8')
        if '200 Connection established' not in response:
            raise Exception(f"无法通过 HTTP 代理建立连接: {response}")
        return remote_socket

    def _connect_via_socks5_proxy(self, host, port):
        remote_socket = socks.socksocket()
        remote_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 4096)
        remote_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 4096)
        remote_socket.set_proxy(socks.SOCKS5, proxies[proxy_index][1], int(proxies[proxy_index][2]))
        remote_socket.connect((host, port))
        return remote_socket

    def _forward_data(self, client_socket, remote_socket):
        try:
            sockets = [client_socket, remote_socket]
            while True:
                read_sockets, _, error_sockets = select.select(sockets, [], sockets, 10)
                if error_sockets:
                    logging.warning("Socket错误，终止连接")
                    break
                for sock in read_sockets:
                    other_sock = client_socket if sock is remote_socket else remote_socket
                    data = sock.recv(4096)
                    if not data:
                        return
                    other_sock.sendall(data)
        finally:
            client_socket.close()
            remote_socket.close()

def run(server_class=HTTPServer, handler_class=ProxyHTTPRequestHandler, port=1080, mode='cycle', interval=60, username='neko', password='123456', use_getip=False):
    global rotate_mode, rotate_interval, proxies, args
    rotate_mode, rotate_interval = mode, interval
    
    if use_getip:
        proxies = get_proxy_from_getip()
    else:
        proxies = load_proxies()
    if proxies:
        logging.info(f"初始代理地址: {proxies[proxy_index]}")
    else:
        logging.error("没有加载到任何代理地址")
        return
    
    server_address, max_workers = ('', port), multiprocessing.cpu_count() * 5
    executor = ThreadPoolExecutor(max_workers=max_workers)
    server = server_class(server_address, handler_class)
    server.username = username
    server.password = password
    if interval > 0:
        thread = threading.Thread(target=rotate_proxies, args=(proxies, interval))
        thread.daemon = True
        thread.start()
    serve_requests(server, executor)

def serve_requests(server, executor):
    try:
        while True:
            request, client_address = server.get_request()
            executor.submit(server.process_request, request, client_address)
    except KeyboardInterrupt:
        pass
    finally:
        executor.shutdown(wait=True)
        server.server_close()

def print_icpscan_banner(port, mode, interval, username, password):
    mode = '循环' if mode == 'cycle' else '单轮'
    print("--------------------------------------------------------")
    print("公众号:樱花庄的本间白猫")
    print("博客:https://y.shironekosan.cn")
    print("Github:https://github.com/honmashironeko/ProxyCat")
    print("Gitcode:https://gitcode.com/honmashironeko/ProxyCat")
    print("--------------------------------------------------------")
    print(f"监听端口: {port}, 代理轮换模式: {mode}, 代理更换时间: {interval}秒")
    print(f"默认账号密码: {username}:{password}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=logoprint.logos())
    parser.add_argument('-p', type=int, default=1080, help='监听端口')
    parser.add_argument('-m', default='cycle', help='代理轮换模式:cycle 表示循环使用,once 表示用完即止')
    parser.add_argument('-t', type=int, default=60, help='代理更换时间(秒),设置为0秒时变成每次请求更换IP')
    parser.add_argument('-up', default='neko:123456', help='指定账号密码,格式为username:password')
    parser.add_argument('-k', action='store_true', help='使用 getip 模块获取代理地址')
    args = parser.parse_args()
    username, password = args.up.split(':')
    print_icpscan_banner(port=args.p, mode=args.m, interval=args.t, username=username, password=password)
    run(port=args.p, mode=args.m, interval=args.t, username=username, password=password, use_getip=args.k)
