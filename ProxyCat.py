from http.server import BaseHTTPRequestHandler, HTTPServer
from concurrent.futures import ThreadPoolExecutor
import multiprocessing
import threading
import logoprint
import requests
import argparse
import logging
import socket
import select
import socks
import time

logging.basicConfig(level=logging.INFO)
proxy_index, rotate_mode, rotate_interval = 0, 'cycle', 60

def load_proxies(file_path='ip.txt'):
    with open(file_path, 'r') as file:
        proxies = [line.strip().split('://') for line in file]
        return [(p[0], *p[1].split(':')) for p in proxies]

def rotate_proxies(proxies, interval):
    global proxy_index
    while True:
        time.sleep(interval)
        if rotate_mode == 'cycle':
            proxy_index = (proxy_index + 1) % len(proxies)
        elif rotate_mode == 'once' and proxy_index < len(proxies) - 1:
            proxy_index += 1
        logging.info(f"切换到代理地址: {proxies[proxy_index]}")

proxies = load_proxies()

class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=1000, pool_maxsize=1000)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        super().__init__(*args, **kwargs)

    def _update_proxy(self):
        global proxy_index
        protocol, host, port = proxies[proxy_index]
        self.proxy_dict = {"http": f"{protocol}://{host}:{port}", "https": f"{protocol}://{host}:{port}"}

    def do_GET(self): self._proxy_request()
    def do_POST(self): self._proxy_request()
    def do_CONNECT(self): self._tunnel_request()

    def _proxy_request(self):
        self._update_proxy()
        data = self.rfile.read(int(self.headers['Content-Length'])) if 'Content-Length' in self.headers else None
        headers = {key: val for key, val in self.headers.items()}
        headers['Connection'] = 'keep-alive'

        try:
            response = self.session.request(self.command, self.path, headers=headers, data=data, 
                proxies=self.proxy_dict, stream=True, timeout=(5, 27))
            self.send_response(response.status_code)
            self.send_headers(response)
            self.forward_content(response)
        except Exception as e:
            self.send_error(500, message=str(e))

    def send_headers(self, response):
        for key, value in response.headers.items():
            if key.lower() != 'connection':
                self.send_header(key, value)
        self.send_header('Connection', 'keep-alive')
        self.end_headers()

    def forward_content(self, response):
        for chunk in response.iter_content(chunk_size=4096):
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
        except Exception as e:
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
        sockets = [client_socket, remote_socket]
        while True:
            read_sockets, _, error_sockets = select.select(sockets, [], sockets, 10)
            if error_sockets:
                break
            for sock in read_sockets:
                other_sock = client_socket if sock is remote_socket else remote_socket
                data = sock.recv(4096)
                if not data:
                    return
                other_sock.sendall(data)

def run(server_class=HTTPServer, handler_class=ProxyHTTPRequestHandler, port=1080, mode='cycle', interval=60):
    global rotate_mode, rotate_interval
    rotate_mode, rotate_interval = mode, interval
    
    server_address, max_workers = ('', port), multiprocessing.cpu_count() * 5
    executor = ThreadPoolExecutor(max_workers=max_workers)
    server = server_class(server_address, handler_class)
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

def print_icpscan_banner(port, mode, interval):
    logoprint.logos()
    mode = '循环' if mode == 'cycle' else '单轮'
    print("--------------------------------------------------------")
    print("公众号:樱花庄的本间白猫")
    print("博客:https://y.shironekosan.cn")
    print("Github:https://github.com/honmashironeko/ProxyCat")
    print("Gitcode:https://gitcode.com/honmashironeko/ProxyCat")
    print("--------------------------------------------------------")
    print(f"监听端口: {port}, 代理轮换模式: {mode}, 代理更换时间: {interval}秒")
    print(f"初始代理地址: {proxies[proxy_index]}")
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=logoprint.logos())
    parser.add_argument('-p', type=int, default=1080, help='监听端口')
    parser.add_argument('-m', default='cycle', help='代理轮换模式:cycle 表示循环使用,once 表示用完即止')
    parser.add_argument('-t', type=int, default=60, help='代理更换时间(秒)')
    args = parser.parse_args()
    print_icpscan_banner(port=args.p, mode=args.m, interval=args.t)
    run(port=args.p, mode=args.m, interval=args.t)
