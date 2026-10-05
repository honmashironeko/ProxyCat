"""
模块名称：modules.proxyserver
功能描述：本地代理转发服务器：在配置端口上同时接受 HTTP 与 SOCKS5 入站请求，维持一个有目标容量的上游出口池（按来源取候选、逐条校验填充、按寿命单独替换）。
职责边界：负责：HTTP / SOCKS5 入站处理与隧道中继、出口池维持（取候选、校验填充、按寿命替换）、出口分配与失败归因、
          IP 名单与代理认证、连接池与并发上限、出口真实 IP 的获取与缓存。不负责：代理抓取与验证评分（见 modules.proxypool 与 modules.modules 的
          check_proxy）、记录持久化（modules.access_log 等）、服务器线程的创建与重启（app.py、ProxyCat.py）。
关键依赖：modules.modules、modules.proxy_workers、modules.access_log、
          modules.domain_stats、modules.access_records、modules.logging_setup、
          modules.loop_noise_filter、modules.pool_config_ini、config.getip、httpx。
已知限制：
1. 上游协议只支持 http / https / socks5；https 上游会真做 TLS，且一律不校验证书。
2. 重试上限固定 2 次，带请求体的明文 HTTP 请求不重试；归因口径分路径：HTTP 转发只记真正的上游传输错误，
   其余失败也照常换出口重试；CONNECT / SOCKS5 隧道把握手失败等非传输错误也计入出口失败。
3. CONNECT 隧道与 SOCKS5 的写回只代表隧道已建立，要等上游回了数据才算成功；_check_worker 返回三态，None 表示这次没有结论。
4. 出口名额绑在连接任务上，_pipe 跑在 asyncio.gather 的子任务里，不能用 asyncio.current_task() 反查，必须显式传参。
5. 一个可用出口都没有时请求在 _wait_for_exit 排队等 exit_wait_timeout 秒，超时才回 503；空闲隧道不占每出口活跃额度。
6. 双栈监听下 IPv4 客户端的对端是 ::ffff:x.x.x.x，必须经 _peer_ip 归一化，否则 IP 名单静默失效；Windows 的 listen backlog 不生效。
7. 上游一字未回即断的 CONNECT 隧道不关客户端连接，由调用方换出口重放已缓冲请求（重放缓冲上限 64 KiB）。
"""

import asyncio, httpx, ipaddress, json, logging, socket, struct, time, base64, os, threading, errno, http.cookiejar, ssl
from collections import OrderedDict
from contextlib import AsyncExitStack, asynccontextmanager
from typing import NamedTuple
from modules.modules import (
    get_message, load_ip_list, load_bypass_whitelist, check_bypass_match, port_in_use,
    parse_bool_lenient, parse_proxy_url, split_host_port, build_socks5_auth_packet,
    normalize_rotation_mode,
)
from modules.access_log import (
    KIND_CONNECT, KIND_HTTP, KIND_SOCKS5, AccessRecord, AccessTracker, ClientIdentity,
    sanitize_proxy,
)
from modules.access_records import RequestRecordStore
from modules.domain_stats import DomainStatsStore
from modules.logging_setup import LogCategory, ThrottledLogger, get_category_logger
from modules.loop_noise_filter import install_loop_noise_filter
from modules.proxy_workers import (
    BLAME_IGNORED, BLAME_RETIRED, ProxyWorkerPool, StandbyQueue,
)
from config.getip import newip_list as getip_newip_list

logger = get_category_logger(LogCategory.PROXY)

logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("hpack").setLevel(logging.WARNING)
logging.getLogger("h2").setLevel(logging.WARNING)

_SERVER_DIR = os.path.dirname(os.path.abspath(__file__))
_BASE_DIR = os.path.dirname(_SERVER_DIR)


def _as_bool(value) -> bool:
    return parse_bool_lenient(value)


def _v4_mapped_literal(address: str) -> str | None:
    if address[:7].lower() != '::ffff:':
        return None
    parts = address[7:].split('.')
    if len(parts) != 4:
        return None
    for part in parts:
        if not (part.isascii() and part.isdigit()):
            return None
        if len(part) > 1 and part[0] == '0':
            return None
        if int(part) > 255:
            return None
    return '.'.join(parts)


def _remaining_time(deadline: float) -> float:
    return max(0.0, deadline - asyncio.get_running_loop().time())


_BODY_CHUNK_SIZE = 64 * 1024

_BODY_READ_TIMEOUT = 30.0

_BODY_TOTAL_TIMEOUT = 300.0

_CLIENT_HEADER_TIMEOUT = 10.0

_IDLE_TUNNEL_TIMEOUT = 300.0

_LISTEN_BACKLOG = 2048

_STREAM_LIMIT = 32768

_RETRY_BACKOFF_SECONDS = 0.2

_TUNNEL_TOTAL_BUDGET_SECONDS = 20.0

_TUNNEL_REPLAY_LIMIT = 64 * 1024

_HAPPY_EYEBALLS_DELAY = 0.25

_RELAY_CHUNK = 64 * 1024

_REQUEST_MAINTENANCE_BUDGET = 5.0

_FILL_PROBE_FANOUT = 4

_FILL_BACKOFF_MAX = 60.0

_ROTATE_RETRY_SECONDS = 2.0

_DEMAND_RECENT_SECONDS = 10.0

_POOL_FETCH_MIN = 3

_FETCH_OVERSUBSCRIBE = 8
_FETCH_MAX_BATCH = 24

_EXIT_REAL_IP_CACHE_LIMIT = 4096

_REAL_IP_PROBE_TIMEOUT = 5.0
_REAL_IP_PROBE_RETRY_SECONDS = 600.0
_REAL_IP_PROBE_FANOUT = 3

_EXPAND_SATURATION_RATIO = 0.8
_EXPAND_RECOVER_UTILIZATION = 0.5
_EXPAND_TRIGGER_SECONDS = 1.0
_EXPAND_RECOVER_SECONDS = 30.0

_EXPAND_MAX_CAPACITY_BOOST = 2

_BURST_EXPAND_COOLDOWN = 5.0

_KEEPALIVE_IDLE_SECONDS = 60
_KEEPALIVE_INTERVAL_SECONDS = 10


def _tune_keepalive(sock) -> None:
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        if not hasattr(socket, 'SIO_KEEPALIVE_VALS'):
            if hasattr(socket, 'TCP_KEEPIDLE'):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, _KEEPALIVE_IDLE_SECONDS)
            if hasattr(socket, 'TCP_KEEPINTVL'):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, _KEEPALIVE_INTERVAL_SECONDS)
            if hasattr(socket, 'TCP_KEEPCNT'):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
            return

        ioctl = getattr(sock, 'ioctl', None)
        if ioctl is None:
            return
        ioctl(socket.SIO_KEEPALIVE_VALS, (
            1, _KEEPALIVE_IDLE_SECONDS * 1000, _KEEPALIVE_INTERVAL_SECONDS * 1000,
        ))
    except Exception:
        pass


_SSL_PROTOCOL_MAX_SIZE = 64 * 1024


def _tune_asyncio_ssl_buffers() -> None:
    try:
        from asyncio import sslproto
        if hasattr(sslproto.SSLProtocol, 'max_size'):
            sslproto.SSLProtocol.max_size = _SSL_PROTOCOL_MAX_SIZE
    except Exception:
        pass


_tune_asyncio_ssl_buffers()

_TLS_CONTEXT_LIMIT = 64
_tls_contexts = OrderedDict()
_tls_contexts_lock = threading.Lock()


class _SessionInjectingTLSContext(ssl.SSLContext):
    def __new__(cls):
        return super().__new__(cls, ssl.PROTOCOL_TLS_CLIENT)

    def __init__(self):
        self.check_hostname = False
        self.verify_mode = ssl.CERT_NONE
        self._session = None

    def remember_session(self, session) -> None:
        self._session = session

    def wrap_bio(self, *args, **kwargs):
        session = self._session
        if session is None or 'session' in kwargs or len(args) >= 5:
            return super().wrap_bio(*args, **kwargs)
        try:
            return super().wrap_bio(*args, session=session, **kwargs)
        except Exception:
            return super().wrap_bio(*args, **kwargs)


def _upstream_tls_context(host, port) -> ssl.SSLContext:
    key = (host, int(port))
    with _tls_contexts_lock:
        context = _tls_contexts.get(key)
        if context is None:
            context = _SessionInjectingTLSContext()
            _tls_contexts[key] = context
            while len(_tls_contexts) > _TLS_CONTEXT_LIMIT:
                _tls_contexts.popitem(last=False)
        else:
            _tls_contexts.move_to_end(key)
    return context


def _remember_upstream_tls_session(host, port, writer) -> None:
    try:
        ssl_object = writer.get_extra_info('ssl_object')
        if ssl_object is None:
            return
        session = ssl_object.session
        if session is None or not session.has_ticket:
            return
        with _tls_contexts_lock:
            context = _tls_contexts.get((host, int(port)))
        if context is not None:
            context.remember_session(session)
    except Exception:
        pass


class _NullCookieJar(http.cookiejar.CookieJar):
    def extract_cookies(self, response, request):
        pass

    def add_cookie_header(self, request):
        pass

_MAX_HEADER_LINES = 100
_MAX_HEADER_BYTES = 64 * 1024

_TUNNEL_SWEEP_INTERVAL = 0.25

_REASON_SILENT_TUNNEL = 'silent-tunnel'


async def _iter_body(reader, length: int, deadline: float):
    remaining = length
    while remaining > 0:
        chunk = await asyncio.wait_for(
            reader.read(min(remaining, _BODY_CHUNK_SIZE)),
            min(_BODY_READ_TIMEOUT, _remaining_time(deadline)),
        )
        if not chunk:
            raise asyncio.IncompleteReadError(partial=b'', expected=remaining)
        remaining -= len(chunk)
        yield chunk


async def _iter_chunked_body(reader, deadline: float):
    while True:
        size_line = await asyncio.wait_for(
            reader.readline(), min(_BODY_READ_TIMEOUT, _remaining_time(deadline)))
        if not size_line:
            raise asyncio.IncompleteReadError(partial=b'', expected=1)
        try:
            size = int(size_line.split(b';', 1)[0].strip() or b'0', 16)
        except ValueError:
            raise ValueError("malformed chunk size line") from None
        if size == 0:
            while True:
                line = await asyncio.wait_for(
                    reader.readline(), min(_BODY_READ_TIMEOUT, _remaining_time(deadline)))
                if line in (b'\r\n', b'\n', b''):
                    break
            return

        remaining = size
        while remaining > 0:
            chunk = await asyncio.wait_for(
                reader.read(remaining), min(_BODY_READ_TIMEOUT, _remaining_time(deadline)))
            if not chunk:
                raise asyncio.IncompleteReadError(partial=b'', expected=remaining)
            remaining -= len(chunk)
            yield chunk
        await asyncio.wait_for(
            reader.readexactly(2), min(_BODY_READ_TIMEOUT, _remaining_time(deadline)))



def _client_request_body(headers, reader, deadline: float):
    if 'chunked' in headers.get('transfer-encoding', '').lower():
        return _iter_chunked_body(reader, deadline)

    declared = headers.get('content-length')
    if declared is None:
        return None
    try:
        size = int(str(declared).strip())
    except ValueError:
        return None
    return _iter_body(reader, size, deadline) if size > 0 else None


_REASON_PHRASES = {
    400: 'Bad Request',
    407: 'Proxy Authentication Required',
    502: 'Bad Gateway',
    503: 'Service Unavailable',
    504: 'Gateway Timeout',
}

_HOP_BY_HOP_HEADERS = frozenset({
    'connection', 'keep-alive', 'proxy-connection', 'proxy-authorization',
    'te', 'trailer', 'transfer-encoding', 'upgrade',
})

_UPSTREAM_TRANSPORT_ERRORS = (
    httpx.ConnectError, httpx.ConnectTimeout,
    httpx.ReadTimeout, httpx.WriteTimeout,
    httpx.ReadError, httpx.WriteError, httpx.CloseError,
    httpx.RemoteProtocolError, httpx.ProxyError,
)

_UPSTREAM_REQUEST_TIMEOUT = httpx.Timeout(30.0)
_UPSTREAM_TIMEOUT_EXTENSIONS = _UPSTREAM_REQUEST_TIMEOUT.as_dict()


def _merge_default_headers(client, headers):
    if not isinstance(headers, dict):
        merged = httpx.Headers(client.headers)
        merged.update(headers)
        return merged
    pairs = []
    overridden = set()
    for key, value in headers.items():
        key_bytes = key if isinstance(key, bytes) else key.encode('ascii')
        value_bytes = value if isinstance(value, bytes) else value.encode('ascii')
        overridden.add(key_bytes.lower())
        pairs.append((key_bytes, value_bytes))
    merged = [pair for pair in client.headers.raw
              if pair[0].lower() not in overridden]
    merged.extend(pairs)
    return merged


def _build_upstream_request(client, method, url, headers, content):
    return httpx.Request(
        method, url,
        headers=_merge_default_headers(client, headers),
        content=content,
        extensions={'timeout': _UPSTREAM_TIMEOUT_EXTENSIONS},
    )


@asynccontextmanager
async def _stream_upstream(client, request):
    response = await client.send(request, stream=True)
    try:
        yield response
    finally:
        await response.aclose()


class UnsupportedUpstreamProxyError(Exception):
    pass

async def run_server(server):
    try:
        await server.start()
    except asyncio.CancelledError:
        logger.info(get_message('server_closing', server.language))
    except Exception as e:
        if not server.stop_server:
            logger.error(f"Server error: {e}")
    finally:
        await server.stop()


_SUPPORTED_PROXY_SCHEMES = frozenset({'http', 'https', 'socks5'})


def validate_proxy(proxy):
    try:
        scheme, _auth, host, port = parse_proxy_url(proxy)
    except ValueError:
        return False

    return bool(host) and scheme in _SUPPORTED_PROXY_SCHEMES and 0 < port < 65536


def _is_ipv4_literal(token: str) -> bool:
    parts = token.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        if not (part.isascii() and part.isdigit()) or len(part) > 3:
            return False
        if int(part) > 255:
            return False
    return True


def _real_ip_token(token: str):
    candidate = token.strip().strip('"').strip()
    if not candidate:
        return None

    if candidate.startswith('[') and ']' in candidate:
        candidate = candidate[1:candidate.index(']')]

    try:
        parsed = ipaddress.ip_address(candidate)
    except ValueError:
        head, sep, tail = candidate.rpartition(':')
        if sep and tail.isdigit() and _is_ipv4_literal(head):
            return head
        return None

    mapped = getattr(parsed, 'ipv4_mapped', None)
    return str(mapped) if mapped is not None else str(parsed)


def _parse_real_ip_echo(text: str):
    raw = (text or '').strip()[:2048]
    if not raw:
        return None
    candidates = []
    if raw.startswith('{'):
        try:
            data = json.loads(raw)
        except ValueError:
            return None
        for field in ('origin', 'ip', 'query'):
            value = data.get(field)
            if isinstance(value, str):
                candidates.extend(value.replace(',', ' ').split())
    else:
        candidates = raw.replace('=', ' ').replace(',', ' ').split()

    parsed = [ip for ip in (_real_ip_token(t) for t in reversed(candidates)) if ip]
    for ip in parsed:
        if ':' not in ip:
            return ip
    return parsed[0] if parsed else None


class MaintenanceOutcome(NamedTuple):
    changed: bool
    fetched: bool
    gained: int

    def __bool__(self):
        return self.changed


_NO_MAINTENANCE = MaintenanceOutcome(False, False, 0)


class _ReplayBuffer:
    __slots__ = ('data', 'overflowed', '_limit')

    def __init__(self, limit):
        self.data = bytearray()
        self._limit = limit
        self.overflowed = False

    def add(self, chunk):
        if self.overflowed:
            return
        if len(self.data) + len(chunk) > self._limit:
            self.overflowed = True
            self.data = bytearray()
            return
        self.data += chunk

    def __len__(self):
        return len(self.data)

    @property
    def replayable(self):
        return not self.overflowed


class AsyncProxyServer:

    def __init__(self, config, pool_service=None):
        self.config = config
        self._pool_service = pool_service
        self._workers = ProxyWorkerPool()
        self._init_config_values(config)
        self._init_server_state()
        self._init_connection_settings()
        self._switch_lock = threading.Lock()

        self.domain_stats = DomainStatsStore(config, _BASE_DIR)
        self.access_records = RequestRecordStore(config, _BASE_DIR)
        self.access_tracker = AccessTracker(
            language=self.language,
            stats=self.domain_stats,
            emit_log=_as_bool(config.get('log_access_enabled', 'true')),
            records=self.access_records,
        )

        self._last_source_error = None

    @property
    def proxies(self):
        return [worker.url for worker in self._workers.roster]

    @proxies.setter
    def proxies(self, urls):
        self._workers.set_workers(list(urls))
        self._sync_current_proxy()

    def _sync_current_proxy(self):
        urls = self.proxies
        if self.current_proxy not in urls:
            self.current_proxy = urls[0] if urls else None

    def active_workers(self):
        now = time.monotonic()
        limit = self.request_interval
        snapshot = []
        for entry in self._workers.snapshot():
            expires_at = entry.get('expires_at') or 0.0
            entry['expires_in'] = max(0.0, expires_at - now) if expires_at else None
            entry['requests_left'] = (
                max(0, limit - entry['requests_served']) if limit > 0 else None
            )
            snapshot.append(entry)
        return snapshot

    def source_proxies(self):
        if self.proxy_source_mode == 'local':
            return self._load_file_proxies()
        return self.proxies

    def roster_revision(self):
        return self._workers.revision

    def _init_config_values(self, config):
        self.port = int(config.get('port', '1080'))
        self.mode = config.get('mode', 'cycle')
        previous_interval = getattr(self, 'interval', None)
        self.interval = int(config.get('interval', '300'))
        self.language = config.get('language', 'cn')
        self.proxy_source_mode = config.get('proxy_source_mode', 'local').lower()
        self.mode = normalize_rotation_mode(self.mode, self.proxy_source_mode)
        self.api_proxy_url = config.get('api_proxy_url', '')
        self.pool_remote_url = config.get('pool_remote_url', '')
        self.check_proxies_on_startup = _as_bool(
            config.get('check_proxies_on_startup', 'True')
        )
        self.check_proxies_on_use = _as_bool(
            config.get('check_proxies_on_use', 'True')
        )
        self.real_ip_probe = parse_bool_lenient(
            config.get('access_records_real_ip_probe'), False
        )
        self._real_ip_probe_endpoints = self._load_real_ip_probe_endpoints()
        self.check_concurrency = int(config.get('check_concurrency', '50'))
        self.max_concurrent_per_proxy = int(config.get('max_concurrent_per_proxy', '0'))
        previous_exit_count = getattr(self, 'exit_count', None)
        pending_trim = getattr(self, '_trim_now', False)
        self.exit_count = max(1, int(
            config.get('exit_count') or config.get('pool_proxy_count') or '5'
        ))
        self.exit_wait_timeout = max(0, int(config.get('exit_wait_timeout', '15')))
        self.auto_expand_enabled = parse_bool_lenient(
            config.get('auto_expand_enabled'), True)
        self._reset_elastic_capacity()
        shrunk = previous_exit_count is not None and self.exit_count < previous_exit_count
        self._trim_now = bool(pending_trim or shrunk)

        self.client_max_keepalive = int(config.get('client_max_keepalive', '8'))
        self.client_keepalive_expiry = int(config.get('client_keepalive_expiry', '30'))
        self.client_idle_timeout = int(config.get('client_idle_timeout', '300'))

        self.users = {}
        if 'Users' in config:
            self.users = dict(config['Users'].items())
        self.auth_required = bool(self.users)

        self.proxy_file = os.path.join(_BASE_DIR, 'config', os.path.basename(config.get('proxy_file', 'ip.txt')))
        self.whitelist_file = os.path.join(_BASE_DIR, 'config', os.path.basename(config.get('whitelist_file', 'whitelist.txt')))
        self.blacklist_file = os.path.join(_BASE_DIR, 'config', os.path.basename(config.get('blacklist_file', 'blacklist.txt')))
        self.ip_auth_priority = config.get('ip_auth_priority', 'whitelist')

        self.test_url = config.get('test_url', 'https://www.baidu.com')
        self.whitelist = load_ip_list(self.whitelist_file)
        self.blacklist = load_ip_list(self.blacklist_file)

        self.request_interval = int(config.get('request_interval', '0'))

        self.bypass_whitelist_file = os.path.join(_BASE_DIR, 'config', os.path.basename(
            config.get('bypass_whitelist_file', 'bypass_whitelist.txt')))
        self.bypass_whitelist = load_bypass_whitelist(self.bypass_whitelist_file)

        self.last_switch_attempt = 0
        self.switch_cooldown = int(config.get('switch_cooldown', '2'))
        if getattr(self, 'proxy_check_cache', None) is None:
            self.proxy_check_cache = {}
        if getattr(self, 'last_check_time', None) is None:
            self.last_check_time = {}
        self.proxy_check_ttl = int(config.get('proxy_check_ttl', '60'))
        self.check_cooldown = int(config.get('check_cooldown', '10'))
        self.proxy_failure_cooldown = int(config.get('proxy_failure_cooldown', '3'))
        self._retry_log = self._throttled_log(
            '_retry_log', lambda: self.language, self.proxy_failure_cooldown)
        self._silent_log = self._throttled_log(
            '_silent_log', lambda: self.language, max(5, self.proxy_failure_cooldown * 5))
        self._ceiling_log = self._throttled_log(
            '_ceiling_log', lambda: self.language, 60)
        self.tunnel_idle_timeout = int(config.get('tunnel_idle_timeout', '10'))

        self._apply_connection_settings(config)

        workers = getattr(self, '_workers', None)
        if workers is not None:
            workers.apply_capacity(self.max_concurrent_per_proxy)
            workers.set_selection(self._selection_mode())
            if previous_interval != self.interval:
                self._replan_expiries()

        tracker = getattr(self, 'access_tracker', None)
        if tracker is not None:
            tracker.language = self.language
            tracker.emit_log = _as_bool(config.get('log_access_enabled', 'true'))

        for store in (getattr(self, 'domain_stats', None),
                      getattr(self, 'access_records', None)):
            if store is None:
                continue
            was_enabled = store.apply_config(config)
            if getattr(self, 'running', False) and was_enabled != store.enabled:
                if store.enabled:
                    store.start()
                else:
                    store.stop()

    def _init_server_state(self):
        self.running = False
        self.stop_server = False
        self._listen_sock = None
        self._acceptor = None
        self._acceptor_stop = None
        self.proxy_thread = None
        self.tasks = set()
        self.last_switch_time = time.time()
        self.current_proxy = None
        self.proxies = []
        self._standby = StandbyQueue()
        self._exit_real_ips = {}
        self._exit_real_ip_probing = set()
        self._idle_watch = {}
        self._sweeper_task = None
        self._last_demand_at = 0.0
        self._fill_backoff = 0.0
        self._next_fill_attempt = 0.0
        self._last_rotate_attempt = 0.0
        self._live_connections = 0
        self._last_burst_expand = 0.0
        self._expand_task = None
        self.known_clients = OrderedDict()
        self.last_start_error = None

        if self.proxy_source_mode == 'local':
            self._apply_local_proxy_list(f"从 {self.proxy_file} 加载本地代理列表")

    def _apply_connection_settings(self, config):
        previous_limit = getattr(self, 'max_concurrent_requests', None)
        self.buffer_size = int(config.get('buffer_size', '8192'))
        self.max_pool_size = int(config.get('max_pool_size', '500'))
        self.max_concurrent_requests = int(config.get('max_concurrent_requests', '1000'))

        self.client_max_connections = max(
            int(config.get('client_max_connections', '1000')),
            self.max_concurrent_per_proxy * 2 if self.max_concurrent_per_proxy
            else self.max_concurrent_requests,
        )

        if (getattr(self, 'request_semaphore', None) is not None
                and previous_limit != self.max_concurrent_requests):
            self.request_semaphore = asyncio.Semaphore(self.max_concurrent_requests)

    def _init_connection_settings(self):
        self.request_semaphore = asyncio.Semaphore(self.max_concurrent_requests)
        self.client_pool = {}
        self.client_pool_lock = threading.Lock()
        self._client_inflight = {}
        self._clients_pending_close = {}
        self._refill_lock = asyncio.Lock()

    @property
    def switching_proxy(self):
        lock = getattr(self, '_refill_lock', None)
        return bool(lock is not None and lock.locked())

    def _reset_switch_timers(self):
        self.last_switch_time = time.time()
        self.last_switch_attempt = 0

    def _apply_local_proxy_list(self, load_notice: str) -> bool:
        logger.info(load_notice)
        urls = self._load_file_proxies()

        if not urls:
            logger.error(f"从文件 {self.proxy_file} 加载代理失败，请检查文件是否存在且包含有效代理")
            return False

        previous = self.proxies
        self.proxies = urls[:self._exit_target]
        self._replan_expiries()
        self._standby.clear()
        self._standby.put(urls)
        self._log_roster_reload(previous)
        logger.info(get_message('proxy_workers_ready', self.language, len(self.proxies)))
        return True

    def _maybe_check_local_proxies(self) -> None:
        if not self.check_proxies_on_startup:
            return
        try:
            self._run_proxy_check_wherever()
        except Exception as e:
            logger.error(f"检查代理时出错: {str(e)}")

    def _handle_source_mode_switch(self) -> None:
        self.last_switch_attempt = 0
        self._standby.clear()

        if self.proxy_source_mode == 'api':
            self.proxies = []
            self.current_proxy = None
            logger.info(get_message('api_mode_notice', self.language))
        elif self.proxy_source_mode == 'pool':
            self.proxies = []
            self.current_proxy = None
            logger.info(get_message('pool_mode_notice', self.language))
        else:
            if self._apply_local_proxy_list(
                f"切换到{'负载均衡' if self.mode == 'loadbalance' else '循环模式'}模式，"
                f"从 {self.proxy_file} 加载代理列表"
            ):
                self._maybe_check_local_proxies()

    def _handle_mode_change(self):
        self._handle_source_mode_switch()

    async def _check_proxies_wrapper(self):
        await self._check_proxies()

    def _schedule_async_task(self, coro):
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._guard_task(coro))
        except RuntimeError:
            loop = self._event_loop if hasattr(self, '_event_loop') and self._event_loop else None
            if loop and loop.is_running():
                asyncio.run_coroutine_threadsafe(self._guard_task(coro), loop)
            else:
                coro.close()
                logger.warning(
                    "无法调度异步任务：事件循环不可用，任务已被丢弃。事件循环状态: %s",
                    "不存在" if loop is None else "未运行"
                )

    @staticmethod
    async def _guard_task(coro):
        try:
            await coro
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"后台任务异常: {e}")

    def _run_proxy_check_wherever(self):
        loop = getattr(self, '_event_loop', None)
        if loop is not None and loop.is_running():
            self._schedule_async_task(self._check_proxies_wrapper())
        else:
            asyncio.run(self._check_proxies())

    def _throttled_log(self, attr: str, language_provider, interval: float):
        current = getattr(self, attr, None)
        if current is None:
            return ThrottledLogger(logger, language_provider, interval)
        current.set_interval(interval)
        return current

    async def async_reload_config(self, new_config, mode_changed=False, source_mode_changed=False):
        old_port = self.port

        self.config.update(new_config)
        self._init_config_values(new_config)

        if self.port != old_port:
            logger.info(get_message('port_changed', self.language, old_port, self.port))

        if mode_changed or source_mode_changed:
            self._handle_mode_change()

    def _running_loop(self):
        loop = getattr(self, '_event_loop', None)
        return loop if loop is not None and loop.is_running() else None

    def _on_loop_thread(self) -> bool:
        return threading.current_thread() is getattr(self, '_loop_thread', None)

    def run_coroutine_sync(self, coro_factory, timeout=30):
        if self._on_loop_thread():
            raise RuntimeError("不能从服务自己的事件循环线程里同步等待协程")

        loop = self._running_loop()
        if loop is not None:
            return asyncio.run_coroutine_threadsafe(coro_factory(), loop).result(timeout=timeout)
        return asyncio.run(coro_factory())

    def apply_config_sync(self, new_config, mode_changed=False, source_mode_changed=False,
                          reset_switch_timers=False, timeout=10) -> None:
        if self._on_loop_thread():
            raise RuntimeError("不能从服务自己的事件循环线程里同步应用配置")

        loop = self._running_loop()
        if loop is not None:
            future = asyncio.run_coroutine_threadsafe(
                self.async_reload_config(new_config, mode_changed, source_mode_changed), loop
            )
            if reset_switch_timers:
                self._reset_switch_timers()
            future.result(timeout=timeout)
            return

        self.config.update(new_config)
        self._init_config_values(new_config)
        if reset_switch_timers:
            self._reset_switch_timers()
        if mode_changed or source_mode_changed:
            self._handle_mode_change()

    def reload_local_proxies(self, run_check: bool) -> None:
        self.last_switch_attempt = 0
        if self._apply_local_proxy_list(f"重新加载代理列表文件 {self.proxy_file}"):
            if run_check:
                self._maybe_check_local_proxies()

    def reload_ip_lists(self) -> None:
        self.whitelist = load_ip_list(self.whitelist_file)
        self.blacklist = load_ip_list(self.blacklist_file)
        self.bypass_whitelist = load_bypass_whitelist(self.bypass_whitelist_file)
        logger.info(get_message('ip_lists_reloaded', self.language,
                                len(self.whitelist), len(self.blacklist),
                                len(self.bypass_whitelist)))

    def close_listener(self) -> None:
        self._stop_acceptor()

    def _startup_check_gate(self) -> bool:
        if not self.check_proxies_on_startup:
            logger.info(get_message('proxy_check_disabled', self.language))
            return False
        logger.info(get_message('proxy_check_start', self.language))
        return True

    async def run_startup_check(self) -> None:
        if self._startup_check_gate():
            await self._check_proxies()

    def run_startup_check_blocking(self) -> None:
        if self._startup_check_gate():
            asyncio.run(self._check_proxies())

    async def _check_proxies(self):
        from modules.modules import check_proxies

        current = self.proxies
        if not current:
            return

        valid_proxies = await check_proxies(
            current, test_url=self.test_url, concurrency=self.check_concurrency
        )
        if not valid_proxies:
            logger.error(get_message('no_valid_proxies', self.language))
            return

        valid = set(valid_proxies)
        checked_at = time.time()
        for url in current:
            self.proxy_check_cache[(url, self.test_url)] = (checked_at, url in valid)
        for url in current:
            if url not in valid:
                self._workers.drop_worker(url, remember=True)
        for url in valid:
            self._workers.note_success(self._workers.find(url))
        self._sync_current_proxy()
        logger.info(get_message('valid_proxies', self.language, len(valid_proxies)))

    def _load_file_proxies(self):
        try:
            proxy_file = os.path.join(_BASE_DIR, 'config', os.path.basename(self.proxy_file))
            if os.path.exists(proxy_file):
                with open(proxy_file, 'r', encoding='utf-8') as f:
                    proxies = [line.strip() for line in f if line.strip()]
                return proxies
            else:
                logger.error(get_message('proxy_file_not_found', self.language, proxy_file))
                return []
        except Exception as e:
            logger.error(get_message('load_proxy_file_error', self.language, str(e)))
            return []

    def _create_listen_socket(self):
        error = None
        for family, address in self._listen_candidates():
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            try:
                if family == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                sock.bind(address)
            except OSError as e:
                sock.close()
                error = e
                continue
            return sock

        if not self._is_port_in_use(error):
            raise error
        raise RuntimeError(
            get_message('port_in_use', self.language, self.port)
        ) from error

    def _listen_candidates(self):
        candidates = []
        if socket.has_ipv6:
            candidates.append((socket.AF_INET6, ('::', self.port)))
        candidates.append((socket.AF_INET, ('0.0.0.0', self.port)))
        return candidates

    @staticmethod
    def _is_port_in_use(error):
        return bool(
            getattr(error, 'winerror', None) in (10013, 10048)
            or getattr(error, 'errno', None) == errno.EADDRINUSE
        )

    def _log_retry(self, remaining):
        self._retry_log.warning(
            'request_retry',
            get_message('request_retry', self.language, remaining),
        )

    @staticmethod
    def _render_response_head(response, keep_alive=False):
        parts = [f'HTTP/1.1 {response.status_code} {response.reason_phrase}\r\n']
        for header_name, header_value in response.headers.items():
            if header_name.lower() not in _HOP_BY_HOP_HEADERS:
                parts.append(f'{header_name}: {header_value}\r\n')
        parts.append('Connection: keep-alive\r\n' if keep_alive else 'Connection: close\r\n')
        parts.append('\r\n')
        return ''.join(parts).encode()

    @staticmethod
    def _response_allows_reuse(response, method) -> bool:
        if method == 'HEAD' or response.status_code in (204, 304):
            return True
        if 'transfer-encoding' in {name.lower() for name in response.headers.keys()}:
            return False
        return response.headers.get('content-length') is not None

    async def _open_upstream(self, host, port, timeout=10, *, tls=False):
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host, port, happy_eyeballs_delay=_HAPPY_EYEBALLS_DELAY,
                ssl=_upstream_tls_context(host, port) if tls else None,
            ),
            timeout=timeout,
        )
        sock = writer.get_extra_info('socket')
        if sock is not None:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            _tune_keepalive(sock)
        return reader, writer

    @staticmethod
    async def _close_upstream(writer) -> None:
        if writer is None:
            return
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    def _accept_loop(self, listen_sock, loop):
        try:
            while not self.stop_server and not self._acceptor_stop.is_set():
                try:
                    conn, _addr = listen_sock.accept()
                except OSError as e:
                    if self.stop_server or self._acceptor_stop.is_set():
                        return
                    logger.debug(f"accept 异常（已忽略继续）: {getattr(e, 'winerror', None) or e.errno}")
                    time.sleep(0.001)
                    continue

                try:
                    conn.setblocking(False)
                    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    _tune_keepalive(conn)
                except OSError:
                    pass

                try:
                    loop.call_soon_threadsafe(self._adopt_connection, conn, loop)
                except RuntimeError:
                    try:
                        conn.close()
                    except OSError:
                        pass
                    return
        finally:
            if not self.stop_server and not self._acceptor_stop.is_set():
                logger.error(
                    f"acceptor 线程意外退出（端口 {self.port}），此后新连接会被系统拒绝"
                )

    def _adopt_connection(self, conn, loop):
        task = loop.create_task(self._serve_accepted(conn, loop))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def _serve_accepted(self, conn, loop):
        self._live_connections += 1
        self._note_listen_pressure()
        try:
            try:
                reader = asyncio.StreamReader(limit=_STREAM_LIMIT)
                protocol = asyncio.StreamReaderProtocol(reader)
                transport, _ = await loop.connect_accepted_socket(lambda: protocol, conn)
                writer = asyncio.StreamWriter(transport, protocol, reader, loop)
            except Exception as e:
                logger.debug(f"接管已建立的连接失败（已关闭）: {e}")
                try:
                    conn.close()
                except OSError:
                    pass
                return
            await self.handle_client(reader, writer)
        finally:
            self._live_connections -= 1

    async def _serve_until_stopped(self) -> None:
        while not self.stop_server:
            await asyncio.sleep(0.2)

    def _stop_acceptor(self) -> None:
        event = getattr(self, '_acceptor_stop', None)
        sock = getattr(self, '_listen_sock', None)
        thread = getattr(self, '_acceptor', None)

        if self._listen_sock is sock:
            self._listen_sock = None
        if event is not None:
            event.set()
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        if thread is not None and thread.is_alive():
            thread.join(timeout=2)

    async def start(self):
        self.stop_server = False
        self.last_start_error = None

        sock = None
        try:
            if port_in_use(self.port):
                raise RuntimeError(
                    get_message('port_in_use', self.language, self.port)
                )

            sock = self._create_listen_socket()

            loop = asyncio.get_running_loop()
            self._event_loop = loop
            self._loop_thread = threading.current_thread()
            self.request_semaphore = asyncio.Semaphore(self.max_concurrent_requests)
            self._refill_lock = asyncio.Lock()
            self._workers.rebind()
            self._reset_elastic_capacity()
            self._workers.apply_capacity(self.max_concurrent_per_proxy)
            self._workers.set_selection(self._selection_mode())
            self._last_demand_at = 0.0
            self._live_connections = 0
            self._fill_backoff = 0.0
            self._next_fill_attempt = 0.0
            self._last_rotate_attempt = 0.0
            self._last_burst_expand = 0.0
            self._expand_task = None
            self._exit_real_ip_probing = set()
            with self.client_pool_lock:
                self.client_pool.clear()
                self._client_inflight.clear()
                self._clients_pending_close.clear()
            install_loop_noise_filter(loop)
            if hasattr(loop, 'set_default_executor'):
                import concurrent.futures
                executor = concurrent.futures.ThreadPoolExecutor(max_workers=max(32, (os.cpu_count() or 1) * 4))
                loop.set_default_executor(executor)

            self.domain_stats.start()
            self.access_records.start()

            self.tasks.add(asyncio.create_task(self.cleanup_clients()))
            self.tasks.add(asyncio.create_task(self._replenish_loop()))
            self._ensure_tunnel_sweeper()
            if self._sweeper_task is not None:
                self.tasks.add(self._sweeper_task)

            if hasattr(os, 'sched_setaffinity'):
                try:
                    os.sched_setaffinity(0, range(os.cpu_count() or 1))
                except Exception:
                    pass

            sock.listen(_LISTEN_BACKLOG)
            self._listen_sock = sock
            self._acceptor_stop = threading.Event()
            self._acceptor = threading.Thread(
                target=self._accept_loop, args=(sock, loop),
                name="proxycat-accept", daemon=True,
            )
            self._acceptor.start()
            sock = None

            self.running = True
            logger.info(get_message('server_running', self.language, '0.0.0.0', self.port))

            await self._serve_until_stopped()

        except Exception as e:
            if not self.stop_server:
                self.last_start_error = str(e)
                logger.error(get_message('server_start_error', self.language, str(e)))
        finally:
            self.running = False
            self._stop_acceptor()
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    async def stop(self):
        self.stop_server = True

        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
            self.tasks.difference_update(tasks)

        self._stop_acceptor()

        try:
            loop = getattr(self, '_event_loop', None)
            if loop:
                default_executor = getattr(loop, '_default_executor', None)
                if default_executor:
                    default_executor.shutdown(wait=False)
        except Exception:
            pass

        self.domain_stats.stop()
        self.access_records.stop()

        if self.running:
            self.running = False
            logger.info(get_message('server_shutting_down', self.language))

    def _expiry_enabled(self) -> bool:
        return self.interval > 0 or self.request_interval > 0

    def _rotation_is_continuous(self) -> bool:
        return (self.proxy_source_mode != 'local'
                and self.mode == 'continuous')

    def _selection_mode(self) -> str:
        if self.proxy_source_mode == 'local' and self.mode == 'cycle':
            return 'order'
        return 'load'

    def _expired_exits(self, current_time):
        if not self._expiry_enabled():
            return []
        return self._workers.expired_workers(current_time, self.request_interval)

    def _replan_expiries(self) -> None:
        self._workers.replan_expiries(self._plan_expiry(time.monotonic()))

    def _plan_expiry(self, current_time) -> float:
        if not self._expiry_enabled() or self.interval <= 0:
            return 0.0
        return current_time + self.interval

    def _fetch_allowed(self, current_time) -> bool:
        return current_time - self.last_switch_attempt >= self.switch_cooldown

    async def _candidate_usable(self, url) -> bool:
        if not self.check_proxies_on_use:
            return True
        return await self._check_worker(url) is True

    def _take_candidates(self, count) -> list:
        taken = []
        while len(taken) < count:
            url = self._standby.take()
            if url is None:
                break
            if self._workers.find(url) is not None or self._workers.recently_retired(url):
                continue
            taken.append(url)
        return taken

    async def _probe_candidates(self, urls) -> list:
        if len(urls) == 1:
            return [await self._candidate_usable(urls[0])]
        results = await asyncio.gather(
            *(self._candidate_usable(url) for url in urls), return_exceptions=True)
        return [result is True for result in results]

    async def _fill_from_standby(self, max_fill=None) -> int:
        filled = 0
        while len(self._workers.roster) < self._exit_target:
            if max_fill is not None and filled >= max_fill:
                break
            batch = self._take_candidates(_FILL_PROBE_FANOUT)
            if not batch:
                break
            leftovers = []
            for url, usable in zip(batch, await self._probe_candidates(batch)):
                if not usable:
                    continue
                if (len(self._workers.roster) >= self._exit_target
                        or (max_fill is not None and filled >= max_fill)):
                    leftovers.append(url)
                    continue
                if self._workers.find(url) is not None:
                    continue
                self._workers.add_worker(url, self._plan_expiry(time.monotonic()))
                filled += 1
                logger.info(get_message('proxy_exit_added', self.language, sanitize_proxy(url)))
            if leftovers:
                self._standby.put(leftovers)
        return filled

    def _reset_elastic_capacity(self):
        self._expansion_extra = 0
        self._capacity_boost = 1
        self._hot_since = None
        self._cool_since = None
        self._expanding = False

    def _elastic_in_use(self) -> bool:
        return self._expansion_extra > 0 or self._capacity_boost != 1

    @property
    def _exit_target(self):
        return self.exit_count + self._expansion_extra

    def _expansion_ceiling(self) -> int:
        return max(self.exit_count, min(self.exit_count * 2, self.max_concurrent_requests))

    @property
    def elastic_active(self) -> bool:
        return (self._elastic_in_use()
                or len(self._workers.roster) > self._exit_target)

    def _drop_expired_when_idle(self) -> None:
        expired = self._expired_exits(time.monotonic())
        if not expired:
            return
        dropped = 0
        for worker in expired:
            if worker.inflight:
                continue
            if self._workers.drop_worker(worker.url):
                dropped += 1
        if dropped:
            self._sync_current_proxy()
            logger.info(get_message('exit_pool_drained', self.language,
                                    len(self._workers.roster)))

    def _lifetime_pending(self, worker, current_time) -> bool:
        if not self._expiry_enabled():
            return False
        return not self._workers.lifetime_ended(
            worker, current_time, self.request_interval)

    def _is_excess(self, worker) -> bool:
        if self._expansion_extra > 0:
            return False
        return len(self._workers.roster) > self.exit_count

    def _release_excess_exits(self, include_live=False) -> bool:
        target = self._exit_target
        current_time = time.monotonic()
        changed = False
        for worker in sorted(
            self._workers.roster,
            key=lambda w: (self._lifetime_pending(w, current_time), w.last_used),
        ):
            if len(self._workers.roster) <= target:
                break
            if worker.inflight:
                continue
            if not include_live and self._lifetime_pending(worker, current_time):
                continue
            self._workers.drop_worker(worker.url)
            changed = True
        if changed:
            self._sync_current_proxy()
        return changed

    async def _review_elastic_capacity(self):
        now = time.monotonic()

        if len(self._workers.roster) > self._exit_target or self._trim_now:
            async with self._refill_lock:
                trim_now = self._trim_now
                if trim_now:
                    released = self._release_excess_exits(include_live=True)
                else:
                    released = self._release_excess_exits()
                if trim_now and len(self._workers.roster) <= self._exit_target:
                    self._trim_now = False
                if released:
                    logger.info(get_message('exit_pool_trimmed', self.language,
                                            len(self._workers.roster)))

        ratio = (self._workers.saturation(self.max_concurrent_per_proxy)
                 if self.auto_expand_enabled else None)

        if ratio is None:
            self._hot_since = None
            self._cool_since = None
            if self._elastic_in_use():
                await self._shrink_elastic_capacity()
            return

        if ratio >= _EXPAND_SATURATION_RATIO:
            self._cool_since = None
            if self._hot_since is None:
                self._hot_since = now
            elif now - self._hot_since >= _EXPAND_TRIGGER_SECONDS:
                await self._grow_elastic_capacity()
                self._hot_since = now
            return

        used_ratio = self._workers.utilization(self.max_concurrent_per_proxy)
        if used_ratio is not None and used_ratio <= _EXPAND_RECOVER_UTILIZATION:
            self._hot_since = None
            if not self._elastic_in_use():
                self._cool_since = None
                return
            if self._cool_since is None:
                self._cool_since = now
            elif now - self._cool_since >= _EXPAND_RECOVER_SECONDS:
                await self._shrink_elastic_capacity()
            return

        self._hot_since = None
        self._cool_since = None

    async def _grow_elastic_capacity(self):
        if self._trim_now:
            return
        if self._expanding:
            return

        self._expanding = True
        try:
            await self._grow_one_step()
        finally:
            self._expanding = False

    async def _grow_one_step(self):
        adopted = max(self._expansion_extra,
                      max(0, len(self._workers.roster) - self.exit_count))
        if adopted > self._expansion_extra:
            self._expansion_extra = adopted

        ceiling_extra = self._expansion_ceiling() - self.exit_count
        if adopted >= ceiling_extra:
            return

        raised_extra = adopted + 1
        self._expansion_extra = raised_extra
        before = len(self._workers.roster)
        outcome = await self._maintain_exit_pool()

        if len(self._workers.roster) > before:
            logger.info(get_message('elastic_expanded', self.language,
                                    len(self._workers.roster)))
            return

        if self._expansion_extra == raised_extra:
            self._expansion_extra = adopted

        if not outcome.fetched or outcome.gained:
            return

        await self._raise_capacity_boost()

    async def _raise_capacity_boost(self):
        if not self.max_concurrent_per_proxy:
            return
        if self._capacity_boost >= _EXPAND_MAX_CAPACITY_BOOST:
            return

        self._capacity_boost = min(
            _EXPAND_MAX_CAPACITY_BOOST, self._capacity_boost * 2)
        self._workers.apply_capacity(
            self.max_concurrent_per_proxy * self._capacity_boost)
        logger.info(get_message('elastic_capacity_boosted', self.language,
                                self._capacity_boost))

    async def _shrink_elastic_capacity(self):
        self._cool_since = None
        changed = False

        if self._capacity_boost != 1:
            self._capacity_boost = 1
            self._workers.apply_capacity(self.max_concurrent_per_proxy)
            changed = True

        if self._expansion_extra:
            self._expansion_extra = 0
            changed = True

        if changed:
            logger.info(get_message('elastic_released', self.language,
                                    len(self._workers.roster)))

    def _note_listen_pressure(self) -> None:
        if not self.auto_expand_enabled or not self.max_concurrent_per_proxy:
            return
        serving_exits = max(self._exit_target, len(self._workers.roster))
        capacity = serving_exits * self.max_concurrent_per_proxy * self._capacity_boost
        if self._live_connections <= capacity:
            return
        at_exit_ceiling = (self._expansion_extra
                           >= self._expansion_ceiling() - self.exit_count)
        if at_exit_ceiling and self._capacity_boost >= _EXPAND_MAX_CAPACITY_BOOST:
            self._ceiling_log.warning(
                'burst-capacity-ceiling',
                f"并发已顶到容量上限，但名册上限（exit_count × 2 = "
                f"{self.exit_count * 2}）与单出口额度放宽（"
                f"{_EXPAND_MAX_CAPACITY_BOOST} 倍）都到顶了，无法再扩。"
                f"要继续扩容请调大「在用出口数」这一项（当前 {self.exit_count}）。",
            )
            return
        now = time.monotonic()
        if now - self._last_burst_expand < _BURST_EXPAND_COOLDOWN:
            return
        if self._expand_task is not None and not self._expand_task.done():
            return
        self._last_burst_expand = now
        try:
            self._expand_task = asyncio.create_task(self._expand_immediately())
        except RuntimeError:
            self._expand_task = None
            return
        self.tasks.add(self._expand_task)
        self._expand_task.add_done_callback(self.tasks.discard)

    async def _expand_immediately(self):
        try:
            ceiling_extra = self._expansion_ceiling() - self.exit_count
            adopted = max(self._expansion_extra,
                          max(0, len(self._workers.roster) - self.exit_count))
            if adopted > self._expansion_extra:
                self._expansion_extra = adopted
            serving = max(self.exit_count + adopted, len(self._workers.roster))
            raise_to = min(ceiling_extra, max(1, serving * 2 - self.exit_count))

            if raise_to > adopted and not self._expanding:
                self._expanding = True
                previous_extra = self._expansion_extra
                reached = False
                try:
                    self._expansion_extra = raise_to
                    before = len(self._workers.roster)
                    await self._maintain_exit_pool(force_fetch=True)
                    reached = len(self._workers.roster) > before
                    if reached:
                        logger.info(get_message('elastic_expanded', self.language,
                                                len(self._workers.roster)))
                finally:
                    if not reached and self._expansion_extra == raise_to:
                        self._expansion_extra = max(previous_extra, adopted)
                    self._expanding = False

            await self._raise_capacity_boost()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"突发扩容出错（已忽略）: {e}")

    async def _fetch_into_standby(self) -> int | None:
        missing = max(1, self._exit_target - len(self._workers.roster))
        wanted = min(missing * _FETCH_OVERSUBSCRIBE, _FETCH_MAX_BATCH)
        try:
            urls = await asyncio.wait_for(
                self._fetch_candidates(wanted), timeout=15
            )
        except asyncio.TimeoutError:
            logger.error(get_message('proxy_get_timeout', self.language))
            return None
        except Exception as e:
            logger.error(get_message('proxy_get_error', self.language, str(e)))
            return None

        if urls is None:
            return None
        if not urls:
            logger.warning(get_message('proxy_batch_fetch_failed', self.language,
                                       get_message('proxy_get_failed', self.language)))
            return 0

        usable = [url for url in urls
                  if self._workers.find(url) is None
                  and not self._workers.recently_retired(url)]
        return self._standby.put(usable)

    async def _replace_exit(self, victim) -> bool:
        replacement = None
        while True:
            batch = self._take_candidates(_FILL_PROBE_FANOUT)
            if not batch:
                break
            usable = [url for url, ok
                      in zip(batch, await self._probe_candidates(batch)) if ok]
            if usable:
                replacement = usable[0]
                if len(usable) > 1:
                    self._standby.put(usable[1:])
                break
        if replacement is None:
            return False

        self._workers.add_worker(replacement, self._plan_expiry(time.monotonic()))
        self._workers.drop_worker(victim.url, remember=False)
        self._sync_current_proxy()
        self.last_switch_time = time.time()
        logger.info(get_message(
            'proxy_exit_rotated', self.language,
            sanitize_proxy(victim.url), sanitize_proxy(replacement),
        ))
        return True

    async def _rotate_expired(self, current_time) -> int:
        rotated = 0
        for victim in self._expired_exits(current_time):
            if self._is_excess(victim):
                self._workers.drop_worker(victim.url)
                self._sync_current_proxy()
                rotated += 1
                continue
            if not await self._replace_exit(victim):
                if self.proxy_source_mode == 'local':
                    self._workers.readmit(victim, self._plan_expiry(time.monotonic()))
                    rotated += 1
                    continue
                break
            rotated += 1
        return rotated

    async def _replace_soonest(self) -> bool:
        if not self._expiry_enabled():
            return False
        roster = self._workers.roster
        if not roster:
            return False
        soonest = min(roster, key=lambda worker: worker.expires_at or float('inf'))
        return await self._replace_exit(soonest)

    async def _maintain_exit_pool(self, force_fetch=False, rotate=False,
                                  max_fill=None) -> MaintenanceOutcome:
        async with self._refill_lock:
            filled = await self._fill_from_standby(max_fill)

            rotated = 0
            if rotate:
                rotated = await self._rotate_expired(time.monotonic())

            current_time = time.time()
            expired = self._expired_exits(time.monotonic())
            deficient = len(self._workers.roster) < self._exit_target

            fetched = False
            gained = 0
            if ((deficient or (rotate and expired))
                    and (force_fetch or self._fetch_allowed(current_time))):
                self.last_switch_attempt = current_time
                result = await self._fetch_into_standby()
                fetched = result is not None
                gained = result or 0
                room = None if max_fill is None else max(0, max_fill - filled)
                filled += await self._fill_from_standby(room)
                if rotate:
                    rotated += await self._rotate_expired(time.monotonic())

            return MaintenanceOutcome(rotated > 0 or filled > 0, fetched, gained)

    async def _maintain_exit_pool_for_request(self, **kwargs) -> MaintenanceOutcome:
        if self._refill_lock.locked():
            return _NO_MAINTENANCE
        try:
            return await asyncio.wait_for(
                self._maintain_exit_pool(**kwargs), _REQUEST_MAINTENANCE_BUDGET)
        except asyncio.TimeoutError:
            self._silent_log.warning(
                'request-maintenance-budget',
                f"请求路径上的出口池维护超过 {_REQUEST_MAINTENANCE_BUDGET:g} 秒（先按现有名册继续，"
                f"后台会接着补）",
            )
            return _NO_MAINTENANCE

    async def _allocate_exit(self, exclude=None):
        self._last_demand_at = time.monotonic()
        wait_deadline = time.monotonic() + self.exit_wait_timeout
        try:
            if not self._workers.roster:
                await self._maintain_exit_pool_for_request(force_fetch=True, max_fill=1)
                if not self._workers.roster:
                    await self._wait_for_exit(wait_deadline)
            elif (self._expired_exits(time.monotonic())
                  and time.monotonic() - self._last_rotate_attempt >= _ROTATE_RETRY_SECONDS):
                self._last_rotate_attempt = time.monotonic()
                await self._maintain_exit_pool_for_request(rotate=True, max_fill=1)

            lease = await self._workers.acquire(asyncio.current_task(), exclude=exclude)
            if lease is None:
                if await self._wait_for_exit(wait_deadline):
                    lease = await self._workers.acquire(
                        asyncio.current_task(), exclude=exclude)
                if lease is None:
                    return None, self.current_proxy

            self.current_proxy = lease.url
            return lease, lease.url

        except Exception as e:
            logger.error(get_message('proxy_allocate_error', self.language, str(e)))
            return None, self.current_proxy

    async def get_next_proxy(self, exclude=None):
        _lease, proxy = await self._allocate_exit(exclude=exclude)
        return proxy

    async def _wait_for_exit(self, deadline=None) -> bool:
        if deadline is None:
            deadline = time.monotonic() + self.exit_wait_timeout
        while not self.stop_server and not self._workers.roster:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            self._last_demand_at = time.monotonic()
            await self._workers.wait_for_roster_change(min(0.5, remaining))
        return bool(self._workers.roster)

    async def _replenish_loop(self):
        while True:
            await asyncio.sleep(1)
            if not self.running:
                return
            try:
                self._workers.expire_idle(wake=True)
                await self._review_elastic_capacity()
                self._schedule_real_ip_probes()

                recent = (time.monotonic() - self._last_demand_at
                          <= _DEMAND_RECENT_SECONDS)
                if not self._rotation_is_continuous() and not recent:
                    self._drop_expired_when_idle()
                    continue

                if time.monotonic() < self._next_fill_attempt:
                    continue
                before = len(self._workers.roster)
                outcome = await self._maintain_exit_pool(rotate=True)
                starved = (len(self._workers.roster) < self._exit_target
                           and len(self._workers.roster) <= before)
                if starved or (outcome.fetched and not outcome.gained):
                    self._fill_backoff = min(
                        max(1.0, self._fill_backoff * 2), _FILL_BACKOFF_MAX)
                else:
                    self._fill_backoff = 0.0
                self._next_fill_attempt = time.monotonic() + self._fill_backoff
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error(f"维持出口池出错（已忽略）: {e}")

    async def _fetch_candidates(self, missing):
        if self.proxy_source_mode == 'api':
            return await self._load_api_proxies(missing)
        if self.proxy_source_mode == 'pool':
            return await self._load_pool_proxies(missing)
        return self._load_file_proxies()

    def _note_source_error(self, error_text: str) -> None:
        reason_type = str(error_text).split(':', 1)[0].strip()
        key = {
            'request': 'proxy_source_error_request',
            'config': 'proxy_source_error_config',
        }.get(reason_type, 'proxy_source_error_unknown')
        self._last_source_error = (get_message(key, self.language), time.time())

    def last_source_error(self):
        if self._last_source_error is None:
            return None
        message, at = self._last_source_error
        return {'message': message, 'at': at}

    async def _load_api_proxies(self, limit=None):
        wanted = None if limit is None else max(int(limit), _POOL_FETCH_MIN)
        try:
            loop = asyncio.get_running_loop()
            proxies = await loop.run_in_executor(None, getip_newip_list, wanted)
        except Exception as e:
            self._note_source_error(str(e))
            logger.error(get_message('proxy_get_error', self.language, str(e)))
            return None
        self._last_source_error = None
        return proxies

    async def _load_pool_proxies(self, limit):
        limit = max(int(limit), _POOL_FETCH_MIN)
        if not self.pool_remote_url:
            return await self._load_inprocess_pool_proxies(limit)
        try:
            async with httpx.AsyncClient(timeout=10, verify=False,
                                         trust_env=False) as client:
                response = await client.get(self.pool_remote_url)
                if response.status_code == 404:
                    logger.warning(get_message('pool_no_proxy', self.language))
                    return []
                if response.status_code != 200:
                    logger.warning(get_message('pool_error_http_status', self.language, response.status_code))
                    return None
                accepted = [line.strip() for line in response.text.split('\n')
                            if line.strip() and validate_proxy(line.strip())]
                if not accepted:
                    logger.warning(get_message('pool_error_invalid_format', self.language, response.text[:100]))
                    return None
                return accepted[:limit]
        except httpx.ConnectError as e:
            logger.error(get_message('pool_error_connect', self.language, str(e)))
            return None
        except httpx.TimeoutException:
            logger.error(get_message('pool_error_timeout', self.language))
            return None
        except Exception as e:
            logger.error(get_message('pool_fetch_failed', self.language, str(e)))
            return None

    async def _load_inprocess_pool_proxies(self, limit):
        if self._pool_service is None:
            logger.error(get_message('pool_unavailable', self.language,
                                      get_message('pool_not_enabled', self.language)))
            return None

        if not self._pool_service.is_running:
            logger.warning(get_message(
                'pool_unavailable',
                self.language,
                self._pool_service.last_error
                or get_message('pool_not_running', self.language),
            ))
            return None

        try:
            entries = await self._pool_service.fetch_proxy_entries(limit)
        except asyncio.TimeoutError:
            logger.warning(get_message('pool_error_timeout', self.language))
            return None
        except Exception as e:
            logger.error(get_message('pool_fetch_failed', self.language, str(e)))
            return None

        accepted = []
        for entry in entries or ():
            url = (entry.get('proxy_url') or '').strip()
            if not validate_proxy(url):
                continue
            real_ip = (entry.get('real_ip') or '').strip()
            if real_ip:
                self._remember_exit_real_ip(url, real_ip)
            accepted.append(url)
        if not accepted:
            logger.warning(get_message('pool_no_proxy', self.language))
        return accepted

    def _store_exit_real_ip(self, url, real_ip):
        if not url:
            return
        self._exit_real_ips.pop(url, None)
        self._exit_real_ips[url] = (real_ip, time.monotonic())
        while len(self._exit_real_ips) > _EXIT_REAL_IP_CACHE_LIMIT:
            self._exit_real_ips.pop(next(iter(self._exit_real_ips)))

    def _remember_exit_real_ip(self, url, real_ip):
        if not url or not real_ip:
            return
        self._store_exit_real_ip(url, real_ip)

    def _real_ip_for(self, url) -> str:
        entry = self._exit_real_ips.get(url)
        return entry[0] if entry and entry[0] else ''

    def _load_real_ip_probe_endpoints(self) -> tuple:
        try:
            from modules import pool_config_ini

            pool_config = pool_config_ini.load_pool_config(
                os.path.join(_BASE_DIR, 'config', 'config.ini'))
            apis = getattr(pool_config.validator, 'ip_check_apis', ()) or ()
            return tuple(str(api) for api in apis
                         if str(api).lower().startswith('https://'))
        except Exception as e:
            logger.warning(f"读取出口 IP 回显端点失败（真实 IP 探测将跳过）: {e}")
            return ()

    def _schedule_real_ip_probes(self):
        if not self.real_ip_probe or self.proxy_source_mode != 'api':
            return
        if not self._real_ip_probe_endpoints:
            return
        pending = [
            worker.url for worker in self._workers.roster
            if worker.url not in self._exit_real_ip_probing
            and self._worker_needs_real_ip_probe(worker)
        ]
        for url in pending[:_REAL_IP_PROBE_FANOUT]:
            self._exit_real_ip_probing.add(url)
            self._schedule_async_task(self._probe_exit_real_ip_wrapper(url))

    def _worker_needs_real_ip_probe(self, worker) -> bool:
        entry = self._exit_real_ips.get(worker.url)
        if entry is None:
            return True
        value, probed_at = entry
        if probed_at < worker.added_at:
            return True
        return (not value
                and time.monotonic() - probed_at >= _REAL_IP_PROBE_RETRY_SECONDS)

    async def _probe_exit_real_ip_wrapper(self, url):
        try:
            value = await self._probe_exit_real_ip(url)
        except asyncio.CancelledError:
            self._exit_real_ip_probing.discard(url)
            raise
        except Exception as e:
            value = ''
            logger.debug(f"探测出口真实 IP 出错 {sanitize_proxy(url)}: {e}")
        self._exit_real_ip_probing.discard(url)
        self._store_exit_real_ip(url, value or '')

    async def _probe_exit_real_ip(self, url):
        for endpoint in self._real_ip_probe_endpoints:
            try:
                async with self._lease_client(url) as client:
                    response = await client.get(
                        endpoint, timeout=_REAL_IP_PROBE_TIMEOUT)
            except Exception:
                continue
            if response.status_code == 200:
                real_ip = _parse_real_ip_echo(response.text)
                if real_ip:
                    return real_ip
        return ''

    def time_until_next_switch(self):
        mode = self.switch_countdown_mode()
        if mode == 'request_count':
            return min((max(0, self.request_interval - w.requests_served)
                        for w in self._workers.roster), default=0)
        if mode == 'time':
            now = time.monotonic()
            return min((max(0.0, w.expires_at - now)
                        for w in self._workers.roster if w.expires_at), default=0.0)
        return 0

    def switch_countdown_mode(self):
        if self.interval > 0:
            return 'time'
        if self.request_interval > 0:
            return 'request_count'
        return 'per_request'

    _KNOWN_CLIENTS_LIMIT = 10000

    def _record_known_client(self, client_key, client_ip, username_display):
        if client_key in self.known_clients:
            self.known_clients.move_to_end(client_key)
            return
        if len(self.known_clients) >= self._KNOWN_CLIENTS_LIMIT:
            self.known_clients.popitem(last=False)
        self.known_clients[client_key] = True
        logger.info(get_message('new_client_connect', self.language, client_ip, username_display))

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
            logger.error(get_message('whitelist_error', self.language, str(e)))
            return False

    def _is_bypass_target(self, host):
        return check_bypass_match(host, self.bypass_whitelist)

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
            username, password = decoded.split(':', 1)

            if username in self.users and self.users[username] == password:
                return username, password

        except Exception:
            pass

        return False

    @staticmethod
    def _peer_ip(writer) -> str:
        peername = writer.get_extra_info('peername') if writer is not None else None
        if not peername:
            return '-'
        address = peername[0]
        literal = _v4_mapped_literal(address)
        if literal is not None:
            return literal
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return address
        mapped = getattr(parsed, 'ipv4_mapped', None)
        return str(mapped) if mapped is not None else address

    def _client_identity(self, writer, username: str = '') -> ClientIdentity:
        return ClientIdentity(ip=self._peer_ip(writer), username=username or '')

    async def _reject(self, writer, access: AccessRecord, status_code: int, reason: str):
        access.failed(reason, status_code)
        phrase = _REASON_PHRASES.get(status_code, '')
        try:
            writer.write(
                f'HTTP/1.1 {status_code} {phrase}\r\nConnection: close\r\n\r\n'.encode()
            )
            await writer.drain()
        except (ConnectionError, ConnectionResetError, ConnectionAbortedError):
            pass

    async def _reject_tunnel(self, writer, access, established, status_code, reason):
        if established:
            access.failed(reason)
            return
        await self._reject(writer, access, status_code, reason)

    async def _write_all(self, writer, data: bytes) -> bool:
        try:
            writer.write(data)
            await writer.drain()
            return True
        except (ConnectionError, ConnectionResetError, ConnectionAbortedError):
            return False

    async def _close_connection(self, writer):
        try:
            if writer and not writer.is_closing():
                writer.write_eof()
                await writer.drain()
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
        except Exception:
            pass

    async def handle_client(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        try:
            client_ip = self._peer_ip(writer)
            if client_ip != '-' and not self.check_ip_auth(client_ip):
                logger.warning(get_message('unauthorized_ip', self.language, client_ip))
                writer.write(b'HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n')
                await writer.drain()
                return

            header_deadline = asyncio.get_running_loop().time() + _CLIENT_HEADER_TIMEOUT
            try:
                first_byte = await asyncio.wait_for(reader.read(1), _CLIENT_HEADER_TIMEOUT)
            except asyncio.TimeoutError:
                return
            if not first_byte:
                return

            if first_byte == b'\x05':
                await self.handle_socks5_connection(reader, writer)
            else:
                await self._handle_client_impl(reader, writer, first_byte, header_deadline)

        except Exception as e:
            logger.error(get_message('client_handle_error', self.language, e))
        finally:
            self._workers.release(task)
            try:
                await self._close_connection(writer)
            finally:
                self.tasks.discard(task)

    async def _pipe(self, reader, writer, remote_side=None, access=None, flow=None,
                    upstream=None, lease=None, record=None, hold_sink_on_dead=False):
        source_side = 'client' if flow == 'to_upstream' else 'upstream'
        sink_side = 'upstream' if flow == 'to_upstream' else 'client'

        def _note_ended(side: str) -> None:
            if access is not None:
                access.tunnel_ended(side)

        clean_eof = False
        try:
            while True:
                try:
                    watching = self._needs_idle_watch(access, flow)
                    if watching:
                        self._ensure_tunnel_sweeper()
                        self._idle_watch[asyncio.current_task()] = (access, upstream)
                    try:
                        data = await reader.read(_RELAY_CHUNK)
                    finally:
                        if watching:
                            self._idle_watch.pop(asyncio.current_task(), None)

                    if not data:
                        _note_ended(source_side)
                        clean_eof = True
                        break
                    if record is not None:
                        record.add(data)
                    if lease is not None:
                        lease.touch()
                    if access is not None:
                        if flow == 'from_upstream':
                            first_relay = not access.upstream_data_seen
                            access.tunnel_relayed()
                            if first_relay:
                                self._note_exit_success(upstream)
                        elif flow == 'to_upstream':
                            access.tunnel_client_data()
                    try:
                        writer.write(data)
                        await writer.drain()
                    except (ConnectionError, ConnectionResetError):
                        if remote_side == 'writer':
                            self._blame_proxy(access, upstream, '')
                        _note_ended(sink_side)
                        break
                except (ConnectionError, ConnectionResetError):
                    if remote_side == 'reader':
                        self._blame_proxy(access, upstream, '')
                    _note_ended(source_side)
                    break
        except asyncio.CancelledError:
            if access is not None and access.swept_as_dead:
                _note_ended('upstream')
                await self._abort_dead_tunnel(access, upstream)
        except Exception as e:
            if remote_side in ('reader', 'writer'):
                self._blame_proxy(access, upstream, '')
            logger.error(
                "隧道中继出错（%s -> %s，出口 %s）: %s",
                source_side, sink_side,
                sanitize_proxy(upstream) if upstream else '直接连接', e,
            )
        finally:
            if hold_sink_on_dead and access is not None and not access.upstream_data_seen:
                pass
            elif clean_eof:
                await self._half_close(writer)
            else:
                await self._close_connection(writer)

    async def _half_close(self, writer):
        try:
            if writer and not writer.is_closing():
                writer.write_eof()
                await writer.drain()
        except Exception:
            pass

    async def _relay_until_both_ends(self, to_upstream, from_upstream, upstream_writer):
        try:
            await asyncio.gather(to_upstream, from_upstream)
        finally:
            await self._close_connection(upstream_writer)

    async def _relay_replayable_tunnel(self, reader, remote_reader, remote_writer, writer,
                                       access, upstream, lease, record):
        to_upstream = asyncio.ensure_future(self._pipe(
            reader, remote_writer, remote_side='writer', access=access,
            flow='to_upstream', upstream=upstream, lease=lease, record=record))
        from_upstream = asyncio.ensure_future(self._pipe(
            remote_reader, writer, remote_side='reader', access=access,
            flow='from_upstream', upstream=upstream, lease=lease,
            hold_sink_on_dead=True))
        try:
            done, _pending = await asyncio.wait(
                {to_upstream, from_upstream}, return_when=asyncio.FIRST_COMPLETED)
            if from_upstream in done and not access.upstream_data_seen:
                to_upstream.cancel()
            await asyncio.gather(to_upstream, from_upstream, return_exceptions=True)
        except asyncio.CancelledError:
            for task in (to_upstream, from_upstream):
                task.cancel()
            await asyncio.gather(to_upstream, from_upstream, return_exceptions=True)
            raise
        finally:
            await self._close_connection(remote_writer)

    def _needs_idle_watch(self, access, flow) -> bool:
        return not (self.tunnel_idle_timeout <= 0 or access is None
                    or flow != 'from_upstream' or access.upstream_data_seen
                    or access.direct)

    def _sweep_idle_tunnels(self):
        if not self._idle_watch:
            return
        for task, (access, _upstream) in list(self._idle_watch.items()):
            if task.done():
                continue
            if self._tunnel_is_dead(access):
                access.swept_as_dead = True
                task.cancel()
            elif self._tunnel_is_abandoned(access):
                access.swept_as_idle = True
                task.cancel()

    def _ensure_tunnel_sweeper(self):
        task = getattr(self, '_sweeper_task', None)
        if task is not None and not task.done():
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._sweeper_task = loop.create_task(self._tunnel_sweep_loop())

    async def _tunnel_sweep_loop(self):
        while True:
            await asyncio.sleep(_TUNNEL_SWEEP_INTERVAL)
            if not self.running and not self._idle_watch:
                return
            try:
                self._sweep_idle_tunnels()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error(f"清扫空闲隧道出错（已忽略）: {e}")

    def _tunnel_is_dead(self, access) -> bool:
        if not access.client_data_seen:
            return False
        return (time.monotonic() - access.last_activity_at) >= self.tunnel_idle_timeout

    def _tunnel_is_abandoned(self, access) -> bool:
        if access.client_data_seen or access.upstream_data_seen:
            return False
        return (time.monotonic() - access.started_at) >= _IDLE_TUNNEL_TIMEOUT

    async def _abort_dead_tunnel(self, access, upstream=None) -> None:
        access.failed(get_message('access_tunnel_no_data', self.language))
        self._schedule_async_task(self._confirm_dead_before_blaming(access, upstream))

    async def _confirm_dead_before_blaming(self, access, upstream) -> None:
        if access is not None and access.proxy_failure_reported:
            return
        if access is not None:
            access.proxy_failure_reported = True
        try:
            await self._check_worker(upstream)
        except Exception as e:
            logger.debug(f"判死前的确认探测出错（已忽略）: {e}")

    def _has_alternative_exit(self, failed_url) -> bool:
        return any(worker.url != failed_url for worker in self._workers.roster)

    def _tunnel_can_replay(self, access, replay, deadline) -> bool:
        if access is None or access.direct or access.upstream_data_seen:
            return False
        if access.tunnel_ended_by != 'upstream':
            return False
        if not replay.replayable:
            return False
        return deadline - asyncio.get_running_loop().time() > 0

    def _blame_proxy(self, access, upstream=None, reason=_REASON_SILENT_TUNNEL) -> None:
        if access is not None and (access.proxy_failure_reported or access.direct):
            return
        if access is not None:
            access.proxy_failure_reported = True
        self._schedule_async_task(self.handle_proxy_failure(upstream, reason))

    async def _review_tunnel_outcome(self, access, upstream=None) -> None:
        if access.upstream_data_seen or not access.client_data_seen:
            return
        if access.tunnel_ended_by != 'upstream':
            return
        self._blame_proxy(access, upstream)

    def _split_proxy_auth(self, proxy_addr):
        if '@' in proxy_addr:
            auth, host = proxy_addr.rsplit('@', 1)
            return auth, host
        return None, proxy_addr

    @staticmethod
    def _socks5_atyp(host):
        try:
            socket.inet_aton(host)
            return 1
        except OSError:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, host)
            return 4
        except OSError:
            return 3

    def _build_client(self, proxy_url=None):
        max_connections = self.client_max_connections
        if proxy_url is None:
            max_connections = max(max_connections, self.max_concurrent_requests)
        kwargs = {
            'limits': httpx.Limits(
                max_keepalive_connections=self.client_max_keepalive,
                max_connections=max_connections,
                keepalive_expiry=self.client_keepalive_expiry,
            ),
            'timeout': 30.0,
            'http2': True,
            'verify': False,
            'follow_redirects': False,
            'trust_env': False,
            'cookies': _NullCookieJar(),
        }
        if proxy_url:
            kwargs['proxies'] = {"all://": proxy_url}
        return httpx.AsyncClient(**kwargs)

    async def _create_client(self, proxy=None):
        proxy_url = None
        if proxy:
            proxy_type, proxy_addr = proxy.split('://', 1)
            proxy_auth, proxy_host_port = self._split_proxy_auth(proxy_addr)
            if proxy_auth:
                proxy_url = f"{proxy_type}://{proxy_auth}@{proxy_host_port}"
            else:
                proxy_url = f"{proxy_type}://{proxy_host_port}"
        return self._build_client(proxy_url)

    async def _acquire_pooled(self, key, factory, *, evict):
        current_time = time.time()
        expired_client = None

        with self.client_pool_lock:
            if key in self.client_pool:
                client, last_used = self.client_pool[key]
                in_use = bool(self._client_inflight.get(key))
                if not client.is_closed and (
                        in_use or current_time - last_used < self.client_idle_timeout):
                    self.client_pool[key] = (client, current_time)
                    return client
                expired_client = self.client_pool.pop(key)[0]

        if expired_client is not None and not expired_client.is_closed:
            await expired_client.aclose()

        try:
            client = factory()
            if asyncio.iscoroutine(client):
                client = await client
        except Exception as e:
            logger.error(f"创建客户端失败: {str(e)}")
            raise

        evicted_client = None
        with self.client_pool_lock:
            if key in self.client_pool:
                evicted_client = client
                winner = self.client_pool[key][0]
            else:
                pool_limit = max(self.max_pool_size,
                                 2 * len(self._workers.roster),
                                 4 * self.exit_count)
                if evict and len(self.client_pool) >= pool_limit:
                    evictable = [k for k in self.client_pool
                                 if not self._client_inflight.get(k)]
                    if evictable:
                        oldest_key = min(evictable, key=lambda x: self.client_pool[x][1])
                        evicted_client, _ = self.client_pool.pop(oldest_key)
                self.client_pool[key] = (client, current_time)
                winner = client

        if evicted_client is not None and not evicted_client.is_closed:
            await evicted_client.aclose()
        return winner

    @asynccontextmanager
    async def _borrow_client(self, key, factory, *, evict):
        client = await self._acquire_pooled(key, factory, evict=evict)
        with self.client_pool_lock:
            self._client_inflight[key] = self._client_inflight.get(key, 0) + 1
        try:
            yield client
        finally:
            pending = None
            with self.client_pool_lock:
                remaining = self._client_inflight.get(key, 1) - 1
                if remaining > 0:
                    self._client_inflight[key] = remaining
                else:
                    self._client_inflight.pop(key, None)
                    pending = self._clients_pending_close.pop(key, None)
            for dead in pending or ():
                if not dead.is_closed:
                    await dead.aclose()

    def _lease_direct_client(self):
        return self._borrow_client('__direct__', self._create_client, evict=False)

    async def handle_socks5_connection(self, reader, writer):
        try:
            try:
                request = await asyncio.wait_for(
                    self._read_socks5_request(reader, writer), _CLIENT_HEADER_TIMEOUT
                )
            except asyncio.TimeoutError:
                logger.debug("SOCKS5 握手超时：客户端未在时限内发完协商报文")
                return
            if request is None:
                return

            username, dst_addr, dst_port, atyp = request
            async with self.request_semaphore:
                await self._socks5_forward(
                    reader, writer, username, dst_addr, dst_port, atyp
                )
        except Exception as e:
            logger.error(get_message('socks5_connection_error', self.language, str(e)))
            writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()

    async def _read_socks5_request(self, reader, writer):
        username = ''
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
                client_ip = self._peer_ip(writer)
                if client_ip != '-':
                    self._record_known_client(
                        (client_ip, username), client_ip, f"{username}:****"
                    )
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
        return username, dst_addr, dst_port, atyp

    async def _socks5_forward(self, reader, writer, username, dst_addr, dst_port, atyp):
        with self.access_tracker.track(
            KIND_SOCKS5, '-', self._client_identity(writer, username), dst_addr, dst_port
        ) as access:
            if self._is_bypass_target(dst_addr):
                try:
                    logger.info(f"绕过代理直连 SOCKS5: {dst_addr}:{dst_port}")
                    access.use_direct()
                    remote_reader, remote_writer = await self._open_upstream(
                        dst_addr, dst_port)
                    if not await self._write_all(
                            writer, b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00'):
                        return
                    access.tunnel_ready()
                    await self._relay_until_both_ends(
                        self._pipe(reader, remote_writer, access=access, flow='to_upstream'),
                        self._pipe(remote_reader, writer, access=access, flow='from_upstream'),
                        remote_writer,
                    )
                    await self._review_tunnel_outcome(access)
                    return
                except Exception as e:
                    logger.error(f"直连 SOCKS5 {dst_addr}:{dst_port} 失败: {e}")
                    access.failed(str(e))
                    writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
                    await writer.drain()
                    return

            max_retries = 2
            retry_count = 0
            last_error = None
            loop = asyncio.get_running_loop()
            deadline = loop.time() + _TUNNEL_TOTAL_BUDGET_SECONDS
            failed_url = None

            while retry_count < max_retries:
                upstream_writer = None
                if retry_count and deadline - loop.time() <= 0:
                    last_error = last_error or "Tunnel time budget exhausted"
                    break
                attempt_budget = (deadline - loop.time()) / (max_retries - retry_count)
                attempt_deadline = loop.time() + attempt_budget
                try:
                    lease, proxy = await self._allocate_exit(exclude=failed_url)
                    if not proxy:
                        raise Exception("No proxy available")
                    failed_url = proxy

                    access.use_proxy(proxy, real_ip=self._real_ip_for(proxy))

                    proxy_type, proxy_addr = proxy.split('://')
                    proxy_auth, proxy_host_port = self._split_proxy_auth(proxy_addr)
                    proxy_host, proxy_port = split_host_port(proxy_host_port)
                    proxy_port = int(proxy_port)

                    remote_reader, remote_writer = await self._open_upstream(
                        proxy_host, proxy_port, timeout=attempt_budget,
                        tls=(proxy_type == 'https'))
                    upstream_writer = remote_writer
                    handshake_timeout = max(0.0, attempt_deadline - loop.time())

                    if proxy_type == 'socks5':
                        await self._initiate_socks5(remote_reader, remote_writer, dst_addr, dst_port,
                                                    atyp, proxy, handshake_timeout)
                    elif proxy_type in ['http', 'https']:
                        await self._initiate_http(remote_reader, remote_writer, dst_addr, dst_port,
                                                  proxy_auth, handshake_timeout)
                    else:
                        raise UnsupportedUpstreamProxyError(
                            f"Unsupported proxy type: {proxy_type}")

                    if proxy_type == 'https':
                        _remember_upstream_tls_session(proxy_host, proxy_port, remote_writer)

                    if not await self._write_all(
                            writer, b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00'):
                        return
                    access.tunnel_ready()
                    if lease is not None:
                        lease.idle()

                    await self._relay_until_both_ends(
                        self._pipe(reader, remote_writer, remote_side='writer',
                                   access=access, flow='to_upstream', upstream=proxy,
                                   lease=lease),
                        self._pipe(remote_reader, writer, remote_side='reader',
                                   access=access, flow='from_upstream', upstream=proxy,
                                   lease=lease),
                        remote_writer,
                    )

                    await self._review_tunnel_outcome(access, proxy)
                    return

                except (asyncio.TimeoutError, ConnectionRefusedError, ConnectionResetError) as e:
                    await self._close_upstream(upstream_writer)
                    last_error = e
                    self._log_retry(max_retries - retry_count - 1)
                    await self.handle_proxy_failure(proxy)
                    retry_count += 1
                    if retry_count < max_retries:
                        await asyncio.sleep(_RETRY_BACKOFF_SECONDS)
                    continue

                except UnsupportedUpstreamProxyError as e:
                    await self._close_upstream(upstream_writer)
                    last_error = e
                    retry_count += 1
                    if retry_count < max_retries:
                        await asyncio.sleep(_RETRY_BACKOFF_SECONDS)
                    continue

                except Exception as e:
                    await self._close_upstream(upstream_writer)
                    last_error = e
                    logger.error(get_message('socks5_connection_error', self.language, str(e)))
                    await self.handle_proxy_failure(proxy)
                    retry_count += 1
                    if retry_count < max_retries:
                        await asyncio.sleep(_RETRY_BACKOFF_SECONDS)
                    continue

            if last_error:
                logger.error(get_message('all_retries_failed', self.language, str(last_error)))
            access.failed(
                str(last_error) if last_error
                else get_message('pool_no_proxy', self.language))
            writer.write(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()

    async def _socks5_upstream_handshake(self, remote_reader, remote_writer,
                                         host, port, atyp, auth, timeout=10.0):
        if auth:
            remote_writer.write(b'\x05\x02\x00\x02')
        else:
            remote_writer.write(b'\x05\x01\x00')
        await remote_writer.drain()

        try:
            auth_method = await asyncio.wait_for(
                remote_reader.readexactly(2), timeout=timeout
            )
            if auth_method[0] != 0x05:
                raise Exception("Invalid SOCKS5 proxy response")

            if auth_method[1] == 0x02 and auth:
                username, password = auth.split(':', 1)
                remote_writer.write(build_socks5_auth_packet(username, password))
                await remote_writer.drain()

                auth_response = await asyncio.wait_for(
                    remote_reader.readexactly(2), timeout=timeout
                )
                if auth_response[1] != 0x00:
                    raise Exception("Authentication failed")

            if atyp == 1:
                remote_writer.write(b'\x05\x01\x00\x01' + socket.inet_aton(host) +
                                    port.to_bytes(2, 'big'))
            elif atyp == 4:
                remote_writer.write(b'\x05\x01\x00\x04' +
                                    socket.inet_pton(socket.AF_INET6, host) +
                                    port.to_bytes(2, 'big'))
            else:
                host_bytes = host.encode()
                remote_writer.write(b'\x05\x01\x00\x03' +
                                    len(host_bytes).to_bytes(1, 'big') +
                                    host_bytes + port.to_bytes(2, 'big'))

            await remote_writer.drain()

            response = await asyncio.wait_for(
                remote_reader.readexactly(4), timeout=timeout
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
                await asyncio.wait_for(remote_reader.readexactly(6), timeout=timeout)
            elif response[3] == 0x03:
                domain_len = (await asyncio.wait_for(
                    remote_reader.readexactly(1), timeout=timeout
                ))[0]
                await asyncio.wait_for(
                    remote_reader.readexactly(domain_len + 2), timeout=timeout
                )
            elif response[3] == 0x04:
                await asyncio.wait_for(remote_reader.readexactly(18), timeout=timeout)
            else:
                raise Exception(f"Unsupported address type: {response[3]}")

        except asyncio.TimeoutError:
            raise Exception("SOCKS5 proxy response timeout")

    async def _initiate_socks5(self, remote_reader, remote_writer, dst_addr, dst_port,
                               atyp=3, proxy=None, timeout=10.0):
        auth = None
        proxy_url = proxy if proxy is not None else self.current_proxy
        if proxy_url:
            _, proxy_addr = proxy_url.split('://', 1)
            auth, _ = self._split_proxy_auth(proxy_addr)

        try:
            await self._socks5_upstream_handshake(
                remote_reader, remote_writer, dst_addr, dst_port, atyp, auth, timeout
            )
        except Exception as e:
            raise Exception(f"SOCKS5 initialization failed: {str(e)}")


    async def _http_connect_handshake(self, remote_reader, remote_writer,
                                      host, port, proxy_auth, timeout=10.0):
        authority = f'[{host}]:{port}' if ':' in host else f'{host}:{port}'
        connect_request = f'CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n'
        if proxy_auth:
            connect_request += f'Proxy-Authorization: Basic {base64.b64encode(proxy_auth.encode()).decode()}\r\n'
        connect_request += '\r\n'
        remote_writer.write(connect_request.encode())
        await remote_writer.drain()

        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        first_line = True
        header_lines = 0
        while True:
            header_lines += 1
            if header_lines > _MAX_HEADER_LINES:
                raise Exception("Upstream proxy CONNECT response too long")
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise asyncio.TimeoutError("Upstream proxy CONNECT handshake timeout")
            try:
                line = await asyncio.wait_for(remote_reader.readline(), timeout=remaining)
            except asyncio.TimeoutError:
                raise asyncio.TimeoutError("Upstream proxy CONNECT handshake timeout")
            if not line:
                raise Exception("Upstream proxy closed connection unexpectedly")
            if first_line:
                first_line = False
                status = None
                parts = line.split(b' ', 2)
                if len(parts) >= 2:
                    try:
                        status = int(parts[1])
                    except ValueError:
                        status = None
                if status is None or not (200 <= status < 300):
                    raise Exception(
                        "Upstream proxy refused CONNECT: "
                        + line[:80].decode('latin-1').strip()
                    )
            if line == b'\r\n':
                break

    async def _initiate_http(self, remote_reader, remote_writer, dst_addr, dst_port, proxy_auth, timeout=10.0):
        await self._http_connect_handshake(
            remote_reader, remote_writer, dst_addr, dst_port, proxy_auth, timeout
        )

    async def _read_headers(self, reader):
        headers = {}
        consumed = 0
        for _ in range(_MAX_HEADER_LINES):
            line = await reader.readline()
            consumed += len(line)
            if consumed > _MAX_HEADER_BYTES:
                logger.debug("请求头超过总字节上限（已断开）")
                return None
            if line == b'\r\n':
                return headers
            if line == b'':
                return None
            try:
                name, value = line.decode('utf-8', errors='ignore').split(':', 1)
                headers[name.strip().lower()] = value.strip()
            except ValueError:
                continue
        logger.debug("请求头超过行数上限（已断开）")
        return None

    @staticmethod
    def _strip_hop_by_hop(client_headers):
        headers = client_headers.copy()
        for hop_header in _HOP_BY_HOP_HEADERS:
            headers.pop(hop_header, None)
        return headers

    def _forward_headers(self, client_headers, proxy):
        headers = self._strip_hop_by_hop(client_headers)

        proxy_type, proxy_addr = proxy.split('://', 1)
        if proxy_type in ('http', 'https') and '@' in proxy_addr:
            auth, _ = proxy_addr.rsplit('@', 1)
            headers['proxy-authorization'] = (
                f'Basic {base64.b64encode(auth.encode()).decode()}'
            )
        return headers

    async def _handle_client_impl(self, reader, writer, first_byte, header_deadline=None):
        loop = asyncio.get_running_loop()
        if header_deadline is None:
            header_deadline = loop.time() + _CLIENT_HEADER_TIMEOUT
        try:
            while True:
                try:
                    request_line = first_byte + await asyncio.wait_for(
                        reader.readline(), _remaining_time(header_deadline))
                except asyncio.TimeoutError:
                    return
                if not request_line:
                    return

                try:
                    method, path, version = request_line.decode('utf-8', errors='ignore').split()
                except (ValueError, UnicodeDecodeError) as e:
                    return

                try:
                    headers = await asyncio.wait_for(
                        self._read_headers(reader), _remaining_time(header_deadline))
                except asyncio.TimeoutError:
                    return
                if headers is None:
                    return

                username = ''
                if self.auth_required:
                    auth_result = self._authenticate(headers)
                    if not auth_result:
                        writer.write(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="Proxy"\r\nConnection: close\r\n\r\n')
                        await writer.drain()
                        return
                    elif isinstance(auth_result, tuple):
                        username, _ = auth_result
                        client_ip = self._peer_ip(writer)
                        if client_ip != '-':
                            self._record_known_client(
                                (client_ip, username), client_ip, f"{username}:***"
                            )

                if method != 'CONNECT' and '100-continue' in headers.get('expect', '').lower():
                    writer.write(b'HTTP/1.1 100 Continue\r\n\r\n')
                    await writer.drain()
                    headers.pop('expect', None)

                client = self._client_identity(writer, username)
                if method == 'CONNECT':
                    with self.access_tracker.track(KIND_CONNECT, method, client) as access:
                        async with self.request_semaphore:
                            await self._handle_connect(path, reader, writer, access)
                    return

                keep_alive = (version == 'HTTP/1.1'
                              and 'close' not in headers.get('connection', '').lower())
                with self.access_tracker.track(KIND_HTTP, method, client) as access:
                    reusable = await self._handle_request(
                        method, path, headers, reader, writer, access,
                        keep_alive=keep_alive)
                if not reusable:
                    return

                self._workers.release(asyncio.current_task())

                try:
                    first_byte = await asyncio.wait_for(reader.read(1), _CLIENT_HEADER_TIMEOUT)
                except asyncio.TimeoutError:
                    return
                if not first_byte or first_byte == b'\x05':
                    return
                header_deadline = loop.time() + _CLIENT_HEADER_TIMEOUT

        except (ConnectionError, ConnectionResetError, ConnectionAbortedError):
            return
        except asyncio.CancelledError:
            return
        except Exception as e:
            if not isinstance(e, (ConnectionError, ConnectionResetError, ConnectionAbortedError,
                                asyncio.CancelledError, asyncio.TimeoutError)):
                logger.error(get_message('client_request_error', self.language, str(e)))

    async def _handle_connect(self, path, reader, writer, access):
        try:
            host, port = split_host_port(path)
        except ValueError:
            await self._reject(writer, access, 400, get_message('access_reason_bad_target', self.language, path))
            return

        access.host, access.port = host, port

        if self._is_bypass_target(host):
            try:
                logger.info(f"绕过代理直连 HTTPS: {host}:{port}")
                access.use_direct()
                remote_reader, remote_writer = await self._open_upstream(host, port)
                if not await self._write_all(
                        writer, b'HTTP/1.1 200 Connection Established\r\n\r\n'):
                    return
                access.tunnel_ready(200)
                await self._relay_until_both_ends(
                    self._pipe(reader, remote_writer, access=access, flow='to_upstream'),
                    self._pipe(remote_reader, writer, access=access, flow='from_upstream'),
                    remote_writer,
                )
                await self._review_tunnel_outcome(access)
                return
            except Exception as e:
                logger.error(f"直连 {host}:{port} 失败: {e}")
                await self._reject(writer, access, 502, get_message('access_reason_direct_failed', self.language, e))
                return

        max_retries = 2
        retry_count = 0
        last_error = None
        loop = asyncio.get_running_loop()
        deadline = loop.time() + _TUNNEL_TOTAL_BUDGET_SECONDS
        failed_url = None
        established = False
        replay = _ReplayBuffer(_TUNNEL_REPLAY_LIMIT)

        while retry_count < max_retries:
            upstream_writer = None
            if retry_count and deadline - loop.time() <= 0:
                await self._reject_tunnel(writer, access, established, 504,
                                          last_error or "Tunnel time budget exhausted")
                return
            attempt_budget = (deadline - loop.time()) / (max_retries - retry_count)
            attempt_deadline = loop.time() + attempt_budget
            try:
                lease, proxy = await self._allocate_exit(exclude=failed_url)
                if not proxy:
                    await self._reject_tunnel(writer, access, established, 503,
                                              get_message('pool_no_proxy', self.language))
                    return
                failed_url = proxy

                access.use_proxy(proxy, real_ip=self._real_ip_for(proxy))

                try:
                    proxy_type, proxy_addr = proxy.split('://')
                    proxy_auth, proxy_host_port = self._split_proxy_auth(proxy_addr)
                    proxy_host, proxy_port = split_host_port(proxy_host_port)
                    proxy_port = int(proxy_port)

                    remote_reader, remote_writer = await self._open_upstream(
                        proxy_host, proxy_port, timeout=attempt_budget,
                        tls=(proxy_type == 'https'))
                    upstream_writer = remote_writer

                    if proxy_type in ('http', 'https'):
                        try:
                            await self._http_connect_handshake(
                                remote_reader, remote_writer, host, port, proxy_auth,
                                timeout=max(0.0, attempt_deadline - loop.time()),
                            )
                        except asyncio.TimeoutError:
                            await self._close_upstream(upstream_writer)
                            await self.handle_proxy_failure(proxy)
                            last_error = "Upstream proxy CONNECT handshake timeout"
                            retry_count += 1
                            if retry_count >= max_retries or not self._has_alternative_exit(proxy):
                                await self._reject_tunnel(writer, access, established, 504, last_error)
                                return
                            self._log_retry(max_retries - retry_count)
                            await asyncio.sleep(_RETRY_BACKOFF_SECONDS)
                            continue
                        except Exception as e:
                            await self._close_upstream(upstream_writer)
                            await self.handle_proxy_failure(proxy)
                            last_error = f"Bad Gateway: {e}"
                            retry_count += 1
                            if retry_count >= max_retries or not self._has_alternative_exit(proxy):
                                await self._reject_tunnel(writer, access, established, 502, last_error)
                                return
                            self._log_retry(max_retries - retry_count)
                            await asyncio.sleep(_RETRY_BACKOFF_SECONDS)
                            continue
                    elif proxy_type == 'socks5':
                        await self._socks5_upstream_handshake(
                            remote_reader, remote_writer, host, port,
                            self._socks5_atyp(host), proxy_auth,
                        )
                    else:
                        raise UnsupportedUpstreamProxyError("Unsupported proxy type")

                    if proxy_type == 'https':
                        _remember_upstream_tls_session(proxy_host, proxy_port, remote_writer)

                    if not established:
                        if not await self._write_all(
                                writer, b'HTTP/1.1 200 Connection Established\r\n\r\n'):
                            return
                        established = True
                    elif len(replay):
                        if not await self._write_all(remote_writer, bytes(replay.data)):
                            return
                        access.tunnel_client_data()
                    access.tunnel_ready(200)
                    if lease is not None:
                        lease.idle()

                    await self._relay_replayable_tunnel(
                        reader, remote_reader, remote_writer, writer,
                        access, proxy, lease, replay,
                    )

                    await self._review_tunnel_outcome(access, proxy)

                    if not self._tunnel_can_replay(access, replay, deadline):
                        return
                    access.retry_tunnel()
                    retry_count += 1
                    if retry_count >= max_retries or not self._has_alternative_exit(proxy):
                        return
                    self._log_retry(max_retries - retry_count)
                    await asyncio.sleep(_RETRY_BACKOFF_SECONDS)
                    continue

                except asyncio.TimeoutError:

                    await self._close_upstream(upstream_writer)
                    await self.handle_proxy_failure(proxy)
                    last_error = "Connection Timeout"
                    retry_count += 1
                    if retry_count >= max_retries or not self._has_alternative_exit(proxy):
                        logger.error(get_message('connect_timeout', self.language))
                        await self._reject_tunnel(writer, access, established, 504, last_error)
                        return
                    self._log_retry(max_retries - retry_count)
                    await asyncio.sleep(_RETRY_BACKOFF_SECONDS)
                    continue
                except UnsupportedUpstreamProxyError as e:
                    await self._close_upstream(upstream_writer)
                    last_error = str(e)
                    retry_count += 1
                    if retry_count < max_retries:
                        self._log_retry(max_retries - retry_count)
                        await asyncio.sleep(_RETRY_BACKOFF_SECONDS)
                        continue
                    await self._reject_tunnel(writer, access, established, 502, last_error)
                    return

                except Exception as e:

                    await self._close_upstream(upstream_writer)
                    await self.handle_proxy_failure(proxy)
                    last_error = str(e)
                    retry_count += 1
                    if retry_count >= max_retries or not self._has_alternative_exit(proxy):
                        await self._reject_tunnel(writer, access, established, 502, last_error)
                        return
                    self._log_retry(max_retries - retry_count)
                    await asyncio.sleep(_RETRY_BACKOFF_SECONDS)
                    continue

            except Exception as e:
                await self._close_upstream(upstream_writer)
                last_error = str(e)
                retry_count += 1
                if retry_count < max_retries:
                    self._log_retry(max_retries - retry_count)
                    await asyncio.sleep(_RETRY_BACKOFF_SECONDS)
                    continue
                await self._reject_tunnel(writer, access, established, 502, last_error)
                return


    async def _handle_request(self, method, path, headers, reader, writer, access,
                              keep_alive=False):
        async with self.request_semaphore, AsyncExitStack() as borrowed_clients:
            target_host = None
            target_port = 0
            host_header = headers.get('host', '')
            if '://' in path:
                request_url = path
                from urllib.parse import urlparse
                parsed = urlparse(path)
                target_host = parsed.hostname
                target_port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            elif host_header:
                request_url = f'http://{host_header}{path}'
                try:
                    target_host, target_port = split_host_port(host_header, default_port=80)
                except ValueError:
                    target_host, target_port = host_header, 80
            else:
                await self._reject(writer, access, 400, get_message('access_reason_bad_target', self.language, path))
                return

            if target_host:
                access.host, access.port = target_host, target_port

            body = _client_request_body(
                headers, reader,
                asyncio.get_running_loop().time() + _BODY_TOTAL_TIMEOUT)
            reuse_ok = keep_alive and body is None
            response_started = False

            if target_host and self._is_bypass_target(target_host):
                try:
                    logger.info(f"绕过代理直连 HTTP: {method} {path}")
                    access.use_direct()
                    client = await borrowed_clients.enter_async_context(
                        self._lease_direct_client())
                    try:
                        request = _build_upstream_request(
                            client, method, request_url,
                            self._strip_hop_by_hop(headers), body)
                        async with _stream_upstream(client, request) as response:
                            response_started = True
                            allow_reuse = self._response_allows_reuse(response, method) and reuse_ok
                            writer.write(self._render_response_head(response, keep_alive=allow_reuse))
                            access.succeeded(response.status_code)
                            try:
                                pending = 0
                                async for chunk in response.aiter_raw():
                                    if not chunk:
                                        break
                                    try:
                                        writer.write(chunk)
                                        pending += len(chunk)
                                        if pending >= self.buffer_size:
                                            await writer.drain()
                                            pending = 0
                                    except (ConnectionError, ConnectionResetError, ConnectionAbortedError):
                                        return
                                await writer.drain()
                            except (ConnectionError, ConnectionResetError, ConnectionAbortedError):
                                return
                            return allow_reuse
                    except Exception as e:
                        if response_started:
                            return
                        logger.error(f"直连请求失败 {path}: {e}")
                        await self._reject(writer, access, 502, get_message('access_reason_direct_failed', self.language, e))
                        return
                except Exception as e:
                    if response_started:
                        return
                    logger.error(f"直连请求失败 {path}: {e}")
                    await self._reject(writer, access, 502, get_message('access_reason_direct_failed', self.language, e))
                    return

            max_retries = 1 if body is not None else 2
            retry_count = 0
            last_error = None
            failed_url = None

            while retry_count < max_retries:
                response_started = False
                try:
                    proxy = await self.get_next_proxy(exclude=failed_url)
                    if not proxy:
                        await self._reject(writer, access, 503, get_message('pool_no_proxy', self.language))
                        return
                    failed_url = proxy

                    access.use_proxy(proxy, real_ip=self._real_ip_for(proxy))

                    try:
                        client = await borrowed_clients.enter_async_context(
                            self._lease_client(proxy))

                        proxy_headers = self._forward_headers(headers, proxy)

                        try:
                            request = _build_upstream_request(
                                client, method, request_url, proxy_headers, body)
                            async with _stream_upstream(client, request) as response:
                                response_started = True
                                allow_reuse = self._response_allows_reuse(response, method) and reuse_ok
                                writer.write(self._render_response_head(response, keep_alive=allow_reuse))
                                access.succeeded(response.status_code)
                                self._note_exit_success(proxy)

                                body_complete = True
                                try:
                                    pending = 0
                                    async for chunk in response.aiter_raw():
                                        if not chunk:
                                            break
                                        try:
                                            writer.write(chunk)
                                            pending += len(chunk)
                                            if pending >= self.buffer_size:
                                                await writer.drain()
                                                pending = 0
                                        except (ConnectionError, ConnectionResetError, ConnectionAbortedError):
                                            return
                                        except Exception:
                                            body_complete = False
                                            break

                                    await writer.drain()
                                except (ConnectionError, ConnectionResetError, ConnectionAbortedError):
                                    return
                                except Exception:
                                    body_complete = False


                                return allow_reuse and body_complete

                        except httpx.RequestError as e:
                            if response_started:
                                return
                            if isinstance(e, _UPSTREAM_TRANSPORT_ERRORS):
                                await self.handle_proxy_failure(proxy)
                            else:
                                logger.error(f"请求未能送达上游（不归因给出口） {method} {request_url}: {e}")

                            last_error = "Request Error"
                            retry_count += 1
                            if retry_count < max_retries:
                                self._log_retry(max_retries - retry_count)
                                await asyncio.sleep(_RETRY_BACKOFF_SECONDS)
                                continue
                            await self._reject(writer, access, 502, last_error)
                            return
                        except Exception as e:
                            if response_started:
                                return
                            if isinstance(e, (ConnectionError, ConnectionResetError, ConnectionAbortedError)):
                                await self.handle_proxy_failure(proxy)

                            last_error = str(e)
                            retry_count += 1
                            if retry_count < max_retries:
                                self._log_retry(max_retries - retry_count)
                                await asyncio.sleep(_RETRY_BACKOFF_SECONDS)
                                continue
                            await self._reject(writer, access, 502, last_error)
                            return


                    except httpx.HTTPError as e:
                        if response_started:
                            return
                        logger.error(f"请求处理错误（不归因给出口） {method} {request_url}: {e}")
                        last_error = str(e)
                        retry_count += 1
                        if retry_count < max_retries:
                            self._log_retry(max_retries - retry_count)
                            await asyncio.sleep(_RETRY_BACKOFF_SECONDS)
                            continue
                        await self._reject(writer, access, 502, last_error)
                        return
                    except Exception as e:
                        if response_started:
                            return
                        if isinstance(e, (ConnectionError, ConnectionResetError, ConnectionAbortedError)):
                            await self.handle_proxy_failure(proxy)

                        last_error = str(e)
                        retry_count += 1
                        if retry_count < max_retries:
                            self._log_retry(max_retries - retry_count)
                            await asyncio.sleep(_RETRY_BACKOFF_SECONDS)
                            continue
                        await self._reject(writer, access, 502, last_error)
                        return


                except Exception as e:
                    if response_started:
                        return
                    if isinstance(e, (ConnectionError, ConnectionResetError, ConnectionAbortedError)):

                        await self.handle_proxy_failure()
                        last_error = str(e)
                        retry_count += 1
                        if retry_count < max_retries:
                            self._log_retry(max_retries - retry_count)
                            await asyncio.sleep(_RETRY_BACKOFF_SECONDS)
                            continue
                        await self._reject(writer, access, 502, last_error)
                        return
                    if not isinstance(e, (asyncio.CancelledError,)):
                        logger.error(f"请求处理错误 {method} {path}: {str(e)}")
                    try:
                        await self._reject(writer, access, 502, str(e))
                    except Exception:
                        pass
                    return

    async def _close_client_for(self, proxy_url):
        with self.client_pool_lock:
            entry = self.client_pool.pop(proxy_url, None)
            if entry is None:
                return
            client = entry[0]
            if self._client_inflight.get(proxy_url, 0) > 0:
                self._clients_pending_close.setdefault(proxy_url, []).append(client)
                return
        if not client.is_closed:
            await client.aclose()

    def _lease_client(self, proxy):
        return self._borrow_client(
            proxy, lambda: self._create_client(proxy), evict=True,
        )

    def _worker_for_failure(self, task, proxy):
        lease = self._workers.lease_of(task)
        if lease is not None:
            return lease, lease.worker
        if proxy:
            return None, self._workers.find(proxy)
        return None, self._workers.find(self.current_proxy)

    async def handle_proxy_failure(self, proxy=None, reason=''):
        try:
            task = asyncio.current_task()
            lease, worker = self._worker_for_failure(task, proxy)
            if worker is None:
                return

            if lease is not None and lease.worker is worker:
                outcome = self._workers.release(task, blame=True, reason=reason)
            else:
                outcome = self._workers.report_failure(worker, reason=reason)

            if outcome is None or outcome == BLAME_IGNORED:
                return

            if reason == _REASON_SILENT_TUNNEL:
                self._silent_log.warning(
                    ('silent', worker.url),
                    get_message(
                        'proxy_silent_upstream', self.language,
                        worker.masked, int(self.tunnel_idle_timeout),
                    ),
                )

            if outcome != BLAME_RETIRED and worker.suspect:
                self._schedule_async_task(self._probe_suspect_worker(worker.url))

            if outcome != BLAME_RETIRED:
                return

            logger.warning(get_message('proxy_worker_retired', self.language, worker.masked))
            self._sync_current_proxy()
            await self._close_client_for(worker.url)
            self._schedule_async_task(self._probe_retired_worker(worker.url))
        except Exception as e:
            logger.error(f"代理失败处理出错: {str(e)}")

    async def _probe_suspect_worker(self, proxy):
        try:
            verdict = await self._check_worker(proxy)
        except Exception as e:
            logger.error(get_message('proxy_check_error', self.language, str(e)))
            return

        if verdict is not False:
            return

        worker = self._workers.find(proxy)
        if worker is None:
            return

        if len(self._workers.roster) <= 1:
            async with self._refill_lock:
                if not len(self._standby) and self._fetch_allowed(time.time()):
                    self.last_switch_attempt = time.time()
                    await self._fetch_into_standby()
                replaced = await self._replace_exit(worker)
            if replaced:
                await self._close_client_for(worker.url)
            return

        if not self._workers.drop_worker(proxy, remember=True):
            return
        logger.warning(get_message('proxy_worker_retired', self.language, worker.masked))
        self._sync_current_proxy()
        await self._close_client_for(worker.url)

    async def _probe_retired_worker(self, proxy):
        try:
            await self._check_worker(proxy)
        except Exception as e:
            logger.error(get_message('proxy_check_error', self.language, str(e)))

    async def switch_proxy(self):
        try:
            current_time = time.time()
            if self.switching_proxy:
                return {'switching': True}

            elapsed = current_time - self.last_switch_attempt
            if elapsed < self.switch_cooldown:
                remaining = round(self.switch_cooldown - elapsed, 1)
                logger.info(f"刷新冷却中，剩余 {remaining:.1f} 秒")
                return {'cooldown': remaining}

            self._standby.clear()
            await self._maintain_exit_pool(force_fetch=True)
            async with self._refill_lock:
                await self._replace_soonest()
            return bool(self.proxies)

        except Exception as e:
            logger.error(get_message('proxy_switch_error', self.language, str(e)))
            return False

    async def _check_worker(self, proxy):
        if not proxy:
            return None

        try:
            test_url = self.test_url
            cache_key = (proxy, test_url)
            current_time = time.time()

            cached = self.proxy_check_cache.get(cache_key)
            if cached is not None and current_time - cached[0] < self.proxy_check_ttl:
                return cached[1]

            last_check = self.last_check_time.get(proxy)
            if last_check is not None and current_time - last_check < self.check_cooldown:
                return None
            self.last_check_time[proxy] = current_time

            try:
                from modules.modules import check_proxy

                is_valid = await check_proxy(proxy, test_url)
            except Exception as e:
                logger.error(f"出口检测错误: {sanitize_proxy(proxy)} - {str(e)}")
                return None

            logger.info(
                f"出口检查结果: {sanitize_proxy(proxy)} - {'有效' if is_valid else '无效'}"
            )
            self.proxy_check_cache[cache_key] = (time.time(), is_valid)
            self._report_proxy_use_to_pool(proxy, is_valid, test_url)
            self._write_back_verdict(proxy, is_valid)
            return is_valid

        except Exception as e:
            logger.error(f"出口检测异常: {str(e)}")
            return None

    def _note_exit_success(self, proxy):
        if not proxy:
            return
        try:
            worker = self._workers.find(proxy)
            if worker is None or (worker.failures == 0 and not worker.suspect):
                return
            self._workers.note_success(worker)
        except Exception as e:
            logger.debug(f"记录出口成功时出错（已忽略）: {e}")

    def _write_back_verdict(self, proxy, is_valid):
        worker = self._workers.find(proxy)
        if worker is None:
            return
        if is_valid:
            self._workers.note_success(worker)
        else:
            self._workers.report_failure(worker, reason='probe')

    def _split_proxy_address(self, proxy_url):
        try:
            address = str(proxy_url).split('://', 1)[-1]
            _auth, host_port = self._split_proxy_auth(address)
            host, port = split_host_port(host_port)
        except (ValueError, AttributeError, TypeError):
            return None
        return (host, int(port)) if host and port else None

    def _report_proxy_use_to_pool(self, proxy, is_valid, test_url):
        if self.proxy_source_mode != 'pool' or self.pool_remote_url or self._pool_service is None:
            return

        parsed = self._split_proxy_address(proxy)
        if parsed is None:
            return

        ip, port = parsed
        try:
            self._schedule_async_task(
                self._pool_service.report_proxy_use(ip, port, is_valid, test_url)
            )
        except Exception as e:
            logger.debug(f"使用期反馈调度失败（已忽略）: {e}")

    def _log_roster_reload(self, previous_urls):
        previous = len(previous_urls)
        current = self.proxies
        if previous == len(current) and set(previous_urls) == set(current):
            return

        samples = ', '.join(sanitize_proxy(url) for url in current[:3])
        if len(current) > 3:
            samples += f" ... (+{len(current) - 3})"
        if not samples:
            samples = get_message('no_proxy', self.language)
        logger.info(get_message('proxy_switch', self.language, len(current), previous))
        logger.info(f"当前出口: {samples}")

    async def cleanup_clients(self):
        while True:
            try:
                with self.client_pool_lock:
                    current_time = time.time()
                    expired_clients = []
                    for proxy, (client, last_used) in list(self.client_pool.items()):
                        if self._client_inflight.get(proxy, 0) > 0:
                            continue
                        if current_time - last_used > self.client_idle_timeout:
                            expired_clients.append(client)
                            del self.client_pool[proxy]
                for client in expired_clients:
                    await client.aclose()
                for cache_key in list(self.proxy_check_cache.keys()):
                    cached_at = self.proxy_check_cache[cache_key][0]
                    if current_time - cached_at > self.proxy_check_ttl:
                        self.proxy_check_cache.pop(cache_key, None)
                live = {proxy for proxy, _test_url in self.proxy_check_cache}
                for proxy in list(self.last_check_time.keys()):
                    if proxy not in live:
                        self.last_check_time.pop(proxy, None)
            except Exception as e:
                logger.error(f"清理客户端池错误: {str(e)}")
            await asyncio.sleep(30)

