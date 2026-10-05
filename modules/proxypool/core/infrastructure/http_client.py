"""
模块名称：modules.proxypool.core.infrastructure.http_client
功能描述：基于 aiohttp 的异步 HTTP 客户端，供抓取插件与代理验证共用；统一管理会话与连接池，把底层异常翻译成
          带可读原因的 HttpClientException，并为 SOCKS 代理提供 aiohttp 原生不支持的连接路径。
职责边界：负责：会话生命周期、连接池参数、默认超时与 connect_timeout 的下发、SOCKS 代理连接建立、异常翻译；不负责：重试策略
          （由调用方决定）、响应内容解析、代理质量判定。
关键依赖：aiohttp、core.domain.exceptions、core.domain.models、core.interfaces.infrastructure；
          可选 aiohttp_socks 仅用于 SOCKS 路径，缺失时该路径请求失败。
已知限制：
  1. 共享会话一律不校验证书（连接器 ssl=False，且按请求传 ssl=True 也会被 aiohttp 降级为不校验；仅按请求传 ssl.SSLContext 才校验），
     故匿名度回显等质量结论类请求实际未校验，第三方/中间人代理可伪造回显；SOCKS 路径按默认仍校验证书。
  2. connect_timeout 对应 aiohttp 的 sock_connect 而非 connect，隧道建立时间不计入连接预算。
  3. _translate 须先按具体类型判定，否则丢超时原因；reason 取值是验证器归因依据，proxy_refused 单独归类，是判定不支持 https 转发的唯一确定性信号。
  4. pool_queue_timeout 由超时类异常、排队达到 _QUEUE_WAIT_INCONCLUSIVE_SECONDS、始终未拿到连接三条共同判定；
     拿到连接后的读超时不归为排队问题。
  5. SOCKS 请求按请求新建并关闭会话，不参与共享连接池，也不受连接池上限约束。
  6. 关闭后 _get_session 抛 reason="client_closed"，调用方不得重试；close() 幂等且关闭标记不复位，重新启用需新建实例。
  7. _PLAIN_PROBE_URL_COUNT=3 对应 validation_endpoints 明文 HTTP 探测清单的条数，两处须同步修改；按层间依赖方向，不得改为导入该清单常量。
"""

import asyncio
import logging
import socket
import time
from typing import Optional

import aiohttp

from core.domain.exceptions import (
    HttpClientException,
    HttpRequestException,
    HttpTimeoutException,
)
from core.domain.models import HttpResponse
from core.interfaces.infrastructure import IHttpClient

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 30

SOCKS_PROXY_SCHEMES = frozenset({"socks4", "socks4a", "socks5", "socks5h"})

_MIN_CONNECTIONS = 256
_PER_HOST_RATIO = 0.25

_QUEUE_WAIT_INCONCLUSIVE_SECONDS = 0.5
_CONGESTION_LOG_INTERVAL_SECONDS = 60.0

_PLAIN_PROBE_URL_COUNT = 3

_last_congestion_log = 0.0

_BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

try:
    from aiohttp_socks import ProxyConnector as _SocksProxyConnector
    _SOCKS_AVAILABLE = True
except ImportError:  # pragma: no cover
    _SocksProxyConnector = None  # type: ignore[assignment]
    _SOCKS_AVAILABLE = False

_PROXY_CONNECTION_ERROR_TYPES: tuple = (aiohttp.ClientProxyConnectionError,)
if _SOCKS_AVAILABLE:  # pragma: no cover
    try:
        from aiohttp_socks import ProxyConnectionError, ProxyError, ProxyTimeoutError
        _PROXY_CONNECTION_ERROR_TYPES = (
            aiohttp.ClientProxyConnectionError,
            ProxyError,
            ProxyConnectionError,
            ProxyTimeoutError,
        )
    except ImportError:
        pass


def describe_error(exc: BaseException) -> str:
    text = str(exc).strip()
    return text or type(exc).__name__


def proxy_scheme(proxy: Optional[str]) -> str:
    if not proxy:
        return ""
    scheme, separator, _ = proxy.partition("://")
    return scheme.lower() if separator else ""


class _PoolQueueProbe:
    def __init__(self):
        self.connected = False
        self._settled_seconds = 0.0
        self._waiting_since = None

    def begin_wait(self):
        self._waiting_since = time.monotonic()

    def end_wait(self):
        if self._waiting_since is not None:
            self._settled_seconds += time.monotonic() - self._waiting_since
            self._waiting_since = None

    def mark_connected(self):
        self.connected = True

    def total_wait_seconds(self) -> float:
        if self._waiting_since is None:
            return self._settled_seconds
        return self._settled_seconds + (time.monotonic() - self._waiting_since)


def _probe_of(trace_config_ctx) -> Optional[_PoolQueueProbe]:
    probe = getattr(trace_config_ctx, "trace_request_ctx", None)
    return probe if isinstance(probe, _PoolQueueProbe) else None


async def _trace_queue_started(session, trace_config_ctx, params):
    probe = _probe_of(trace_config_ctx)
    if probe is not None:
        probe.begin_wait()


async def _trace_queue_finished(session, trace_config_ctx, params):
    probe = _probe_of(trace_config_ctx)
    if probe is not None:
        probe.end_wait()


async def _trace_connected(session, trace_config_ctx, params):
    probe = _probe_of(trace_config_ctx)
    if probe is not None:
        probe.mark_connected()


def _build_trace_config() -> aiohttp.TraceConfig:
    trace_config = aiohttp.TraceConfig()
    trace_config.on_connection_queued_start.append(_trace_queue_started)
    trace_config.on_connection_queued_end.append(_trace_queue_finished)
    trace_config.on_connection_create_end.append(_trace_connected)
    trace_config.on_connection_reuseconn.append(_trace_connected)
    return trace_config


def _validation_request_upper_bound(validator) -> int:
    identity = len(getattr(validator, "identity_echo_apis", None) or ())
    plain_identity = len(getattr(validator, "plain_identity_echo_apis", None) or ())
    ip_apis = len(getattr(validator, "ip_check_apis", None) or ())

    bound = 1 + identity + ip_apis
    if getattr(validator, "check_anonymity", False):
        bound += identity + plain_identity + _PLAIN_PROBE_URL_COUNT
    return bound


def _log_pool_congestion(url: str, waited: float) -> None:
    global _last_congestion_log
    now = time.monotonic()
    if now - _last_congestion_log < _CONGESTION_LOG_INTERVAL_SECONDS:
        return
    _last_congestion_log = now
    logger.warning(
        f"本机连接池排队 {waited:.1f} 秒后超时（{url}）：本轮不下结论。"
        f"检测并发可能超出本机连接能力，可调低 validator.max_concurrent。"
    )


class AioHttpClient(IHttpClient):
    def __init__(self, default_timeout: int = DEFAULT_TIMEOUT_SECONDS):
        self._session: Optional[aiohttp.ClientSession] = None
        self._family_sessions: dict[int, aiohttp.ClientSession] = {}
        self._session_lock = asyncio.Lock()
        self._default_timeout = default_timeout
        self._max_connections = _MIN_CONNECTIONS
        self._session_stale = False
        self._closed = False
        self._trace_config = _build_trace_config()

    def apply_config(self, config) -> None:
        timeout = config.plugins.request_timeout_seconds
        if timeout != self._default_timeout:
            logger.info(f"HTTP 客户端默认超时已更新: {self._default_timeout} -> {timeout} 秒")
            self._default_timeout = timeout

        limit = self._resolve_connection_limit(config)
        if limit != self._max_connections:
            logger.info(
                f"HTTP 连接池上限已更新: {self._max_connections} -> {limit}"
            )
            self._max_connections = limit
            self._session_stale = True

    @staticmethod
    def _resolve_connection_limit(config) -> int:
        validator = getattr(config, "validator", None)
        max_concurrent = getattr(validator, "max_concurrent", 0) or 0
        try:
            max_concurrent = int(max_concurrent)
        except (TypeError, ValueError):
            max_concurrent = 0

        return max(
            _MIN_CONNECTIONS,
            max_concurrent * _validation_request_upper_bound(validator),
        )

    def _new_session(self, family: Optional[int] = None) -> aiohttp.ClientSession:
        connector = aiohttp.TCPConnector(
            family=socket.AF_UNSPEC if family is None else family,
            limit=self._max_connections,
            limit_per_host=max(1, int(self._max_connections * _PER_HOST_RATIO)),
            ttl_dns_cache=300,
            ssl=False,
        )
        return aiohttp.ClientSession(
            connector=connector,
            headers={"User-Agent": _BROWSER_USER_AGENT},
            trace_configs=[self._trace_config],
        )

    async def _drop_sessions(self) -> None:
        for session in [self._session, *self._family_sessions.values()]:
            if session is not None and not session.closed:
                await session.close()
        self._session = None
        self._family_sessions = {}
        self._session_stale = False

    async def _get_session(self, family: Optional[int] = None) -> aiohttp.ClientSession:
        if self._closed:
            raise HttpClientException("HTTP 客户端已关闭", reason="client_closed")

        async with self._session_lock:
            if self._closed:
                raise HttpClientException("HTTP 客户端已关闭", reason="client_closed")

            if self._session_stale:
                await self._drop_sessions()

            if family is None:
                if self._session is not None and self._session.closed:
                    self._session = None
                if self._session is None:
                    self._session = self._new_session()
                return self._session

            session = self._family_sessions.get(family)
            if session is not None and session.closed:
                session = None
            if session is None:
                session = self._new_session(family)
                self._family_sessions[family] = session
            return session

    async def _request(self, method: str, url: str, proxy: Optional[str],
                       timeout: Optional[int], connect_timeout: Optional[float] = None,
                       family: Optional[int] = None, **kwargs) -> HttpResponse:
        total = timeout or self._default_timeout
        probe = _PoolQueueProbe()

        try:
            if proxy_scheme(proxy) in SOCKS_PROXY_SCHEMES:
                return await self._request_via_socks(
                    method, url, proxy, total, connect_timeout, **kwargs
                )

            session = await self._get_session(family)
            return await self._send(
                session, method, url, total, connect_timeout,
                probe=probe, proxy=proxy, **kwargs
            )

        except HttpClientException:
            raise
        except Exception as e:
            raise self._translate(
                e, url, total, connect_timeout,
                pool_wait_seconds=probe.total_wait_seconds(),
                connected=probe.connected,
            ) from e

    @staticmethod
    async def _send(session: aiohttp.ClientSession, method: str, url: str,
                    total: float, connect_timeout: Optional[float],
                    probe: Optional[_PoolQueueProbe] = None,
                    **kwargs) -> HttpResponse:
        request_timeout = aiohttp.ClientTimeout(total=total, sock_connect=connect_timeout)
        async with session.request(
            method, url, timeout=request_timeout,
            trace_request_ctx=probe, **kwargs
        ) as response:
            text = await response.text()
            return HttpResponse(
                status=response.status,
                text=text,
                headers=dict(response.headers),
            )

    async def _request_via_socks(self, method: str, url: str, proxy: str,
                                 total: float, connect_timeout: Optional[float],
                                 **kwargs) -> HttpResponse:
        if not _SOCKS_AVAILABLE:
            raise HttpRequestException(
                f"无法使用 SOCKS 代理 {proxy}: 缺少 aiohttp_socks 依赖",
                reason="socks_unsupported",
            )

        connector = _SocksProxyConnector.from_url(proxy)
        try:
            async with aiohttp.ClientSession(connector=connector) as session:
                return await self._send(
                    session, method, url, total, connect_timeout, **kwargs
                )
        except HttpClientException:
            raise
        except Exception as e:
            raise self._translate(e, url, total, connect_timeout, proxy) from e

    @staticmethod
    def _translate(exc: Exception, url: str, total: float,
                   connect_timeout: Optional[float],
                   proxy: Optional[str] = None,
                   *, pool_wait_seconds: float = 0.0,
                   connected: bool = False) -> HttpClientException:
        connect_budget = connect_timeout or total

        if (not connected
                and pool_wait_seconds >= _QUEUE_WAIT_INCONCLUSIVE_SECONDS
                and isinstance(exc, asyncio.TimeoutError)):
            _log_pool_congestion(url, pool_wait_seconds)
            return HttpTimeoutException(
                f"本机连接池排队 {pool_wait_seconds:.1f} 秒后超时 {url}",
                reason="pool_queue_timeout",
            )

        if isinstance(exc, aiohttp.ConnectionTimeoutError):
            return HttpTimeoutException(
                f"连接超时 {url}（{connect_budget} 秒内未能建立连接）",
                reason="connect_timeout",
            )
        if isinstance(exc, aiohttp.SocketTimeoutError):
            return HttpTimeoutException(
                f"读取超时 {url}（{total} 秒内未收到响应）",
                reason="read_timeout",
            )
        if isinstance(exc, asyncio.TimeoutError):
            return HttpTimeoutException(
                f"请求超时 {url}（{total} 秒内无响应）",
                reason="total_timeout",
            )
        if isinstance(exc, aiohttp.ClientHttpProxyError):
            status = getattr(exc, "status", None)
            return HttpRequestException(
                f"代理拒绝建立隧道（CONNECT 返回 {status}）: {describe_error(exc)}",
                reason="proxy_refused",
            )
        if isinstance(exc, _PROXY_CONNECTION_ERROR_TYPES):
            target = proxy or "代理"
            return HttpRequestException(
                f"连接代理失败 {target}: {describe_error(exc)}",
                reason="proxy_connect",
            )
        if isinstance(exc, aiohttp.ClientConnectorDNSError):
            return HttpRequestException(
                f"域名解析失败 {url}: {describe_error(exc)}",
                reason="dns",
            )
        if isinstance(exc, aiohttp.ServerDisconnectedError):
            return HttpRequestException(
                f"连接被对端断开 {url}: {describe_error(exc)}",
                reason="disconnect",
            )
        if isinstance(exc, aiohttp.ClientError):
            return HttpRequestException(
                f"请求失败 {url}: {describe_error(exc)}",
                reason="request",
            )
        return HttpClientException(
            f"请求异常 {url}: {describe_error(exc)}",
            reason="unexpected",
        )

    async def get(self, url: str, proxy: Optional[str] = None,
                  timeout: Optional[int] = None,
                  connect_timeout: Optional[float] = None,
                  family: Optional[int] = None,
                  **kwargs) -> HttpResponse:
        return await self._request(
            "GET", url, proxy, timeout, connect_timeout, family=family, **kwargs
        )

    async def post(self, url: str, data: Optional[dict] = None,
                   json: Optional[dict] = None,
                   proxy: Optional[str] = None,
                   timeout: Optional[int] = None,
                   connect_timeout: Optional[float] = None,
                   **kwargs) -> HttpResponse:
        if data is not None:
            kwargs["data"] = data
        if json is not None:
            kwargs["json"] = json
        return await self._request("POST", url, proxy, timeout, connect_timeout, **kwargs)

    async def close(self) -> None:
        self._closed = True
        await self._drop_sessions()


__all__ = [
    "AioHttpClient",
    "describe_error",
    "proxy_scheme",
    "DEFAULT_TIMEOUT_SECONDS",
    "SOCKS_PROXY_SCHEMES",
]
