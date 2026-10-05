"""
模块名称：modules.proxypool.core.services.validation_endpoints
功能描述：代理验证所用外部端点的可用性管理与身份回显基线：按 TTL 直连预筛端点、剔除本网络不可达者，
采集端点自身响应特征（注入头部、origin 链、本机公网出口 IP）并解析端点文本中的出口 IP。
职责边界：负责端点清单的持有与热更新、直连可达性预筛与单个地址按需补探、端点基线的采集与查询、整体可用性结论，
并提供身份回显与出口 IP 解析（parse_identity_echo、parse_exit_ip、pick_exit_ip）；不负责单个代理验证流程，匿名度判定在 ProxyValidator。
关键依赖：IHttpClient、IConfigManager、core.domain.models.canonical_ip。
已知限制：
1. 状态为进程内内存态，不跨进程持久化；未预筛时查询按原清单放行、可用性判定为 True。
2. is_reachable_directly、baseline_for、direct_latency_ms 未命中返回 None；调用方需区分 None 与 False。
3. ensure_reachable 仅对空串返回 None，对未命中新鲜预筛结果的非空地址现探一次并记入状态后返回布尔值；跳过现探会把目标站不可达归因为代理失败。
4. 预筛为不带代理的直连探测，只回答本机到端点是否可达，不构成对代理可用性的结论。
5. 失败结论按 TTL 记账（预筛 300 秒、本机公网 IP 1800 秒，含查询失败），单次直连探测超时 5 秒。
6. ip_check_apis、identity_echo_apis 必须 https，plain_identity_echo_apis 必须真 http，不合规条目被剔除并记 warning。
7. 由 https 回显端点派生的明文端点只保留 netloc 与 path，query 与 fragment 会被丢弃。
8. 出口 IP 优先返回 origin 链尾最近的 IPv4，无 IPv4 时返回链尾最近的合法地址；host_public_ip 每个地址族只保留第一个值。
"""

import asyncio
import ipaddress
import json
import logging
import socket
import time
from dataclasses import dataclass, field
from typing import Optional, Sequence
from urllib.parse import urlparse

from core.domain.models import canonical_ip
from core.interfaces.infrastructure import IHttpClient, IConfigManager

logger = logging.getLogger(__name__)

_REQUIRED_ENDPOINT_SCHEME = "https"

_PLAIN_ENDPOINT_SCHEME = "http"

_DEFAULT_TTL_SECONDS = 300.0

_HOST_IP_TTL_SECONDS = 1800.0

_DIRECT_PROBE_TIMEOUT_SECONDS = 5.0

_HTTP_PROBE_URLS = (
    "http://connectivitycheck.platform.hicloud.com/generate_204",
    "http://cp.cloudflare.com",
    "http://detectportal.firefox.com/success.txt",
)

_DEFAULT_IDENTITY_ENDPOINTS = (
    "https://httpbin.org/anything",
    "https://httpbingo.org/anything",
)


def _as_plain_http(urls: Sequence[str]) -> list[str]:
    plain: list[str] = []
    for url in urls:
        parsed = urlparse(str(url))
        if not parsed.netloc:
            continue
        plain.append(f"http://{parsed.netloc}{parsed.path or '/'}")
    return list(dict.fromkeys(plain))


def https_only(urls: Sequence[str], *, label: str) -> list[str]:
    kept: list[str] = []
    for url in urls:
        if urlparse(str(url)).scheme.lower() == _REQUIRED_ENDPOINT_SCHEME:
            kept.append(url)
        else:
            logger.warning("%s 中的端点不是 https，已剔除: %s", label, url)
    return kept


def plain_http_only(urls: Sequence[str], *, label: str) -> list[str]:
    kept: list[str] = []
    for url in urls:
        text = str(url).strip()
        if not text:
            continue
        if urlparse(text).scheme.lower() == _PLAIN_ENDPOINT_SCHEME:
            kept.append(text)
        else:
            logger.warning("%s 中的端点不是明文 http，已剔除: %s", label, url)
    return kept


@dataclass
class IdentityEcho:

    chain: list[str]
    header_names: frozenset[str]
    raw_headers: dict


def parse_identity_echo(text: str) -> Optional[IdentityEcho]:
    raw = (text or "").strip()
    if not raw.startswith("{"):
        return None

    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None

    if not isinstance(data, dict):
        return None

    headers = data.get("headers")
    header_names = frozenset()
    if isinstance(headers, dict):
        header_names = frozenset(str(k).lower() for k in headers)

    chain = _parse_origin_chain(data.get("origin"))
    if not chain and not header_names:
        return None

    return IdentityEcho(
        chain=chain,
        header_names=header_names,
        raw_headers=headers if isinstance(headers, dict) else {},
    )


def _parse_origin_chain(origin) -> list[str]:
    if origin is None:
        return []

    if isinstance(origin, (list, tuple)):
        candidates = [str(item) for item in origin]
    else:
        candidates = str(origin).split(",")

    chain: list[str] = []
    for candidate in candidates:
        candidate = candidate.strip()
        if not candidate:
            continue
        canonical = canonical_ip(candidate)
        if canonical is not None:
            chain.append(canonical)
    return chain


@dataclass
class EndpointBaseline:

    url: str
    injected_headers: frozenset[str]
    direct_chain_length: int
    injected_header_values: dict[str, str] = field(default_factory=dict)


@dataclass
class _EndpointState:

    url: str
    reachable: bool = False
    latency_ms: Optional[float] = None
    baseline: Optional[EndpointBaseline] = None


class ValidationEndpoints:

    def __init__(self, http_client: IHttpClient, config_manager: IConfigManager):
        self._http_client = http_client
        self._config_manager = config_manager

        self._plain_identity_endpoints: list[str] = []
        self._ip_check_endpoints: list[str] = []
        self._host_ip_override: dict[int, str] = {}
        self.check_anonymity = True
        self._cached_host_ips: dict[int, str] = {}
        self._host_ip_checked_at: float = 0.0
        self._host_ip_lock = asyncio.Lock()
        config = self._config_manager.get_config()
        self._apply_validator_config(config.validator)

        self._ttl_seconds = _DEFAULT_TTL_SECONDS
        self._states: dict[str, _EndpointState] = {}
        self._last_refresh_at: float = 0.0
        self._refresh_lock = asyncio.Lock()

    def _apply_validator_config(self, validator_config) -> None:
        self._target_url = validator_config.target_url

        configured = str(getattr(validator_config, "host_public_ip", "") or "").strip()
        overrides = parse_host_ip_list(configured)
        if configured and not overrides:
            logger.warning(
                "validator.host_public_ip 里没有可用的 IP（%r），按未配置处理，"
                "将改为直连查询站点获取", configured
            )
        self._host_ip_override = overrides
        if not self._host_ip_override:
            self._cached_host_ips = {}
            self._host_ip_checked_at = 0.0

        self.check_anonymity = bool(
            getattr(validator_config, "check_anonymity", True)
        )

        self._ip_check_endpoints = https_only(
            list(getattr(validator_config, "ip_check_apis", None) or []),
            label="validator.ip_check_apis",
        )

        endpoints = list(getattr(validator_config, "identity_echo_apis", None)
                         or _DEFAULT_IDENTITY_ENDPOINTS)
        self._identity_endpoints = https_only(
            endpoints, label="validator.identity_echo_apis"
        )
        extra_plain = plain_http_only(
            getattr(validator_config, "plain_identity_echo_apis", None) or [],
            label="validator.plain_identity_echo_apis",
        )
        self._plain_identity_endpoints = list(dict.fromkeys(
            _as_plain_http(self._identity_endpoints) + extra_plain
        ))

    def apply_config(self, config) -> None:
        old_endpoints = list(self._identity_endpoints)
        old_plain_endpoints = list(self._plain_identity_endpoints)
        old_target = self._target_url

        self._apply_validator_config(config.validator)

        if (old_endpoints != list(self._identity_endpoints)
                or old_plain_endpoints != list(self._plain_identity_endpoints)
                or old_target != self._target_url):
            logger.info(
                "验证端点配置已更新: target=%s->%s, identity_endpoints=%d->%d,"
                " plain_identity_endpoints=%d->%d",
                old_target, self._target_url,
                len(old_endpoints), len(self._identity_endpoints),
                len(old_plain_endpoints), len(self._plain_identity_endpoints),
            )
            self._invalidate()

    def _invalidate(self) -> None:
        self._states.clear()
        self._last_refresh_at = 0.0

    async def ensure_ready(self) -> None:
        if self._is_fresh():
            return

        async with self._refresh_lock:
            if self._is_fresh():
                return
            await self._refresh()

    def _is_fresh(self) -> bool:
        if not self._states:
            return False
        return (time.monotonic() - self._last_refresh_at) < self._ttl_seconds

    async def ensure_reachable(self, url: str) -> Optional[bool]:
        if not url:
            return None

        if self._is_fresh():
            state = self._states.get(url)
            if state is not None:
                return state.reachable

        async with self._refresh_lock:
            if self._is_fresh():
                state = self._states.get(url)
                if state is not None:
                    return state.reachable
            probed = await self._probe_direct(url)
            self._states[url] = probed
            return probed.reachable

    async def _refresh(self) -> None:
        urls = self._candidate_urls()

        results = await asyncio.gather(
            *(self._probe_direct(url) for url in urls),
            return_exceptions=True,
        )

        states: dict[str, _EndpointState] = {}
        for url, result in zip(urls, results):
            if isinstance(result, _EndpointState):
                states[url] = result
            else:
                logger.debug("端点直连探测异常 %s: %s", url, result)
                states[url] = _EndpointState(url=url, reachable=False)

        self._states = states
        self._last_refresh_at = time.monotonic()

        reachable = [u for u, s in states.items() if s.reachable]
        logger.info(
            "验证端点直连预筛完成: 可达 %d/%d, 目标站可达=%s, 本机公网IP=%s",
            len(reachable), len(states),
            self.is_reachable_directly(self._target_url),
            self.host_public_ip() or "未知",
        )
        for url in states:
            if url not in reachable:
                logger.debug("端点直连不可达，本轮剔除: %s", url)

    def _candidate_urls(self) -> list[str]:
        urls = [self._target_url]
        urls.extend(self._identity_endpoints)
        if self.check_anonymity:
            urls.extend(self._plain_identity_endpoints)
            urls.extend(_HTTP_PROBE_URLS)
        return list(dict.fromkeys(urls))

    async def _probe_direct(self, url: str) -> _EndpointState:
        state = _EndpointState(url=url)
        start = time.monotonic()
        try:
            response = await self._http_client.get(
                url, timeout=_DIRECT_PROBE_TIMEOUT_SECONDS
            )
        except Exception as exc:
            logger.debug("端点直连失败 %s: %s", url, exc)
            return state

        state.latency_ms = (time.monotonic() - start) * 1000.0

        if response.status >= 400:
            logger.debug("端点直连返回错误状态 %s: %s", url, response.status)
            return state

        state.reachable = True

        identity = parse_identity_echo(response.text)
        if identity is not None:
            state.baseline = EndpointBaseline(
                url=url,
                injected_headers=frozenset(identity.header_names),
                injected_header_values={
                    str(name).lower(): str(value)
                    for name, value in identity.raw_headers.items()
                },
                direct_chain_length=len(identity.chain),
            )

        return state

    @property
    def target_url(self) -> str:
        return self._target_url

    def identity_endpoints(self) -> list[str]:
        return self._healthy_or_all(self._identity_endpoints)

    def plain_identity_endpoints(self) -> list[str]:
        return self._healthy_or_all(self._plain_identity_endpoints)

    def http_probe_endpoints(self) -> list[str]:
        return self._healthy_or_all(list(_HTTP_PROBE_URLS))

    def _healthy_or_all(self, urls: list[str]) -> list[str]:
        if not self._states:
            return list(urls)

        healthy = [url for url in urls
                   if self._states.get(url) and self._states[url].reachable]
        return healthy

    def baseline_for(self, url: str) -> Optional[EndpointBaseline]:
        state = self._states.get(url)
        return state.baseline if state else None

    def host_public_ips(self) -> tuple[str, ...]:
        source = self._host_ip_override or self._cached_host_ips
        return tuple(source[version] for version in (4, 6) if source.get(version))

    def host_public_ip(self) -> Optional[str]:
        ips = self.host_public_ips()
        return ips[0] if ips else None

    async def ensure_host_ip(self) -> Optional[str]:
        if self._host_ip_override:
            return self.host_public_ip()

        if self._host_ip_fresh():
            return self.host_public_ip()

        async with self._host_ip_lock:
            if self._host_ip_fresh():
                return self.host_public_ip()
            await self._refresh_host_ip()
        return self.host_public_ip()

    def _host_ip_fresh(self) -> bool:
        if not self._host_ip_checked_at:
            return False
        return (time.monotonic() - self._host_ip_checked_at) < _HOST_IP_TTL_SECONDS

    async def _probe_family(self, version: int, af: int) -> Optional[str]:
        for url in self._ip_check_endpoints:
            try:
                response = await self._http_client.get(
                    url, timeout=_DIRECT_PROBE_TIMEOUT_SECONDS, family=af
                )
            except Exception as exc:
                logger.debug("按 IPv%d 查询本机出口 IP 失败 %s: %s", version, url, exc)
                continue

            if getattr(response, "status", 0) != 200:
                continue

            ip = parse_exit_ip(getattr(response, "text", ""))
            if ip and ipaddress.ip_address(ip).version == version:
                return ip
        return None

    async def _refresh_host_ip(self) -> None:
        results = await asyncio.gather(
            self._probe_family(4, socket.AF_INET),
            self._probe_family(6, socket.AF_INET6),
            return_exceptions=True,
        )

        found: dict[int, str] = {}
        for version, result in zip((4, 6), results):
            if isinstance(result, str) and result:
                found[version] = result
        self._cached_host_ips = found
        self._host_ip_checked_at = time.monotonic()

        if found:
            logger.info(
                "本机公网出口 IP: %s",
                "，".join(f"IPv{v} {found[v]}" for v in sorted(found)),
            )
            return

        logger.warning(
            "本机公网出口 IP 查询失败（%d 个端点、两族各试一遍），匿名度将无法判定；"
            "可在池设置的 validator.host_public_ip 里直接填写",
            len(self._ip_check_endpoints),
        )

    def host_ip_source(self) -> str:
        if self._host_ip_override:
            return "configured"
        return "detected" if self._cached_host_ips else ""

    def is_reachable_directly(self, url: str) -> Optional[bool]:
        state = self._states.get(url)
        return state.reachable if state else None

    def direct_latency_ms(self, url: str) -> Optional[float]:
        state = self._states.get(url)
        return state.latency_ms if state else None

    def ordered_by_latency(self, urls: Sequence[str]) -> list[str]:
        probed: list[tuple[float, int, str]] = []
        unknown: list[tuple[int, str]] = []

        for index, url in enumerate(urls):
            latency = self.direct_latency_ms(url)
            if latency is None:
                unknown.append((index, url))
            else:
                probed.append((latency, index, url))

        probed.sort(key=lambda item: (item[0], item[1]))
        return [url for _, _, url in probed] + [url for _, url in unknown]

    def network_available(self) -> bool:
        if not self._states:
            return True
        return any(state.reachable for state in self._states.values())

    def identity_available(self) -> bool:
        if not self._states:
            return True
        return any(
            self._states.get(url) and self._states[url].reachable
            for url in self._identity_endpoints
        )


__all__ = [
    "ValidationEndpoints",
    "EndpointBaseline",
    "IdentityEcho",
    "parse_identity_echo",
]

_JSON_IP_FIELDS = ("ip", "origin", "query", "address")


def _parse_exit_ip_from_key_value_lines(raw: str) -> Optional[str]:
    for line in raw.splitlines():
        key, separator, value = line.partition("=")
        if separator and key.strip().lower() == "ip":
            chain = [part.strip() for part in value.split(",")]
            exit_ip = pick_exit_ip(chain)
            if exit_ip:
                return exit_ip
    return None


def _parse_exit_ip_from_json(raw: str) -> Optional[str]:
    parsed = parse_identity_echo(raw)
    if parsed is not None and parsed.chain:
        return pick_exit_ip(parsed.chain)

    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None

    if not isinstance(data, dict):
        return None

    for field_name in _JSON_IP_FIELDS:
        value = data.get(field_name)
        if not isinstance(value, str) or not value.strip():
            continue
        chain = [part.strip() for part in value.split(",")]
        exit_ip = pick_exit_ip(chain)
        if exit_ip:
            return exit_ip
    return None


def parse_exit_ip(text: str) -> Optional[str]:
    raw = (text or "").strip()
    if not raw:
        return None

    if raw.startswith("{"):
        return _parse_exit_ip_from_json(raw)

    from_lines = _parse_exit_ip_from_key_value_lines(raw)
    if from_lines:
        return from_lines

    return pick_exit_ip([part.strip() for part in raw.split(",")])


def pick_exit_ip(chain: Sequence[str]) -> Optional[str]:
    if not chain:
        return None

    for candidate in reversed(chain):
        canonical = canonical_ip(candidate)
        if canonical is not None and ipaddress.ip_address(canonical).version == 4:
            return canonical

    for candidate in reversed(chain):
        canonical = canonical_ip(candidate)
        if canonical is not None:
            return canonical
    return None


def parse_host_ip_list(text: str) -> dict[int, str]:
    resolved: dict[int, str] = {}
    for part in str(text or "").replace("，", ",").split(","):
        canonical = canonical_ip(part.strip())
        if canonical is None:
            continue
        resolved.setdefault(ipaddress.ip_address(canonical).version, canonical)
    return resolved
