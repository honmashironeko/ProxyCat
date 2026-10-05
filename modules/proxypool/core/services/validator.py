"""
模块名称：modules.proxypool.core.services.validator
功能描述：代理池的单代理质量验证器：存活探测先行把关（不过即止），通过后并发发出身份与明文探测，
          产出带失败归因的 ProxyValidationResult；本轮做哪几项由 ValidationMode 决定。
职责边界：负责：单代理验证流水线的编排（存活闸门、探测对冲竞速）、失败归因（代理／我方／目标站）、
          身份回显解读与匿名度判定、方案能力正负判定；不负责：端点预筛与直连基线（ValidationEndpoints）、
          健康评分、HTTP 异常翻译、结论落库、策略（见 HealthScorer、AioHttpClient、validation_apply、validation_policy）。
关键依赖：IHttpClient、IConfigManager、IProxyValidator、ValidationEndpoints、core.domain.models。
已知限制：
1. 「没测成」与「代理失败」不可互换：ok=None、INCONCLUSIVE 或身份字段为 None 均表示本轮无结论，写入层须跳过以保留旧值；ok=False 才是归因于代理的失败。
2. 实例由 DI 容器单例持有；并发由内部信号量统一把持；validate_proxy 以结果对象表达失败（验证过程异常兜底为 INCONCLUSIVE），批量验证由调用方自行 gather。
3. 失败原因字符串与 http_client 的 reason 同源，改其一须同步核对四张归因表；pool_queue_timeout 属本机连接池排队，必须最先判为无结论。
4. 竞速按直连延迟逐个补发候选，总窗口不超过 _RACE_LAUNCH_WINDOW_SECONDS；max_concurrent 热更新会换新信号量，在飞验证归还旧信号量、不被打断。
5. 匿名度靠明文回显路径判定；回显端点整体不可用、本机公网 IP 未知、探针未发出或开关关闭时不下结论；其余判不出等级时兜底 transparent 并标记 anonymity_fallback。
6. 方案能力的否定结论：https 须代理明确拒绝 CONNECT 且回显端点可用，超时不下结论；http 由明文探测端点直连可达且竞速全败（含超时）时给出。
7. can_attribute_failure 比存活归因更严：须本机网络可用且 test_url 未被判为直连不可达，弱证据宁可漏记不可误杀。
8. test_url 的直连可达性须在归因前由 ensure_reachable 探明并记入端点状态：未知会被当作可达，目标站故障会被误记为代理失败。
"""

import asyncio
import ipaddress
import json
import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Optional, Sequence
from urllib.parse import urlparse

from core.interfaces.services import IProxyValidator
from modules.modules import sanitize_proxy
from core.interfaces.infrastructure import IHttpClient, IConfigManager
from core.domain.models import (
    canonical_ip,
    ProbeKind,
    ProbeOutcome,
    ProxyValidationResult,
    ValidationMode,
    ValidationOutcome,
)
from core.services.validation_endpoints import (
    IdentityEcho,
    ValidationEndpoints,
    https_only,
    parse_exit_ip,
    parse_identity_echo,
    pick_exit_ip,
)

logger = logging.getLogger(__name__)

_IP_FRAGMENT = re.compile(r"[0-9a-fA-F:.]+")

_PROXY_REVEAL_HEADERS = frozenset({
    "x-forwarded-for",
    "x-real-ip",
    "via",
    "proxy-connection",
    "x-proxy-id",
    "forwarded",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-originating-ip",
    "x-remote-ip",
    "x-remote-addr",
    "x-client-ip",
})

_FALLBACK_ANONYMITY = "transparent"


def _extract_ips(value: str) -> list[str]:
    found: list[str] = []
    for fragment in _IP_FRAGMENT.findall(str(value)):
        candidate = fragment
        if candidate.count(".") == 3 and ":" in candidate:
            head, _, tail = candidate.rpartition(":")
            if not tail or tail.isdigit():
                candidate = head
        if candidate.count(".") != 3 and candidate.count(":") < 2:
            continue
        canonical = canonical_ip(candidate)
        if canonical is not None:
            found.append(canonical)
    return found


def _scan_header_ips(echo: IdentityEcho, baseline, host_public_ips: Sequence[str]
                     ) -> tuple[bool, bool]:
    baseline_values = baseline.injected_header_values if baseline else {}

    leaked = False
    added = False
    for name, value in (echo.raw_headers or {}).items():
        key = str(name).lower()
        text = str(value)
        if baseline_values.get(key) == text:
            continue

        is_new = key not in baseline_values
        if is_new and key in _PROXY_REVEAL_HEADERS:
            added = True

        baseline_ips = _extract_ips(baseline_values.get(key, ""))
        for ip in _extract_ips(text):
            if ip in host_public_ips:
                leaked = True
            elif is_new or not baseline_ips:
                added = True
    return leaked, added


_PROXY_UNREACHABLE_REASONS = frozenset({
    "connect_timeout",
    "proxy_connect",
    "dns",
})

_OUR_FAULT_REASONS = frozenset({
    "socks_unsupported",
})

_TUNNEL_REFUSED_REASONS = frozenset({"proxy_refused"})

_LOCAL_CONGESTION_REASONS = frozenset({"pool_queue_timeout"})

_HEDGE_MIN_SECONDS = 0.2
_HEDGE_MAX_SECONDS = 1.5

_PREFER_IDENTITY_GRACE_SECONDS = 1.5

_RACE_LAUNCH_WINDOW_SECONDS = 1.5


@dataclass(frozen=True)
class _Attempt:

    value: object = None
    reason: Optional[str] = None
    proven_scheme: Optional[str] = None


@dataclass(frozen=True)
class _RaceOutcome:

    value: object = None
    failure_reasons: frozenset[str] = frozenset()
    proven_schemes: frozenset[str] = frozenset()


@dataclass(frozen=True)
class _IdentitySample:

    url: str
    exit_ip: str
    identity: Optional[IdentityEcho] = None


@dataclass(frozen=True)
class _AnonymityVerdict:

    level: Optional[str] = None
    fallback: bool = False


@dataclass
class _LivenessProbe:

    ok: bool
    latency_ms: Optional[float] = None
    reason: Optional[str] = None

    @property
    def outcome(self) -> ProbeOutcome:
        return ProbeOutcome(
            kind=ProbeKind.LIVENESS,
            ok=self.ok,
            latency_ms=self.latency_ms,
            reason=self.reason,
        )


@dataclass
class _IdentityProbe:

    sample: Optional[_IdentitySample] = None
    tunnel_refused: bool = False
    proven_https: bool = False
    attributable: bool = False
    reason: Optional[str] = None

    @property
    def real_ip(self) -> Optional[str]:
        return self.sample.exit_ip if self.sample else None

    @property
    def outcome(self) -> ProbeOutcome:
        if self.sample is not None:
            return ProbeOutcome(kind=ProbeKind.TUNNEL, ok=True)
        return ProbeOutcome(
            kind=ProbeKind.TUNNEL,
            ok=False if self.attributable else None,
            reason=self.reason or "no_identity",
        )


class ProxyValidator(IProxyValidator):

    def __init__(
        self,
        http_client: IHttpClient,
        config_manager: IConfigManager,
        endpoints: Optional[ValidationEndpoints] = None,
    ):
        self._http_client = http_client
        self._config_manager = config_manager
        self._endpoints = endpoints or ValidationEndpoints(http_client, config_manager)

        config = self._config_manager.get_config()
        self._apply_validator_config(config.validator)

        self._semaphore = asyncio.Semaphore(self._max_concurrent)

        logger.info(
            f"代理验证器已初始化: target={self._target_url}, "
            f"timeout={self._timeout}s, connect_timeout={self._connect_timeout}s, "
            f"max_concurrent={self._max_concurrent}"
        )

    def _apply_validator_config(self, validator_config) -> None:
        self._target_url = validator_config.target_url
        self._timeout = validator_config.timeout_seconds
        self._max_concurrent = max(1, validator_config.max_concurrent)
        self._connect_timeout = validator_config.connect_timeout_seconds
        self._ip_apis = https_only(
            validator_config.ip_check_apis, label="validator.ip_check_apis"
        )

    @property
    def max_concurrent(self) -> int:
        return self._max_concurrent

    @property
    def endpoints(self) -> ValidationEndpoints:
        return self._endpoints

    def can_attribute_failure(self, test_url: str) -> bool:
        if not self._endpoints.network_available():
            return False
        return self._endpoints.is_reachable_directly(test_url) is not False

    def apply_config(self, config) -> None:
        validator_config = config.validator

        old_target = self._target_url
        old_timeout = self._timeout
        old_concurrent = self._max_concurrent
        old_connect_timeout = self._connect_timeout

        self._apply_validator_config(validator_config)
        self._endpoints.apply_config(config)

        if self._max_concurrent != old_concurrent:
            self._semaphore = asyncio.Semaphore(self._max_concurrent)

        logger.info(
            f"验证器配置已更新: target={old_target}->{self._target_url}, "
            f"timeout={old_timeout}->{self._timeout}s, "
            f"connect_timeout={old_connect_timeout}->{self._connect_timeout}s, "
            f"max_concurrent={old_concurrent}->{self._max_concurrent}"
        )

    async def validate_proxy(
        self,
        proxy_url: str,
        mode: ValidationMode = ValidationMode.FULL,
        test_url: Optional[str] = None,
    ) -> ProxyValidationResult:
        if not isinstance(mode, ValidationMode):
            try:
                mode = ValidationMode(mode)
            except ValueError as exc:
                raise ValueError(f"未知的验证模式: {mode!r}") from exc

        semaphore = self._semaphore
        async with semaphore:
            try:
                return await self._validate(
                    proxy_url, mode, test_url or self._target_url
                )
            except Exception as e:
                logger.debug(f"验证代理异常 {sanitize_proxy(proxy_url)}: {e}")
                return self._build_result(
                    proxy_url,
                    ValidationOutcome.INCONCLUSIVE,
                    error_message=f"验证过程异常: {e}",
                    error_reason="validator_error",
                )

    async def _validate(
        self, proxy_url: str, mode: ValidationMode, test_url: str
    ) -> ProxyValidationResult:
        await self._endpoints.ensure_ready()
        await self._endpoints.ensure_reachable(test_url)
        if self._anonymity_check_enabled():
            await self._endpoints.ensure_host_ip()

        if not self._endpoints.network_available():
            return self._build_result(
                proxy_url,
                ValidationOutcome.INCONCLUSIVE,
                error_message="本机网络不可用（所有检测端点直连均失败）",
                error_reason="network_down",
            )

        liveness = await self._probe_liveness(proxy_url, test_url)
        probes: list[ProbeOutcome] = [liveness.outcome]

        if not liveness.ok:
            return self._attribute_target_failure(
                proxy_url, liveness.reason, probes, test_url
            )

        identity_task: Optional[asyncio.Task] = None
        plain_identity_task: Optional[asyncio.Task] = None
        plain_task: Optional[asyncio.Task] = None
        if mode in (ValidationMode.IDENTITY, ValidationMode.FULL):
            identity_task = asyncio.create_task(self._probe_identity(proxy_url))
            if self._anonymity_check_enabled():
                plain_identity_task = asyncio.create_task(
                    self._probe_plain_identity(proxy_url)
                )
            if mode is ValidationMode.FULL and self._scheme_of(test_url) != "http":
                plain_task = asyncio.create_task(self._probe_plain_http(proxy_url))

        identity = await self._settle(identity_task)
        plain_identity = await self._settle(plain_identity_task)
        plain_outcome = await self._settle(plain_task)

        if identity is not None:
            probes.append(identity.outcome)
        if plain_outcome is not None:
            probes.append(plain_outcome)

        capabilities = self._resolve_capabilities(
            liveness, identity, plain_outcome, test_url
        )

        verdict = self._judge_identity_anonymity(identity, plain_identity)

        return self._build_result(
            proxy_url,
            ValidationOutcome.OK,
            delay_ms=liveness.latency_ms,
            real_ip=identity.real_ip if identity else None,
            anonymity_level=verdict.level,
            anonymity_fallback=verdict.fallback,
            supports_http=capabilities["http"],
            supports_https=capabilities["https"],
            probes=probes,
        )

    async def _probe_liveness(
        self, proxy_url: str, test_url: str
    ) -> _LivenessProbe:
        url = test_url
        start = time.monotonic()
        try:
            response = await self._http_client.get(
                url,
                proxy=proxy_url,
                timeout=self._timeout,
                connect_timeout=self._connect_timeout or None,
                allow_redirects=True,
            )
        except Exception as e:
            return _LivenessProbe(
                ok=False, reason=getattr(e, "reason", None) or "unknown"
            )

        if response.status < 400:
            return _LivenessProbe(
                ok=True, latency_ms=(time.monotonic() - start) * 1000.0
            )

        logger.debug(f"代理 {sanitize_proxy(proxy_url)} 访问测试地址返回状态码 {response.status}")
        return _LivenessProbe(ok=False, reason=f"status_{response.status}")

    async def _probe_identity(self, proxy_url: str) -> _IdentityProbe:
        candidates = self._identity_candidates()
        if not candidates:
            return _IdentityProbe(reason="no_identity_endpoints")

        outcome = await self._race(
            candidates,
            lambda url: self._fetch_identity(proxy_url, url),
            prefer=lambda sample: sample.identity is not None,
            prefer_grace_seconds=_PREFER_IDENTITY_GRACE_SECONDS,
        )

        sample = outcome.value if isinstance(outcome.value, _IdentitySample) else None
        if sample is not None:
            return _IdentityProbe(
                sample=sample, proven_https="https" in outcome.proven_schemes
            )

        attributable = self._endpoints.identity_available()
        if attributable:
            logger.warning(
                "代理 %s 可达但全部 %d 个出口 IP 检测端点都失败，"
                "本轮拿不到出口 IP 与匿名度",
                proxy_url, len(candidates),
            )

        return _IdentityProbe(
            tunnel_refused=bool(outcome.failure_reasons & _TUNNEL_REFUSED_REASONS),
            proven_https="https" in outcome.proven_schemes,
            attributable=attributable,
            reason="no_identity" if attributable else "identity_endpoints_down",
        )

    async def _probe_plain_identity(self, proxy_url: str) -> Optional[_IdentityProbe]:
        candidates = self._endpoints.ordered_by_latency(
            self._endpoints.plain_identity_endpoints()
        )
        if not candidates:
            return None

        outcome = await self._race(
            candidates,
            lambda url: self._fetch_identity(proxy_url, url),
            prefer=lambda sample: sample.identity is not None,
            prefer_grace_seconds=_PREFER_IDENTITY_GRACE_SECONDS,
        )
        sample = outcome.value if isinstance(outcome.value, _IdentitySample) else None
        if sample is None or sample.identity is None:
            return None
        return _IdentityProbe(
            sample=sample, proven_https="https" in outcome.proven_schemes
        )

    async def _probe_plain_http(self, proxy_url: str) -> ProbeOutcome:
        urls = self._endpoints.ordered_by_latency(
            self._endpoints.http_probe_endpoints()
        )
        if not urls:
            return ProbeOutcome(
                kind=ProbeKind.PLAIN_HTTP, ok=None, reason="no_probe_endpoints"
            )

        outcome = await self._race(
            urls,
            lambda url: self._fetch_plain_http(proxy_url, url),
        )
        if isinstance(outcome.value, float):
            return ProbeOutcome(
                kind=ProbeKind.PLAIN_HTTP, ok=True, latency_ms=outcome.value
            )

        if any(self._endpoints.is_reachable_directly(url) for url in urls):
            reason = sorted(outcome.failure_reasons)[0] if outcome.failure_reasons else "unreachable"
            return ProbeOutcome(
                kind=ProbeKind.PLAIN_HTTP, ok=False, reason=reason
            )
        return ProbeOutcome(
            kind=ProbeKind.PLAIN_HTTP, ok=None, reason="probe_endpoints_down"
        )

    async def _fetch_identity(self, proxy_url: str, url: str) -> _Attempt:
        scheme = self._scheme_of(url)
        try:
            response = await self._http_client.get(
                url,
                proxy=proxy_url,
                timeout=self._timeout,
                connect_timeout=self._connect_timeout or None,
                allow_redirects=True,
                ssl=True,
            )
        except Exception as e:
            reason = getattr(e, "reason", None) or "unknown"
            logger.debug(f"身份回显请求失败 {url}（代理 {sanitize_proxy(proxy_url)}）: {e}")
            return _Attempt(reason=reason)

        if response.status != 200:
            return _Attempt(reason=f"status_{response.status}", proven_scheme=scheme)

        identity = parse_identity_echo(response.text)
        exit_ip = pick_exit_ip(identity.chain) if identity else None
        if exit_ip:
            return _Attempt(
                value=_IdentitySample(url=url, exit_ip=exit_ip, identity=identity),
                proven_scheme=scheme,
            )

        plain_ip = parse_exit_ip(response.text)
        if plain_ip:
            return _Attempt(
                value=_IdentitySample(url=url, exit_ip=plain_ip),
                proven_scheme=scheme,
            )

        logger.debug(f"身份回显响应无法解析 {url}（代理 {sanitize_proxy(proxy_url)}）")
        return _Attempt(reason="unparsable", proven_scheme=scheme)

    async def _fetch_plain_http(self, proxy_url: str, url: str) -> _Attempt:
        start = time.monotonic()
        try:
            response = await self._http_client.get(
                url,
                proxy=proxy_url,
                timeout=self._timeout,
                connect_timeout=self._connect_timeout or None,
                allow_redirects=False,
            )
        except Exception as e:
            reason = getattr(e, "reason", None) or "unknown"
            logger.debug(f"明文探测失败 {url}（代理 {sanitize_proxy(proxy_url)}）: {e}")
            return _Attempt(reason=reason)

        if response.status >= 400:
            return _Attempt(reason=f"status_{response.status}")
        return _Attempt(value=(time.monotonic() - start) * 1000.0)

    def _attribute_target_failure(
        self,
        proxy_url: str,
        reason: Optional[str],
        probes: Sequence[ProbeOutcome],
        test_url: str,
    ) -> ProxyValidationResult:
        if reason in _LOCAL_CONGESTION_REASONS:
            return self._build_result(
                proxy_url,
                ValidationOutcome.INCONCLUSIVE,
                error_message="本机连接池排队超时，本次不下结论",
                error_reason=reason,
                probes=probes,
            )

        if reason in _OUR_FAULT_REASONS:
            return self._build_result(
                proxy_url,
                ValidationOutcome.INCONCLUSIVE,
                error_message="本地缺少 SOCKS 支持，无法验证该代理",
                error_reason=reason,
                probes=probes,
            )

        if reason in _PROXY_UNREACHABLE_REASONS:
            outcome = ValidationOutcome.PROXY_UNREACHABLE
            message = "无法连接代理"
            error_reason = reason
        else:
            reachable = self._endpoints.is_reachable_directly(test_url)
            if reachable is False:
                outcome = ValidationOutcome.INCONCLUSIVE
                message = "测试地址当前不可达，无法判断代理是否可用"
                error_reason = "target_unreachable"
            else:
                outcome = ValidationOutcome.PROXY_FAILED
                message = "代理无法转发请求"
                error_reason = reason

        logger.debug(f"代理 {sanitize_proxy(proxy_url)} 连通性失败: {message}（{error_reason}）")
        return self._build_result(
            proxy_url,
            outcome,
            error_message=message,
            error_reason=error_reason,
            probes=probes,
        )

    def _resolve_capabilities(
        self,
        liveness: _LivenessProbe,
        identity: Optional[_IdentityProbe],
        plain: Optional[ProbeOutcome],
        test_url: str,
    ) -> dict[str, Optional[bool]]:
        capabilities: dict[str, Optional[bool]] = {"http": None, "https": None}

        if liveness.ok:
            self._mark_capability(capabilities, test_url)

        if identity is not None:
            if identity.proven_https:
                capabilities["https"] = True
            elif identity.tunnel_refused and self._endpoints.identity_available():
                capabilities["https"] = False

        if plain is not None and plain.ok is not None and capabilities["http"] is None:
            capabilities["http"] = plain.ok

        return capabilities

    def _anonymity_check_enabled(self) -> bool:
        config = self._config_manager.get_config()
        return bool(getattr(getattr(config, "validator", None),
                            "check_anonymity", True))

    def _judge_identity_anonymity(
        self,
        identity: Optional[_IdentityProbe],
        plain_identity: Optional[_IdentityProbe] = None,
    ) -> "_AnonymityVerdict":
        if not self._anonymity_check_enabled():
            return _AnonymityVerdict()

        if identity is None and plain_identity is None:
            return _AnonymityVerdict()

        host_public_ips = self._endpoints.host_public_ips()
        if not host_public_ips:
            return _AnonymityVerdict()

        for probe in (plain_identity, identity):
            if probe is None or probe.sample is None or probe.sample.identity is None:
                continue
            level = self._judge_anonymity(
                probe.sample.identity,
                self._endpoints.baseline_for(probe.sample.url),
                host_public_ips,
            )
            if level is not None:
                return _AnonymityVerdict(level=level)

        exit_ip = identity.real_ip if identity else None
        if exit_ip in host_public_ips:
            return _AnonymityVerdict(level="transparent")

        if identity is not None and identity.sample is None and not identity.attributable:
            return _AnonymityVerdict()

        return _AnonymityVerdict(level=_FALLBACK_ANONYMITY, fallback=True)

    def _hedge_seconds(self, urls: Sequence[str]) -> float:
        best_ms = min(
            (
                latency
                for latency in (
                    self._endpoints.direct_latency_ms(url) for url in urls
                )
                if latency is not None
            ),
            default=None,
        )
        if best_ms is None:
            hedge = _HEDGE_MIN_SECONDS
        else:
            hedge = min(_HEDGE_MAX_SECONDS, max(_HEDGE_MIN_SECONDS, best_ms * 2 / 1000.0))

        if len(urls) > 1:
            hedge = min(hedge, _RACE_LAUNCH_WINDOW_SECONDS / (len(urls) - 1))
        return hedge

    async def _race(
        self,
        urls: Sequence[str],
        fetch: Callable[[str], object],
        *,
        prefer: Optional[Callable[[object], bool]] = None,
        prefer_grace_seconds: float = 0.0,
    ) -> _RaceOutcome:
        candidates = list(urls)
        if not candidates:
            return _RaceOutcome()

        hedge = self._hedge_seconds(candidates)
        pending: dict[asyncio.Task, str] = {}
        launched = 0
        next_launch_at = time.monotonic()
        reasons: set[str] = set()
        schemes: set[str] = set()
        fallback_value = None
        grace_until: Optional[float] = None

        try:
            while True:
                if launched < len(candidates) and time.monotonic() >= next_launch_at:
                    url = candidates[launched]
                    launched += 1
                    task = asyncio.create_task(fetch(url), name=f"race_{url}")
                    pending[task] = url
                    next_launch_at = time.monotonic() + hedge

                if not pending:
                    if launched >= len(candidates):
                        break
                    await asyncio.sleep(max(0.0, next_launch_at - time.monotonic()))
                    continue

                wait_for = None
                if launched < len(candidates):
                    wait_for = max(0.0, next_launch_at - time.monotonic())
                if grace_until is not None:
                    grace_left = max(0.0, grace_until - time.monotonic())
                    wait_for = grace_left if wait_for is None else min(wait_for, grace_left)

                done, _ = await asyncio.wait(
                    set(pending), timeout=wait_for, return_when=asyncio.FIRST_COMPLETED
                )
                if not done:
                    if grace_until is not None and time.monotonic() >= grace_until:
                        break
                    continue

                for task in done:
                    pending.pop(task, None)
                    if task.cancelled() or task.exception() is not None:
                        continue
                    attempt = task.result()
                    if not isinstance(attempt, _Attempt):
                        continue
                    if attempt.reason:
                        reasons.add(attempt.reason)
                    if attempt.proven_scheme:
                        schemes.add(attempt.proven_scheme)
                    if attempt.value is None:
                        continue

                    if prefer is None or prefer(attempt.value):
                        return _RaceOutcome(
                            value=attempt.value,
                            failure_reasons=frozenset(reasons),
                            proven_schemes=frozenset(schemes),
                        )

                    if fallback_value is None:
                        fallback_value = attempt.value
                        grace_until = time.monotonic() + prefer_grace_seconds

                if grace_until is not None and time.monotonic() >= grace_until:
                    break
        finally:
            await self._cancel_tasks(*pending)

        return _RaceOutcome(
            value=fallback_value,
            failure_reasons=frozenset(reasons),
            proven_schemes=frozenset(schemes),
        )

    @staticmethod
    async def _cancel_tasks(*tasks: Optional[asyncio.Task]) -> None:
        pending = [task for task in tasks if task is not None and not task.done()]
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    @staticmethod
    async def _settle(task: Optional[asyncio.Task]):
        if task is None:
            return None
        try:
            return await task
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.debug(f"探测任务异常: {exc}")
            return None

    def _identity_candidates(self) -> list[str]:
        identity = self._endpoints.ordered_by_latency(
            self._endpoints.identity_endpoints()
        )
        ip_echo = [
            url
            for url in self._endpoints.ordered_by_latency(self._ip_apis)
            if self._endpoints.is_reachable_directly(url) is not False
        ]
        return list(dict.fromkeys(identity + ip_echo))

    def _scheme_of(self, url: str) -> Optional[str]:
        scheme = urlparse(url).scheme.lower()
        return scheme if scheme in ("http", "https") else None

    @staticmethod
    def _mark_capability(capabilities: dict, url: str) -> None:
        scheme = urlparse(url).scheme.lower()
        if scheme in capabilities:
            capabilities[scheme] = True

    def _build_result(
        self,
        proxy_url: str,
        outcome: ValidationOutcome,
        delay_ms: Optional[float] = None,
        error_message: Optional[str] = None,
        error_reason: Optional[str] = None,
        real_ip: Optional[str] = None,
        anonymity_level: Optional[str] = None,
        anonymity_fallback: bool = False,
        supports_http: Optional[bool] = None,
        supports_https: Optional[bool] = None,
        probes: Sequence[ProbeOutcome] = (),
    ) -> ProxyValidationResult:
        return ProxyValidationResult(
            proxy_url=proxy_url,
            outcome=outcome,
            delay_ms=delay_ms if outcome is ValidationOutcome.OK else None,
            error_message=error_message,
            error_reason=error_reason,
            real_ip=real_ip,
            validated_at=datetime.now(),
            anonymity_level=anonymity_level,
            anonymity_fallback=anonymity_fallback,
            supports_http=supports_http,
            supports_https=supports_https,
            probes=tuple(probes),
        )

    @staticmethod
    def _judge_anonymity(
        echo: IdentityEcho,
        baseline,
        host_public_ips: Sequence[str],
    ) -> Optional[str]:
        if not echo.header_names:
            return None

        if any(ip in echo.chain for ip in host_public_ips):
            return "transparent"

        leaked, proxy_signal = _scan_header_ips(echo, baseline, host_public_ips)
        if leaked:
            return "transparent"

        if proxy_signal:
            return "anonymous"

        direct_chain_length = baseline.direct_chain_length if baseline else 1
        if len(echo.chain) > direct_chain_length:
            return "anonymous"

        return "elite"


