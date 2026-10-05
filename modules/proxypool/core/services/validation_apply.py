"""
模块名称：modules.proxypool.core.services.validation_apply
功能描述：把一次代理验证的结论翻译成代理记录的字段更新，并编排写库、删除与归属地入队的动作分发。
          批量验证任务与自动重验证循环共用这里的判定口径，避免各处对失败认定、旧值保留与健康分的理解不一致。
职责边界：负责：结论性判定、字段更新组装（计数器、延迟统计、方案能力、健康分）、身份类字段的测到才写策略，以及
          动作分发编排（写库、删除、归属地通道由调用方以回调注入）与更新、删除操作的描述值。
          不负责：数据库读写（由调用方经仓储或写队列完成）、验证流程本身（见 ProxyValidator）与归属地查询（由调用方补充）。
关键依赖：core.domain.models、core.services.health_scorer。
已知限制：
  1. result.is_conclusive 为假时返回 None，调用方必须一个字段都不写；误写 validated_at 会让该代理在自动重验证中跳过整个周期。
  2. 身份类字段测到才写：real_ip、anonymity_level/anonymity_fallback、supports_https/http 无结论时留旧值，等级与兜底须成对写入。
     归属地入队须用 effective_real_ip（本轮未测到出口 IP 时回退库里的旧值），改用 result.real_ip 会让只缺地区的代理永远补不上。
  3. 请求级样本按（成功数、样本数）累加；本轮无可计样本时返回 None，调用方不得把这两列写 0，否则会清零已攒样本。
  4. quality_assessed_at 只在 mode 为 FULL 且 result.fully_assessed 为真时推进，它是下一轮判断要不要补测的依据。
  5. 延迟与方差测到才写，方差须用更新前的均值计算（先算方差再更新均值）；failure_count 成功清零、失败加一。
  6. health_score 用更新后的有效值（fields 优先于 proxy 旧值）计算；调用方要补的字段（如归属地）在返回的 fields 外自行追加。
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from core.domain.models import (
    DBOperation,
    Proxy,
    ProxyValidationResult,
    ValidationMode,
)
from core.services.health_scorer import HealthScorer

logger = logging.getLogger(__name__)


@dataclass
class ValidationUpdate:

    fields: dict = field(default_factory=dict)
    new_total_checks: int = 0
    new_success_count: int = 0
    effective_real_ip: Optional[str] = None
    effective_anonymity: str = "unverified"


APPLY_INCONCLUSIVE = "inconclusive"
APPLY_SKIPPED = "skipped"
APPLY_CLEANUP = "cleanup"
APPLY_APPLIED = "applied"


def decide_validation_action(
    result: ProxyValidationResult,
    *,
    mode: ValidationMode = ValidationMode.FULL,
    proxy: Optional[Proxy] = None,
    scorer: Optional[HealthScorer] = None,
    skip=None,
    cleanup=None,
) -> tuple:
    applied = build_validation_update(result, proxy, mode=mode, scorer=scorer)
    if applied is None:
        return APPLY_INCONCLUSIVE, None

    if skip is not None:
        reason = skip(result)
        if reason:
            return reason, applied

    if cleanup is not None:
        reason = cleanup(result, dict(applied.fields))
        if reason:
            return reason, applied

    return APPLY_APPLIED, applied


async def dispatch_validation_action(
    result: ProxyValidationResult,
    *,
    mode: ValidationMode = ValidationMode.FULL,
    proxy: Optional[Proxy] = None,
    scorer: Optional[HealthScorer] = None,
    skip=None,
    cleanup=None,
    sink,
    cleanup_sink=None,
    geo_predicate=None,
    geo_sink=None,
) -> tuple:
    action, applied = decide_validation_action(
        result, mode=mode, proxy=proxy, scorer=scorer, skip=skip, cleanup=cleanup,
    )

    if action == APPLY_APPLIED:
        ip_for_geo = applied.effective_real_ip
        if ip_for_geo and geo_sink is not None:
            if geo_predicate is None or geo_predicate(proxy, applied.fields):
                geo_sink(ip_for_geo)
        await sink(applied)
    elif action != APPLY_INCONCLUSIVE and cleanup_sink is not None:
        await cleanup_sink(applied)

    return action, applied


def build_update_operation(proxy: Proxy, applied: "ValidationUpdate") -> DBOperation:
    return DBOperation(
        operation_type="update",
        table="proxies",
        data=dict(applied.fields),
        where={"id": proxy.id},
    )


def build_delete_operation(proxy: Proxy) -> DBOperation:
    return DBOperation(
        operation_type="delete",
        table="proxies",
        data={},
        where={"id": proxy.id, "ip": proxy.ip, "port": proxy.port},
    )


def build_validation_update(
    result: ProxyValidationResult,
    proxy: Optional[Proxy] = None,
    *,
    mode: ValidationMode = ValidationMode.FULL,
    now: Optional[datetime] = None,
    scorer: Optional[HealthScorer] = None,
) -> Optional[ValidationUpdate]:
    if not result.is_conclusive:
        return None

    now = now or datetime.now()
    scorer = scorer or HealthScorer()

    total_checks = ((proxy.total_checks or 0) if proxy else 0) + 1
    success_count = ((proxy.success_count or 0) if proxy else 0) + (1 if result.is_valid else 0)

    fields: dict = {
        "is_valid": int(result.is_valid),
        "validated_at": result.validated_at.isoformat(),
        "total_checks": total_checks,
        "success_count": success_count,
    }

    if result.delay_ms is not None:
        fields["delay_ms"] = result.delay_ms

    probe_samples = _accumulate_probe_samples(result, proxy)
    if probe_samples is not None:
        fields["probe_success_count"], fields["probe_total_count"] = probe_samples

    if mode is ValidationMode.FULL and result.fully_assessed:
        fields["quality_assessed_at"] = result.validated_at.isoformat()

    effective_real_ip = result.real_ip if result.real_ip is not None else (
        proxy.real_ip if proxy else None
    )
    effective_anonymity = result.anonymity_level if result.anonymity_level is not None else (
        (proxy.anonymity_level if proxy else None) or "unverified"
    )

    if result.real_ip is not None:
        fields["real_ip"] = result.real_ip
    if result.anonymity_level is not None:
        fields["anonymity_level"] = result.anonymity_level
        fields["anonymity_fallback"] = int(result.anonymity_fallback)
    if result.supports_https is not None:
        fields["supports_https"] = int(result.supports_https)
    if result.supports_http is not None:
        fields["supports_http"] = int(result.supports_http)

    if result.is_valid:
        fields["failure_count"] = 0
        fields.update(_build_quality_fields(result, proxy, total_checks, now))
    else:
        previous_failures = (proxy.failure_count or 0) if proxy else 0
        fields["failure_count"] = previous_failures + 1

    fields["health_score"] = _score(
        scorer, proxy, fields, total_checks, success_count,
        effective_anonymity,
    )

    return ValidationUpdate(
        fields=fields,
        new_total_checks=total_checks,
        new_success_count=success_count,
        effective_real_ip=effective_real_ip,
        effective_anonymity=effective_anonymity,
    )


def _accumulate_probe_samples(
    result: ProxyValidationResult, proxy: Optional[Proxy]
) -> Optional[tuple[int, int]]:
    probe_success, probe_total = result.probe_samples
    if probe_total <= 0:
        return None

    previous_success = (proxy.probe_success_count or 0) if proxy else 0
    previous_total = (proxy.probe_total_count or 0) if proxy else 0
    return previous_success + probe_success, previous_total + probe_total


def _build_quality_fields(
    result: ProxyValidationResult,
    proxy: Optional[Proxy],
    total_checks: int,
    now: datetime,
) -> dict:
    fields: dict = {}

    previous_avg = proxy.avg_delay_ms if proxy else None

    if result.delay_ms is not None:
        if proxy is not None:
            variance = HealthScorer.calculate_delay_variance(
                proxy.delay_variance, previous_avg, result.delay_ms, total_checks
            )
            fields["delay_variance"] = variance
        fields["avg_delay_ms"] = HealthScorer.calculate_avg_delay(
            previous_avg, result.delay_ms, total_checks
        )

    if proxy is not None:
        fields["total_valid_seconds"] = HealthScorer.calculate_total_valid_seconds(
            proxy.total_valid_seconds or 0.0, proxy.last_valid_at, True, now
        )
    else:
        fields["total_valid_seconds"] = 0.0
    fields["last_valid_at"] = now.isoformat()

    return fields


def _score(
    scorer: HealthScorer,
    proxy: Optional[Proxy],
    fields: dict,
    total_checks: int,
    success_count: int,
    effective_anonymity: str,
) -> float:
    effective_avg_delay = fields.get(
        "avg_delay_ms", proxy.avg_delay_ms if proxy else None
    )
    effective_variance = fields.get(
        "delay_variance", proxy.delay_variance if proxy else None
    )
    effective_valid_seconds = fields.get(
        "total_valid_seconds", (proxy.total_valid_seconds or 0.0) if proxy else 0.0
    )

    temp = Proxy(
        delay_ms=fields.get("delay_ms", proxy.delay_ms if proxy else None),
        success_count=success_count,
        total_checks=total_checks,
        probe_success_count=fields.get(
            "probe_success_count", (proxy.probe_success_count or 0) if proxy else 0
        ),
        probe_total_count=fields.get(
            "probe_total_count", (proxy.probe_total_count or 0) if proxy else 0
        ),
        created_at=proxy.created_at if proxy else None,
        anonymity_level=effective_anonymity,
        avg_delay_ms=effective_avg_delay,
        delay_variance=effective_variance,
        last_valid_at=proxy.last_valid_at if proxy else None,
        total_valid_seconds=effective_valid_seconds,
    )
    return scorer.calculate(temp)


__all__ = [
    "ValidationUpdate",
    "build_delete_operation",
    "build_update_operation",
    "build_validation_update",
    "decide_validation_action",
    "dispatch_validation_action",
]
