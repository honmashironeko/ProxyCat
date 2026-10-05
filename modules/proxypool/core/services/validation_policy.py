"""
模块名称：modules.proxypool.core.services.validation_policy
功能描述：验证强度策略：按代理上次完整评估时间、配置间隔与已有身份数据，在完整、身份补测、轻量存活三档里选一档。
          身份量几乎不随时间变化、不必每轮重测；自动重验证循环与批量任务共用本判断以保证强度一致。
职责边界：负责：选出本轮验证强度、解析测试地址；不负责：验证本身（ProxyValidator）与结论落地（validation_apply）。
关键依赖：标准库 datetime；core.domain.models。
已知限制：
1. 三档优先级 FULL > IDENTITY > LIVENESS；full_recheck_interval_minutes 缺失、非法或 ≤ 0 时按 0 处理，语义为每轮都做完整评估。
2. 判据只看 quality_assessed_at、real_ip 与 anonymity_level；始终测不到出口 IP 的代理在完整重测周期前为 IDENTITY，到周期为 FULL。
3. anonymity_level 缺失、为空或等于 unverified 时触发匿名度补测，返回 IDENTITY；其余取值不触发。
4. config.validator.check_anonymity 为 False 时匿名度缺口不补测，IDENTITY 仅由缺失 real_ip 触发。
5. proxy 为 None（尚无记录的新代理）按 FULL 处理。
6. resolve_test_url 在插件未配置或 test_url 为空串时回退全局 [Server] test_url，各调用方必须认同同一地址。
"""

import logging
from datetime import datetime
from typing import Optional

from core.domain.models import Proxy, ValidationMode

logger = logging.getLogger(__name__)

_INTERVAL_ALWAYS_FULL = 0


def full_recheck_interval_minutes(config) -> int:
    section = getattr(config, "auto_revalidation", None)
    value = getattr(section, "full_recheck_interval_minutes", 0) or 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def pick_validation_mode(
    proxy: Optional[Proxy],
    config,
    *,
    now: Optional[datetime] = None,
) -> ValidationMode:
    interval_minutes = full_recheck_interval_minutes(config)
    if interval_minutes <= _INTERVAL_ALWAYS_FULL:
        return ValidationMode.FULL

    assessed_at = getattr(proxy, "quality_assessed_at", None) if proxy else None
    if assessed_at is None:
        return ValidationMode.FULL

    elapsed_minutes = ((now or datetime.now()) - assessed_at).total_seconds() / 60.0
    if elapsed_minutes >= interval_minutes:
        return ValidationMode.FULL

    if not getattr(proxy, "real_ip", None):
        return ValidationMode.IDENTITY
    if getattr(config.validator, "check_anonymity", True) and (
            (getattr(proxy, "anonymity_level", "unverified") or "unverified") == "unverified"):
        return ValidationMode.IDENTITY

    return ValidationMode.LIVENESS


def resolve_test_url(plugin_config, global_target_url: str) -> str:
    configured = getattr(plugin_config, "test_url", "") or ""
    return configured.strip() or global_target_url


__all__ = [
    "pick_validation_mode",
    "full_recheck_interval_minutes",
    "resolve_test_url",
]
