"""
模块名称：modules.config_validation
功能描述：[Server] 段配置项的校验与归一化：键名白名单、类型转换、取值范围校验、布尔与枚举取值归一，并渲染面板可直接使用的展示值，供保存流程在写盘前拒绝非法输入。
职责边界：负责：[Server] 段配置项的逐键校验、归一化与展示值渲染；不负责：配置落盘与热重载、[Pool] 段校验（由 modules.pool_config_ini 负责）。
关键依赖：modules.modules 的 DEFAULT_CONFIG（白名单）、TRUE_WORDS / FALSE_WORDS（布尔词表）、
          render_config_error（错误文案）；标准库 functools、typing、logging（仅用于创建模块级 logger）。
已知限制：
  1. 白名单即 DEFAULT_CONFIG 的键集合：新增 [Server] 键若未进入 DEFAULT_CONFIG，保存时会按未知键拒绝。
  2. 未在 _SERVER_RULES 登记的键按纯文本处理，只截断首尾空白，不做类型与范围检查。
  3. 布尔词表直接引用 modules.modules 的 TRUE_WORDS / FALSE_WORDS，与运行期宽松解析共用同一份，改词表会同时改变两处判定。
  4. display_level 接受 0 / 1 / 2；字面量 3 归一为 2；其余非整数或越界值报错。
  5. mode 的合法值按来源分两组：本地来源 cycle / loadbalance，API 与维护池 continuous / request，本模块两组都放行。
  6. ConfigValidationError 默认文案固定为中文；其他界面语言须由调用方调 localized(language) 取得。
  7. 布尔项展示值须归一为 'true' / 'false'：面板按小写后等于 'true' 判定勾选，原样返回 yes / on / 1 会显示为未勾选。
"""

import logging
from functools import partial
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from modules.modules import (
    DEFAULT_CONFIG, FALSE_WORDS, TRUE_WORDS, render_config_error,
)

logger = logging.getLogger(__name__)

_TRUE_VALUES = TRUE_WORDS
_FALSE_VALUES = FALSE_WORDS

_VALID_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


class ConfigValidationError(ValueError):

    def __init__(self, key: str, value: Any, reason_key: str, *reason_args: Any):
        self.key = key
        self.value = value
        self.reason_key = reason_key
        self.reason_args = reason_args
        super().__init__(self.localized('cn'))

    def localized(self, language: str) -> str:
        return render_config_error(
            self.key, self.value, self.reason_key, self.reason_args, language
        )


def _as_int(value: Any, key: str, *, low: int | None = None,
            high: int | None = None) -> str:
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        raise ConfigValidationError(key, value, "config_reason_expected_int") from None

    if low is not None and number < low:
        raise ConfigValidationError(key, value, "config_reason_min", low)
    if high is not None and number > high:
        raise ConfigValidationError(key, value, "config_reason_max", high)
    return str(number)


def _as_bool(value: Any, key: str) -> str:
    text = str(value).strip().lower()
    if text in _TRUE_VALUES:
        return "true"
    if text in _FALSE_VALUES:
        return "false"
    raise ConfigValidationError(key, value, "config_reason_expected_bool")


def _as_display_level(value: Any, key: str) -> str:
    if str(value).strip() == '3':
        return '2'
    return _as_int(value, key, low=0, high=2)


def _as_choice(value: Any, key: str, allowed: tuple[str, ...], *, lower: bool = True) -> str:
    text = str(value).strip()
    normalized = text.lower() if lower else text.upper()
    if normalized not in allowed:
        raise ConfigValidationError(key, value, "config_reason_expected_choice",
                                    '、'.join(allowed))
    return normalized


def _as_text(value: Any, key: str) -> str:
    return str(value).strip()


def _as_url(value: Any, key: str) -> str:
    text = str(value).strip()
    if not text:
        return ''
    parts = urlsplit(text)
    if parts.scheme not in ('http', 'https') or not parts.netloc:
        raise ConfigValidationError(key, value, "config_reason_expected_url")
    return text


def _as_upper_choice(value: Any, key: str, allowed: tuple[str, ...]) -> str:
    return _as_choice(value, key, allowed, lower=False)


_SERVER_RULES: dict[str, Callable[[Any, str], str]] = {
    'port':                     partial(_as_int, low=1, high=65535),
    'web_port':                 partial(_as_int, low=1, high=65535),
    'interval':                 partial(_as_int, low=0),
    'request_interval':         partial(_as_int, low=0),
    'display_level':            _as_display_level,
    'switch_cooldown':          partial(_as_int, low=0),
    'proxy_check_ttl':          partial(_as_int, low=0),
    'check_cooldown':           partial(_as_int, low=0),
    'proxy_failure_cooldown':   partial(_as_int, low=0),
    'tunnel_idle_timeout':      partial(_as_int, low=0),
    'buffer_size':              partial(_as_int, low=1024),
    'max_concurrent_requests':  partial(_as_int, low=1),
    'max_pool_size':            partial(_as_int, low=1),
    'check_concurrency':        partial(_as_int, low=1, high=1000),
    'max_concurrent_per_proxy': partial(_as_int, low=0, high=10000),
    'exit_count':               partial(_as_int, low=1, high=1000),
    'exit_wait_timeout':        partial(_as_int, low=0, high=600),
    'client_max_connections':   partial(_as_int, low=1),
    'client_max_keepalive':     partial(_as_int, low=0, high=64),
    'client_keepalive_expiry':  partial(_as_int, low=0),
    'client_idle_timeout':      partial(_as_int, low=1),

    'check_proxies_on_startup': _as_bool,
    'check_proxies_on_use':     _as_bool,
    'auto_expand_enabled':      _as_bool,

    'version_check_url':        _as_url,

    'mode':                     partial(_as_choice, allowed=(
        'cycle', 'loadbalance', 'continuous', 'request')),
    'proxy_source_mode':        partial(_as_choice, allowed=('local', 'api', 'pool')),
    'ip_auth_priority':         partial(_as_choice, allowed=('whitelist', 'blacklist')),
    'language':                 partial(_as_choice, allowed=('cn', 'en')),
    'log_level':                partial(_as_upper_choice, allowed=_VALID_LOG_LEVELS),
    'log_max_bytes':            partial(_as_int, low=1024),
    'log_backup_count':         partial(_as_int, low=1),
    'log_access_enabled':       _as_bool,

    'domain_stats_enabled':     _as_bool,
    'domain_stats_flush_interval': partial(_as_int, low=1),
    'domain_stats_retention_days': partial(_as_int, low=0),

    'access_records_enabled':        _as_bool,
    'access_records_flush_interval': partial(_as_int, low=1),
    'access_records_retention_days': partial(_as_int, low=0),
    'access_records_max_rows':       partial(_as_int, low=0),
    'access_records_buffer_size':    partial(_as_int, low=100),
    'access_records_real_ip_probe':  _as_bool,
}

_ALLOWED_SERVER_KEYS = frozenset(DEFAULT_CONFIG)

_REJECTED_SERVER_KEYS = frozenset({'users', 'Users'})


def validate_server_updates(updates: Mapping[str, Any]) -> dict[str, str]:
    normalized: dict[str, str] = {}

    for key, value in updates.items():
        if key in _REJECTED_SERVER_KEYS:
            raise ConfigValidationError(key, value, "config_reason_users_via_api")

        if key not in _ALLOWED_SERVER_KEYS:
            raise ConfigValidationError(key, value, "config_reason_unknown_key")

        rule = _SERVER_RULES.get(key, _as_text)
        normalized[key] = rule(value, key)

    return normalized


def display_server_values(section: Mapping[str, Any]) -> dict[str, str]:
    displayed: dict[str, str] = {}
    for key, value in section.items():
        if _SERVER_RULES.get(key) is _as_bool:
            try:
                displayed[key] = _as_bool(value, key)
            except ConfigValidationError:
                displayed[key] = str(value)
        else:
            displayed[key] = str(value)
    return displayed


__all__ = [
    "ConfigValidationError",
    "display_server_values",
    "validate_server_updates",
]
