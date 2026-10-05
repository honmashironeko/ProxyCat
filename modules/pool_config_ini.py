"""
模块名称：modules.pool_config_ini
功能描述：把 config/config.ini 的 [Pool] 段与代理池 Config 对象树互转：反射数据模型得到键名与类型、强制取值、校验数值区间与
          格式、渲染该段文本，并负责该段的引导式创建与旧 config.yaml 迁移；界面呈现与取值规则需随新增字段手工补。
职责边界：负责：键名映射、类型强制、取值校验、共享项派生、[Pool] 段渲染与落盘重写、引导式创建与存量迁移、启动与热重载两条读取路径、
          界面提交规范化、表单描述与进程内池启动判断；不负责：配置保存接口的流程编排（POST /api/config）、热重载与变更通知
          （core.infrastructure.config_manager）、区间与格式之外的运行期校验（由各使用方校验）。
关键依赖：core.config（配置数据模型）、core.domain.models（canonical_ip）、modules.modules（原子写、真值字面量）、PyYAML（仅迁移路径）。
已知限制：
  1. 导入本模块会经 modules.proxypool 把池子项目目录注入 sys.path，其后的 core.* 才能导入；该导入勿删、勿后置。
  2. 布尔值只认 TRUE_WORDS 与 FALSE_WORDS，其余字面量一律抛 PoolConfigError：strict=True 直接抛出，strict=False 丢该项回默认值。
  3. 数值区间查 _POOL_RANGE_RULES（含上界），格式查 _POOL_VALUE_RULES（host_public_ip 走 IP 文本校验）；未列入的键只做类型强制。
  4. 列表类配置在 ini 里用英文逗号分隔；读取时关闭插值，[Users] 段的键名大小写敏感，其余段的键名折回小写。
  5. 引导式创建与排版同步会重写 [Pool] 段全部内容，该段原有注释不保留；其余段内容不动，行尾统一为平台换行符。
  6. 按插件的重验证开关与周期存放在数据库而非本段；DEPRECATED_KEYS 解析时跳过、渲染时清除、界面不展示。
  7. describe_pool_schema 的 unit 不走 _text：空译文回落到中文会把 en 的计次单位显示成「个」。
"""

import dataclasses
import logging
import re
import shutil
import typing
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

import yaml

from modules.modules import FALSE_WORDS, TRUE_WORDS, ini_parser, render_config_error

from modules.proxypool import POOL_DIR  # noqa: F401
from core.config import Config
from core.domain.models import canonical_ip

logger = logging.getLogger(__name__)

POOL_SECTION = "Pool"

USERS_SECTION = "Users"

_TRUE_VALUES = TRUE_WORDS
_FALSE_VALUES = FALSE_WORDS

LocalizedText = Mapping[str, str]

_LANGUAGE_CN = "cn"


def _text(spec: LocalizedText, language: str = _LANGUAGE_CN) -> str:
    return spec.get(language) or spec.get(_LANGUAGE_CN, "")


DERIVED_KEYS = frozenset({
    "validator.target_url",
})

DEPRECATED_KEYS = frozenset({
    "enabled",
    "auto_cleanup.interval_minutes",
    "performance.auto_adjust_concurrency",
    "performance.cpu_threshold_percent",
    "performance.memory_threshold_percent",
    "validator.max_ip_retries",
    "validator.deadline_seconds",
    "validator.adaptive_timeout_enabled",
    "validator.min_timeout_seconds",
    "plugins.auto_validate_on_fetch",
    "plugins.auto_geoip_on_fetch",
    "performance.invalid_proxy_retention_days",
    "performance.cleanup_interval_hours",
    "geoip.api_url",
    "geoip.use_proxy",
    "geoip.timeout_seconds",
    "geoip.max_retries",
    "logging.format",
    "logging.level",
})


class PoolConfigError(ValueError):
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


def _iter_leaf_fields() -> typing.Iterator[tuple[str, type, Any]]:
    default_config = Config()
    for section_field in dataclasses.fields(Config):
        section_cls = section_field.type
        if isinstance(section_cls, str):
            section_cls = type(getattr(default_config, section_field.name))
        if not dataclasses.is_dataclass(section_cls):
            continue

        default_section = getattr(default_config, section_field.name)
        for leaf in dataclasses.fields(section_cls):
            yield (
                f"{section_field.name}.{leaf.name}",
                leaf.type,
                getattr(default_section, leaf.name),
            )


def _coerce(key: str, raw: str, target_type: type) -> Any:
    text = raw.strip()

    if target_type is bool:
        lowered = text.lower()
        if lowered in _TRUE_VALUES:
            return True
        if lowered in _FALSE_VALUES:
            return False
        raise PoolConfigError(key, raw, "config_reason_expected_bool")

    if target_type is int:
        try:
            return int(text)
        except ValueError:
            raise PoolConfigError(key, raw, "config_reason_expected_int") from None

    if target_type is float:
        try:
            return float(text)
        except ValueError:
            raise PoolConfigError(key, raw, "config_reason_expected_float") from None

    if typing.get_origin(target_type) is list:
        items = [item.strip() for item in text.split(",") if item.strip()]
        if not items:
            raise PoolConfigError(key, raw, "config_reason_expected_comma_list")
        return items

    return raw


_POOL_RANGE_RULES: dict[str, tuple[float | None, float | None]] = {
    "database.backup_interval_hours": (1, None),
    "database.backup_retention_days": (1, None),
    "database.pool_max_readers": (1, 64),
    "validator.timeout_seconds": (1, None),
    "validator.connect_timeout_seconds": (0, None),
    "validator.max_concurrent": (1, 10000),
    "plugins.scan_interval_seconds": (1, None),
    "plugins.default_interval_minutes": (1, None),
    "plugins.execution_timeout_seconds": (1, None),
    "plugins.request_timeout_seconds": (1, None),
    "plugins.max_parallel_plugins": (1, None),
    "plugins.max_retries_on_failure": (0, None),
    "plugins.retry_base_delay_seconds": (0, 3600),
    "auto_revalidation.interval_minutes": (1, None),
    "auto_revalidation.full_recheck_interval_minutes": (0, None),
    "auto_cleanup.max_failures": (1, None),
    "auto_cleanup.min_health_score": (0, None),
    "auto_cleanup.min_checks_before_cleanup": (1, None),
    "auto_cleanup.max_age_days_if_invalid": (1, None),
    "use_feedback.invalid_threshold": (1, None),
    "write_queue.batch_size": (1, None),
    "write_queue.max_retries": (0, None),
    "write_queue.max_queue_size": (1, None),
    "logging.max_bytes": (1024, None),
    "logging.backup_count": (1, None),
}


def _check_range(key: str, value: Any, raw: Any) -> None:
    bounds = _POOL_RANGE_RULES.get(key)
    if bounds is None:
        return

    low, high = bounds
    if low is not None and value < low:
        raise PoolConfigError(key, raw, "config_reason_min", low)
    if high is not None and value > high:
        raise PoolConfigError(key, raw, "config_reason_max", high)


def _check_ip_text(key: str, value: Any, raw: Any) -> None:
    text = str(value).strip()
    if not text:
        return

    seen: set[int] = set()
    for part in text.replace("，", ",").split(","):
        canonical = canonical_ip(part.strip())
        if canonical is None:
            raise PoolConfigError(key, raw, "config_reason_expected_ip")
        version = 6 if ":" in canonical else 4
        if version in seen:
            raise PoolConfigError(key, raw, "config_reason_expected_ip")
        seen.add(version)


_POOL_VALUE_RULES: dict[str, typing.Callable[[str, Any, Any], None]] = {
    "validator.host_public_ip": _check_ip_text,
}


def _check_value(key: str, value: Any, raw: Any) -> None:
    rule = _POOL_VALUE_RULES.get(key)
    if rule is not None:
        rule(key, value, raw)



from modules.modules import read_config_text as _read_config_text
from modules.modules import write_text_atomic as _atomic_write_text



def parse_pool_section(pool_section: Mapping[str, str], strict: bool = True) -> Config:
    from core.config import build_config

    nested: dict[str, dict[str, Any]] = {}
    field_types = {key: target for key, target, _ in _iter_leaf_fields()}

    for key, raw in pool_section.items():
        if key in DERIVED_KEYS:
            logger.debug("池配置项 %s 由 [Server] 派生，忽略 [Pool] 段中的取值", key)
            continue
        if key in DEPRECATED_KEYS:
            logger.debug("池配置项 %s 已废弃，忽略", key)
            continue
        if key not in field_types:
            logger.warning("忽略无法识别的池配置项: %s", key)
            continue

        try:
            value = _coerce(key, raw, field_types[key])
            _check_range(key, value, raw)
            _check_value(key, value, raw)
        except PoolConfigError:
            if strict:
                raise
            logger.warning("池配置项 %s 的值非法（%r），该项使用默认值", key, raw)
            continue

        section_name, leaf_name = key.split(".", 1)
        nested.setdefault(section_name, {})[leaf_name] = value

    return build_config(nested)


def build_pool_config(
    server_section: Mapping[str, str],
    pool_section: Mapping[str, str],
    strict: bool = True,
) -> Config:
    config = parse_pool_section(pool_section, strict=strict)

    test_url = (server_section.get("test_url") or "").strip()
    if test_url:
        config.validator.target_url = test_url

    return config


def _to_ini_text(value: Any, target_type: type) -> str:
    if target_type is bool:
        return "true" if value else "false"
    if typing.get_origin(target_type) is list:
        return ", ".join(str(item) for item in value)
    return str(value)


def dump_pool_config(config: Config) -> dict[str, str]:
    dumped: dict[str, str] = {}
    for key, target_type, _ in _iter_leaf_fields():
        if key in DERIVED_KEYS:
            continue
        section_name, leaf_name = key.split(".", 1)
        value = getattr(getattr(config, section_name), leaf_name)
        dumped[key] = _to_ini_text(value, target_type)

    return dumped


def _field_type_name(target_type: Any) -> str:
    if target_type is bool:
        return "bool"
    if target_type is int:
        return "int"
    if target_type is float:
        return "float"
    if typing.get_origin(target_type) is list:
        return "list"
    return "text"

POOL_FIELD_LABELS = {
    'database.path': {
        'title': {'cn': '数据库文件路径', 'en': 'Database file path'},
        'hint': {'cn': '改动需重启池服务；相对路径从 proxypool 目录起算', 'en': 'Relative paths start from the proxypool directory; changes need a pool restart'},
    },
    'database.pool_max_readers': {
        'title': {'cn': '读连接数上限', 'en': 'Max read connections'},
        'hint': {'cn': '调大要多占文件句柄；改动需重启池服务', 'en': 'Raising it costs more file handles; needs a pool restart'},
        'unit': {'cn': '个', 'en': ''},
    },
    'database.backup_enabled': {
        'title': {'cn': '自动备份', 'en': 'Automatic backup'},
        'hint': {'cn': '保存即生效；关掉后不再生成新备份', 'en': 'Applies immediately; turning it off stops new backups'},
    },
    'database.backup_interval_hours': {
        'title': {'cn': '备份间隔', 'en': 'Backup interval'},
        'hint': {'cn': '自动备份关闭时不生效；调小会增加磁盘占用', 'en': 'No effect while automatic backup is off; a shorter interval uses more disk'},
        'unit': {'cn': '小时', 'en': 'h'},
    },
    'database.backup_retention_days': {
        'title': {'cn': '备份保留', 'en': 'Backup retention'},
        'hint': {'cn': '决定能恢复到多久以前', 'en': 'Determines how far back you can restore from'},
        'unit': {'cn': '天', 'en': 'd'},
    },

    'validator.check_anonymity': {
        'title': {'cn': '检查匿名度', 'en': 'Check anonymity'},
        'hint': {'cn': '开启后每个代理会多一次明文探测请求', 'en': 'Costs one extra plaintext probe request per proxy'},
    },
    'validator.host_public_ip': {
        'title': {'cn': '本机公网 IP', 'en': 'Host public IP'},
        'hint': {'cn': '双栈主机两族各填一个、逗号隔开；留空则无法判定匿名度', 'en': 'Dual-stack: one address per family, comma-separated; empty disables anonymity judging'},
    },
    'validator.timeout_seconds': {
        'title': {'cn': '验证总超时', 'en': 'Overall timeout'},
        'hint': {'cn': '一次验证的总上限；调小会误杀偏慢的可用代理', 'en': 'The cap for a full validation; too low kills slow but usable proxies'},
        'unit': {'cn': '秒', 'en': 's'},
    },
    'validator.connect_timeout_seconds': {
        'title': {'cn': '连接超时', 'en': 'Connect timeout'},
        'hint': {'cn': '0 表示不单独限制，只受总超时约束；调小可加快整批验证', 'en': '0 = no separate limit (overall timeout still applies); lowering it speeds up batches'},
        'unit': {'cn': '秒', 'en': 's'},
    },
    'validator.max_concurrent': {
        'title': {'cn': '同时验证数', 'en': 'Concurrent validations'},
        'hint': {'cn': '调高会多占本机连接与 socket；站点限流时调低', 'en': 'Higher values use more local sockets; lower it if the test site rate-limits'},
        'unit': {'cn': '个', 'en': ''},
    },
    'validator.identity_echo_apis': {
        'title': {'cn': '身份回显接口', 'en': 'Identity echo endpoints'},
        'hint': {'cn': '必须是 https，逗号分隔；连不上的自动跳过', 'en': 'https only, comma-separated; unreachable ones are skipped'},
    },
    'validator.plain_identity_echo_apis': {
        'title': {'cn': '明文回显接口', 'en': 'Plaintext echo endpoints'},
        'hint': {'cn': '必须是 http，逗号分隔；代理够不到默认站点时补', 'en': 'http only, comma-separated; fill in sites your proxies can reach'},
    },
    'validator.ip_check_apis': {
        'title': {'cn': 'IP 回显接口', 'en': 'IP-only echo endpoints'},
        'hint': {'cn': '必须是 https；上面的接口拿不到结果时兜底', 'en': 'https only; used when the endpoints above get nothing'},
    },

    'plugins.scan_interval_seconds': {
        'title': {'cn': '插件检查间隔', 'en': 'Plugin scan interval'},
        'hint': {'cn': '改了只会变检查快慢，各插件自己的抓取周期不动', 'en': 'Only how quickly due plugins are noticed; their own intervals are unchanged'},
        'unit': {'cn': '秒', 'en': 's'},
    },
    'plugins.default_interval_minutes': {
        'title': {'cn': '新插件周期', 'en': 'New plugin interval'},
        'hint': {'cn': '改动只影响之后新建的插件，已有插件保持各自的周期', 'en': 'Applies to newly added plugins only; existing ones keep their own intervals'},
        'unit': {'cn': '分钟', 'en': 'min'},
    },
    'plugins.execution_timeout_seconds': {
        'title': {'cn': '整轮抓取超时', 'en': 'Whole-run timeout'},
        'hint': {'cn': '给整轮抓取设的硬时限，调太小会打断耗时长的正常抓取', 'en': 'Caps a whole run; too low aborts slow fetches that would otherwise finish'},
        'unit': {'cn': '秒', 'en': 's'},
    },
    'plugins.request_timeout_seconds': {
        'title': {'cn': '单次请求超时', 'en': 'Request timeout'},
        'hint': {'cn': '按单个网页请求计算，每个请求都单独受它限制', 'en': 'Counted per web request, not per plugin run'},
        'unit': {'cn': '秒', 'en': 's'},
    },
    'plugins.max_parallel_plugins': {
        'title': {'cn': '插件并发上限', 'en': 'Max parallel plugins'},
        'hint': {'cn': '调高可缩短整批抓取时间，同时更占资源', 'en': 'Higher finishes batches sooner but uses more resources'},
        'unit': {'cn': '个', 'en': ''},
    },
    'plugins.max_retries_on_failure': {
        'title': {'cn': '失败重试次数', 'en': 'Retries on failure'},
        'hint': {'cn': '0 表示失败即放弃；它数的是额外次数，不是总次数', 'en': '0 = give up at once; counts extra attempts, not total tries'},
        'unit': {'cn': '次', 'en': ''},
    },
    'plugins.retry_base_delay_seconds': {
        'title': {'cn': '首次重试等待', 'en': 'First retry wait'},
        'hint': {'cn': '每次重试等待翻倍；0 表示不等待、立即重试', 'en': 'Wait doubles after each retry; 0 = retry immediately'},
        'unit': {'cn': '秒', 'en': 's'},
    },

    'auto_revalidation.enabled': {
        'title': {'cn': '定时重新验证', 'en': 'Periodic re-validation'},
        'hint': {'cn': '关掉后失效的代理不会自动被发现，状态保持原样', 'en': 'Off means a proxy that dies keeps its last recorded state'},
    },
    'auto_revalidation.interval_minutes': {
        'title': {'cn': '重验证周期', 'en': 'Re-check interval'},
        'hint': {'cn': '只作全局默认，单个插件的周期在插件管理里另设', 'en': "A default only; each plugin's own interval is set under Plugins"},
        'unit': {'cn': '分钟', 'en': 'min'},
    },
    'auto_revalidation.only_valid_proxies': {
        'title': {'cn': '只查可用代理', 'en': 'Valid proxies only'},
        'hint': {'cn': '失效的不会被自动翻回可用（须手动验证），换来每轮更快', 'en': 'Dead proxies will not come back automatically, only via manual runs; each round is faster'},
    },
    'auto_revalidation.run_on_start': {
        'title': {'cn': '启动时先查一遍', 'en': 'Check on startup'},
        'hint': {'cn': '关掉时首轮检查要排到一个周期之后', 'en': 'Off schedules the first round a full interval after startup'},
    },
    'auto_revalidation.full_recheck_interval_minutes': {
        'title': {'cn': '完整检测周期', 'en': 'Full recheck interval'},
        'hint': {'cn': '0 表示每轮都做完整检测（更慢）；平时只测存活', 'en': '0 = full assessment every round (slower); routine rounds stay liveness-only'},
        'unit': {'cn': '分钟', 'en': 'min'},
    },

    'auto_cleanup.enabled': {
        'title': {'cn': '自动清理', 'en': 'Auto cleanup'},
        'hint': {'cn': '关闭后不删任何代理；删除不可恢复', 'en': 'Nothing is deleted when off; deletions cannot be undone'},
    },
    'auto_cleanup.min_health_score': {
        'title': {'cn': '健康分下限', 'en': 'Minimum health score'},
        'hint': {'cn': '还要检查次数达标才淘汰；0 表示不按评分淘汰', 'en': 'Also requires the check-count minimum; 0 disables score-based cleanup'},
        'unit': {'cn': '分', 'en': 'pts'},
    },
    'auto_cleanup.min_checks_before_cleanup': {
        'title': {'cn': '最少检查次数', 'en': 'Minimum checks before cleanup'},
        'hint': {'cn': '检查次数未达标不按评分淘汰；调小易误删新代理', 'en': 'Score cleanup waits for this many checks; lowering it risks deleting fresh proxies'},
        'unit': {'cn': '次', 'en': ''},
    },
    'auto_cleanup.max_failures': {
        'title': {'cn': '连续验证失败', 'en': 'Consecutive check failures'},
        'hint': {'cn': '一次成功就把计数清零；调小会更快删除不可用代理', 'en': 'One success resets the count; lower it to delete unusable proxies sooner'},
        'unit': {'cn': '次', 'en': ''},
    },
    'auto_cleanup.max_age_days_if_invalid': {
        'title': {'cn': '失效代理保留', 'en': 'Invalid proxy retention'},
        'hint': {'cn': '从判定失效起算；调小会更快删除', 'en': 'The clock starts at invalidation; lower it to delete sooner'},
        'unit': {'cn': '天', 'en': 'd'},
    },

    'use_feedback.enabled': {
        'title': {'cn': '使用期反馈', 'en': 'Use-time feedback'},
        'hint': {'cn': '转发失败达阈值才判失效；关掉后只信验证结果', 'en': 'Forwarding failures count toward invalidation; off means only validation results decide'},
    },
    'use_feedback.invalid_threshold': {
        'title': {'cn': '转发失败阈值', 'en': 'Forwarding failure threshold'},
        'hint': {'cn': '成功一次即清零；调低会让更多代理被判失效', 'en': 'One success resets the streak; lowering it flags more proxies as invalid'},
        'unit': {'cn': '次', 'en': ''},
    },

    'write_queue.batch_size': {
        'title': {'cn': '每批写入条数', 'en': 'Records per write batch'},
        'hint': {'cn': '调大更省写入次数，但记录落库更晚', 'en': 'Bigger batches mean fewer writes but records reach the database later'},
        'unit': {'cn': '条', 'en': ''},
    },
    'write_queue.max_retries': {
        'title': {'cn': '写入尝试次数', 'en': 'Write attempts per batch'},
        'hint': {'cn': '0 或 1 都表示失败就放弃；调大可扛写库临时故障', 'en': '0 or 1 both mean give up on failure; raise it to ride out transient DB failures'},
        'unit': {'cn': '次', 'en': ''},
    },
    'write_queue.max_queue_size': {
        'title': {'cn': '待写队列上限', 'en': 'Pending write queue cap'},
        'hint': {'cn': '保存后要重启才生效；排满后新写入会被拒', 'en': 'Needs a restart to take effect; new writes are rejected once full'},
        'unit': {'cn': '条', 'en': ''},
    },

    'logging.file_path': {
        'title': {'cn': '日志文件路径', 'en': 'Log file path'},
        'hint': {'cn': '相对路径从 modules/proxypool/ 算起', 'en': 'Relative paths are resolved from modules/proxypool/'},
    },
    'logging.max_bytes': {
        'title': {'cn': '单文件上限', 'en': 'Max file size'},
        'hint': {'cn': '调小则轮转更频繁，磁盘占用 ≈ 单文件上限 × 保留份数', 'en': 'Lower it to rotate more often; disk use ≈ size × files kept'},
        'unit': {'cn': '字节', 'en': 'bytes'},
    },
    'logging.backup_count': {
        'title': {'cn': '历史文件保留', 'en': 'Rotated files to keep'},
        'hint': {'cn': '超出后自动删掉最旧的，磁盘占用不会无限增长', 'en': 'Oldest rotated files are deleted once the count is exceeded'},
        'unit': {'cn': '份', 'en': ''},
    },
}

POOL_GROUP_SUBTITLES = {
    'database': {'cn': '数据存在哪、怎么备份', 'en': 'Where data lives and how it is backed up'},
    'validator': {'cn': '什么样的代理算可用', 'en': 'What counts as a usable proxy'},
    'plugins': {'cn': '多久去各来源抓一次', 'en': 'How often each source is scraped'},
    'auto_revalidation': {'cn': '失效的代理怎么被发现', 'en': 'How dead proxies get noticed'},
    'auto_cleanup': {'cn': '什么样的代理会被删掉', 'en': 'Which proxies get deleted'},
    'use_feedback': {'cn': '转发失败算不算数', 'en': 'Whether forwarding failures count'},
    'write_queue': {'cn': '记录攒多少再落库', 'en': 'How records are batched into the database'},
    'logging': {'cn': '日志写多大、留几份', 'en': 'Log size and how many are kept'},
}

_POOL_VISIBLE_WHEN = {
    'database.backup_interval_hours': 'database.backup_enabled=true',
    'database.backup_retention_days': 'database.backup_enabled=true',
    'auto_revalidation.interval_minutes': 'auto_revalidation.enabled=true',
    'auto_revalidation.only_valid_proxies': 'auto_revalidation.enabled=true',
    'auto_revalidation.run_on_start': 'auto_revalidation.enabled=true',
    'auto_revalidation.full_recheck_interval_minutes': 'auto_revalidation.enabled=true',
    'auto_cleanup.min_health_score': 'auto_cleanup.enabled=true',
    'auto_cleanup.min_checks_before_cleanup': 'auto_cleanup.enabled=true',
    'auto_cleanup.max_failures': 'auto_cleanup.enabled=true',
    'auto_cleanup.max_age_days_if_invalid': 'auto_cleanup.enabled=true',
    'use_feedback.invalid_threshold': 'use_feedback.enabled=true',
}


def describe_pool_schema(language: str = _LANGUAGE_CN) -> list[dict[str, Any]]:
    field_types = {key: target for key, target, _ in _iter_leaf_fields()}

    groups = []
    for group_title, fields in POOL_SECTION_LAYOUT:
        known = []
        for key, doc in fields:
            if key not in field_types:
                continue
            descriptor: dict[str, Any] = {
                "key": key,
                "doc": _text(doc, language),
                "type": _field_type_name(field_types[key]),
            }
            label = POOL_FIELD_LABELS.get(key)
            if label:
                descriptor["title"] = _text(label["title"], language)
                descriptor["hint"] = _text(label["hint"], language)
                unit = (label.get("unit") or {}).get(language, "")
                if unit:
                    descriptor["unit"] = unit
            if key in _POOL_ADVANCED_KEYS:
                descriptor["tier"] = "advanced"
            visible_when = _POOL_VISIBLE_WHEN.get(key)
            if visible_when:
                descriptor["visible_when"] = visible_when
            bounds = _POOL_RANGE_RULES.get(key)
            if bounds is not None:
                low, high = bounds
                if low is not None:
                    descriptor["low"] = low
                if high is not None:
                    descriptor["high"] = high
            known.append(descriptor)
        if known:
            group_id = known[0]["key"].split(".", 1)[0]
            group = {
                "title": _text(group_title, language),
                "id": group_id,
                "fields": known,
            }
            subtitle = POOL_GROUP_SUBTITLES.get(group_id)
            if subtitle:
                group["sub"] = _text(subtitle, language)
            groups.append(group)
    return groups

_POOL_ADVANCED_KEYS = frozenset({
    "database.path", "database.pool_max_readers",
    "database.backup_interval_hours", "database.backup_retention_days",
    "validator.host_public_ip", "validator.timeout_seconds",
    "validator.connect_timeout_seconds", "validator.max_concurrent",
    "validator.identity_echo_apis", "validator.plain_identity_echo_apis",
    "validator.ip_check_apis",
    "plugins.execution_timeout_seconds", "plugins.request_timeout_seconds",
    "plugins.max_parallel_plugins", "plugins.max_retries_on_failure",
    "plugins.retry_base_delay_seconds",
    "auto_revalidation.full_recheck_interval_minutes",
    "auto_cleanup.min_health_score", "auto_cleanup.min_checks_before_cleanup",
    "auto_cleanup.max_failures", "auto_cleanup.max_age_days_if_invalid",
    "use_feedback.invalid_threshold",
    "write_queue.max_retries", "write_queue.max_queue_size",
    "logging.file_path",
})


def normalize_pool_updates(updates: Mapping[str, Any]) -> dict[str, str]:
    field_types = {key: target for key, target, _ in _iter_leaf_fields()}
    normalized: dict[str, str] = {}

    for key, value in updates.items():
        if key in DEPRECATED_KEYS:
            logger.debug("忽略已废弃的池配置项: %s", key)
            continue

        if key in DERIVED_KEYS:
            raise PoolConfigError(key, value, "config_reason_derived_key")

        if key not in field_types:
            raise PoolConfigError(key, value, "config_reason_unknown_key")

        target = field_types[key]
        if typing.get_origin(target) is list and isinstance(value, (list, tuple)):
            items = [str(item).strip() for item in value if str(item).strip()]
            if not items:
                raise PoolConfigError(key, value, "config_reason_expected_value")
            coerced = items
        else:
            coerced = _coerce(key, str(value), target)
            _check_range(key, coerced, value)
            _check_value(key, coerced, value)

        normalized[key] = _to_ini_text(coerced, target)

    return normalized


def should_autostart_pool(server_section: Mapping[str, str]) -> bool:
    source_mode = (server_section.get("proxy_source_mode") or "local").strip().lower()
    if source_mode != "pool":
        return False
    return not (server_section.get("pool_remote_url") or "").strip()


def migrate_from_yaml(yaml_path: str | Path) -> dict[str, str]:
    path = Path(yaml_path)
    if not path.is_file():
        logger.info("未找到旧的池配置文件 %s，跳过迁移", path)
        return {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError) as e:
        logger.error("读取旧池配置文件失败，将使用默认配置: %s", e)
        return {}

    if not isinstance(data, dict):
        logger.error("旧池配置文件的根节点不是映射，将使用默认配置")
        return {}

    known_keys = {key for key, _, _ in _iter_leaf_fields()}
    migrated: dict[str, str] = {}

    for section_name, section_data in data.items():
        if not isinstance(section_data, dict):
            continue
        for leaf_name, value in section_data.items():
            key = f"{section_name}.{leaf_name}"
            if key in DERIVED_KEYS or key not in known_keys:
                logger.info("迁移时跳过配置项: %s", key)
                continue
            target_type = next(t for k, t, _ in _iter_leaf_fields() if k == key)
            if target_type is bool:
                migrated[key] = "true" if value else "false"
            elif typing.get_origin(target_type) is list and isinstance(value, list):
                migrated[key] = ", ".join(str(item) for item in value)
            else:
                migrated[key] = str(value)

    logger.info("已从 %s 迁移 %d 个池配置项", path, len(migrated))
    return migrated


def default_pool_section() -> dict[str, str]:
    return dump_pool_config(Config())




POOL_SECTION_LAYOUT: tuple[
    tuple[LocalizedText, tuple[tuple[str, LocalizedText], ...]], ...
] = (
    ({"cn": "数据库", "en": "Database"}, (
        ("database.path", {
            "cn": "代理池所有数据存放的文件（SQLite 格式）。填相对路径时以 modules/proxypool/ 目录为起点。改这一项保存后不会立即生效，需重启池服务 —— 库在启动时就已经打开了",
            "en": "File holding all pool data (SQLite). A relative path is resolved from the modules/proxypool/ directory. Changes here do not take effect until the pool service restarts — the database is opened at startup",
        }),
        ("database.pool_max_readers", {
            "cn": "同时查询数据库的连接数上限，写入固定只占 1 个连接。调大能让并发查询更顺畅，也会多占用一些文件句柄；池子不大时保持默认即可。改这一项保存后不会立即生效，需重启池服务",
            "en": "Maximum simultaneous read connections; writes always use a single connection. Raising it smooths concurrent queries at the cost of more file handles — keep the default for a small pool. Changes here do not take effect until the pool service restarts",
        }),
        ("database.backup_enabled", {
            "cn": "是否按下面的间隔自动备份数据库；保存后立即生效（关掉即停，重新打开即起）",
            "en": "Whether to back the database up automatically at the interval below. Takes effect as soon as it is saved (turning it off stops it, turning it back on starts it)",
        }),
        ("database.backup_interval_hours", {
            "cn": "自动备份的间隔（小时）",
            "en": "Automatic backup interval (hours)",
        }),
        ("database.backup_retention_days", {
            "cn": "备份文件保留多少天，超期自动删除",
            "en": "How many days to keep backup files before deleting them",
        }),
    )),
    ({"cn": "代理验证", "en": "Proxy validation"}, (
        ("validator.check_anonymity", {
            "cn": "是否检查代理的匿名度。匿名度靠「目标站点实际收到了哪些请求头」判定，只在经代理发一次明文请求时才测得出来；关掉后不再发这类请求、也不再判匿名度，已经测出来的等级原样保留",
            "en": "Whether to check proxy anonymity. It is judged by the request headers the target actually received, which requires one plaintext request through the proxy. Turning it off stops those requests and stops updating anonymity; levels already measured are kept",
        }),
        ("validator.host_public_ip", {
            "cn": "本机公网出口 IP，判定「透明代理」时的对比基准。双栈主机两族各填一个、用逗号隔开（IPv4 与 IPv6 各至多一个），两族都会参与比对；只填一个也能用。留空时 ProxyCat 会**不经过代理**直接访问 IP 查询站点获取（每小时最多一次）；在这里填上你自己的出口 IP 可以完全免掉这次对外请求。留空或拿不到时无法判定匿名度，那一项会保持原样",
            "en": "Your machine's public IP, the reference for detecting transparent proxies. On a dual-stack host give one address per family, comma-separated (at most one IPv4 and one IPv6); both take part in the comparison, and a single address also works. When empty, ProxyCat queries an IP lookup site directly (bypassing any proxy) at most once an hour; filling in your own exit IP removes that external request entirely. Without it anonymity cannot be judged and that field keeps its previous value",
        }),
        ("validator.timeout_seconds", {
            "cn": "验证一个代理最多等多少秒，超过就判为不可用。所有探测请求都按这个上限",
            "en": "How long one proxy validation may take, in seconds; past that it counts as unusable. Every probe request is bounded by this",
        }),
        ("validator.connect_timeout_seconds", {
            "cn": "连接代理最多等多少秒。失效的代理大多卡在连不上这一步，调小它可以明显加快整批验证；填 0 表示不单独限制，只受上面的总超时约束",
            "en": "How long to wait while connecting to the proxy, in seconds. Most dead proxies stall at this step, so lowering it speeds a batch up noticeably; 0 means no separate limit - only the overall timeout above applies",
        }),
        ("validator.max_concurrent", {
            "cn": "同时验证多少个代理。每次验证连的是不同主机，可以放心调高；同时它也决定本机连接池上限与可打开的 socket 数（一次验证会并发发出十几个请求），受限环境应调低；如果测试站点开始限流（表现为大量代理突然超时），也调低一些",
            "en": "How many proxies to validate at once. Each validation talks to a different host, so raising it is safe; it also sets this machine's connection-pool ceiling and open-socket budget (one validation fires a dozen-odd requests at once), so lower it on constrained hosts. Lower it too if the test site starts rate-limiting you (many proxies timing out at once)",
        }),
        ("validator.identity_echo_apis", {
            "cn": "用来探测出口 IP 和匿名度的接口，多个用英文逗号分隔，必须是 https。这类接口要能返回 origin 与 headers，一次请求就能同时得出出口 IP、匿名度和 HTTPS 支持情况。连不上的会被自动跳过；可用的按直连延迟排序后逐个补发竞速，不按条数截断，多写的留作替补",
            "en": "Endpoints used to detect the exit IP and anonymity, comma-separated, https only. They must return origin and headers so one request yields the exit IP, anonymity and HTTPS support. Unreachable ones are skipped automatically; the reachable ones are raced in order of direct-connect latency, with no cap on how many take part — extras serve as spares",
        }),
        ("validator.plain_identity_echo_apis", {
            "cn": "补充的明文回显接口，多个用英文逗号分隔，必须是 http。匿名度靠「目标实际收到了哪些请求头」判定，明文路径是它的标准观测面，默认用的是上面几个接口的明文地址。如果代理够不到那些站点、导致匿名度总被判成兜底档，可以把代理能访问的回显站点填在这里",
            "en": "Extra plaintext echo endpoints, comma-separated, http only. Anonymity is judged by the headers the target actually received, and plain HTTP is its standard vantage point; by default the plaintext addresses of the endpoints above are used. If your proxies cannot reach those sites and anonymity keeps falling back, list echo sites they can reach here",
        }),
        ("validator.ip_check_apis", {
            "cn": "只返回 IP 的接口，多个用英文逗号分隔，必须是 https。上面的接口都拿不到结果时用它们兜底，同样按直连延迟逐个补发竞速，不按条数截断",
            "en": "IP-only echo endpoints, comma-separated, https only. They are the fallback when the endpoints above yield nothing; likewise raced in order of direct-connect latency, with no cap on how many take part",
        }),
    )),
    ({"cn": "抓取插件", "en": "Fetch plugins"}, (
        ("plugins.scan_interval_seconds", {
            "cn": "多久检查一次有没有插件该抓取了（秒）。它只决定检查的频率，不改变各插件自己的抓取周期",
            "en": "How often to check whether any plugin is due, in seconds. It only controls the checking frequency, not each plugin's own fetch interval",
        }),
        ("plugins.default_interval_minutes", {
            "cn": "新插件默认多久抓取一次（分钟）。每个插件都可以单独调整自己的周期",
            "en": "Default fetch interval for a new plugin, in minutes. Each plugin's interval can be adjusted individually",
        }),
        ("plugins.execution_timeout_seconds", {
            "cn": "单个插件一次抓取最多跑多少秒，超时就中断",
            "en": "How long a single plugin run may take, in seconds; past that it is aborted",
        }),
        ("plugins.request_timeout_seconds", {
            "cn": "插件请求一次网页最多等多少秒；目标站点打不开时按这个时间等待",
            "en": "How long a plugin waits for a single web request, in seconds; when the target site is down this is how long it waits",
        }),
        ("plugins.max_parallel_plugins", {
            "cn": "最多同时运行几个插件",
            "en": "Maximum number of plugins running at the same time",
        }),
        ("plugins.max_retries_on_failure", {
            "cn": "插件抓取失败后额外重试几次。填 2 表示最多一共尝试 3 次",
            "en": "Extra retries after a plugin run fails. A value of 2 means up to 3 attempts in total",
        }),
        ("plugins.retry_base_delay_seconds", {
            "cn": "插件失败后重试前等待的秒数。每多试一次等待翻倍（第 1 次等 1 倍、第 2 次 2 倍、第 3 次 4 倍），避免短时间内反复打同一个站点",
            "en": "Seconds to wait before retrying a failed plugin. The wait doubles each attempt (1x, 2x, 4x ...) so the same site is not hammered in quick succession",
        }),
    )),
    ({"cn": "自动重新验证", "en": "Automatic re-validation"}, (
        ("auto_revalidation.enabled", {
            "cn": "是否定时重新检查已入库的代理还能不能用",
            "en": "Whether stored proxies are re-checked periodically for liveness",
        }),
        ("auto_revalidation.interval_minutes", {
            "cn": "默认多久重新检查一遍（分钟）。每个插件可以在「插件管理」里单独设置自己的周期",
            "en": "Default re-check interval in minutes. Each plugin's own interval can be set individually under Plugins",
        }),
        ("auto_revalidation.only_valid_proxies", {
            "cn": "只检查当前可用的代理，跳过已经判定失效的",
            "en": "Only check proxies currently marked valid, skipping those already known to be dead",
        }),
        ("auto_revalidation.run_on_start", {
            "cn": "启动后马上先检查一遍，而不是等满一个周期",
            "en": "Run one round right after startup instead of waiting a full interval",
        }),
        ("auto_revalidation.full_recheck_interval_minutes", {
            "cn": "多久做一次完整检测（分钟）。日常检查只看代理还通不通；出口 IP、匿名度、协议支持这些信息很少变，隔较长时间重新测一遍即可",
            "en": "How often to run a full assessment, in minutes. Routine rounds only check liveness; the exit IP, anonymity and protocol support rarely change, so re-measuring them at a longer interval is enough",
        }),
    )),
    ({"cn": "自动清理", "en": "Automatic cleanup"}, (
        ("auto_cleanup.enabled", {
            "cn": "是否自动删除质量太差的代理。删除不可恢复，拿不准时先关掉它只做检查",
            "en": "Whether to delete proxies whose quality is too low. Deletion is irreversible - if unsure, turn it off and only run the checks",
        }),
        ("auto_cleanup.min_health_score", {
            "cn": "健康分低于这个值的代理会被删除，同时还要满足下一条的次数要求",
            "en": "Proxies scoring below this health value are deleted, provided the check-count requirement below is also met",
        }),
        ("auto_cleanup.min_checks_before_cleanup", {
            "cn": "至少检查过多少次才允许按评分淘汰，避免刚入库的代理因为样本太少被误删",
            "en": "How many checks a proxy must have before it can be dropped by score, so freshly stored ones are not deleted on too little evidence",
        }),
        ("auto_cleanup.max_failures", {
            "cn": "连续失败这么多次就删除",
            "en": "Delete after this many consecutive failures",
        }),
        ("auto_cleanup.max_age_days_if_invalid", {
            "cn": "判定失效后最多再保留几天，超过就删除",
            "en": "Keep a dead proxy for at most this many days before deleting it",
        }),
    )),
    ({"cn": "使用期反馈", "en": "Use-time feedback"}, (
        ("use_feedback.enabled", {
            "cn": "代理在实际转发中不通时，是否把它记为一次失败并在连续失败达阈值后标记失效。"
                  "检测分不清「代理坏了」和「我们自己网络抖动」，阈值就是用来吃掉后者的；"
                  "关掉后池只信自己的验证结果",
            "en": "Whether to count a proxy that fails during real forwarding and mark it invalid "
                  "after enough consecutive failures. The check cannot tell a broken proxy from a "
                  "hiccup on our side - the threshold absorbs the latter; when off, the pool trusts "
                  "only its own validation results",
        }),
        ("use_feedback.invalid_threshold", {
            "cn": "连续失败这么多次就标记失效，期间任何一次成功都会清零",
            "en": "Mark the proxy invalid after this many consecutive failures; any success resets it",
        }),
    )),
    ({"cn": "写入队列", "en": "Write queue"}, (
        ("write_queue.batch_size", {
            "cn": "攒够多少条记录才一次性写进数据库",
            "en": "How many records to accumulate before writing them to the database in one batch",
        }),
        ("write_queue.max_retries", {
            "cn": "一批记录最多尝试写几次（含第一次）。填 0 或 1 都表示失败就放弃",
            "en": "How many times to attempt a batch write, first attempt included. 0 and 1 both mean give up on failure",
        }),
        ("write_queue.max_queue_size", {
            "cn": "等待写入的任务最多排多少个。排满后新任务会被拒绝，以免占用过多内存。这一项保存后不会立即生效，需重启服务（队列容量在创建时固定，中途改会丢掉已排队的数据）",
            "en": "Maximum number of pending write tasks. Once full, new tasks are rejected to keep memory in check. This one does not take effect on save — restart the service (the queue capacity is fixed at construction, and changing it mid-flight would drop queued data)",
        }),
    )),
    ({"cn": "日志", "en": "Logging"}, (
        ("logging.file_path", {
            "cn": "代理池的日志文件。填相对路径时以 modules/proxypool/ 目录为起点",
            "en": "The pool log file. A relative path is resolved from the modules/proxypool/ directory",
        }),
        ("logging.max_bytes", {
            "cn": "单个日志文件的大小上限（字节）。写满后自动换一个新文件，旧文件继续保留",
            "en": "Maximum size of a single log file in bytes. Once full it rotates to a new file and the old one is kept",
        }),
        ("logging.backup_count", {
            "cn": "最多保留几个历史日志文件",
            "en": "Maximum number of rotated log files to keep",
        }),
    )),
)


def render_pool_section(values: Mapping[str, str]) -> str:
    effective = default_pool_section()
    effective.update(values)
    for deprecated_key in DEPRECATED_KEYS:
        effective.pop(deprecated_key, None)

    lines = [
        "[Pool]",
        "# 代理资源池配置。修改后保存即可热生效，无需重启；",
        "# 也可以通过 Web 界面的「池设置」页面修改 —— 两边是同一份配置。",
        "# " + "=" * 66,
        "",
    ]

    rendered_keys: set[str] = set()
    for group_spec, fields in POOL_SECTION_LAYOUT:
        group_title = _text(group_spec)
        group_lines: list[str] = []
        for key, doc_spec in fields:
            value = effective.get(key)
            if value is None:
                continue
            rendered_keys.add(key)
            group_lines.append(f"# {_text(doc_spec)}")
            group_lines.append(f"{key} = {value}")

        if not group_lines:
            continue

        if group_title:
            lines.append(f"# ── {group_title} " + "─" * max(4, 56 - len(group_title) * 2))
        lines.extend(group_lines)
        lines.append("")

    extras = {k: v for k, v in effective.items() if k not in rendered_keys}
    if extras:
        lines.append("# ── 其他 " + "─" * 56)
        for key in sorted(extras):
            lines.append(f"{key} = {extras[key]}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _splice_section(ini_text: str, section: str, block: str) -> str:
    section_pattern = re.compile(rf"^\s*\[{re.escape(section)}\]\s*$")
    any_section_pattern = re.compile(r"^\s*\[.+\]\s*$")

    lines = ini_text.splitlines(keepends=True)
    start = next((i for i, line in enumerate(lines) if section_pattern.match(line)), None)

    if start is None:
        head = ini_text.rstrip("\n")
        return f"{head}\n\n{block}" if head else block

    end = len(lines)
    for i in range(start + 1, len(lines)):
        if any_section_pattern.match(lines[i]):
            end = i
            break

    return "".join(lines[:start]) + block + "".join(lines[end:])


def sync_pool_section_text(ini_path: str | Path,
                           updates: Mapping[str, str] | None = None) -> bool:
    ini_path = Path(ini_path)
    if not ini_path.is_file():
        return False

    try:
        original = _read_config_text(ini_path)
    except (OSError, UnicodeDecodeError) as e:
        logger.error("读取 %s 失败，跳过 [Pool] 段排版: %s", ini_path, e)
        return False

    current = read_ini_sections(ini_path).get(POOL_SECTION, {})
    if updates:
        current.update(updates)

    updated = _splice_section(original, POOL_SECTION, render_pool_section(current))

    if updated == original:
        return False

    try:
        _atomic_write_text(ini_path, updated)
    except OSError as e:
        logger.error("写入 %s 失败，[Pool] 段保持原样: %s", ini_path, e)
        return False

    return True


def ensure_pool_section(ini_path: str | Path, yaml_path: str | Path) -> bool:
    ini_path = Path(ini_path)
    ini_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        original = _read_config_text(ini_path) if ini_path.is_file() else ""
    except (OSError, UnicodeDecodeError) as e:
        logger.error("读取 %s 失败，池将使用默认配置: %s", ini_path, e)
        return False

    known_keys = {key for key, _, _ in _iter_leaf_fields()}
    existing = read_ini_sections(ini_path).get(POOL_SECTION, {})
    if any(key in known_keys for key in existing):
        return sync_pool_section_text(ini_path)

    migrated = migrate_from_yaml(yaml_path)
    source = "旧 config.yaml" if migrated else "默认值"

    if original:
        backup_path = ini_path.with_suffix(
            f".ini.bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        try:
            shutil.copy(ini_path, backup_path)
            logger.info("原配置已备份到 %s", backup_path)
        except OSError as e:
            logger.error("备份 %s 失败，中止配置迁移以避免丢失原配置: %s", ini_path, e)
            return False

    updated = _splice_section(original, POOL_SECTION, render_pool_section(migrated))

    try:
        _atomic_write_text(ini_path, updated)
    except OSError as e:
        logger.error("写入 %s 失败，池将使用默认配置: %s", ini_path, e)
        return False

    logger.info("已从%s写入 %d 个池配置项到 [Pool] 段", source, len(migrated))

    yaml_file = Path(yaml_path)
    if yaml_file.is_file():
        try:
            yaml_file.rename(yaml_file.with_suffix(".yaml.migrated"))
            logger.info("旧配置 %s 已重命名为 .migrated", yaml_file)
        except OSError as e:
            logger.warning("重命名旧配置 %s 失败（不影响运行）: %s", yaml_file, e)

    return True


def read_ini_sections(ini_path: str | Path) -> dict[str, dict[str, str]]:
    from configparser import ConfigParser, Error as ConfigParserError

    parser = ini_parser()
    if not Path(ini_path).is_file():
        return {}
    try:
        parser.read_string(_read_config_text(ini_path))
    except (OSError, UnicodeDecodeError, ConfigParserError) as e:
        logger.error("读取 %s 失败: %s", ini_path, e)
        return {}

    sections = {}
    for section in parser.sections():
        items = dict(parser.items(section))
        if section != USERS_SECTION:
            items = {key.lower(): value for key, value in items.items()}
        sections[section] = items
    return sections


def _load_pool_config(ini_path: str | Path, *, require_sections: bool) -> "Config | None":
    sections = read_ini_sections(ini_path)
    if require_sections and not sections:
        return None
    return build_pool_config(
        sections.get("Server", {}),
        sections.get(POOL_SECTION, {}),
        strict=False,
    )


def load_pool_config(ini_path: str | Path) -> Config:
    return _load_pool_config(ini_path, require_sections=False)


def reload_pool_config(ini_path: str | Path) -> "Config | None":
    return _load_pool_config(ini_path, require_sections=True)


__all__ = [
    "POOL_SECTION",
    "PoolConfigError",
    "parse_pool_section",
    "build_pool_config",
    "dump_pool_config",
    "read_ini_sections",
    "load_pool_config",
    "ensure_pool_section",
    "sync_pool_section_text",
    "normalize_pool_updates",
    "describe_pool_schema",
    "render_pool_section",
    "reload_pool_config",
    "POOL_SECTION_LAYOUT",
    "POOL_FIELD_LABELS",
    "should_autostart_pool",
    "migrate_from_yaml",
    "default_pool_section",
]
