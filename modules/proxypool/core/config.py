"""
模块名称：modules.proxypool.core.config
功能描述：代理池的配置数据模型：定义 Config 与各配置节 dataclass 及默认值，并把「节名 → 字段名」嵌套字典覆盖式解析为 Config 实例。
职责边界：负责：配置模型定义、默认值与嵌套字典解析；不负责：配置文件读写与热重载（infrastructure.config_manager）、
          取值校验与类型转换（modules.pool_config_ini）。
关键依赖：标准库 dataclasses、logging；不依赖内部模块。
已知限制：
  1. 无类型转换与取值校验：值按原样写入，类型错误要到使用处才暴露；未知节名、非 dict 的节与节内未知字段均被静默忽略。
  2. 某节构造抛 TypeError/ValueError 时该节整体退回默认值并记 warning，其余节照常解析。
  3. 默认值即出厂契约：modules.pool_config_ini 读取本模块默认值渲染 config.ini 的 [Pool] 段，改默认值须同步出厂配置。
  4. database.path 与 logging.file_path 默认是相对路径，使用前须经 core.paths.resolve_pool_path 锚定，否则落到进程工作目录。
  5. validator 的列表字段（identity_echo_apis 等）按传入列表原样保存，元素类型与可用性由调用方保证。
"""

import dataclasses
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class DatabaseConfig:
    path: str = "data/proxies.db"
    backup_enabled: bool = True
    backup_interval_hours: int = 24
    backup_retention_days: int = 7
    pool_max_readers: int = 4


@dataclass
class ValidatorConfig:
    target_url: str = "https://www.baidu.com"
    check_anonymity: bool = True
    host_public_ip: str = ""
    timeout_seconds: int = 5
    connect_timeout_seconds: float = 2.0
    max_concurrent: int = 400
    identity_echo_apis: list[str] = field(default_factory=lambda: [
        "https://httpbin.org/anything",
        "https://httpbingo.org/anything",
        "https://eu.httpbin.org/anything",
    ])
    plain_identity_echo_apis: list[str] = field(default_factory=lambda: [
        "http://postman-echo.com/get",
    ])
    ip_check_apis: list[str] = field(default_factory=lambda: [
        "https://icanhazip.com",
        "https://checkip.amazonaws.com",
        "https://api.ip.sb/ip",
        "https://realip.cc/simple",
        "https://httpbin.org/ip",
        "https://api.ipify.org",
        "https://ipinfo.io/json",
        "https://ipwho.is/",
        "https://www.cloudflare.com/cdn-cgi/trace",
    ])


@dataclass
class PluginsConfig:
    scan_interval_seconds: int = 60
    default_interval_minutes: int = 60
    execution_timeout_seconds: int = 300
    request_timeout_seconds: int = 30
    max_parallel_plugins: int = 3
    max_retries_on_failure: int = 2
    retry_base_delay_seconds: float = 10.0


@dataclass
class AutoRevalidationConfig:
    enabled: bool = True
    interval_minutes: int = 360
    only_valid_proxies: bool = True
    run_on_start: bool = True
    full_recheck_interval_minutes: int = 1440


@dataclass
class AutoCleanupConfig:
    enabled: bool = True
    max_failures: int = 3
    min_health_score: float = 10.0
    min_checks_before_cleanup: int = 3
    max_age_days_if_invalid: int = 3


@dataclass
class UseFeedbackConfig:
    enabled: bool = True
    invalid_threshold: int = 3


@dataclass
class WriteQueueConfig:
    batch_size: int = 100
    max_retries: int = 3
    max_queue_size: int = 10000


@dataclass
class LoggingConfig:
    file_path: str = "logs/proxy_pool.log"
    max_bytes: int = 10485760
    backup_count: int = 5


@dataclass
class Config:
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    validator: ValidatorConfig = field(default_factory=ValidatorConfig)
    plugins: PluginsConfig = field(default_factory=PluginsConfig)
    write_queue: WriteQueueConfig = field(default_factory=WriteQueueConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    auto_revalidation: AutoRevalidationConfig = field(default_factory=AutoRevalidationConfig)
    auto_cleanup: AutoCleanupConfig = field(default_factory=AutoCleanupConfig)
    use_feedback: UseFeedbackConfig = field(default_factory=UseFeedbackConfig)


def build_config(data: dict[str, Any] | None = None) -> Config:
    config = Config()
    if not data:
        return config

    for config_field in dataclasses.fields(Config):
        section_name = config_field.name
        section_data = data.get(section_name)
        if not isinstance(section_data, dict):
            continue

        sub_cls = config_field.type
        if isinstance(sub_cls, str):
            sub_cls = type(getattr(config, section_name))

        if not dataclasses.is_dataclass(sub_cls):
            continue

        default_instance = getattr(config, section_name)
        sub_kwargs = {}
        for sub_field in dataclasses.fields(sub_cls):
            if sub_field.name in section_data:
                sub_kwargs[sub_field.name] = section_data[sub_field.name]
            else:
                sub_kwargs[sub_field.name] = getattr(default_instance, sub_field.name)

        try:
            setattr(config, section_name, sub_cls(**sub_kwargs))
        except (TypeError, ValueError) as e:
            logger.warning("配置节 %s 解析失败，使用默认值: %s", section_name, e)

    return config
