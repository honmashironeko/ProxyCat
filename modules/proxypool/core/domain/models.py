"""
模块名称：modules.proxypool.core.domain.models
功能描述：代理池的领域模型与字段取值契约：定义代理记录、验证结论、探测结果、插件配置与归属地等数据结构，
          以及成功率、存活占比、出口 IP 是否与入口不同等派生只读量。
职责边界：负责：数据结构定义、字段语义与派生计算、URL 与对象的互转（Proxy.from_url）；不负责：
          持久化、验证算法与健康评分、任何 I/O（分别见 core.data.repositories、core.services）。
关键依赖：仅标准库。
已知限制：
1. 模型是进程内普通对象，无并发保护，跨线程共享需调用方自行加锁；时间字段为 naive 本地时间，与 aware 时间混用会抛 TypeError。
2. 中文列用「未知」表示查过但查不到；Proxy 的英文列与 code 列用 None 表示尚未查询，GeoLocation/GeoRecord 的 country_code 用空串表示未查到。
3. 写归属地前须先看 is_known：全「未知」的 GeoLocation/GeoName 会覆盖库里已有值。
4. ProxyValidationResult.is_valid 只由 ValidationOutcome.OK 派生；skip_validation 插件跳过验证直接入库 is_valid=1。
5. ProbeOutcome.ok 的 None（未测成）必须与 False（确实失败）分开，误判会拉低整池成功率。
6. exit_ip_differs 与 canonical_ip 按 ipaddress 规范化后比较（折叠 IPv4-mapped IPv6），字段缺失或解析失败时返回 False。
7. Proxy.from_url 只接受点分四段 IPv4 字面量与必填端口；proxy_url 仅在用户名与密码同时存在时注入认证信息。
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Mapping, Optional
from urllib.parse import urlparse
import ipaddress
import re


def canonical_ip(value: str) -> Optional[str]:
    try:
        addr = ipaddress.ip_address(value.strip())
    except (ValueError, AttributeError):
        return None
    mapped = getattr(addr, "ipv4_mapped", None)
    return str(mapped or addr)


ANONYMITY_LEVELS = ('transparent', 'anonymous', 'elite', 'unverified')

SUPPORTED_PROTOCOLS = ('http', 'https', 'socks5')


class ValidationOutcome(str, Enum):
    OK = "ok"
    PROXY_UNREACHABLE = "proxy_unreachable"
    PROXY_FAILED = "proxy_failed"
    INCONCLUSIVE = "inconclusive"


@dataclass
class Proxy:
    id: Optional[int] = None
    protocol: str = ""
    ip: str = ""
    port: int = 0
    username: Optional[str] = None
    password: Optional[str] = None
    region: str = "未知"
    country: str = "未知"
    province: str = "未知"
    city: str = "未知"
    region_en: Optional[str] = None
    country_en: Optional[str] = None
    province_en: Optional[str] = None
    city_en: Optional[str] = None
    country_code: Optional[str] = None
    subdivision_code: Optional[str] = None
    geo_source: Optional[str] = None
    delay_ms: Optional[float] = None
    is_valid: bool = True
    is_favorite: bool = False
    failure_count: int = 0
    real_ip: Optional[str] = None
    source_plugin: str = ""
    created_at: Optional[datetime] = None
    validated_at: Optional[datetime] = None
    health_score: float = 0.0
    success_count: int = 0
    total_checks: int = 0
    anonymity_level: str = "unverified"
    anonymity_fallback: bool = False
    supports_https: bool = False
    supports_http: bool = False
    quality_assessed_at: Optional[datetime] = None
    avg_delay_ms: Optional[float] = None
    delay_variance: Optional[float] = None
    last_valid_at: Optional[datetime] = None
    total_valid_seconds: float = 0.0
    probe_success_count: int = 0
    probe_total_count: int = 0

    @property
    def success_rate(self) -> float:
        if self.total_checks == 0:
            return 0.0
        return self.success_count / self.total_checks

    @property
    def probe_success_rate(self) -> float:
        if self.probe_total_count <= 0:
            return 0.0
        return self.probe_success_count / self.probe_total_count

    @property
    def age_hours(self) -> float:
        if not self.created_at:
            return 0.0
        delta = datetime.now() - self.created_at
        return delta.total_seconds() / 3600.0

    @property
    def uptime_ratio(self) -> float:
        age_seconds = self.age_hours * 3600.0
        if age_seconds <= 0:
            return 0.0
        ratio = self.total_valid_seconds / age_seconds
        return max(0.0, min(1.0, ratio))

    @property
    def proxy_url(self) -> str:
        if self.username and self.password:
            return f"{self.protocol}://{self.username}:{self.password}@{self.ip}:{self.port}"
        return f"{self.protocol}://{self.ip}:{self.port}"

    @property
    def exit_ip_differs(self) -> bool:
        if not self.ip or not self.real_ip:
            return False
        entry = canonical_ip(self.ip)
        exit_address = canonical_ip(self.real_ip)
        if entry is None or exit_address is None:
            return False
        return entry != exit_address

    @staticmethod
    def from_url(url: str, source_plugin: str) -> "Proxy":
        try:
            parsed = urlparse(url)

            if not parsed.scheme:
                raise ValueError(f"缺少协议: {url}")

            if not parsed.hostname:
                raise ValueError(f"缺少主机名: {url}")

            if not parsed.port:
                raise ValueError(f"缺少端口: {url}")

            protocol = parsed.scheme.lower()
            if protocol not in SUPPORTED_PROTOCOLS:
                raise ValueError(f"不支持的协议: {protocol}")

            ip = parsed.hostname
            ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
            if not re.match(ip_pattern, ip):
                raise ValueError(f"无效的 IP 地址: {ip}")

            parts = ip.split('.')
            for part in parts:
                if int(part) > 255:
                    raise ValueError(f"无效的 IP 地址: {ip}")

            port = parsed.port
            if not (1 <= port <= 65535):
                raise ValueError(f"无效的端口: {port}")

            username = parsed.username
            password = parsed.password

            return Proxy(
                protocol=protocol,
                ip=ip,
                port=port,
                username=username,
                password=password,
                source_plugin=source_plugin
            )
        except Exception as e:
            raise ValueError(f"解析代理 URL 失败 {url}: {str(e)}")



@dataclass
class PluginConfig:
    name: str
    enabled: bool = True
    interval_minutes: int = 60
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    reval_enabled: bool = True
    reval_interval_minutes: int = 0
    test_url: str = ""
    skip_validation: bool = False


@dataclass
class ProxyFilter:
    protocol: Optional[str] = None
    region: Optional[str] = None
    min_delay: Optional[int] = None
    max_delay: Optional[int] = None
    is_valid: Optional[bool] = None
    source: Optional[str] = None
    sort_by: Optional[str] = None
    sort_order: Optional[str] = None
    ip: Optional[str] = None
    is_favorite: Optional[bool] = None
    anonymity_level: Optional[str] = None
    min_health_score: Optional[float] = None
    supports_https: Optional[bool] = None


@dataclass
class DBOperation:
    operation_type: str
    table: str
    data: dict | list[dict]
    where: Optional[dict] = None


@dataclass
class HttpResponse:
    status: int
    text: str
    headers: dict


class ValidationMode(str, Enum):
    LIVENESS = "liveness"
    IDENTITY = "identity"
    FULL = "full"


class ProbeKind(str, Enum):
    LIVENESS = "liveness"
    TUNNEL = "tunnel"
    PLAIN_HTTP = "plain_http"


@dataclass(frozen=True)
class ProbeOutcome:
    kind: ProbeKind
    ok: Optional[bool]
    latency_ms: Optional[float] = None
    reason: Optional[str] = None


@dataclass
class ProxyValidationResult:
    proxy_url: str
    outcome: ValidationOutcome
    validated_at: datetime
    delay_ms: Optional[float] = None
    error_message: Optional[str] = None
    real_ip: Optional[str] = None
    anonymity_level: Optional[str] = None
    anonymity_fallback: bool = False
    supports_https: Optional[bool] = None
    supports_http: Optional[bool] = None
    error_reason: Optional[str] = None
    probes: tuple[ProbeOutcome, ...] = ()

    @property
    def is_valid(self) -> bool:
        return self.outcome is ValidationOutcome.OK

    @property
    def is_conclusive(self) -> bool:
        return self.outcome is not ValidationOutcome.INCONCLUSIVE

    @property
    def probe_samples(self) -> tuple[int, int]:
        conclusive = [p for p in self.probes if p.ok is not None]
        return sum(1 for p in conclusive if p.ok), len(conclusive)

    @property
    def fully_assessed(self) -> bool:
        kinds = {p.kind for p in self.probes}
        if not {ProbeKind.LIVENESS, ProbeKind.TUNNEL} <= kinds:
            return False
        return all(p.ok is not None for p in self.probes)


@dataclass
class GeoName:
    country: str = "未知"
    province: str = "未知"
    city: str = "未知"

    def to_string(self) -> str:
        parts = [self.country]
        if self.province != "未知":
            parts.append(self.province)
        if self.city != "未知":
            parts.append(self.city)
        return " ".join(parts)

    @property
    def is_known(self) -> bool:
        return any(
            part and part != "未知" for part in (self.country, self.province, self.city)
        )


@dataclass
class GeoLocation:
    zh: GeoName = field(default_factory=GeoName)
    en: GeoName = field(default_factory=GeoName)

    country_code: str = ""
    subdivision_code: str = ""
    source: str = ""
    untranslated: Mapping[str, bool] = field(default_factory=dict)

    def to_string(self) -> str:
        return self.zh.to_string()

    def to_string_en(self) -> str:
        return self.en.to_string()

    @property
    def is_known(self) -> bool:
        return self.zh.is_known or self.en.is_known

    @property
    def is_complete(self) -> bool:
        return self.zh.is_known and self.en.is_known


@dataclass(frozen=True)
class GeoRecord:
    country_code: str = ""
    subdivision_code: str = ""
    country_names: Mapping[str, str] = field(default_factory=dict)
    subdivision_names: Mapping[str, str] = field(default_factory=dict)
    city_names: Mapping[str, str] = field(default_factory=dict)
    source: str = ""

    @property
    def is_china(self) -> bool:
        return self.country_code == "CN"


@dataclass
class PluginStatus:
    name: str
    enabled: bool
    interval_minutes: int
    last_run: Optional[datetime]
    next_run: Optional[datetime]
    last_error: Optional[str] = None
    last_error_key: Optional[str] = None
    is_loaded: bool = False
    test_url: str = ""
    reval_enabled: bool = True
    reval_interval_minutes: int = 0
    skip_validation: bool = False
