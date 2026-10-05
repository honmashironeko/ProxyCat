"""
模块名称：modules.proxypool.core.interfaces.services
功能描述：代理池领域服务的抽象契约：采集插件、代理验证器、GeoIP 查询、插件管理器，
          以及插件执行时注入的 PluginContext；上层（应用层、批量任务）只依赖这些接口。
职责边界：负责：声明各服务的调用契约与返回值、异常语义；不负责：实现细节与运行时状态，
          接口不做 I/O、不持有配置，具体实现见 core.services（geoip、validator、plugin_manager）与 plugins/*.py。
关键依赖：core.domain.models（ProxyValidationResult / GeoLocation / PluginStatus / ValidationMode）。
已知限制：
  1. fetch_proxies 抓取失败必须抛异常，返回空列表会被调度当成「该源本次无代理」并推进成功状态。
  2. IProxyPlugin.name 与 version 无调用方读取，插件以文件名 stem 作为配置、调度与来源记录键。
  3. validate_proxy 验证失败仍须返回结果对象（以 outcome 表达失败类型），仅实现自身出错才可抛异常。
  4. get_location 的 async 签名不表示实现必须异步，可纯本地查表；库不可用时返回「未知」对象而非报错。
  5. enable_plugin / disable_plugin 对不存在的插件不抛异常，但会新建并落库 PluginConfig；
     reload_plugin 失败返回 False，保留原实现。
  6. set_plugin_test_url 非法地址抛 ValueError，set_plugin_validation 负数间隔抛 InvalidParameterException。
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from dataclasses import dataclass
import logging
from core.domain.models import (
    ProxyValidationResult,
    GeoLocation,
    PluginStatus,
    ValidationMode,
)


@dataclass
class PluginContext:
    http_client: 'IHttpClient'
    logger: logging.Logger
    config: 'Config'


class IProxyPlugin(ABC):
    @abstractmethod
    async def fetch_proxies(self, context: PluginContext) -> List[str]:
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        pass


class IProxyValidator(ABC):
    @abstractmethod
    async def validate_proxy(self, proxy_url: str,
                             mode: ValidationMode = ValidationMode.FULL,
                             test_url: Optional[str] = None) -> ProxyValidationResult:
        pass

    @abstractmethod
    def apply_config(self, config: 'Config') -> None:
        pass

    @abstractmethod
    def can_attribute_failure(self, test_url: str) -> bool:
        pass


class IGeoIPService(ABC):
    @abstractmethod
    def load_database(self) -> bool:
        pass

    @abstractmethod
    async def get_location(self, ip: str) -> GeoLocation:
        pass

    @abstractmethod
    def close(self) -> None:
        pass


class IPluginManager(ABC):
    @abstractmethod
    async def start(self) -> None:
        pass

    @abstractmethod
    async def stop(self) -> None:
        pass

    @abstractmethod
    async def scan_plugins(self) -> None:
        pass

    @abstractmethod
    async def execute_plugin(self, plugin_name: str) -> List[str]:
        pass

    @abstractmethod
    async def deduplicate_proxies(self, proxies: List[str]) -> List[str]:
        pass

    @abstractmethod
    def enable_plugin(self, plugin_name: str) -> None:
        pass

    @abstractmethod
    def disable_plugin(self, plugin_name: str) -> None:
        pass

    @abstractmethod
    def set_plugin_interval(self, plugin_name: str, minutes: int) -> None:
        pass

    @abstractmethod
    def get_plugin_status(self) -> dict[str, PluginStatus]:
        pass

    @abstractmethod
    def apply_config(self, config: 'Config') -> None:
        pass

    @abstractmethod
    async def reload_plugin(self, plugin_name: str) -> bool:
        pass

    @abstractmethod
    def set_plugin_test_url(self, plugin_name: str, test_url: str) -> None:
        pass

    @abstractmethod
    def set_plugin_validation(self, plugin_name: str, reval_enabled: bool,
                              reval_interval_minutes: int,
                              skip_validation: bool) -> None:
        pass

    @abstractmethod
    def should_skip_validation(self, plugin_name: str) -> bool:
        pass

    @abstractmethod
    def resolve_test_url(self, plugin_name: str) -> str:
        pass
