"""
模块名称：modules.proxypool.core.interfaces.repository
功能描述：数据仓库的抽象契约：声明代理与插件配置的读写方法签名、参数、返回值与失败语义，上层服务只依赖接口。
职责边界：负责：声明代理与插件配置的读写契约（方法签名与失败语义）；不负责：SQL、表结构、连接与事务等实现细节。
关键依赖：core.domain.models（Proxy / PluginConfig / ProxyFilter）；标准库 abc 与 typing。
已知限制：
1. 业务性结果由返回值表达（数量、对象、None、布尔）；参数与基础设施错误仍抛异常，调用方需两者都处理。
2. 写方法收到空列表或空字典即无操作；add 忽略传入对象的 id，主键由存储层分配。
3. update_where 的 where 键会直接进 SQL 列名，实现必须限定在白名单列内。
4. get_existing_ip_ports 的键是 "ip:port"，必须带端口，同一 IP 的不同端口算两个代理。
5. get_geo_fields_by_real_ip 是合并语义，缺失级别不得覆盖已有值为「未知」。
6. IPluginConfigRepository.save 为整体覆盖，get 无记录返回 None，调用方应回退默认配置。
7. get_stats 六键：total/valid/invalid_proxies、protocol/region_distribution、
   anonymity_fallback_proxies。
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from core.domain.models import Proxy, PluginConfig, ProxyFilter


class IProxyRepository(ABC):
    @abstractmethod
    async def add(self, proxy: Proxy) -> int:
        pass

    @abstractmethod
    async def add_batch(self, proxies: List[Proxy]) -> int:
        pass

    @abstractmethod
    async def update(self, proxy_id: int, updates: dict) -> bool:
        pass

    @abstractmethod
    async def update_batch(self, updates: list[tuple[int, dict]]) -> int:
        pass

    @abstractmethod
    async def update_where(self, where: dict, updates: dict) -> int:
        pass

    @abstractmethod
    async def delete_batch(self, proxy_ids: list[int]) -> int:
        pass

    @abstractmethod
    async def get_by_id(self, proxy_id: int) -> Optional[Proxy]:
        pass

    @abstractmethod
    async def find(self, filter: ProxyFilter, page: int = 1,
                   page_size: int = 50) -> List[Proxy]:
        pass

    @abstractmethod
    async def count(self, filter: ProxyFilter) -> int:
        pass

    @abstractmethod
    async def get_geo_fields_by_real_ip(self, real_ip: str) -> Optional[dict]:
        pass

    @abstractmethod
    async def get_ips_missing_geo_codes(self) -> List[str]:
        pass

    @abstractmethod
    async def find_without_checks(self) -> List[Proxy]:
        pass

    @abstractmethod
    async def get_existing_ip_ports(self) -> set[str]:
        pass

    @abstractmethod
    async def delete_invalid(self) -> int:
        pass

    @abstractmethod
    async def get_stats(self) -> dict:
        pass

    @abstractmethod
    async def find_by_ip_port(self, ip: str, port: int) -> Optional[Proxy]:
        pass

    @abstractmethod
    async def get_sources(self) -> List[str]:
        pass


class IPluginConfigRepository(ABC):
    @abstractmethod
    async def get(self, plugin_name: str) -> Optional[PluginConfig]:
        pass

    @abstractmethod
    async def save(self, config: PluginConfig) -> None:
        pass

    @abstractmethod
    async def get_all(self) -> List[PluginConfig]:
        pass
