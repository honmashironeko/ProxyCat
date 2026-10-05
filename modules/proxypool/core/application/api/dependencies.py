"""
模块名称：modules.proxypool.core.application.api.dependencies
功能描述：路由层获取服务的统一入口：容器注册的服务按接口类型解析，去重缓存、备份管理器、数据清理器、归属地解析器与语言提供者由宿主启动时注入。
职责边界：负责：持有并暴露 DI 容器与各注入项的进程内引用；不负责：实例创建、注册、生命周期与注入时机（见 core.application.app.Application 与宿主）。
关键依赖：core.infrastructure 的 di_container、dedup_cache 模块，以及 core.interfaces 下供容器解析的接口类型。
已知限制：
  1. 容器与注入项都是模块级全局引用，仅能通过 set_* 传入新实例或 None 替换，无专用清空接口；多进程部署时各进程各持一份，互不可见。
  2. 停池只清空 container 与 dedup_cache，backup_manager、data_cleaner、geo_resolver、language_provider 刻意保留。
  3. get_container 未初始化时抛 RuntimeError，属装配顺序问题，不自愈也不应重试。
  4. get_geodb 延迟导入并吞掉一切异常返回 None，表示「未启用」，调用方不得视为错误。
  5. get_dedup_cache 返回 None 时调用方必须回落查库，不能当作异常吞掉。
  6. get_language 永不抛异常也不返回空串，缺省一律 'cn'；语言必须以函数注入，缓存字符串会一直用旧语言。
"""

from typing import Callable, Optional

from core.infrastructure.di_container import DIContainer
from core.infrastructure.dedup_cache import DedupCache
from core.interfaces.repository import IProxyRepository, IPluginConfigRepository
from core.interfaces.services import IPluginManager, IProxyValidator
from core.interfaces.infrastructure import IWriteQueue, IConfigManager


_container: Optional[DIContainer] = None
_dedup_cache: Optional[DedupCache] = None
_backup_manager = None
_data_cleaner = None
_geo_resolver = None
_language_provider: Optional[Callable[[], str]] = None


def set_container(container: Optional[DIContainer]) -> None:
    global _container
    _container = container


def set_dedup_cache(dedup_cache: Optional[DedupCache]) -> None:
    global _dedup_cache
    _dedup_cache = dedup_cache


def get_container() -> DIContainer:
    global _container
    if _container is None:
        raise RuntimeError("依赖注入容器未初始化，请先调用 set_container()")
    return _container


def get_proxy_repository() -> IProxyRepository:
    container = get_container()
    return container.resolve(IProxyRepository)


def get_plugin_config_repository() -> IPluginConfigRepository:
    container = get_container()
    return container.resolve(IPluginConfigRepository)


def get_plugin_manager() -> IPluginManager:
    container = get_container()
    return container.resolve(IPluginManager)


def get_proxy_validator() -> IProxyValidator:
    container = get_container()
    return container.resolve(IProxyValidator)


def get_write_queue() -> IWriteQueue:
    container = get_container()
    return container.resolve(IWriteQueue)


def get_config_manager() -> IConfigManager:
    container = get_container()
    return container.resolve(IConfigManager)


def get_dedup_cache() -> Optional[DedupCache]:
    return _dedup_cache


def set_backup_manager(manager) -> None:
    global _backup_manager
    _backup_manager = manager


def get_backup_manager():
    return _backup_manager


def set_data_cleaner(cleaner) -> None:
    global _data_cleaner
    _data_cleaner = cleaner


def get_data_cleaner():
    return _data_cleaner


def set_geo_resolver(resolver) -> None:
    global _geo_resolver
    _geo_resolver = resolver


def get_geo_resolver():
    return _geo_resolver


def get_geodb():
    try:
        from core.infrastructure.geodb import GeoDatabase

        return get_container().resolve(GeoDatabase)
    except Exception:
        return None


def set_language_provider(provider: Optional[Callable[[], str]]) -> None:
    global _language_provider
    _language_provider = provider


def get_language() -> str:
    if _language_provider is None:
        return 'cn'
    try:
        return _language_provider() or 'cn'
    except Exception:
        return 'cn'

