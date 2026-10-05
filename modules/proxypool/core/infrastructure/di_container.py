"""
模块名称：modules.proxypool.core.infrastructure.di_container
功能描述：极简依赖注入容器，登记 Application 创建好的服务实例，供路由层按接口类型取用。
职责边界：负责：保存接口到实例的绑定并按接口类型解析出实例；不负责：实例的创建与生命周期，由 core.application.app.Application 统一创建后注册。
关键依赖：core.domain.exceptions。
已知限制：
1. 只支持注册现成实例这一种绑定方式，重复注册同一接口会抛 DependencyInjectionException。
2. resolve 按类型精确匹配，不做子类匹配；未注册的接口会抛 DependencyNotRegisteredError。
3. 容器不创建也不销毁实例，resolve 返回的始终是注册时传入的那个对象。
"""

from typing import Any, Dict, Type
from core.domain.exceptions import (
    DependencyNotRegisteredError,
    DependencyInjectionException
)


class DIContainer:
    def __init__(self):
        self._singletons: Dict[Type, Any] = {}

    def register_instance(self, interface: Type, instance: Any) -> None:
        if interface in self._singletons:
            raise DependencyInjectionException(
                f"接口 {interface.__name__} 已经注册"
            )
        self._singletons[interface] = instance

    def resolve(self, interface: Type) -> Any:
        if interface not in self._singletons:
            raise DependencyNotRegisteredError(
                f"未注册的依赖: {interface.__name__}"
            )

        return self._singletons[interface]
