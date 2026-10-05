"""
模块名称：modules.proxypool.core.interfaces.infrastructure
功能描述：基础设施层的能力契约（写入队列、HTTP 客户端、配置管理器）；调用方面向本模块的 ABC 编程，
          不直接依赖 core.infrastructure 下的具体实现，实现可整套替换而调用方无需改动。
职责边界：负责：声明基础设施能力的方法签名、参数语义与失败方式；不负责：实现细节与资源生命周期（见 core.infrastructure.*）、实例选型（由应用层 DI 装配决定）。
关键依赖：core.domain.models（DBOperation、HttpResponse）。
已知限制：
1. 接口只做签名约束，方法体为空；实现方漏实现抽象方法时，实例化才由 ABC 报错，导入时不报。
2. enqueue 是受理制：返回只代表已入队，落库由后台消费者稍后完成；未启动或已停止抛 WriteQueueException，队列满抛 WriteQueueFullException。
3. IWriteQueue.stop() 必须有时间上限，已受理未落库的条目必须给出明确数量，不得静默丢弃；未启动时调用直接返回。
4. 非 2xx 照常返回 HttpResponse，网络层失败才抛 HttpClientException；timeout 为整次请求上限，connect_timeout 仅约束建连。
5. IHttpClient.get 的 family 缺省 AF_UNSPEC 由系统选；传 AF_INET / AF_INET6 只走该地址族，双栈主机须钉死地址族才能分别问出两族出口 IP。
6. IConfigManager 的 get_config 返回内部对象而非副本、绝不返回 None，调用方不得就地修改；apply 先替换再通知，不得因单个订阅者失败而中断或抛异常。
"""

from abc import ABC, abstractmethod
from typing import Callable, Optional
from core.domain.models import DBOperation, HttpResponse


class IWriteQueue(ABC):
    @abstractmethod
    async def start(self) -> None:
        pass

    @abstractmethod
    async def stop(self) -> None:
        pass

    @abstractmethod
    async def enqueue(self, operation: DBOperation) -> None:
        pass

    @abstractmethod
    def apply_config(self, config: 'Config') -> None:
        pass


class IHttpClient(ABC):
    @abstractmethod
    async def get(self, url: str, proxy: Optional[str] = None,
                  timeout: Optional[int] = None,
                  connect_timeout: Optional[float] = None,
                  family: Optional[int] = None,
                  **kwargs) -> HttpResponse:
        pass

    @abstractmethod
    async def post(self, url: str, data: Optional[dict] = None,
                   json: Optional[dict] = None,
                   proxy: Optional[str] = None,
                   timeout: Optional[int] = None,
                   connect_timeout: Optional[float] = None,
                   **kwargs) -> HttpResponse:
        pass

    @abstractmethod
    def apply_config(self, config: 'Config') -> None:
        pass

    @abstractmethod
    async def close(self) -> None:
        pass


class IConfigManager(ABC):
    @abstractmethod
    def get_config(self) -> 'Config':
        pass

    @abstractmethod
    async def apply(self, new_config: 'Config') -> None:
        pass

    @abstractmethod
    def subscribe(self, callback: Callable[['Config'], None]) -> None:
        pass
