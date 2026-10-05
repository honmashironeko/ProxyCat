"""
模块名称：modules.proxypool.core.infrastructure.config_manager
功能描述：配置的内存态与变更通知：持有当前生效的 Config 对象，登记订阅者，并在 apply 时把新配置推送给全部订阅者。
职责边界：负责：保存当前生效的 Config、登记订阅者、分发变更通知；不负责：配置文件的读写与持久化
          （见 modules.pool_config_ini）、配置字典到 Config 的解析（见 core.config.build_config）。
关键依赖：core.config.Config、core.interfaces.infrastructure.IConfigManager；标准库 asyncio、logging。
已知限制：
  1. get_config 返回内部持有的同一对象而非副本，调用方不得就地修改；改配置必须走 apply()，否则订阅者收不到通知。
  2. subscribe 按相等性去重，等值回调只登记一次；订阅后无法注销。
  3. 订阅者回调的异常被逐个捕获并记日志，不阻断其余订阅者，也不会从 apply() 抛出。
  4. apply() 先替换配置再通知，回调内 get_config() 读到的已是新配置；apply() 无并发保护，并发调用会相互覆盖。
  5. 回调按注册顺序串行等待，某个异步回调耗时过长会推迟其后订阅者的通知。
  6. 通知遍历订阅者列表期间新增的订阅者会在本轮通知中被调用。
"""

import asyncio
import logging
from typing import Callable, List

from core.config import Config
from core.interfaces.infrastructure import IConfigManager

logger = logging.getLogger(__name__)


class ConfigManager(IConfigManager):
    def __init__(self, config: Config):
        self._config: Config = config
        self._subscribers: List[Callable[[Config], None]] = []
        logger.info("配置管理器已初始化")

    def get_config(self) -> Config:
        return self._config

    async def apply(self, new_config: Config) -> None:
        logger.info("开始应用新配置")
        self._config = new_config
        await self._notify_subscribers(new_config)
        logger.info("新配置已应用")

    def subscribe(self, callback: Callable[[Config], None]) -> None:
        if callback not in self._subscribers:
            self._subscribers.append(callback)
            name = callback.__name__ if hasattr(callback, '__name__') else str(callback)
            logger.info(f"已订阅配置变更通知: {name}")

    async def _notify_subscribers(self, new_config: Config) -> None:
        logger.info(f"通知 {len(self._subscribers)} 个订阅者配置已变更")

        for callback in self._subscribers:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(new_config)
                else:
                    callback(new_config)
            except Exception as e:
                name = callback.__name__ if hasattr(callback, '__name__') else str(callback)
                logger.error(f"配置变更回调执行失败 {name}: {e}", exc_info=True)
