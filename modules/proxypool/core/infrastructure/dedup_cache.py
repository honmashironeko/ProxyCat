"""
模块名称：modules.proxypool.core.infrastructure.dedup_cache
功能描述：代理去重的内存索引，键为 "ip:port"；抓取流程在入库前用它判断代理是否已存在。键必须带端口：
          数据库对 (ip, port) 建了唯一约束，同一 IP 的不同端口是两个不同的代理，只按 IP 去重会误丢。
职责边界：负责：维护全量 ip:port 集合与 contains 判断、批量增删；不负责：数据库写入（写队列落库后由调用方同步）、入库规则（见 PluginManager）、跨进程一致性。
关键依赖：ConnectionPool（加载与重建时取读连接）。
已知限制：
1. 纯内存，多进程部署时每个进程各持一份，只能靠 rebuild() 周期性纠偏。
2. 未初始化时集合为空，contains() 会把所有代理判为不存在；判断前先看 is_initialized，漏判由数据库 (ip, port) 唯一约束兜底。
3. contains() 同步且不加锁，依赖集合替换与增删的原子性；增删在 asyncio.Lock 内异步完成。
4. rebuild() 不改变 is_initialized，只用于初始化之后的漂移纠偏。
5. load_from_db() 抛异常时缓存内容与状态都不变。
"""

import asyncio
import logging
from typing import Set

logger = logging.getLogger(__name__)


class DedupCache:
    def __init__(self):
        self._cache: Set[str] = set()
        self._lock = asyncio.Lock()
        self._initialized = False

    @property
    def is_initialized(self) -> bool:
        return self._initialized

    async def load_from_db(self, connection_pool: 'ConnectionPool') -> None:
        await self._reload_from_db(connection_pool, mark_initialized=True)
        logger.info(f"去重缓存已加载: {len(self._cache)} 个 ip:port 对")

    def contains(self, ip: str, port: int) -> bool:
        return f"{ip}:{port}" in self._cache

    async def add_batch(self, pairs: list[tuple[str, int]]) -> None:
        if not pairs:
            return
        async with self._lock:
            for ip, port in pairs:
                self._cache.add(f"{ip}:{port}")

    async def remove_batch(self, pairs: list[tuple[str, int]]) -> None:
        if not pairs:
            return
        async with self._lock:
            for ip, port in pairs:
                self._cache.discard(f"{ip}:{port}")

    async def rebuild(self, connection_pool: 'ConnectionPool') -> None:
        await self._reload_from_db(connection_pool, mark_initialized=False)
        logger.info(f"去重缓存已重建: {len(self._cache)} 个 ip:port 对")

    async def _reload_from_db(self, connection_pool: 'ConnectionPool',
                              *, mark_initialized: bool) -> None:
        async with connection_pool.acquire_reader() as db:
            async with db.execute("SELECT ip, port FROM proxies") as cursor:
                rows = await cursor.fetchall()
                async with self._lock:
                    self._cache = {f"{row[0]}:{row[1]}" for row in rows}
                    if mark_initialized:
                        self._initialized = True
