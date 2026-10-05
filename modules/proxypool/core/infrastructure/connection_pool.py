"""
模块名称：modules.proxypool.core.infrastructure.connection_pool
功能描述：SQLite 异步连接池（WAL 模式）。写连接固定 1 个并由 asyncio.Lock 串行化，读连接按 max_readers 池化、经 asyncio.Queue 分发。
连接在 initialize() 时一次性建立并长期复用；写连接不并行是因为 SQLite 写操作文件级互斥，多开只会互相阻塞。
职责边界：负责：连接生命周期与借出归还、PRAGMA 调优、启动时清理 WAL 孤儿文件、关闭时关停池中的读连接与写连接。
不负责：SQL 构造与执行、事务之上的业务语义（见 core.data.repositories）、数据库文件创建与建表（见 core.database）。
关键依赖：aiosqlite（第三方异步 SQLite 驱动）。
已知限制：
1. 使用前必须显式 await initialize()；未初始化时任何 acquire 抛 RuntimeError，初始化失败不回收已建连接，应丢弃实例重建。
2. 读连接归还后被下一个借用者复用，块内不得留下未读完的游标或未结束的事务；池空时阻塞等待且无超时。
3. 读连接预设 row_factory=aiosqlite.Row 与 PRAGMA query_only=ON，任何写入抛 OperationalError。
4. acquire_writer 的整个 async with 块同属一个事务：正常退出自动 commit，异常退出自动 rollback。
5. 回滚捕获 BaseException：任务取消时若不回滚，事务保持打开而锁已释放，下一个持锁者提交会带上半截写入。
6. close() 等待借出的读连接归还，上限 30 秒；超时只关闭池中的读连接，之后归还的读连接无人关闭；实例须在单一事件循环内使用，WAL 孤儿文件被占用时跳过清理。
"""

import asyncio
import aiosqlite
import logging
import os
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)


class ConnectionPool:
    def __init__(self, db_path: str, max_readers: int = 4):
        self._db_path = db_path
        self._max_readers = max_readers

        self._writer: aiosqlite.Connection | None = None
        self._write_lock = asyncio.Lock()

        self._reader_pool: asyncio.Queue[aiosqlite.Connection] = asyncio.Queue()

        self._outstanding_readers: int = 0
        self._all_returned: asyncio.Event = asyncio.Event()
        self._all_returned.set()
        self._closing: bool = False

        self._initialized = False

    @property
    def db_path(self) -> str:
        return self._db_path

    async def initialize(self) -> None:
        if self._initialized:
            logger.debug("连接池已初始化，跳过重复调用")
            return

        wal_path = self._db_path + "-wal"
        if os.path.exists(wal_path):
            try:
                tmp = await aiosqlite.connect(self._db_path)
                await tmp.execute("PRAGMA busy_timeout=2000")
                await tmp.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                await tmp.close()
                logger.info("WAL 孤儿文件已清理: %s", wal_path)
            except Exception:
                logger.debug("WAL 文件被占用或无法访问，跳过清理: %s", wal_path)

        self._writer = await aiosqlite.connect(self._db_path)
        await self._writer.execute("PRAGMA journal_mode=WAL")
        await self._writer.execute("PRAGMA synchronous=NORMAL")
        await self._writer.execute("PRAGMA cache_size=-8192")
        await self._writer.execute("PRAGMA busy_timeout=5000")
        await self._writer.execute("PRAGMA mmap_size=67108864")

        for i in range(self._max_readers):
            reader = await aiosqlite.connect(self._db_path)
            await reader.execute("PRAGMA journal_mode=WAL")
            await reader.execute("PRAGMA cache_size=-4096")
            await reader.execute("PRAGMA busy_timeout=5000")
            await reader.execute("PRAGMA mmap_size=67108864")
            await reader.execute("PRAGMA query_only=ON")
            reader.row_factory = aiosqlite.Row
            await self._reader_pool.put(reader)

        self._closing = False
        self._outstanding_readers = 0
        self._all_returned.set()

        self._initialized = True
        logger.info(
            f"连接池已初始化: db={self._db_path}, "
            f"writer=1, readers={self._max_readers}, mode=WAL"
        )

    @asynccontextmanager
    async def acquire_reader(self):
        if not self._initialized:
            raise RuntimeError("连接池尚未初始化，请先调用 initialize()")

        if self._closing:
            raise RuntimeError("连接池正在关闭，无法获取读连接")

        conn = await self._reader_pool.get()

        self._outstanding_readers += 1
        self._all_returned.clear()

        try:
            yield conn
        finally:
            await self._reader_pool.put(conn)

            self._outstanding_readers -= 1
            if self._outstanding_readers <= 0:
                self._outstanding_readers = 0
                self._all_returned.set()

    @asynccontextmanager
    async def acquire_writer(self):
        if not self._initialized:
            raise RuntimeError("连接池尚未初始化，请先调用 initialize()")

        async with self._write_lock:
            try:
                yield self._writer
                await self._writer.commit()
            except BaseException:
                await self._writer.rollback()
                raise

    async def close(self) -> None:
        if not self._initialized:
            return

        self._closing = True

        if self._outstanding_readers > 0:
            logger.info(
                f"等待 {self._outstanding_readers} 个借出的读连接归还..."
            )
            try:
                await asyncio.wait_for(self._all_returned.wait(), timeout=30.0)
            except asyncio.TimeoutError:
                logger.warning(
                    f"等待读连接归还超时（30秒），"
                    f"仍有 {self._outstanding_readers} 个读连接未归还，强制关闭"
                )

        closed_readers = 0
        while not self._reader_pool.empty():
            try:
                conn = self._reader_pool.get_nowait()
                await conn.close()
                closed_readers += 1
            except asyncio.QueueEmpty:
                break
            except Exception as e:
                logger.warning(f"关闭读连接时出错: {e}")

        if self._writer:
            try:
                await self._writer.close()
            except Exception as e:
                logger.warning(f"关闭写连接时出错: {e}")
            self._writer = None

        self._initialized = False
        self._closing = False
        self._outstanding_readers = 0
        self._all_returned.set()

        logger.info(
            f"连接池已关闭: 回收读连接 {closed_readers} 个, 写连接 1 个"
        )
