"""
模块名称：modules.proxypool.core.data_cleaner
功能描述：代理池数据库的按需维护：优化（ANALYZE / REINDEX / VACUUM）与统计查询，供面板的「数据库」页在用户操作时调用。
职责边界：负责：数据库优化与统计查询；不负责：删除代理（见 auto_revalidator 的自动清理判据）、批量落库（见 core.data.write_queue）与调度触发。
关键依赖：ConnectionPool（读连接池与 db_path）、aiosqlite。
已知限制：
  1. VACUUM 不能在事务内执行，优化走 aiosqlite.connect 底层连接而非连接池的 acquire_writer。
  2. 优化持锁时长不受限；池内写方等待上限约 5 秒后报错，重试仍失败的操作会被丢弃。
  3. 异常收敛为返回值（空字典 / False）并记日志，不向外抛；调用方拿到空字典时需按「无数据」处理。
  4. db_size_mb 在库文件不存在时为 0。
  5. 各方法按需调用，没有内部调度，调用频率与时机由使用者决定。
"""

import logging
import aiosqlite

logger = logging.getLogger(__name__)


class DataCleaner:
    def __init__(self, connection_pool: 'ConnectionPool'):
        self._pool = connection_pool
        logger.info("数据库维护器已初始化")

    async def get_database_stats(self) -> dict:
        try:
            async with self._pool.acquire_reader() as db:
                stats = {}

                async with db.execute("SELECT COUNT(*) FROM proxies") as cursor:
                    stats['total_proxies'] = (await cursor.fetchone())[0]

                async with db.execute(
                    "SELECT COUNT(*) FROM proxies WHERE is_valid = 1"
                ) as cursor:
                    stats['valid_proxies'] = (await cursor.fetchone())[0]

                async with db.execute(
                    "SELECT COUNT(*) FROM proxies WHERE is_valid = 0"
                ) as cursor:
                    stats['invalid_proxies'] = (await cursor.fetchone())[0]

            import os
            if os.path.exists(self._pool.db_path):
                stats['db_size_mb'] = os.path.getsize(self._pool.db_path) / (1024 * 1024)
            else:
                stats['db_size_mb'] = 0

            return stats

        except Exception as e:
            logger.error(f"获取数据库统计信息失败: {e}", exc_info=True)
            return {}

    async def optimize_database(self) -> bool:
        try:
            logger.info("开始优化数据库...")

            async with aiosqlite.connect(self._pool.db_path) as db:
                await db.execute("PRAGMA busy_timeout=5000")
                await db.execute("ANALYZE")
                await db.execute("REINDEX")
                await db.execute("VACUUM")
                await db.commit()

            logger.info("数据库优化完成")
            return True

        except Exception as e:
            logger.error(f"数据库优化失败: {e}", exc_info=True)
            return False
