"""
模块名称：modules.proxypool.core.data.write_queue
功能描述：异步写入队列，把调用方零散的数据库写操作聚合为批量执行。enqueue 一条 DBOperation
         后立即返回，消费者凑够 batch_size 或等满 consumer_timeout 后按操作类型分组写库。
职责边界：负责：写操作缓冲、按批分组执行、失败重试与指数退避、去重缓存同步维护、队列容量背压。
          不负责：DBOperation 构造与 where 语义（由上游决定）、具体 SQL 与事务实现（见 core.data.repositories）。
关键依赖：core.interfaces.repository、core.interfaces.infrastructure、core.domain.models、
          core.domain.exceptions、core.infrastructure.dedup_cache（可选注入）、modules.modules。
已知限制：
1. enqueue 成功只代表入队、不代表落库；重试用尽、组内降级写不进、stop() 排空超时都会真丢弃条目并计入 dropped_count。
2. 只处理 proxies 表的 insert／update／delete 条目，其余静默跳过；update 缺 where、delete 缺 where.id 时跳过并记 warning。
3. 组间按「插入 → 更新 → 删除」固定顺序执行，不可更改：同批里刚插入的记录随后更新才匹配得到行；单组重试用尽不影响其余组，失败组汇总成一条 WriteQueueException 上报。
4. 重试按分组独立，最多 max(1, max_retries) 次；第 k 次失败后等 _RETRY_BASE_DELAY*2^k 秒再试，k 从 0 起，首次尝试不等待；重试函数须可重复执行。
5. 去重缓存只登记确实写入库的 (ip, port)：把写失败的也登记会让后续抓取一直跳过这些地址，直到缓存重建。
6. 须在同一事件循环内单消费者使用；队列满时 enqueue 抛 WriteQueueFullException；apply_config 只热更新 batch_size、max_retries。
"""

import asyncio
import logging
from typing import Optional, TYPE_CHECKING

from core.interfaces.infrastructure import IWriteQueue
from core.interfaces.repository import IProxyRepository
from core.domain.models import DBOperation, Proxy
from core.domain.exceptions import WriteQueueException, WriteQueueFullException
from modules.modules import sanitize_proxy

if TYPE_CHECKING:
    from core.infrastructure.dedup_cache import DedupCache

logger = logging.getLogger(__name__)

_MAX_RETRIES: int = 3

_DRAIN_TIMEOUT: float = 15.0
_RETRY_BASE_DELAY: float = 0.1


class AsyncWriteQueue(IWriteQueue):
    def __init__(
        self,
        proxy_repository: IProxyRepository,
        batch_size: int = 100,
        consumer_timeout: float = 0.1,
        dedup_cache: 'DedupCache' = None,
        max_queue_size: int = 10000,
        max_retries: int = _MAX_RETRIES,
    ):
        self._proxy_repository = proxy_repository
        self._max_queue_size = max(1, max_queue_size)
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=self._max_queue_size)
        self._batch_size = max(1, batch_size)
        self._consumer_timeout = consumer_timeout
        self._dedup_cache: Optional['DedupCache'] = dedup_cache
        self._max_retries = max_retries
        self._consumer_task: Optional[asyncio.Task] = None
        self._running = False
        self._drain_timeout = _DRAIN_TIMEOUT
        self._dropped_operations = 0
        self._pending_operations = 0
        self._group_dropped = 0

    @property
    def dropped_count(self) -> int:
        return self._dropped_operations

    def _mark_done(self, count: int) -> None:
        for _ in range(count):
            self._pending_operations -= 1
            self._queue.task_done()


    async def start(self) -> None:
        if self._running:
            logger.warning("AsyncWriteQueue 已经在运行")
            return

        try:
            self._running = True
            self._consumer_task = asyncio.create_task(self._consumer())
            logger.info("AsyncWriteQueue 已启动")
        except Exception as e:
            self._running = False
            raise WriteQueueException(f"启动写入队列失败: {str(e)}")

    async def stop(self) -> None:
        if not self._running:
            return

        try:
            self._running = False

            try:
                await asyncio.wait_for(self._queue.join(), timeout=self._drain_timeout)
            except asyncio.TimeoutError:
                abandoned = self._queue.qsize() + self._pending_operations
                self._dropped_operations += abandoned
                logger.error(
                    "写入队列在 %.0f 秒内未能排空，放弃 %d 条待写操作"
                    "（累计丢弃 %d 条），停止消费者",
                    self._drain_timeout, abandoned, self._dropped_operations,
                )

            if self._consumer_task:
                self._consumer_task.cancel()
                try:
                    await self._consumer_task
                except asyncio.CancelledError:
                    pass

            logger.info("AsyncWriteQueue 已停止")
        except Exception as e:
            raise WriteQueueException(f"停止写入队列失败: {str(e)}")

    async def enqueue(self, operation: DBOperation) -> None:
        if not self._running:
            raise WriteQueueException("写入队列未启动或已停止")

        try:
            self._queue.put_nowait(operation)
        except asyncio.QueueFull:
            raise WriteQueueFullException(
                f"写入队列已满（当前容量 {self._max_queue_size}），"
                f"请等待消费者处理后重试"
            )
        except Exception as e:
            raise WriteQueueException(f"加入队列失败: {str(e)}")

    def apply_config(self, config: 'Config') -> None:
        old_batch_size = self._batch_size
        old_max_retries = self._max_retries

        self._batch_size = max(1, config.write_queue.batch_size)
        self._max_retries = config.write_queue.max_retries

        logger.info(
            f"AsyncWriteQueue 配置已更新: "
            f"batch_size={old_batch_size}->{self._batch_size}, "
            f"max_retries={old_max_retries}->{self._max_retries}"
        )


    async def _consumer(self) -> None:
        while True:
            operations: list[DBOperation] = []

            try:
                while len(operations) < self._batch_size:
                    try:
                        operation = await asyncio.wait_for(
                            self._queue.get(),
                            timeout=self._consumer_timeout,
                        )
                        operations.append(operation)
                        self._pending_operations += 1
                    except asyncio.TimeoutError:
                        break

                if not operations:
                    if not self._running:
                        break
                    continue

                dropped = await self._execute_batch(operations)
                if dropped:
                    self._dropped_operations += dropped

                self._mark_done(len(operations))

            except asyncio.CancelledError:
                self._mark_done(len(operations))
                raise
            except Exception as e:
                self._dropped_operations += len(operations)
                logger.error(
                    "丢弃 %d 条始终写不进去的操作（累计丢弃 %d 条）: %s",
                    len(operations), self._dropped_operations, e, exc_info=True,
                )
                self._mark_done(len(operations))


    async def _execute_batch(self, operations: list[DBOperation]) -> int:
        self._group_dropped = 0
        insert_proxy_ops: list[DBOperation] = []
        update_proxy_ops: list[DBOperation] = []
        delete_proxy_ops: list[DBOperation] = []

        for op in operations:
            if op.table != "proxies":
                continue
            if op.operation_type == "insert":
                insert_proxy_ops.append(op)
            elif op.operation_type == "update":
                update_proxy_ops.append(op)
            elif op.operation_type == "delete":
                delete_proxy_ops.append(op)

        failures: list[tuple[str, Exception]] = []

        groups = (
            ("批量插入代理", self._batch_insert_proxies, insert_proxy_ops),
            ("批量更新代理", self._batch_update_proxies, update_proxy_ops),
            ("批量删除代理", self._batch_delete_proxies, delete_proxy_ops),
        )

        for label, handler, ops in groups:
            if not ops:
                continue
            try:
                await self._retry_with_backoff(handler, ops, group_label=label)
            except Exception as e:
                logger.error("%s 最终失败: %s", label, e)
                failures.append((label, e))

        if failures:
            detail = "; ".join(f"{label}: {err}" for label, err in failures)
            raise WriteQueueException(
                f"批量写入有 {len(failures)} 组失败 —— {detail}"
            )

        return self._group_dropped


    async def _batch_insert_proxies(self, ops: list[DBOperation]) -> None:
        data_list: list[dict] = []
        for op in ops:
            if isinstance(op.data, list):
                data_list.extend(op.data)
            else:
                data_list.append(op.data)

        if not data_list:
            return

        proxies = [self._dict_to_proxy(d) for d in data_list]

        written: list[Proxy] = []
        try:
            inserted_count = await self._proxy_repository.add_batch(proxies)
            written = list(proxies)
        except Exception as e:
            logger.warning("批量插入失败（%s），改为逐条写入以避免整批丢失", e)
            inserted_count = 0
            for proxy in proxies:
                try:
                    inserted_count += await self._proxy_repository.add_batch([proxy])
                    written.append(proxy)
                except Exception as inner:
                    logger.warning("跳过一条无法写入的代理 %s: %s",
                                   sanitize_proxy(proxy.proxy_url), inner)

        if len(written) < len(proxies):
            lost = len(proxies) - len(written)
            self._group_dropped += lost
            logger.error(
                "批量插入丢行: %d/%d 条写不进库（累计丢弃 %d 条）",
                lost, len(proxies), self._dropped_operations + self._group_dropped,
            )

        logger.debug(f"批量插入代理完成: {inserted_count} 条")

        if self._dedup_cache is not None:
            dedup_pairs: list[tuple[str, int]] = [
                (p.ip, p.port) for p in written
            ]
            if dedup_pairs:
                await self._dedup_cache.add_batch(dedup_pairs)

    async def _batch_update_proxies(self, ops: list[DBOperation]) -> None:
        by_where: dict[tuple, list[DBOperation]] = {}
        for op in ops:
            if not op.where:
                logger.warning(f"跳过缺少 where 的更新操作: {op}")
                continue
            by_where.setdefault(tuple(sorted(op.where)), []).append(op)

        for where_keys, group in by_where.items():
            if where_keys == ("id",):
                updates = [
                    (op.where["id"], op.data) for op in group if op.data
                ]
                if not updates:
                    continue
                affected = await self._proxy_repository.update_batch(updates)
                logger.debug(
                    f"批量更新代理完成: 提交 {len(updates)} 条，受影响 {affected} 行"
                )
                continue

            for op in group:
                if not op.data:
                    continue
                affected = await self._proxy_repository.update_where(
                    dict(op.where), op.data
                )
                logger.debug(
                    f"按条件更新代理完成: {op.where}，受影响 {affected} 行"
                )

    async def _batch_delete_proxies(self, ops: list[DBOperation]) -> None:
        proxy_ids: list[int] = []
        dedup_pairs: list[tuple[str, int]] = []

        for op in ops:
            if not op.where or "id" not in op.where:
                logger.warning(f"跳过缺少 where.id 的删除操作: {op}")
                continue
            proxy_ids.append(op.where["id"])

            ip = op.where.get("ip")
            port = op.where.get("port")
            if ip is not None and port is not None:
                dedup_pairs.append((ip, int(port)))

        if not proxy_ids:
            return

        deleted = await self._proxy_repository.delete_batch(proxy_ids)
        logger.debug(f"批量删除代理完成: 提交 {len(proxy_ids)} 条，实际删除 {deleted} 行")

        if self._dedup_cache is not None and dedup_pairs:
            await self._dedup_cache.remove_batch(dedup_pairs)


    async def _retry_with_backoff(
        self,
        func,
        ops: list[DBOperation],
        group_label: str,
    ) -> None:
        max_attempts = max(1, self._max_retries)
        for attempt in range(max_attempts):
            try:
                await func(ops)
                return
            except Exception as e:
                if attempt < max_attempts - 1:
                    delay = _RETRY_BASE_DELAY * (2 ** attempt)
                    logger.warning(
                        f"{group_label}失败，第 {attempt + 1}/{max_attempts} 次尝试"
                        f"（{delay:.2f}s 后重试）: {e}"
                    )
                    await asyncio.sleep(delay)
                else:
                    logger.error(
                        f"{group_label}失败，已尝试 {max_attempts} 次后放弃: {e}",
                        exc_info=True,
                    )
                    raise


    def _dict_to_proxy(self, data: dict) -> Proxy:
        from datetime import datetime

        return Proxy(
            id=data.get("id"),
            protocol=data.get("protocol", ""),
            ip=data.get("ip", ""),
            port=data.get("port", 0),
            username=data.get("username"),
            password=data.get("password"),
            region=data.get("region", "未知"),
            country=data.get("country", "未知"),
            province=data.get("province", "未知"),
            city=data.get("city", "未知"),
            region_en=data.get("region_en"),
            country_en=data.get("country_en"),
            province_en=data.get("province_en"),
            city_en=data.get("city_en"),
            delay_ms=data.get("delay_ms"),
            is_valid=data.get("is_valid", True),
            is_favorite=data.get("is_favorite", False),
            failure_count=data.get("failure_count", 0),
            real_ip=data.get("real_ip"),
            source_plugin=data.get("source_plugin", ""),
            created_at=(
                datetime.fromisoformat(data["created_at"])
                if data.get("created_at")
                else None
            ),
            validated_at=(
                datetime.fromisoformat(data["validated_at"])
                if data.get("validated_at")
                else None
            ),
            health_score=data.get("health_score", 0.0),
            success_count=data.get("success_count", 0),
            total_checks=data.get("total_checks", 0),
            anonymity_level=data.get("anonymity_level", "unverified"),
            anonymity_fallback=bool(data.get("anonymity_fallback", 0)),
            supports_https=data.get("supports_https", False),
            supports_http=data.get("supports_http", False),
            quality_assessed_at=(
                datetime.fromisoformat(data["quality_assessed_at"])
                if data.get("quality_assessed_at")
                else None
            ),
            avg_delay_ms=data.get("avg_delay_ms"),
            delay_variance=data.get("delay_variance"),
            last_valid_at=(
                datetime.fromisoformat(data["last_valid_at"])
                if data.get("last_valid_at")
                else None
            ),
            total_valid_seconds=data.get("total_valid_seconds", 0.0),
            probe_success_count=data.get("probe_success_count", 0),
            probe_total_count=data.get("probe_total_count", 0),
            country_code=data.get("country_code"),
            subdivision_code=data.get("subdivision_code"),
            geo_source=data.get("geo_source"),
        )
