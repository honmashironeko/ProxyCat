"""
模块名称：modules.proxypool.core.services.geo_resolver
功能描述：出口 IP 归属地的异步解析流水线：验证阶段只上报出口 IP，查询与写库全部由后台消费者完成，不占验证的墙钟时间。
职责边界：负责：出口 IP 去重入队、后台消费解析、结果合并写回 region 系列字段、随应用启停；
          不负责：查询与缓存（GeoIPService）、出口 IP 来源与验证时机（validator）。
关键依赖：IGeoIPService、IWriteQueue、GeoName / ProxyFilter / DBOperation、标准库 asyncio。
已知限制：
  1. 队列、去重集合与尝试计数为进程内内存态，重启后未处理请求丢失；出口 IP 不变的代理要等下一次完整评估或启动补漏（一次最多 5000 条）才重新入队。
  2. 队列满时丢弃新请求且不阻塞调用方；每条任务无论成败都会从 _pending 移除并 task_done()，漏掉会让该 IP 不再被重新入队。
  3. 同一 IP 在 1800 秒窗口内最多尝试 3 次，窗口过期自动重新计数，解析成功即清零。
  4. 更新以 where={"real_ip": ip} 定位，同一出口 IP 的一批代理共享一次查询与一次 UPDATE；中英地名各自独立判断，两套都没拿到时不写库、也不清尝试计数。
  5. 与库里旧值合并时，只有两侧都是真实国家名且不同才整条以本次为准，其余情况本次缺省的字段沿用旧值。
  6. 所有方法必须在池的事件循环线程内调用；实例不加锁，队列、去重集合与尝试计数都不做跨线程同步。
"""

import asyncio
import logging
import time
from typing import Optional

from core.domain.models import DBOperation, GeoName, ProxyFilter
from core.interfaces.infrastructure import IWriteQueue
from core.interfaces.services import IGeoIPService

logger = logging.getLogger(__name__)

_QUEUE_SIZE = 2000

_WORKER_COUNT = 4

_ATTEMPT_WINDOW_SECONDS = 1800.0
_MAX_ATTEMPTS_PER_IP_IN_WINDOW = 3

_AUTO_RECOMPUTE_LIMIT = 5000


_UNKNOWN_NAME = "未知"


def _known_name(value: Optional[str]) -> str:
    text = (value or "").strip()
    return text if text and text != _UNKNOWN_NAME else ""


def _merge_with_existing(name: GeoName, existing: Optional[dict], suffix: str) -> GeoName:
    if not existing:
        return name

    old_country = _known_name(existing.get("country" + suffix))
    new_country = _known_name(name.country)
    if old_country and new_country and old_country != new_country:
        return name

    country = name.country
    if not new_country:
        country = old_country or name.country

    province = name.province
    if province == _UNKNOWN_NAME:
        province = existing.get("province" + suffix) or _UNKNOWN_NAME

    city = name.city
    if city == _UNKNOWN_NAME:
        city = existing.get("city" + suffix) or _UNKNOWN_NAME

    return GeoName(country=country, province=province, city=city)


class GeoResolver:

    def __init__(
        self,
        geoip_service: IGeoIPService,
        write_queue: IWriteQueue,
        proxy_repository=None,
        geodb=None,
    ):
        self._geoip = geoip_service
        self._write_queue = write_queue
        self._repository = proxy_repository
        self._geodb = geodb

        self._queue: asyncio.Queue = asyncio.Queue(maxsize=_QUEUE_SIZE)
        self._pending: set[str] = set()
        self._attempts: dict[str, tuple[float, int]] = {}
        self._workers: list[asyncio.Task] = []
        self._running = False
        self._resolved_count = 0
        self._dropped_count = 0

    async def start(self) -> bool:
        if self._running:
            return False

        self._running = True
        self._workers = [
            asyncio.create_task(self._consume(), name=f"geo_resolver_{index}")
            for index in range(_WORKER_COUNT)
        ]
        logger.info(
            "归属地解析流水线已启动（队列容量 %d，并发 %d）", _QUEUE_SIZE, _WORKER_COUNT
        )
        await self._backfill_missing()
        return True

    async def _backfill_missing(self) -> None:
        if self._repository is None:
            return

        offline_ready = bool(self._geodb is not None and self._geodb.available)
        try:
            page = 1
            queued = 0
            skipped = 0
            while True:
                proxies = await self._repository.find(
                    ProxyFilter(is_valid=True), page=page, page_size=5000
                )
                if not proxies:
                    break
                for proxy in proxies:
                    if not proxy.real_ip:
                        continue
                    no_region = (
                        not (proxy.region_en or "").strip()
                        and (proxy.region or "未知") == "未知"
                    )
                    missing_codes = offline_ready and proxy.country_code is None
                    if not (no_region or missing_codes):
                        continue
                    if queued >= _AUTO_RECOMPUTE_LIMIT:
                        skipped += 1
                        continue
                    if self.schedule(proxy.real_ip):
                        queued += 1
                if len(proxies) < 5000:
                    break
                page += 1

            if queued:
                logger.info(
                    "归属地补漏：%d 个代理入队（没有地区 / 缺规范代码）", queued
                )
            if skipped:
                logger.info(
                    "归属地补漏：另有 %d 个超出本次上限（%d）未入队，"
                    "可在面板上手动触发「重算归属地」",
                    skipped, _AUTO_RECOMPUTE_LIMIT,
                )
        except Exception as e:
            logger.warning("归属地补漏失败（非致命）: %s", e)

    async def stop(self) -> None:
        self._running = False

        workers, self._workers = self._workers, []
        for worker in workers:
            if not worker.done():
                worker.cancel()
        if workers:
            await asyncio.gather(*workers, return_exceptions=True)

        abandoned = len(self._pending)
        self._pending.clear()
        self._attempts.clear()
        while not self._queue.empty():
            try:
                self._queue.get_nowait()
                self._queue.task_done()
            except asyncio.QueueEmpty:
                break

        if abandoned or self._resolved_count or self._dropped_count:
            logger.info(
                "归属地解析流水线已停止（已解析 %d 条，放弃 %d 条，队列满丢弃 %d 条）",
                self._resolved_count, abandoned, self._dropped_count,
            )

    def schedule(self, ip: str) -> bool:
        if not self._running or not ip:
            return False

        if ip in self._pending:
            return False

        now = time.monotonic()
        window_start, count = self._attempts.get(ip, (now, 0))
        if now - window_start >= _ATTEMPT_WINDOW_SECONDS:
            window_start, count = now, 0
        if count >= _MAX_ATTEMPTS_PER_IP_IN_WINDOW:
            logger.debug("归属地解析: %s 在本窗口内已尝试 %d 次，跳过", ip, count)
            return False

        try:
            self._queue.put_nowait(ip)
        except asyncio.QueueFull:
            self._dropped_count += 1
            logger.debug("归属地解析队列已满，丢弃: %s", ip)
            return False

        self._pending.add(ip)
        self._attempts[ip] = (window_start, count + 1)
        return True

    async def _consume(self) -> None:
        while self._running:
            try:
                ip = await self._queue.get()
            except asyncio.CancelledError:
                raise

            try:
                await self._resolve(ip)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.debug("归属地解析失败 %s: %s", ip, e)
            finally:
                self._pending.discard(ip)
                self._queue.task_done()

    async def _load_existing_geo(self, ip: str) -> Optional[dict]:
        if self._repository is None:
            return None
        try:
            return await self._repository.get_geo_fields_by_real_ip(ip)
        except Exception as e:
            logger.debug("读取 %s 的现有归属地失败（按无旧值处理）: %s", ip, e)
            return None

    async def _resolve(self, ip: str) -> None:
        location = await self._geoip.get_location(ip)

        existing = await self._load_existing_geo(ip)
        zh = _merge_with_existing(location.zh, existing, suffix="")
        en = _merge_with_existing(location.en, existing, suffix="_en")

        updates: dict = {}
        if location.zh.is_known:
            updates.update({
                "region": zh.to_string(),
                "country": zh.country,
                "province": zh.province,
                "city": zh.city,
            })
        if location.en.is_known:
            updates.update({
                "region_en": en.to_string(),
                "country_en": en.country,
                "province_en": en.province,
                "city_en": en.city,
            })

        if location.source:
            updates["geo_source"] = location.source

        if location.country_code:
            updates.update({
                "country_code": location.country_code,
                "subdivision_code": location.subdivision_code,
            })

        if not updates:
            logger.debug("归属地查询未拿到任何信息，不写库: %s", ip)
            return

        self._attempts.pop(ip, None)

        await self._write_queue.enqueue(
            DBOperation(
                operation_type="update",
                table="proxies",
                data=updates,
                where={"real_ip": ip},
            )
        )
        self._resolved_count += 1
        logger.debug("归属地已解析: %s -> %s", ip, location.to_string())

    def stats(self) -> dict:
        return {
            "running": self._running,
            "workers": len(self._workers),
            "queued": self._queue.qsize(),
            "pending": len(self._pending),
            "resolved": self._resolved_count,
            "dropped": self._dropped_count,
        }
