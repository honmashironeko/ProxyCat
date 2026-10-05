"""
模块名称：modules.proxypool.core.services.geoip
功能描述：IP 归属地查询服务：查本地离线库并按 IP 缓存，一次查询给出中英两套名称与规范代码。
职责边界：负责：查离线库、按 IP 缓存、渲染中英名称与代码。
          不负责：数据文件更新（core.infrastructure.geodb）、查询时机与结果写回（GeoResolver）。
关键依赖：core.infrastructure.geodb、core.services.geo_names、core.domain.models、core.interfaces.services。
已知限制：
1. 离线库缺失或损坏时不抛异常，一律返回全「未知」的 GeoLocation；load_database 返回 False 并记 WARNING。
2. 缓存 TTL 分两档：中英齐全 24 小时，只拿到一套或未查到 1 小时；上限 10000 条，超出后按写入时间淘汰最旧的一半。
3. 调用方须先看 is_known 再决定是否写库，否则「未知」会覆盖库里已有的归属地。
4. 缓存是进程内内存态且不加锁，所有读写都必须在池的事件循环线程内进行。
5. close() 只记日志、缓存保留，关闭不等同于失效。
6. 查询是内存映射上的二分查找、无 await 点，async 签名仅为满足 IGeoIPService 契约。
"""

import logging
import time
from typing import Optional

from core.interfaces.services import IGeoIPService
from core.domain.models import GeoLocation
from core.infrastructure.geodb import GeoDatabase
from core.services.geo_names import render_names

logger = logging.getLogger(__name__)

_CACHE_TTL_SECONDS = 24 * 3600

_PARTIAL_TTL_SECONDS = 3600

_MAX_CACHE_ENTRIES = 10000


class GeoIPService(IGeoIPService):

    def __init__(self, geodb=None):
        self._geodb = GeoDatabase() if geodb is None else geodb

        self._location_cache: dict[str, tuple[float, float, GeoLocation]] = {}

    def load_database(self) -> bool:
        if self._geodb.available:
            logger.info("离线归属地库已就绪（GeoLite2 + 纯真）")
            return True

        logger.warning(
            "离线归属地库不可用：数据文件缺失或损坏，所有代理的归属地都将是空的。"
            "可在面板的「代理池 → 数据库 → 归属地库」点「更新归属地库」下载，"
            "或执行 python -m core.infrastructure.geodb"
        )
        return False

    async def get_location(self, ip: str) -> GeoLocation:
        now = time.time()

        cached = self._location_cache.get(ip)
        if cached is not None:
            cached_at, ttl, location = cached
            if now - cached_at < ttl:
                return location
            del self._location_cache[ip]

        result = self._lookup_offline(ip)
        if result is None:
            self._location_cache[ip] = (now, _PARTIAL_TTL_SECONDS, GeoLocation())
            return GeoLocation()

        ttl = _CACHE_TTL_SECONDS if result.is_complete else _PARTIAL_TTL_SECONDS
        self._location_cache[ip] = (now, ttl, result)
        if len(self._location_cache) > _MAX_CACHE_ENTRIES:
            self._trim_location_cache()
        return result

    def _lookup_offline(self, ip: str) -> Optional[GeoLocation]:
        if self._geodb is None or not self._geodb.available:
            return None
        try:
            record = self._geodb.lookup(ip)
            if record is None:
                return None
            zh, en, untranslated = render_names(record)
        except Exception as e:
            logger.warning(f"离线归属地查询失败 {ip}: {e}")
            return None

        return GeoLocation(
            zh=zh,
            en=en,
            country_code=record.country_code,
            subdivision_code=record.subdivision_code,
            source=record.source,
            untranslated=untranslated,
        )

    def _trim_location_cache(self) -> None:
        entries = sorted(self._location_cache.items(), key=lambda item: item[1][0])
        for ip, _ in entries[:len(entries) // 2]:
            del self._location_cache[ip]

    def close(self) -> None:
        logger.debug("GeoIP 服务已关闭")
