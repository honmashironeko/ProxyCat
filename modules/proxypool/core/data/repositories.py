"""
模块名称：modules.proxypool.core.data.repositories
功能描述：proxies 与 plugin_configs 两张表的 SQLite 仓储实现，向上暴露领域对象
          （Proxy / PluginConfig）与少量统计、查询结果，不暴露数据库行与游标；
          行与对象转换、列白名单、SQL 拼装都收在模块内部。
职责边界：负责：两张表的增删改查、行到领域对象的映射、写入前的字段合法性校验；不负责：
          连接与事务管理（见 ConnectionPool）、业务规则（见 auto_revalidator）、缓存同步（见 DedupCache 的调用方）。
关键依赖：aiosqlite、core.interfaces.repository、core.domain.models、core.domain.exceptions。
已知限制：
1. 插入列集合分散在 _INSERT_COLUMNS、_proxy_values、_row_to_proxy 与 write_queue._dict_to_proxy，增列须同步；错位静默写错列。
2. 排序字段与 update_where 的键会拼进 SQL，因此都走白名单；白名单外的键被拒绝或回落，不会拼进 SQL。
3. 老库可能缺后加的列，读取靠 _safe_get 兜底，手写 SQL（如 get_stats）要自己接住 OperationalError；两个同名 _safe_get 的 NULL 语义不同。
4. upsert 冲突时 _PRESERVED_ON_CONFLICT 的列保留原值，其余列里地理、出口 IP、匿名度、探测计数仅在确实测到时覆盖，占位默认值不覆盖。
5. 异常映射：IntegrityError 只在 add/add_batch/save 转 DataValidationException，其余位置转 RepositoryException。
6. 数据库错误转 DatabaseConnectionException；find/count 的 InvalidParameterException 原样上抛。
7. find 排序回落：sort_by 不在白名单退回 delay_ms，sort_order 非 asc/desc 退回 asc；排序键为 NULL 的行统一排最后。
"""

import aiosqlite
import logging
from typing import List, Optional
from datetime import datetime
from core.interfaces.repository import IProxyRepository, IPluginConfigRepository
from core.domain.models import (
    ANONYMITY_LEVELS,
    SUPPORTED_PROTOCOLS,
    Proxy,
    PluginConfig,
    ProxyFilter,
)
from core.domain.exceptions import (
    RepositoryException,
    DataValidationException,
    DatabaseConnectionException,
    InvalidParameterException,
    QueryBuildException
)

logger = logging.getLogger(__name__)

_INSERT_COLUMNS = (
    "protocol, ip, port, username, password, region, country, province, city, "
    "region_en, country_en, province_en, city_en, "
    "delay_ms, is_valid, is_favorite, failure_count, real_ip, source_plugin, "
    "created_at, validated_at, health_score, success_count, total_checks, "
    "anonymity_level, anonymity_fallback, supports_https, supports_http, "
    "quality_assessed_at, "
    "avg_delay_ms, probe_success_count, probe_total_count, "
    "delay_variance, last_valid_at, total_valid_seconds, "
    "country_code, subdivision_code, geo_source"
)

_PRESERVED_ON_CONFLICT = (
    "ip", "port", "is_favorite", "created_at",
    "delay_variance", "last_valid_at", "total_valid_seconds",
)

_UNKNOWN_PLACEHOLDER = "未知"

_PLACEHOLDER_GUARDED_COLUMNS = ("region", "country", "province", "city")

_UNVERIFIED_GUARDED_COLUMNS = ("anonymity_level",)

_NULLABLE_MEASURED_COLUMNS = (
    "region_en", "country_en", "province_en", "city_en",
    "country_code", "subdivision_code", "geo_source",
    "real_ip", "delay_ms", "avg_delay_ms", "quality_assessed_at",
)

_FALSEY_PLACEHOLDER_COLUMNS = (
    "anonymity_fallback", "supports_https", "supports_http",
    "probe_success_count", "probe_total_count",
)

_WHERE_COLUMNS = frozenset({"id", "real_ip", "ip", "port", "source_plugin"})

_COLUMN_NAMES = tuple(
    column.strip() for column in _INSERT_COLUMNS.split(",")
)


def _conflict_set_expression(column: str) -> str:
    if column in _PLACEHOLDER_GUARDED_COLUMNS:
        return (f"CASE WHEN excluded.{column} IS NULL OR excluded.{column} = '{_UNKNOWN_PLACEHOLDER}' "
                f"THEN proxies.{column} ELSE excluded.{column} END")
    if column in _UNVERIFIED_GUARDED_COLUMNS:
        return (f"CASE WHEN excluded.{column} IS NULL OR excluded.{column} = 'unverified' "
                f"THEN proxies.{column} ELSE excluded.{column} END")
    if column in _NULLABLE_MEASURED_COLUMNS:
        return f"COALESCE(excluded.{column}, proxies.{column})"
    if column in _FALSEY_PLACEHOLDER_COLUMNS:
        return f"CASE WHEN excluded.{column} THEN excluded.{column} ELSE proxies.{column} END"
    return f"excluded.{column}"


_UPSERT_PROXY_SQL = (
    f"INSERT INTO proxies ({_INSERT_COLUMNS}) "
    f"VALUES ({', '.join('?' for _ in _COLUMN_NAMES)}) "
    "ON CONFLICT(ip, port) DO UPDATE SET "
    + ", ".join(
        f"{column} = {_conflict_set_expression(column)}"
        for column in _COLUMN_NAMES
        if column not in _PRESERVED_ON_CONFLICT
    )
)


def _proxy_values(proxy: Proxy) -> tuple:
    return (
        proxy.protocol,
        proxy.ip,
        proxy.port,
        proxy.username,
        proxy.password,
        proxy.region,
        proxy.country,
        proxy.province,
        proxy.city,
        proxy.region_en,
        proxy.country_en,
        proxy.province_en,
        proxy.city_en,
        proxy.delay_ms,
        int(proxy.is_valid),
        int(proxy.is_favorite),
        proxy.failure_count,
        proxy.real_ip,
        proxy.source_plugin,
        proxy.created_at.isoformat() if proxy.created_at else datetime.now().isoformat(),
        proxy.validated_at.isoformat() if proxy.validated_at else None,
        proxy.health_score,
        proxy.success_count,
        proxy.total_checks,
        proxy.anonymity_level,
        int(proxy.anonymity_fallback),
        int(proxy.supports_https),
        int(proxy.supports_http),
        proxy.quality_assessed_at.isoformat() if proxy.quality_assessed_at else None,
        proxy.avg_delay_ms,
        proxy.probe_success_count,
        proxy.probe_total_count,
        proxy.delay_variance,
        proxy.last_valid_at.isoformat() if proxy.last_valid_at else None,
        proxy.total_valid_seconds,
        proxy.country_code,
        proxy.subdivision_code,
        proxy.geo_source,
    )


class ProxyRepository(IProxyRepository):
    def __init__(self, connection_pool: 'ConnectionPool'):
        self._pool = connection_pool

    async def add(self, proxy: Proxy) -> int:
        try:
            self._validate_proxy(proxy)

            async with self._pool.acquire_writer() as db:
                cursor = await db.execute(_UPSERT_PROXY_SQL, _proxy_values(proxy))
                return cursor.lastrowid
        except aiosqlite.IntegrityError as e:
            raise DataValidationException(f"代理数据完整性错误: {str(e)}").with_message_key(
                "pool_repo_integrity_error", str(e))
        except aiosqlite.OperationalError as e:
            raise DatabaseConnectionException(f"数据库操作失败: {str(e)}")
        except (DataValidationException, DatabaseConnectionException):
            raise
        except Exception as e:
            raise RepositoryException(f"添加代理失败: {str(e)}")

    async def add_batch(self, proxies: List[Proxy]) -> int:
        if not proxies:
            return 0

        try:
            for proxy in proxies:
                self._validate_proxy(proxy)

            async with self._pool.acquire_writer() as db:
                await db.executemany(
                    _UPSERT_PROXY_SQL,
                    [_proxy_values(proxy) for proxy in proxies],
                )
                return len(proxies)
        except aiosqlite.IntegrityError as e:
            raise DataValidationException(f"代理数据完整性错误: {str(e)}")
        except aiosqlite.OperationalError as e:
            raise DatabaseConnectionException(f"数据库操作失败: {str(e)}")
        except (DataValidationException, DatabaseConnectionException):
            raise
        except Exception as e:
            raise RepositoryException(f"批量添加代理失败: {str(e)}")

    async def update(self, proxy_id: int, updates: dict) -> bool:
        if not updates:
            return False

        try:
            self._validate_update_fields(updates)

            set_clause = ', '.join([f"{key} = ?" for key in updates.keys()])
            values = list(updates.values())
            values.append(proxy_id)

            async with self._pool.acquire_writer() as db:
                cursor = await db.execute(
                    f"UPDATE proxies SET {set_clause} WHERE id = ?",
                    values
                )
                return cursor.rowcount > 0
        except aiosqlite.OperationalError as e:
            raise DatabaseConnectionException(f"数据库操作失败: {str(e)}")
        except (DataValidationException, DatabaseConnectionException):
            raise
        except Exception as e:
            raise RepositoryException(f"更新代理失败: {str(e)}")

    async def update_where(self, where: dict, updates: dict) -> int:
        if not updates or not where:
            return 0

        invalid_where = set(where.keys()) - _WHERE_COLUMNS
        if invalid_where:
            raise DataValidationException(
                f"不允许作为更新条件的字段: {', '.join(sorted(invalid_where))}"
            ).with_message_key("pool_field_where_not_allowed",
                               ", ".join(sorted(invalid_where)))

        try:
            self._validate_update_fields(updates)

            set_clause = ', '.join(f"{key} = ?" for key in updates.keys())
            where_clause = ' AND '.join(f"{key} = ?" for key in where.keys())
            values = list(updates.values()) + list(where.values())

            async with self._pool.acquire_writer() as db:
                cursor = await db.execute(
                    f"UPDATE proxies SET {set_clause} WHERE {where_clause}",
                    values
                )
                return cursor.rowcount
        except aiosqlite.OperationalError as e:
            raise DatabaseConnectionException(f"数据库操作失败: {str(e)}")
        except (DataValidationException, DatabaseConnectionException):
            raise
        except Exception as e:
            raise RepositoryException(f"按条件更新代理失败: {str(e)}")

    async def update_batch(self, updates: list[tuple[int, dict]]) -> int:
        if not updates:
            return 0

        try:
            async with self._pool.acquire_writer() as db:
                total_affected = 0
                for proxy_id, data in updates:
                    if not data:
                        continue
                    self._validate_update_fields(data)
                    set_clause = ', '.join(f"{k} = ?" for k in data.keys())
                    values = list(data.values()) + [proxy_id]
                    cursor = await db.execute(
                        f"UPDATE proxies SET {set_clause} WHERE id = ?", values
                    )
                    total_affected += cursor.rowcount
                return total_affected
        except aiosqlite.OperationalError as e:
            raise DatabaseConnectionException(f"数据库操作失败: {str(e)}")
        except (DataValidationException, DatabaseConnectionException):
            raise
        except Exception as e:
            raise RepositoryException(f"批量更新代理失败: {str(e)}")

    async def delete_batch(self, proxy_ids: list[int]) -> int:
        if not proxy_ids:
            return 0

        try:
            async with self._pool.acquire_writer() as db:
                placeholders = ','.join('?' * len(proxy_ids))
                cursor = await db.execute(
                    f"DELETE FROM proxies WHERE id IN ({placeholders})",
                    proxy_ids
                )
                return cursor.rowcount
        except aiosqlite.OperationalError as e:
            raise DatabaseConnectionException(f"数据库操作失败: {str(e)}")
        except Exception as e:
            raise RepositoryException(f"批量删除代理失败: {str(e)}")

    async def delete_invalid(self) -> int:
        try:
            async with self._pool.acquire_writer() as db:
                cursor = await db.execute(
                    "DELETE FROM proxies WHERE is_valid = 0"
                )
                return cursor.rowcount
        except aiosqlite.OperationalError as e:
            raise DatabaseConnectionException(f"数据库操作失败: {str(e)}")
        except Exception as e:
            raise RepositoryException(f"删除无效代理失败: {str(e)}")

    async def get_by_id(self, proxy_id: int) -> Optional[Proxy]:
        try:
            async with self._pool.acquire_reader() as db:
                async with db.execute(
                    "SELECT * FROM proxies WHERE id = ?",
                    (proxy_id,)
                ) as cursor:
                    row = await cursor.fetchone()
                    if row:
                        return self._row_to_proxy(row)
                    return None
        except aiosqlite.OperationalError as e:
            raise DatabaseConnectionException(f"数据库操作失败: {str(e)}")
        except Exception as e:
            raise RepositoryException(f"查询代理失败: {str(e)}")

    async def find(self, filter: ProxyFilter, page: int = 1,
                   page_size: int = 50) -> List[Proxy]:
        try:
            query, params = self._build_query(filter)

            sort_by = filter.sort_by or 'delay_ms'
            sort_order = filter.sort_order or 'asc'

            allowed_sort_fields = [
                'delay_ms', 'protocol', 'region', 'validated_at', 'created_at',
                'health_score', 'anonymity_level',
                'success_count', 'total_checks', 'avg_delay_ms',
                'failure_count', 'is_favorite', 'supports_https',
                'success_rate',
                'region_en',
            ]
            if sort_by not in allowed_sort_fields:
                sort_by = 'delay_ms'

            if sort_order.lower() not in ['asc', 'desc']:
                sort_order = 'asc'

            if sort_by == 'success_rate':
                sort_expr = (
                    "CASE WHEN total_checks = 0 THEN 0.0 "
                    "ELSE CAST(success_count AS REAL) / total_checks END"
                )
                query += (
                    f" ORDER BY ({sort_expr}) IS NULL,"
                    f" ({sort_expr}) {sort_order.upper()}"
                )
            else:
                query += (
                    f" ORDER BY {sort_by} IS NULL, {sort_by} {sort_order.upper()}"
                )

            offset = (page - 1) * page_size
            query += " LIMIT ? OFFSET ?"
            params.extend([page_size, offset])

            async with self._pool.acquire_reader() as db:
                async with db.execute(query, params) as cursor:
                    rows = await cursor.fetchall()
                    return [self._row_to_proxy(row) for row in rows]
        except InvalidParameterException:
            raise
        except ValueError as e:
            raise QueryBuildException(f"查询构建失败: {str(e)}").with_message_key(
                "pool_repo_query_build_failed", str(e))
        except aiosqlite.OperationalError as e:
            raise DatabaseConnectionException(f"数据库操作失败: {str(e)}")
        except (QueryBuildException, DatabaseConnectionException):
            raise
        except Exception as e:
            raise RepositoryException(f"查询代理列表失败: {str(e)}")

    async def count(self, filter: ProxyFilter) -> int:
        try:
            query, params = self._build_query(filter)

            query = query.replace("SELECT *", "SELECT COUNT(*)", 1)

            async with self._pool.acquire_reader() as db:
                async with db.execute(query, params) as cursor:
                    row = await cursor.fetchone()
                    return row[0] if row else 0
        except InvalidParameterException:
            raise
        except ValueError as e:
            raise QueryBuildException(f"查询构建失败: {str(e)}")
        except aiosqlite.OperationalError as e:
            raise DatabaseConnectionException(f"数据库操作失败: {str(e)}")
        except (QueryBuildException, DatabaseConnectionException):
            raise
        except Exception as e:
            raise RepositoryException(f"统计代理数量失败: {str(e)}")

    async def get_geo_fields_by_real_ip(self, real_ip: str) -> Optional[dict]:
        columns = (
            "region, country, province, city, "
            "region_en, country_en, province_en, city_en, "
            "country_code, subdivision_code"
        )
        try:
            async with self._pool.acquire_reader() as db:
                async with db.execute(
                    f"SELECT {columns} FROM proxies WHERE real_ip = ? LIMIT 1",
                    (real_ip,),
                ) as cursor:
                    row = await cursor.fetchone()
                    if row is None:
                        return None
                    names = [c.strip() for c in columns.split(",")]
                    return dict(zip(names, row))
        except aiosqlite.OperationalError as e:
            raise DatabaseConnectionException(f"数据库操作失败: {str(e)}")
        except (DatabaseConnectionException,):
            raise
        except Exception as e:
            raise RepositoryException(f"查询出口 IP 的现有归属地失败: {str(e)}")

    async def get_ips_missing_geo_codes(self) -> List[str]:
        try:
            async with self._pool.acquire_reader() as db:
                async with db.execute(
                    "SELECT DISTINCT real_ip FROM proxies "
                    "WHERE real_ip IS NOT NULL AND real_ip != '' "
                    "AND country_code IS NULL"
                ) as cursor:
                    rows = await cursor.fetchall()
                    return [row[0] for row in rows]
        except aiosqlite.OperationalError as e:
            raise DatabaseConnectionException(f"数据库操作失败: {str(e)}")
        except (DatabaseConnectionException,):
            raise
        except Exception as e:
            raise RepositoryException(f"查询待补归属地代码的 IP 失败: {str(e)}")

    async def find_without_checks(self) -> List[Proxy]:
        try:
            async with self._pool.acquire_reader() as db:
                async with db.execute(
                    "SELECT * FROM proxies WHERE total_checks = 0 OR total_checks IS NULL"
                ) as cursor:
                    rows = await cursor.fetchall()
                    return [self._row_to_proxy(row) for row in rows]
        except aiosqlite.OperationalError as e:
            raise DatabaseConnectionException(f"数据库操作失败: {str(e)}")
        except (DatabaseConnectionException,):
            raise
        except Exception as e:
            raise RepositoryException(f"查询未验证代理失败: {str(e)}")

    async def get_existing_ip_ports(self) -> set[str]:
        try:
            async with self._pool.acquire_reader() as db:
                async with db.execute("SELECT ip, port FROM proxies") as cursor:
                    rows = await cursor.fetchall()
                    return {f"{row[0]}:{row[1]}" for row in rows}
        except aiosqlite.OperationalError as e:
            raise DatabaseConnectionException(f"数据库操作失败: {str(e)}")
        except Exception as e:
            raise RepositoryException(f"获取 IP 列表失败: {str(e)}")

    async def get_stats(self) -> dict:
        try:
            async with self._pool.acquire_reader() as db:
                async with db.execute("SELECT COUNT(*) FROM proxies") as cursor:
                    row = await cursor.fetchone()
                    total_proxies = row[0] if row else 0

                async with db.execute("SELECT COUNT(*) FROM proxies WHERE is_valid = 1") as cursor:
                    row = await cursor.fetchone()
                    valid_proxies = row[0] if row else 0

                invalid_proxies = total_proxies - valid_proxies

                try:
                    async with db.execute(
                        "SELECT COUNT(*) FROM proxies WHERE anonymity_fallback = 1"
                    ) as cursor:
                        row = await cursor.fetchone()
                        anonymity_fallback_proxies = row[0] if row else 0
                except aiosqlite.OperationalError as e:
                    logger.warning("统计匿名度兜底条数失败（可能缺列）: %s", e)
                    anonymity_fallback_proxies = 0

                protocol_distribution = {}
                async with db.execute("SELECT protocol, COUNT(*) FROM proxies GROUP BY protocol") as cursor:
                    rows = await cursor.fetchall()
                    for row in rows:
                        protocol_distribution[row[0]] = row[1]

                region_distribution = {}
                async with db.execute(
                    "SELECT region, COUNT(*) as count FROM proxies GROUP BY region ORDER BY count DESC LIMIT 10"
                ) as cursor:
                    rows = await cursor.fetchall()
                    for row in rows:
                        region_distribution[row[0]] = row[1]

                return {
                    'total_proxies': total_proxies,
                    'valid_proxies': valid_proxies,
                    'invalid_proxies': invalid_proxies,
                    'anonymity_fallback_proxies': anonymity_fallback_proxies,
                    'protocol_distribution': protocol_distribution,
                    'region_distribution': region_distribution,
                }
        except aiosqlite.OperationalError as e:
            raise DatabaseConnectionException(f"数据库操作失败: {str(e)}")
        except Exception as e:
            raise RepositoryException(f"获取统计信息失败: {str(e)}")

    async def find_by_ip_port(self, ip: str, port: int) -> Optional[Proxy]:
        try:
            async with self._pool.acquire_reader() as db:
                async with db.execute(
                    "SELECT * FROM proxies WHERE ip = ? AND port = ?",
                    (ip, port)
                ) as cursor:
                    row = await cursor.fetchone()
                    return self._row_to_proxy(row) if row else None
        except aiosqlite.OperationalError as e:
            raise DatabaseConnectionException(f"数据库操作失败: {str(e)}")
        except Exception as e:
            raise RepositoryException(f"查询代理失败: {str(e)}")

    async def get_sources(self) -> list[str]:
        try:
            async with self._pool.acquire_reader() as db:
                async with db.execute(
                    "SELECT DISTINCT source_plugin FROM proxies ORDER BY source_plugin"
                ) as cursor:
                    rows = await cursor.fetchall()
                    return [
                        row['source_plugin'] for row in rows
                        if row['source_plugin']
                    ]
        except aiosqlite.OperationalError as e:
            raise DatabaseConnectionException(f"数据库操作失败: {str(e)}")
        except Exception as e:
            raise RepositoryException(f"获取代理来源列表失败: {str(e)}")

    def _build_query(self, filter: ProxyFilter) -> tuple[str, list]:
        query = "SELECT * FROM proxies WHERE 1=1"
        params = []

        if filter.protocol:
            if filter.protocol not in SUPPORTED_PROTOCOLS:
                raise InvalidParameterException(
                    'param_invalid_protocol', filter.protocol)
            query += " AND protocol = ?"
            params.append(filter.protocol)

        if filter.region:
            if filter.region.startswith('-'):
                exclude_region = filter.region[1:]
                pattern = f"%{exclude_region}%"
                query += (" AND (region IS NULL OR region NOT LIKE ?)"
                          " AND (region_en IS NULL OR region_en NOT LIKE ?)")
                params.append(pattern)
                params.append(pattern)
            else:
                pattern = f"%{filter.region}%"
                query += " AND (region LIKE ? OR region_en LIKE ?)"
                params.append(pattern)
                params.append(pattern)

        if filter.ip:
            query += " AND ip LIKE ?"
            params.append(f"%{filter.ip}%")

        if filter.min_delay is not None:
            if filter.min_delay < 0:
                raise InvalidParameterException(
                    'param_negative_min_delay', filter.min_delay)
            query += " AND delay_ms >= ?"
            params.append(filter.min_delay)

        if filter.max_delay is not None:
            if filter.max_delay < 0:
                raise InvalidParameterException(
                    'param_negative_max_delay', filter.max_delay)
            query += " AND delay_ms <= ?"
            params.append(filter.max_delay)

        if filter.is_valid is not None:
            query += " AND is_valid = ?"
            params.append(int(filter.is_valid))

        if filter.is_favorite is not None:
            query += " AND is_favorite = ?"
            params.append(int(filter.is_favorite))

        if filter.source:
            query += " AND source_plugin = ?"
            params.append(filter.source)

        if filter.anonymity_level:
            if filter.anonymity_level not in ANONYMITY_LEVELS:
                raise InvalidParameterException(
                    'param_invalid_anonymity', filter.anonymity_level)
            query += " AND anonymity_level = ?"
            params.append(filter.anonymity_level)

        if filter.min_health_score is not None:
            if filter.min_health_score < 0:
                raise InvalidParameterException(
                    'param_negative_min_health', filter.min_health_score)
            query += " AND health_score >= ?"
            params.append(filter.min_health_score)

        if filter.supports_https is not None:
            query += " AND supports_https = ?"
            params.append(int(filter.supports_https))

        return query, params

    def _row_to_proxy(self, row: aiosqlite.Row) -> Proxy:
        def _safe_get(key, default=None):
            try:
                val = row[key]
                return val if val is not None else default
            except (KeyError, IndexError):
                return default

        return Proxy(
            id=row['id'],
            protocol=row['protocol'],
            ip=row['ip'],
            port=row['port'],
            username=_safe_get('username'),
            password=_safe_get('password'),
            region=row['region'],
            country=row['country'],
            province=row['province'],
            city=row['city'],
            region_en=_safe_get('region_en'),
            country_en=_safe_get('country_en'),
            province_en=_safe_get('province_en'),
            city_en=_safe_get('city_en'),
            delay_ms=row['delay_ms'],
            is_valid=bool(row['is_valid']),
            is_favorite=bool(_safe_get('is_favorite', 0)),
            failure_count=int(_safe_get('failure_count', 0)),
            real_ip=row['real_ip'],
            source_plugin=row['source_plugin'],
            created_at=datetime.fromisoformat(row['created_at']) if row['created_at'] else None,
            validated_at=datetime.fromisoformat(row['validated_at']) if row['validated_at'] else None,
            health_score=float(_safe_get('health_score', 0.0)),
            success_count=int(_safe_get('success_count', 0)),
            total_checks=int(_safe_get('total_checks', 0)),
            anonymity_level=str(_safe_get('anonymity_level', 'unverified')),
            anonymity_fallback=bool(_safe_get('anonymity_fallback', 0)),
            supports_https=bool(_safe_get('supports_https', 0)),
            supports_http=bool(_safe_get('supports_http', 0)),
            quality_assessed_at=datetime.fromisoformat(_safe_get('quality_assessed_at')) if _safe_get('quality_assessed_at') else None,
            avg_delay_ms=float(_safe_get('avg_delay_ms')) if _safe_get('avg_delay_ms') is not None else None,
            delay_variance=float(_safe_get('delay_variance')) if _safe_get('delay_variance') is not None else None,
            last_valid_at=datetime.fromisoformat(_safe_get('last_valid_at')) if _safe_get('last_valid_at') else None,
            total_valid_seconds=float(_safe_get('total_valid_seconds', 0.0)),
            probe_success_count=int(_safe_get('probe_success_count', 0)),
            probe_total_count=int(_safe_get('probe_total_count', 0)),
            country_code=_safe_get('country_code'),
            subdivision_code=_safe_get('subdivision_code'),
            geo_source=_safe_get('geo_source'),
        )

    def _validate_proxy(self, proxy: Proxy) -> None:
        if not proxy.protocol:
            raise DataValidationException("协议不能为空").with_message_key(
                "pool_field_protocol_required")

        if proxy.protocol not in SUPPORTED_PROTOCOLS:
            raise DataValidationException(f"不支持的协议: {proxy.protocol}").with_message_key(
                "pool_field_protocol_unsupported", proxy.protocol)

        if not proxy.ip:
            raise DataValidationException("IP 地址不能为空").with_message_key(
                "pool_field_ip_required")

        if not proxy.port or proxy.port < 1 or proxy.port > 65535:
            raise DataValidationException(f"无效的端口: {proxy.port}").with_message_key(
                "pool_field_port_invalid", proxy.port)

        if not proxy.source_plugin:
            raise DataValidationException("来源插件不能为空").with_message_key(
                "pool_field_source_required")

    def _validate_update_fields(self, updates: dict) -> None:
        allowed_fields = {
            'protocol', 'ip', 'port', 'username', 'password',
            'region', 'country', 'province', 'city',
            'region_en', 'country_en', 'province_en', 'city_en',
            'delay_ms', 'is_valid', 'real_ip', 'source_plugin', 'validated_at',
            'failure_count', 'is_favorite',
            'health_score', 'success_count', 'total_checks',
            'anonymity_level', 'anonymity_fallback',
            'supports_https', 'supports_http',
            'quality_assessed_at', 'avg_delay_ms',
            'delay_variance', 'last_valid_at', 'total_valid_seconds',
            'probe_success_count', 'probe_total_count',
            'country_code', 'subdivision_code', 'geo_source',
        }

        invalid_fields = set(updates.keys()) - allowed_fields
        if invalid_fields:
            raise DataValidationException(
                f"不允许更新的字段: {', '.join(invalid_fields)}"
            ).with_message_key("pool_field_update_not_allowed", ", ".join(invalid_fields))

        if 'protocol' in updates and updates['protocol'] not in SUPPORTED_PROTOCOLS:
            raise DataValidationException(f"不支持的协议: {updates['protocol']}").with_message_key(
                "pool_field_protocol_unsupported", updates['protocol'])

        if 'port' in updates:
            port = updates['port']
            if not isinstance(port, int) or port < 1 or port > 65535:
                raise DataValidationException(f"无效的端口: {port}").with_message_key(
                    "pool_field_port_invalid", port)

        if 'is_valid' in updates and not isinstance(updates['is_valid'], (bool, int)):
            raise DataValidationException(f"无效的 is_valid 值: {updates['is_valid']}").with_message_key(
                "pool_field_is_valid_invalid", updates['is_valid'])

        if 'anonymity_level' in updates:
            if updates['anonymity_level'] not in ANONYMITY_LEVELS:
                raise DataValidationException(f"无效的匿名等级: {updates['anonymity_level']}").with_message_key(
                    "pool_field_anonymity_invalid", updates['anonymity_level'])


class PluginConfigRepository(IPluginConfigRepository):
    def __init__(self, connection_pool: 'ConnectionPool'):
        self._pool = connection_pool

    async def get(self, plugin_name: str) -> Optional[PluginConfig]:
        try:
            async with self._pool.acquire_reader() as db:
                async with db.execute(
                    "SELECT * FROM plugin_configs WHERE name = ?",
                    (plugin_name,)
                ) as cursor:
                    row = await cursor.fetchone()
                    if row:
                        return self._row_to_config(row)
                    return None
        except aiosqlite.OperationalError as e:
            raise DatabaseConnectionException(f"数据库操作失败: {str(e)}")
        except Exception as e:
            raise RepositoryException(f"查询插件配置失败: {str(e)}")

    async def save(self, config: PluginConfig) -> None:
        try:
            self._validate_config(config)

            async with self._pool.acquire_writer() as db:
                await db.execute(
                    """
                    INSERT OR REPLACE INTO plugin_configs
                    (name, enabled, interval_minutes, last_run, next_run,
                     reval_enabled, reval_interval_minutes, test_url, skip_validation)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        config.name,
                        int(config.enabled),
                        config.interval_minutes,
                        config.last_run.isoformat() if config.last_run else None,
                        config.next_run.isoformat() if config.next_run else None,
                        int(config.reval_enabled),
                        config.reval_interval_minutes,
                        config.test_url or "",
                        int(config.skip_validation),
                    )
                )
        except aiosqlite.IntegrityError as e:
            raise DataValidationException(f"插件配置数据完整性错误: {str(e)}").with_message_key(
                "pool_repo_plugin_integrity_error", str(e))
        except aiosqlite.OperationalError as e:
            raise DatabaseConnectionException(f"数据库操作失败: {str(e)}")
        except (DataValidationException, DatabaseConnectionException):
            raise
        except Exception as e:
            raise RepositoryException(f"保存插件配置失败: {str(e)}")

    async def get_all(self) -> List[PluginConfig]:
        try:
            async with self._pool.acquire_reader() as db:
                async with db.execute("SELECT * FROM plugin_configs") as cursor:
                    rows = await cursor.fetchall()
                    return [self._row_to_config(row) for row in rows]
        except aiosqlite.OperationalError as e:
            raise DatabaseConnectionException(f"数据库操作失败: {str(e)}")
        except Exception as e:
            raise RepositoryException(f"查询所有插件配置失败: {str(e)}")

    def _row_to_config(self, row: aiosqlite.Row) -> PluginConfig:
        return PluginConfig(
            name=row['name'],
            enabled=bool(row['enabled']),
            interval_minutes=row['interval_minutes'],
            last_run=datetime.fromisoformat(row['last_run']) if row['last_run'] else None,
            next_run=datetime.fromisoformat(row['next_run']) if row['next_run'] else None,
            reval_enabled=bool(self._safe_get(row, 'reval_enabled', 1) or 0),
            reval_interval_minutes=int(self._safe_get(row, 'reval_interval_minutes', 0) or 0),
            test_url=str(self._safe_get(row, 'test_url', '') or ''),
            skip_validation=bool(self._safe_get(row, 'skip_validation', 0) or 0),
        )

    @staticmethod
    def _safe_get(row: aiosqlite.Row, key: str, default):
        return row[key] if key in row.keys() else default

    def _validate_config(self, config: PluginConfig) -> None:
        if not config.name:
            raise DataValidationException("插件名称不能为空").with_message_key(
                "pool_field_plugin_name_required")

        if config.interval_minutes < 1:
            raise DataValidationException(f"运行间隔必须大于 0: {config.interval_minutes}").with_message_key(
                "pool_field_plugin_interval_invalid", config.interval_minutes)

        if config.reval_interval_minutes < 0:
            raise DataValidationException(
                f"重验证间隔不能为负数: {config.reval_interval_minutes}"
            ).with_message_key("pool_field_reval_interval_invalid",
                               config.reval_interval_minutes)
