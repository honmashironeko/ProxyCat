"""
模块名称：modules.proxypool.core.application.api.routes.proxies
功能描述：代理池的查询、随机取用、计数、统计、来源、导入导出与收藏操作；不含 Web 框架依赖，返回普通字典或 RawResponse 供适配层序列化。
职责边界：负责：查询参数校验、筛选条件组装、结果序列化格式（json/text/csv）与导出文件名；不负责：HTTP 路由注册与请求解析
          （modules.proxypool_api）、数据访问（ProxyRepository）、代理验证（core.application.batch_tasks）。
关键依赖：core.application.api.dependencies（仓库与界面语言）、core.application.api.http_types、
          core.domain.models、core.domain.exceptions、core.application.batch_tasks、modules.modules。
已知限制：
  1. 参数错误应抛 InvalidParameterException（带文案键）；裸 ValueError 仍渲染 400 但丢掉文案键，只有非 ValueError 才落 500。
  2. EXPORT_LIMIT（50000）同时约束 page_size、limit 与导出；传 limit 时 page 被强制为 1，等效取前 limit 条。
  3. _proxy_to_dict 的归属地 NULL 表示「还没查过」而非「未知」，不要改填文案，前端据此回退中文列；exit_ip_differs 在列表与随机查询响应透出，导出不带。
  4. 随机取用按页粒度抽样，各条概率不严格相等，计数非 0 但页为空仍报 404；toggle_favorite 无幂等参数，重复调用在两状态间来回切换。
  5. CSV 导出带 UTF-8 BOM，_csv_safe 给以 = + - @ 开头的字段加前导单引号防公式注入；表头列数与顺序是对外契约。
  6. import_proxies 全部解析失败 success=False，全部已存在 success=True、proxy_count=0；
     message 与 proxy_count 要同看。
"""

import csv
import io
import logging
import random
from datetime import datetime
from typing import Optional

from core.application import batch_tasks
from core.application.api.dependencies import (
    get_language,
    get_proxy_repository,
)
from core.application.api.http_types import ApiError, RawResponse, json_download
from core.domain.exceptions import InvalidParameterException
from core.domain.models import SUPPORTED_PROTOCOLS
from modules.modules import get_message

logger = logging.getLogger(__name__)

EXPORT_LIMIT = 50000


def _proxy_to_dict(proxy) -> dict:
    return {
        "id": proxy.id,
        "proxy_url": proxy.proxy_url,
        "protocol": proxy.protocol,
        "ip": proxy.ip,
        "port": proxy.port,
        "username": proxy.username,
        "password": proxy.password,
        "real_ip": proxy.real_ip,
        "exit_ip_differs": proxy.exit_ip_differs,
        "region": proxy.region,
        "country": proxy.country,
        "province": proxy.province,
        "city": proxy.city,
        "region_en": proxy.region_en,
        "country_en": proxy.country_en,
        "province_en": proxy.province_en,
        "city_en": proxy.city_en,
        "delay_ms": proxy.delay_ms,
        "validated_at": proxy.validated_at.isoformat() if proxy.validated_at else None,
        "source_plugin": proxy.source_plugin,
        "is_favorite": proxy.is_favorite,
        "is_valid": proxy.is_valid,
        "health_score": proxy.health_score,
        "anonymity_level": proxy.anonymity_level,
        "anonymity_fallback": proxy.anonymity_fallback,
        "supports_https": proxy.supports_https,
        "supports_http": proxy.supports_http,
        "quality_assessed_at": (proxy.quality_assessed_at.isoformat()
                                if proxy.quality_assessed_at else None),
        "success_rate": round(proxy.success_rate, 3),
        "avg_delay_ms": proxy.avg_delay_ms,
        "total_checks": proxy.total_checks or 0,
        "probe_success_rate": round(proxy.probe_success_rate, 3),
        "probe_total_count": proxy.probe_total_count or 0,
    }


def _build_filter(
    protocol: Optional[str] = None,
    region: Optional[str] = None,
    min_delay: Optional[int] = None,
    max_delay: Optional[int] = None,
    status: Optional[str] = None,
    source: Optional[str] = None,
    sort_by: Optional[str] = None,
    sort_order: Optional[str] = None,
    ip: Optional[str] = None,
    is_favorite: Optional[bool] = None,
    anonymity_level: Optional[str] = None,
    min_health_score: Optional[float] = None,
    supports_https: Optional[bool] = None,
):
    from core.domain.models import ANONYMITY_LEVELS, ProxyFilter

    if protocol and protocol.lower() not in SUPPORTED_PROTOCOLS:
        raise InvalidParameterException('param_invalid_protocol', protocol)

    if status and status.lower() not in ('valid', 'invalid'):
        raise InvalidParameterException('param_invalid_status', status)

    if min_delay is not None and min_delay < 0:
        raise InvalidParameterException('param_negative_min_delay', min_delay)

    if max_delay is not None and max_delay < 0:
        raise InvalidParameterException('param_negative_max_delay', max_delay)

    if min_delay is not None and max_delay is not None and min_delay > max_delay:
        raise InvalidParameterException(
            'param_delay_range_reversed', min_delay, max_delay)

    if min_health_score is not None and min_health_score < 0:
        raise InvalidParameterException(
            'param_negative_min_health', min_health_score)

    if anonymity_level and anonymity_level.lower() not in ANONYMITY_LEVELS:
        raise InvalidParameterException('param_invalid_anonymity', anonymity_level)

    is_valid = None
    if status:
        is_valid = status.lower() == 'valid'

    return ProxyFilter(
        protocol=protocol.lower() if protocol else None,
        region=region,
        min_delay=min_delay,
        max_delay=max_delay,
        is_valid=is_valid,
        source=source,
        sort_by=sort_by,
        sort_order=sort_order,
        ip=ip,
        is_favorite=is_favorite,
        anonymity_level=anonymity_level.lower() if anonymity_level else None,
        min_health_score=min_health_score,
        supports_https=supports_https,
    )


async def get_proxies(
    protocol: Optional[str] = None,
    region: Optional[str] = None,
    min_delay: Optional[int] = None,
    max_delay: Optional[int] = None,
    status: Optional[str] = None,
    source: Optional[str] = None,
    sort_by: Optional[str] = None,
    sort_order: Optional[str] = None,
    limit: Optional[int] = None,
    page: int = 1,
    page_size: int = 50,
    format: str = "json",
    ip: Optional[str] = None,
    is_favorite: Optional[bool] = None,
    anonymity_level: Optional[str] = None,
    min_health_score: Optional[float] = None,
    supports_https: Optional[bool] = None,
):
    if format.lower() not in ('json', 'text'):
        raise InvalidParameterException(
            'param_invalid_export_format', format, 'json / text')

    if page < 1:
        raise InvalidParameterException('param_page_must_be_positive', page)

    if page_size < 1:
        raise InvalidParameterException(
            'param_page_size_must_be_positive', page_size)
    if page_size > EXPORT_LIMIT:
        raise InvalidParameterException(
            'param_page_size_too_large', EXPORT_LIMIT, page_size)

    if limit is not None:
        if limit < 1:
            raise InvalidParameterException('param_limit_must_be_positive', limit)
        if limit > EXPORT_LIMIT:
            raise InvalidParameterException('param_limit_too_large', EXPORT_LIMIT, limit)
        page_size = limit
        page = 1

    filter_obj = _build_filter(
        protocol=protocol, region=region, min_delay=min_delay, max_delay=max_delay,
        status=status, source=source, sort_by=sort_by, sort_order=sort_order,
        ip=ip, is_favorite=is_favorite, anonymity_level=anonymity_level,
        min_health_score=min_health_score, supports_https=supports_https,
    )

    proxies = await get_proxy_repository().find(filter_obj, page=page, page_size=page_size)

    if format.lower() == 'text':
        return RawResponse(content="\n".join(proxy.proxy_url for proxy in proxies))

    return [_proxy_to_dict(proxy) for proxy in proxies]


async def get_random_proxy(
    protocol: Optional[str] = None,
    region: Optional[str] = None,
    min_delay: Optional[int] = None,
    max_delay: Optional[int] = None,
    status: Optional[str] = None,
    source: Optional[str] = None,
    format: str = "json",
    ip: Optional[str] = None,
    is_favorite: Optional[bool] = None,
    anonymity_level: Optional[str] = None,
    min_health_score: Optional[float] = None,
    supports_https: Optional[bool] = None,
):
    language = get_language()
    if format.lower() not in ('json', 'text'):
        raise ApiError(400, get_message('pool_random_proxy_bad_format', language))

    filter_obj = _build_filter(
        protocol=protocol, region=region, min_delay=min_delay, max_delay=max_delay,
        status=status, source=source, ip=ip, is_favorite=is_favorite,
        anonymity_level=anonymity_level, min_health_score=min_health_score,
        supports_https=supports_https,
    )

    repository = get_proxy_repository()
    total_count = await repository.count(filter_obj)

    if total_count == 0:
        raise ApiError(404, get_message('pool_no_matching_proxies', language))

    rand_page_size = 100
    total_pages = (total_count + rand_page_size - 1) // rand_page_size
    proxies = await repository.find(
        filter_obj, page=random.randint(1, total_pages), page_size=rand_page_size
    )

    if not proxies:
        raise ApiError(404, get_message('pool_no_matching_proxies', language))

    proxy = random.choice(proxies)

    if format.lower() == 'text':
        return RawResponse(content=proxy.proxy_url)

    return _proxy_to_dict(proxy)


async def get_proxies_count(
    protocol: Optional[str] = None,
    region: Optional[str] = None,
    min_delay: Optional[int] = None,
    max_delay: Optional[int] = None,
    status: Optional[str] = None,
    source: Optional[str] = None,
    ip: Optional[str] = None,
    is_favorite: Optional[bool] = None,
    anonymity_level: Optional[str] = None,
    min_health_score: Optional[float] = None,
    supports_https: Optional[bool] = None,
):
    filter_obj = _build_filter(
        protocol=protocol, region=region, min_delay=min_delay, max_delay=max_delay,
        status=status, source=source, ip=ip, is_favorite=is_favorite,
        anonymity_level=anonymity_level, min_health_score=min_health_score,
        supports_https=supports_https,
    )

    return {"count": await get_proxy_repository().count(filter_obj)}


async def get_stats():
    return await get_proxy_repository().get_stats()


async def get_sources():
    return {"sources": await get_proxy_repository().get_sources()}


async def import_proxies(proxies: list[str]):
    from core.domain.models import Proxy

    if not proxies:
        raise InvalidParameterException('param_proxy_list_empty')

    language = get_language()
    repository = get_proxy_repository()

    parsed = []
    for proxy_url in proxies:
        candidate = proxy_url.strip()
        if not candidate:
            continue
        try:
            parsed.append(Proxy.from_url(candidate, "manual_import"))
        except Exception as e:
            logger.warning(f"解析代理失败 {candidate}: {e}")

    if not parsed:
        return {
            "success": False,
            "message": get_message('pool_import_no_valid_proxy', language),
            "proxy_count": 0,
        }

    unique_proxies = []
    for proxy in parsed:
        if not await repository.find_by_ip_port(proxy.ip, proxy.port):
            unique_proxies.append(proxy)

    if not unique_proxies:
        return {
            "success": True,
            "message": get_message('pool_import_duplicated', language),
            "proxy_count": 0,
        }

    task_id = batch_tasks.new_task_id()
    batch_tasks.spawn(
        batch_tasks.validate_and_save_proxies_task(
            task_id, "manual_import", [p.proxy_url for p in unique_proxies]
        ),
        task_id,
    )
    return {
        "success": True,
        "message": get_message('pool_import_validating', language, len(unique_proxies)),
        "proxy_count": len(unique_proxies),
        "task_id": task_id,
    }


async def export_proxies(
    protocol: Optional[str] = None,
    region: Optional[str] = None,
    min_delay: Optional[int] = None,
    max_delay: Optional[int] = None,
    status: Optional[str] = None,
    source: Optional[str] = None,
    ip: Optional[str] = None,
    is_favorite: Optional[bool] = None,
    anonymity_level: Optional[str] = None,
    min_health_score: Optional[float] = None,
    supports_https: Optional[bool] = None,
    format: str = "txt",
):
    if format.lower() not in ('txt', 'json', 'csv'):
        raise InvalidParameterException(
            'param_invalid_export_format', format, 'txt / json / csv')

    filter_obj = _build_filter(
        protocol=protocol, region=region, min_delay=min_delay, max_delay=max_delay,
        status=status, source=source, ip=ip, is_favorite=is_favorite,
        anonymity_level=anonymity_level, min_health_score=min_health_score,
        supports_https=supports_https,
    )

    proxies = await get_proxy_repository().find(
        filter_obj, page=1, page_size=EXPORT_LIMIT
    )

    if not proxies:
        raise ApiError(404, get_message('pool_no_matching_proxies', get_language()))

    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    export_format = format.lower()

    if export_format == 'txt':
        return RawResponse(
            content="\n".join(p.proxy_url for p in proxies),
            filename=f"proxies_{stamp}.txt",
        )

    if export_format == 'json':
        return json_download(
            [
                {
                    "protocol": p.protocol,
                    "ip": p.ip,
                    "port": p.port,
                    "username": p.username,
                    "password": p.password,
                    "url": p.proxy_url,
                    "region": p.region,
                    "region_en": p.region_en,
                    "delay_ms": p.delay_ms,
                    "is_valid": p.is_valid,
                    "real_ip": p.real_ip,
                    "source_plugin": p.source_plugin,
                    "validated_at": p.validated_at.isoformat() if p.validated_at else None,
                }
                for p in proxies
            ],
            filename=f"proxies_{stamp}.json",
        )

    return RawResponse(
        content='﻿' + _render_csv(proxies, get_language()),
        mimetype="text/csv; charset=utf-8",
        filename=f"proxies_{stamp}.csv",
    )


_CSV_FORMULA_PREFIXES = ('=', '+', '-', '@')


def _csv_safe(value) -> str:
    text = '' if value is None else str(value)
    if text[:1] in _CSV_FORMULA_PREFIXES:
        return "'" + text
    return text


def _render_csv(proxies, language: str = "cn") -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        get_message('csv_col_protocol', language),
        get_message('csv_col_ip', language),
        get_message('csv_col_port', language),
        get_message('csv_col_username', language),
        get_message('csv_col_password', language),
        get_message('csv_col_proxy_url', language),
        get_message('csv_col_region', language),
        get_message('csv_col_delay_ms', language),
        get_message('csv_col_status', language),
        get_message('csv_col_real_ip', language),
        get_message('csv_col_source', language),
        get_message('csv_col_validated_at', language),
    ])
    for p in proxies:
        writer.writerow([_csv_safe(cell) for cell in (
            p.protocol,
            p.ip,
            p.port,
            p.username or '',
            p.password or '',
            p.proxy_url,
            p.region,
            p.delay_ms if p.delay_ms else '',
            get_message('csv_status_valid' if p.is_valid else 'csv_status_invalid',
                        language),
            p.real_ip or '',
            p.source_plugin,
            p.validated_at.strftime('%Y-%m-%d %H:%M:%S') if p.validated_at else '',
        )])
    return output.getvalue()


async def toggle_favorite(proxy_id: int):
    repository = get_proxy_repository()
    language = get_language()

    proxy = await repository.get_by_id(proxy_id)
    if not proxy:
        raise ApiError(404, get_message('pool_proxy_not_found', language))

    new_favorite = not getattr(proxy, 'is_favorite', False)
    await repository.update(proxy_id, {'is_favorite': int(new_favorite)})

    return {
        "success": True,
        "is_favorite": new_favorite,
        "message": get_message(
            'pool_favorite_added' if new_favorite else 'pool_favorite_removed', language
        ),
    }


__all__ = [
    "get_proxies",
    "get_random_proxy",
    "get_proxies_count",
    "get_stats",
    "get_sources",
    "import_proxies",
    "export_proxies",
    "toggle_favorite",
]
