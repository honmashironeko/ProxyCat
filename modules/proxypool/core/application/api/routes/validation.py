"""
模块名称：modules.proxypool.core.application.api.routes.validation
功能描述：代理池批量操作的业务入口：批量验证、全面检测、批量删除、使用期反馈、本机出口 IP 查询，以及后台任务的状态查询与取消。
          只实现业务逻辑、不依赖 Web 框架：返回普通字典（适配层负责序列化），参数错误抛带文案键的异常，业务性错误抛 ApiError。
职责边界：负责：批量操作的参数校验与任务创建、删除时同步去重缓存、使用期反馈的失败计数与失效标记；不负责：HTTP 路由注册与请求解析（见 modules.proxypool_api）。
          后台任务执行与状态表见 core.application.batch_tasks，入库判据见 core.application.ingest。
关键依赖：core.application.batch_tasks、core.application.api.dependencies（仓库/验证器/去重缓存/配置/语言）、
          core.application.api.http_types.ApiError、core.domain.models、modules.modules。
已知限制：
  1. _use_failure_streak 是模块级内存表，只跑在池自己的事件循环内、无需加锁；进程重启后重新累计，达到 10000 条后的下一次计数整表清空。
  2. test_url 非空且不可归因（can_attribute_failure）的失败被忽略；达阈值写 is_valid=0、清零 total_checks，不写 validated_at。
  3. total_checks=0 让记录重回重验证候选（find_without_checks 按 0 选取，绕过 only_valid_proxies）；测通后 is_valid 翻回真。
  4. 有去重缓存时删除前必须先取出 (ip, port) 再删，失效代理要分页扫，否则缓存残留产生幽灵去重；缓存同步失败只记警告，删除结果照常返回。
  5. 任务接口语义：创建返回 running/queued 快照而非结果；cancel 对已结束任务报 success=False；查询对不存在或过期任务报 404。
  6. 批量操作静默忽略不存在的 id（validate_batch_proxies 全部 id 缺失才报 404）；get_host_ip 在验证器缺少 endpoints 时静默返回空基准。
  7. validate_batch_proxies 的目标须按 id 与地址成对收集，拆成平行列表会因缺失 id 错位、把结果写到别的代理。
"""

import logging
from typing import Optional

from core.application import batch_tasks
from core.application.api.dependencies import (
    get_proxy_repository, get_proxy_validator, get_dedup_cache, get_language,
    get_config_manager,
)
from core.application.api.http_types import ApiError
from core.domain.exceptions import InvalidParameterException
from modules.modules import get_message

logger = logging.getLogger(__name__)

_PAIR_SCAN_PAGE_SIZE = 5000

_use_failure_streak: dict[tuple, int] = {}

_USE_STREAK_MAX_ENTRIES = 10000


def _remember_use_failure(key: tuple) -> int:
    if len(_use_failure_streak) >= _USE_STREAK_MAX_ENTRIES:
        _use_failure_streak.clear()
    streak = _use_failure_streak.get(key, 0) + 1
    _use_failure_streak[key] = streak
    return streak


async def report_proxy_use(ip: str, port, ok: bool, test_url: str = "") -> None:
    config = get_config_manager().get_config()
    settings = getattr(config, "use_feedback", None)
    if settings is None or not getattr(settings, "enabled", False):
        return

    repository = get_proxy_repository()
    proxy = await repository.find_by_ip_port(ip, port)
    if proxy is None:
        return

    key = (str(ip), int(port))

    if ok:
        if _use_failure_streak.pop(key, 0):
            logger.info(f"代理 {ip}:{port} 使用期恢复可用，连续失败计数清零")
        return

    if test_url and not get_proxy_validator().can_attribute_failure(test_url):
        logger.debug(f"代理 {ip}:{port} 使用期失败不可归因（本机链路或测试地址不可达），已忽略")
        return

    threshold = max(1, int(getattr(settings, "invalid_threshold", 3) or 1))
    streak = _remember_use_failure(key)

    if streak < threshold:
        logger.debug(f"代理 {ip}:{port} 使用期连续失败 {streak}/{threshold} 次")
        return

    try:
        written = await repository.update(proxy.id, {"is_valid": 0, "total_checks": 0})
    except Exception as e:
        logger.error(f"代理 {ip}:{port} 标记失效时写库失败（计数保留，下次重试）: {e}")
        return

    _use_failure_streak.pop(key, None)
    if written:
        logger.warning(
            f"代理 {ip}:{port} 使用期连续失败 {threshold} 次，已标记为失效"
            f"（列入下一轮重验证候选）"
        )
    else:
        logger.error(f"代理 {ip}:{port} 标记失效失败：记录已不存在")

_VALID_VALIDATION_MODES = ("auto", "liveness", "full")



async def validate_all_proxies(is_valid_filter: bool):
    task_id = batch_tasks.new_task_id()
    batch_tasks.spawn(
        batch_tasks.validate_all_proxies_task(task_id, is_valid_filter), task_id
    )
    return {
        "task_id": task_id,
        "status": "queued",
        "message": get_message('pool_validation_task_created', get_language()),
    }


async def update_all_geo():
    task_id = batch_tasks.new_task_id()
    batch_tasks.spawn(batch_tasks.update_all_geo_task(task_id), task_id)
    return {
        "task_id": task_id,
        "status": "queued",
        "message": get_message('pool_full_check_task_created', get_language()),
    }


async def validate_batch_proxies(proxy_ids: list[int], mode: str = "auto"):
    if not proxy_ids:
        raise InvalidParameterException('param_proxy_ids_empty')
    if mode not in _VALID_VALIDATION_MODES:
        raise InvalidParameterException(
            'param_invalid_validation_mode', mode, ' / '.join(_VALID_VALIDATION_MODES)
        )

    language = get_language()
    repository = get_proxy_repository()
    targets = []
    for proxy_id in proxy_ids:
        proxy = await repository.get_by_id(proxy_id)
        if proxy:
            targets.append((proxy_id, proxy.proxy_url))

    if not targets:
        raise ApiError(404, get_message('pool_validation_no_valid_proxy', language))

    task_id = batch_tasks.new_task_id()
    batch_tasks.spawn(
        batch_tasks.validate_selected_proxies_task(task_id, targets, mode),
        task_id,
    )
    return {
        "task_id": task_id,
        "status": "running",
        "message": get_message('pool_validating_proxies', language, len(targets)),
    }


async def delete_invalid_proxies():
    from core.domain.models import ProxyFilter

    language = get_language()
    repository = get_proxy_repository()
    dedup_cache = get_dedup_cache()

    pairs = []
    if dedup_cache is not None:
        page = 1
        while True:
            batch = await repository.find(
                ProxyFilter(is_valid=False), page=page, page_size=_PAIR_SCAN_PAGE_SIZE
            )
            if not batch:
                break
            pairs.extend((proxy.ip, proxy.port) for proxy in batch)
            if len(batch) < _PAIR_SCAN_PAGE_SIZE:
                break
            page += 1

    count = await repository.delete_invalid()

    if count == 0:
        return {
            "success": True,
            "message": get_message('pool_no_invalid_proxies', language),
            "deleted_count": 0,
        }

    await _sync_dedup_cache_removal(dedup_cache, pairs, "失效代理")

    logger.info(f"已删除 {count} 个失效代理")
    return {
        "success": True,
        "message": get_message('pool_invalid_proxies_deleted', language, count),
        "deleted_count": count,
    }


async def delete_batch_proxies(proxy_ids: list[int]):
    if not proxy_ids:
        raise InvalidParameterException('param_proxy_ids_empty')

    language = get_language()
    repository = get_proxy_repository()
    dedup_cache = get_dedup_cache()

    pairs = []
    if dedup_cache is not None:
        for proxy_id in proxy_ids:
            proxy = await repository.get_by_id(proxy_id)
            if proxy is not None:
                pairs.append((proxy.ip, proxy.port))

    deleted_count = await repository.delete_batch(proxy_ids)
    await _sync_dedup_cache_removal(dedup_cache, pairs, "批量删除代理")

    logger.info(f"批量删除了 {deleted_count} 个代理")
    return {
        "success": True,
        "message": get_message('pool_proxies_deleted', language, deleted_count),
        "deleted_count": deleted_count,
    }


async def _sync_dedup_cache_removal(dedup_cache, pairs, scene: str) -> None:
    if dedup_cache is None or not pairs:
        return

    try:
        await dedup_cache.remove_batch(pairs)
        logger.info(f"已从去重缓存中移除 {len(pairs)} 个键（{scene}）")
    except Exception as e:
        logger.warning(f"{scene}后同步去重缓存失败（非致命）: {e}")


async def get_host_ip():
    validator = get_proxy_validator()
    endpoints = getattr(validator, "endpoints", None)
    if endpoints is None:
        return {
            "host_public_ip": None,
            "host_public_ipv4": None,
            "host_public_ipv6": None,
            "source": "",
            "check_anonymity": True,
        }

    resolved = getattr(endpoints, "host_public_ips", None)
    ips = list(resolved()) if callable(resolved) else []
    ipv4 = next((ip for ip in ips if ":" not in ip), None)
    ipv6 = next((ip for ip in ips if ":" in ip), None)

    return {
        "host_public_ip": endpoints.host_public_ip(),
        "host_public_ipv4": ipv4,
        "host_public_ipv6": ipv6,
        "source": endpoints.host_ip_source(),
        "check_anonymity": bool(getattr(endpoints, "check_anonymity", True)),
    }


async def get_task_status(task_id: str):
    batch_tasks.cleanup_task_status()
    task_store = batch_tasks.background_tasks_status

    if task_id not in task_store:
        raise ApiError(404, get_message('pool_task_not_found', get_language()))

    return task_store[task_id]


async def cancel_task(task_id: str):
    language = get_language()
    if task_id not in batch_tasks.background_tasks_status:
        raise ApiError(404, get_message('pool_task_not_found', language))

    cancelled = await batch_tasks.cancel_task(task_id)
    if not cancelled:
        return {
            "success": False,
            "message": get_message('pool_task_already_finished', language),
        }

    return {"success": True, "message": get_message('pool_task_cancelled', language)}


async def list_all_tasks(status: Optional[str] = None):
    batch_tasks.cleanup_task_status()
    task_store = batch_tasks.background_tasks_status

    wanted = status.lower() if status else None
    tasks = []
    for task_id, task_data in task_store.items():
        task_info = {"task_id": task_id}
        if isinstance(task_data, dict):
            task_info.update(task_data)
        else:
            task_info["data"] = str(task_data)

        if wanted and task_info.get("status", "") != wanted:
            continue
        tasks.append(task_info)

    return {"tasks": tasks, "total": len(tasks)}


__all__ = [
    "validate_all_proxies",
    "update_all_geo",
    "validate_batch_proxies",
    "delete_invalid_proxies",
    "delete_batch_proxies",
    "get_host_ip",
    "get_task_status",
    "list_all_tasks",
    "cancel_task",
]
