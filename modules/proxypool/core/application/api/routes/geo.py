"""
模块名称：modules.proxypool.core.application.api.routes.geo
功能描述：归属地维护端点：查询离线库状态、触发数据文件更新、按离线库重算存量记录；更新与重算都登记为后台任务、由面板按 task_id 轮询。
职责边界：负责：把离线库的状态、更新、重算暴露成可调用的操作并生成任务 id；不负责：HTTP 路由
          注册与线程绑定（见 modules.proxypool_api）、数据文件的下载实现（见 core.infrastructure.geodb）、
          任务的执行与状态表（见 batch_tasks）、归属地查询本身（见 core.services.geoip）。
关键依赖：core.application.api.dependencies 的进程内注入、core.application.batch_tasks、
          core.infrastructure.geodb、modules.modules 的文案表。
已知限制：
  1. 三个端点都必须在池的事件循环线程上调用（路由侧用 _bind_query / _bind_no_args 绑定）。
  2. 状态查询要求仓库可用：容器未装配或仓库解析失败时待重算数按 0 返回并记一条 warning。
  3. 重算只挑 country_code 为 NULL 的出口 IP（real_ip 非空且 DISTINCT），已解析过的记录不会被重算。
  4. 重算的完成信号是解析队列排空（每秒轮询 pending 归零），并发解析时 done 会被压低（以 0 兜底）。
  5. 更新任务把运行中的 geodb 实例（可能为 None）透传给下载流程：换入新文件前必须先释放句柄，否则 Windows 上 os.replace 会被拒绝。
  6. 重算要求解析服务已启用：resolver 为 None 时抛 ApiError(503) 且不创建任务，任务内部还会再判一次。
"""

import logging

from core.application import batch_tasks
from core.application.api.dependencies import (
    get_geodb,
    get_geo_resolver,
    get_language,
    get_proxy_repository,
)
from core.application.api.http_types import ApiError
from core.infrastructure.geodb import describe_databases
from modules.modules import get_message

logger = logging.getLogger(__name__)



async def get_geo_status() -> dict:
    geodb = get_geodb()
    available = bool(geodb is not None and geodb.available)

    pending = 0
    try:
        repository = get_proxy_repository()
    except Exception as e:
        logger.warning(f"代理仓库不可用，待重算记录数按 0 处理: {e}")
        repository = None

    if repository is not None:
        try:
            pending = len(await repository.get_ips_missing_geo_codes())
        except Exception as e:
            logger.warning(f"统计待重算归属地的记录数失败（按 0 处理）: {e}")

    return {
        "available": available,
        "files": describe_databases(),
        "pending_recompute": pending,
    }


async def start_geo_update() -> dict:
    task_id = batch_tasks.new_task_id()
    batch_tasks.spawn(
        batch_tasks.update_geo_databases_task(task_id, get_geodb()), task_id
    )
    return {
        "task_id": task_id,
        "status": "queued",
        "message": get_message('pool_geo_update_task_created', get_language()),
    }


async def start_geo_recompute() -> dict:
    language = get_language()
    if get_geo_resolver() is None:
        raise ApiError(503, get_message('pool_geo_recompute_disabled', language))

    task_id = batch_tasks.new_task_id()
    batch_tasks.spawn(batch_tasks.recompute_geo_task(task_id), task_id)
    return {
        "task_id": task_id,
        "status": "queued",
        "message": get_message('pool_geo_recompute_task_created', language),
    }


__all__ = [
    "get_geo_status",
    "start_geo_update",
    "start_geo_recompute",
]
