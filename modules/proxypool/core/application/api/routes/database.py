"""
模块名称：modules.proxypool.core.application.api.routes.database
功能描述：数据库维护端点的业务逻辑：备份列表、备份恢复、数据库统计与优化（ANALYZE + REINDEX + VACUUM）。
          返回普通字典，失败统一抛 ApiError；备份列表与恢复是纯文件操作，池停止时同样可用。
职责边界：负责：备份文件枚举与格式化、按名恢复、数据库统计与优化动作；不负责：HTTP 路由注册与请求
          解析（见 modules.proxypool_api）、备份文件的定时创建（见 core.backup.DatabaseBackup）、
          恢复前必须先停池的把关（由适配层负责）。
关键依赖：core.application.api.dependencies 的进程内注入、core.application.api.http_types.ApiError、
          core.backup 的恢复原因码、modules.modules 的文案表。
已知限制：
  1. 未注入备份管理器或清理器时按「功能未启用」抛 ApiError(404)，不得降级成 AttributeError。
  2. 备份列表是同步文件操作；created_at 被格式化成 "%Y-%m-%d %H:%M:%S" 字符串，改格式要同步改前端。
  3. 恢复只覆盖库文件，不校验备份与当前库的版本兼容性；成功后必须重启池才会加载新数据。
  4. _RESTORE_FAILURE_MESSAGES 的原因码须与 core.backup 的 last_restore_error_code 同步，未命中的码会误报为 400。
  5. get_database_stats 与 optimize_database 需池在运行；VACUUM 会长时间独占数据库锁。
"""

import logging

from core.application.api.dependencies import (
    get_backup_manager,
    get_data_cleaner,
    get_language,
)
from core.application.api.http_types import ApiError
from modules.modules import get_message

logger = logging.getLogger(__name__)

_RESTORE_FAILURE_MESSAGES: dict[str, tuple[str, bool]] = {
    'invalid_backup': ('pool_backup_restore_invalid_backup', False),
    'wal_locked': ('pool_backup_restore_wal_locked', False),
    'verify_failed': ('pool_backup_restore_verify_failed', False),
    'error': ('pool_backup_restore_error', True),
}


def list_backups() -> dict:
    manager = get_backup_manager()
    if manager is None:
        raise ApiError(404, get_message('pool_db_backup_disabled', get_language()))

    backups = []
    for entry in manager.list_backups():
        backups.append({
            "filename": entry["filename"],
            "size": entry["size"],
            "created_at": entry["created_at"].strftime("%Y-%m-%d %H:%M:%S"),
        })
    return {"backups": backups}


async def restore_backup(filename: str) -> dict:
    manager = get_backup_manager()
    language = get_language()
    if manager is None:
        raise ApiError(404, get_message('pool_db_backup_disabled', language))

    if not await manager.restore_backup_file(filename):
        failure = _RESTORE_FAILURE_MESSAGES.get(manager.last_restore_error_code)
        if failure is None:
            raise ApiError(400, get_message('pool_backup_restore_bad_name', language))
        key, with_detail = failure
        if with_detail:
            raise ApiError(
                500, get_message(key, language, manager.last_restore_error)
            )
        raise ApiError(500, get_message(key, language))

    logger.warning("数据库已从备份 %s 恢复，请重启代理池以加载恢复后的数据", filename)
    return {
        "success": True,
        "message": get_message('pool_backup_restore_success', language),
    }


async def get_database_stats() -> dict:
    cleaner = get_data_cleaner()
    if cleaner is None:
        raise ApiError(
            404, get_message('pool_db_maintenance_disabled', get_language())
        )

    stats = await cleaner.get_database_stats()
    return {"stats": stats}


async def optimize_database() -> dict:
    cleaner = get_data_cleaner()
    language = get_language()
    if cleaner is None:
        raise ApiError(404, get_message('pool_db_maintenance_disabled', language))

    if not await cleaner.optimize_database():
        raise ApiError(500, get_message('pool_db_optimize_failed', language))

    return {"success": True, "message": get_message('pool_db_optimize_done', language)}


__all__ = [
    "list_backups",
    "restore_backup",
    "get_database_stats",
    "optimize_database",
]
