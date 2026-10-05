"""
模块名称：modules.proxypool.core.application.api.routes.plugins
功能描述：抓取插件的管理操作接口：列出状态、启停、设置运行周期与检测地址、设置验证策略、立即执行、热重载。
职责边界：负责：插件管理操作的参数校验与结果组装；不负责：HTTP 路由注册与请求解析（见 modules.proxypool_api）、插件加载、调度与落盘（见 PluginManager）。
关键依赖：core.application.api.dependencies（插件管理器、语言）、core.application.batch_tasks、modules.modules（文案表）。
已知限制：
1. 本模块主动判定的参数错误必须是 InvalidParameterException（带文案键）或 ApiError(400)，管理器抛出的同类异常须原样穿透，不得吞成 500。
2. 请求体值原样透传：reval_interval_minutes 经 int() 转换兜底；minutes 与 test_url 未转换，类型错误会落 500。
3. skip_validation 只对已加载插件开放，落到伪插件名 manual_import 会让手动导入全部跳过验证，面板上无从发现。
4. test_url 空串或全空白表示继承全局检测地址，reval_interval_minutes 为 0 表示继承全局重验证周期。
5. 立即执行只创建后台任务即返回，进度须按 task_id 轮询；任务状态为进程内存态且有 TTL，进程重启后不可查。
6. 热重载的可预期失败（插件不存在、执行中、加载返回 None）返回 200 + success=False，仅未预期异常报 500。
"""

import logging

from core.application import batch_tasks
from core.application.api.dependencies import get_language, get_plugin_manager
from core.application.api.http_types import ApiError
from core.domain.exceptions import InvalidParameterException
from modules.modules import get_message

logger = logging.getLogger(__name__)

_PLUGIN_ACTION_MESSAGES: dict[bool, tuple[str, str]] = {
    True: ('pool_plugin_enable_failed', 'pool_plugin_enabled'),
    False: ('pool_plugin_disable_failed', 'pool_plugin_disabled'),
}


async def list_plugins():
    status_dict = get_plugin_manager().get_plugin_status()
    return [
        {
            "name": status.name,
            "enabled": status.enabled,
            "interval_minutes": status.interval_minutes,
            "last_run": status.last_run.isoformat() if status.last_run else None,
            "next_run": status.next_run.isoformat() if status.next_run else None,
            "last_error": (
                get_message(status.last_error_key, get_language())
                if status.last_error_key else status.last_error
            ),
            "is_loaded": status.is_loaded,
            "test_url": status.test_url,
            "reval_enabled": status.reval_enabled,
            "reval_interval_minutes": status.reval_interval_minutes,
            "skip_validation": status.skip_validation,
        }
        for status in status_dict.values()
    ]


async def set_plugin_enabled(plugin_name: str, enabled: bool):
    manager = get_plugin_manager()
    action = "启用" if enabled else "禁用"
    language = get_language()
    failed_key, done_key = _PLUGIN_ACTION_MESSAGES[enabled]

    try:
        if enabled:
            manager.enable_plugin(plugin_name)
        else:
            manager.disable_plugin(plugin_name)
    except Exception as e:
        logger.error(f"{action}插件失败: {e}", exc_info=True)
        raise ApiError(500, get_message(failed_key, language, str(e)))

    return {"success": True, "message": get_message(done_key, language, plugin_name)}


async def set_plugin_interval(plugin_name: str, minutes: int):
    if minutes < 1:
        raise InvalidParameterException(
            'param_interval_must_be_positive', minutes)

    language = get_language()
    try:
        get_plugin_manager().set_plugin_interval(plugin_name, minutes)
    except InvalidParameterException:
        raise
    except Exception as e:
        logger.error(f"设置插件运行周期失败: {e}", exc_info=True)
        raise ApiError(500, get_message('pool_plugin_interval_failed', language, str(e)))

    return {
        "success": True,
        "message": get_message('pool_plugin_interval_set', language, plugin_name, minutes),
    }


async def set_plugin_test_url(plugin_name: str, test_url: str = ""):
    language = get_language()
    try:
        get_plugin_manager().set_plugin_test_url(plugin_name, test_url)
    except ValueError as e:
        raise ApiError(400, str(e))
    except Exception as e:
        logger.error(f"设置插件测试地址失败: {e}", exc_info=True)
        raise ApiError(500, get_message('pool_plugin_test_url_failed', language, str(e)))

    if (test_url or "").strip():
        message = get_message('pool_plugin_test_url_set', language, plugin_name, test_url)
    else:
        message = get_message('pool_plugin_test_url_inherited', language, plugin_name)
    return {"success": True, "message": message}


async def set_plugin_validation(plugin_name: str, reval_enabled: bool = True,
                                reval_interval_minutes: int = 0,
                                skip_validation: bool = False):
    language = get_language()
    manager = get_plugin_manager()

    try:
        reval_interval_minutes = int(reval_interval_minutes)
    except (TypeError, ValueError):
        raise ApiError(400, get_message(
            'param_reval_interval_not_int', language, reval_interval_minutes))

    if skip_validation and plugin_name not in manager.get_plugin_status():
        raise ApiError(404, get_message('pool_plugin_not_loaded', language, plugin_name))

    try:
        manager.set_plugin_validation(
            plugin_name, reval_enabled, reval_interval_minutes, bool(skip_validation)
        )
    except InvalidParameterException:
        raise
    except ValueError as e:
        raise ApiError(400, str(e))
    except Exception as e:
        logger.error(f"设置插件验证策略失败: {e}", exc_info=True)
        raise ApiError(500, get_message('pool_plugin_validation_failed', language, str(e)))

    return {
        "success": True,
        "message": get_message('pool_plugin_validation_set', language, plugin_name),
    }


async def run_plugin(plugin_name: str):
    manager = get_plugin_manager()
    language = get_language()
    if plugin_name not in manager.get_plugin_status():
        raise ApiError(404, get_message('pool_plugin_not_loaded', language, plugin_name))

    task_id = batch_tasks.new_task_id()
    batch_tasks.spawn(batch_tasks.run_plugin_task(task_id, plugin_name), task_id)

    return {
        "task_id": task_id,
        "status": "running",
        "message": get_message('pool_plugin_run_task_created', language, plugin_name),
    }


async def reload_plugin(plugin_name: str):
    language = get_language()
    try:
        success = await get_plugin_manager().reload_plugin(plugin_name)
    except Exception as e:
        logger.error(f"热重载插件失败: {e}", exc_info=True)
        raise ApiError(500, get_message('pool_plugin_reload_failed', language, str(e)))

    if success:
        return {
            "success": True,
            "message": get_message('pool_plugin_reload_success', language, plugin_name),
        }

    return {
        "success": False,
        "message": get_message('pool_plugin_reload_rejected', language, plugin_name),
    }


__all__ = [
    "list_plugins",
    "set_plugin_enabled",
    "set_plugin_interval",
    "set_plugin_test_url",
    "set_plugin_validation",
    "run_plugin",
    "reload_plugin",
]
