"""
模块名称：modules.proxypool_api
功能描述：代理池的 Web 适配层：把 ProxyPoolService 门面包装成 /api/pool 前缀的 Flask 蓝图，与其余接口共用同一端口。
职责边界：负责：查询参数与 JSON 体的解析及类型强制、把处理函数结果序列化为响应、把异常映射成统一的错误响应、
          池启停与状态查询端点、蓝图内各条 URL 规则的注册；不负责：业务逻辑（core.application.api.routes）、
          跨线程调用与超时控制（ProxyPoolService）、token 鉴权（由注册方统一添加）。
关键依赖：modules.proxypool_service、modules.modules、modules.pool_config_ini（延迟导入）、
          core.application.api.routes、core.application.api.dependencies、
          core.application.api.http_types、core.domain.exceptions、Flask。
已知限制：
  1. 查询参数按处理函数签名作白名单解析：签名里没有的参数被静默忽略，非字符串参数传空串按未传处理；只有 bool / int / float 注解会被强制转换。
  2. 每个请求占用一个 Web 工作线程直到池返回结果，超时三档：QUERY_TIMEOUT 10 秒、MUTATION_TIMEOUT 20 秒、HEAVY_TIMEOUT 60 秒。
  3. 异常映射顺序：先按 _EXCEPTION_MAP 匹配；再由 ApiError 带出状态码；ValueError 映射 400；其余落 500 兜底。
  4. 数据层与适配层的参数异常 InvalidParameterException 继承 ValueError 映射 400；RepositoryException 族漏列入表才落 500。
  5. /api/pool 前缀与成功响应的数据结构是对外契约，改动会破坏既有对接方。
  6. 备份恢复要求池已停止（判据是 has_live_thread 而不是 is_running），且经 asyncio.run 在池事件循环之外执行。
  7. 蓝图自身不带鉴权，单独挂载将没有任何 token 校验；鉴权由注册方（app.py 的 before_request）提供。
  8. /status 的统计查询失败只记 warning 并把 stats 置为 null，状态端点仍返回 success；不得因此让状态端点整体失败。
"""

import asyncio
import inspect
import logging
from functools import wraps
from typing import Any, Callable, Union, get_args, get_origin

from flask import Blueprint, Response, jsonify, request

from core.application.api.dependencies import get_language
from core.application.api.http_types import ApiError, RawResponse
from core.domain.exceptions import (
    DataValidationException,
    InvalidParameterException,
    ProxyValidationException,
    QueryBuildException,
    WriteQueueFullException,
)
from core.application.api.routes import plugins as plugin_routes
from core.application.api.routes import proxies as proxy_routes
from core.application.api.routes import validation as validation_routes
from core.application.api.routes import database as database_routes
from core.application.api.routes import geo as geo_routes
from modules.proxypool_service import (
    PoolTimeoutError,
    PoolUnavailableError,
    ProxyPoolService,
)
from modules.modules import FALSE_WORDS, TRUE_WORDS, get_message

logger = logging.getLogger(__name__)

QUERY_TIMEOUT = 10.0

MUTATION_TIMEOUT = 20.0

HEAVY_TIMEOUT = 60.0

_TRUE_VALUES = TRUE_WORDS
_FALSE_VALUES = FALSE_WORDS

_EXCEPTION_MAP: tuple[tuple[type, int, str], ...] = (
    (PoolUnavailableError, 503, "pool_unavailable"),
    (PoolTimeoutError, 504, "pool_timeout"),
    (DataValidationException, 400, "invalid_parameter"),
    (QueryBuildException, 400, "invalid_parameter"),
    (ProxyValidationException, 400, "invalid_parameter"),
    (WriteQueueFullException, 503, "queue_full"),
)

_ERROR_CODE_MESSAGE_KEYS: dict[str, str] = {
    "pool_unavailable": 'pool_unavailable',
    "pool_timeout": 'pool_error_timeout',
    "invalid_parameter": 'pool_invalid_parameters',
    "queue_full": 'pool_request_failed',
    "api_error": 'pool_request_failed',
    "internal_error": 'pool_internal_error',
}

_LIFECYCLE_ACTIONS = ("start", "stop", "restart")


def _unwrap_optional(annotation: Any) -> Any:
    if get_origin(annotation) is Union:
        inner = [a for a in get_args(annotation) if a is not type(None)]
        if len(inner) == 1:
            return inner[0]
    return annotation


def _coerce(raw: str, target: Any) -> Any:
    if target is bool:
        lowered = raw.strip().lower()
        if lowered in _TRUE_VALUES:
            return True
        if lowered in _FALSE_VALUES:
            return False
        raise ValueError(f"expected a boolean: {raw!r}")
    if target is int:
        return int(raw)
    if target is float:
        return float(raw)
    return raw


def _signature_params(handler: Callable) -> dict[str, inspect.Parameter]:
    return inspect.signature(handler).parameters


def _query_params(handler: Callable) -> dict:
    params: dict[str, Any] = {}

    for name, parameter in _signature_params(handler).items():
        if name not in request.args:
            continue

        raw = request.args.get(name)
        target = _unwrap_optional(parameter.annotation)
        if target is inspect.Parameter.empty:
            target = str

        if raw == "" and target is not str:
            continue

        params[name] = _coerce(raw, target)

    return params


def _body_params(handler: Callable, path_params: dict) -> dict:
    body = request.get_json(silent=True)
    if body is None:
        body = {}
    if not isinstance(body, dict):
        raise InvalidParameterException('param_body_must_be_json')

    params: dict[str, Any] = {}
    missing: list[str] = []

    for name, parameter in _signature_params(handler).items():
        if name in path_params:
            params[name] = path_params[name]
        elif name in body:
            params[name] = body[name]
        elif parameter.default is inspect.Parameter.empty:
            missing.append(name)

    if missing:
        raise InvalidParameterException('param_missing_fields', ', '.join(missing))

    return params


def _to_response(result: Any):
    if isinstance(result, RawResponse):
        response = Response(result.content, content_type=result.mimetype)
        if result.filename:
            response.headers["Content-Disposition"] = (
                f"attachment; filename={result.filename}"
            )
        return response
    return jsonify(result)


def _render_exception(exc: Exception, language: str) -> str:
    key = getattr(exc, 'message_key', '')
    if not key:
        return str(exc)
    return get_message(key, language, *getattr(exc, 'message_args', ()))


def _error_response(exc: Exception, language: str = 'cn'):
    for exc_type, status, error_code in _EXCEPTION_MAP:
        if isinstance(exc, exc_type):
            message_key = _ERROR_CODE_MESSAGE_KEYS.get(error_code, 'pool_request_failed')
            logger.warning(get_message(message_key, language, exc))
            return jsonify({
                "status": "error",
                "message": _render_exception(exc, language),
                "error_code": error_code,
            }), status

    if isinstance(exc, ApiError):
        return jsonify({
            "status": "error", "message": exc.message, "error_code": "api_error",
        }), exc.status_code

    if isinstance(exc, ValueError):
        logger.warning(get_message('pool_invalid_parameters', language, exc))
        return jsonify({
            "status": "error", "message": _render_exception(exc, language),
            "error_code": "invalid_parameter",
        }), 400

    logger.error(get_message('pool_request_failed', language, exc), exc_info=True)
    return jsonify({
        "status": "error", "message": get_message('pool_internal_error', language),
        "error_code": "internal_error",
    }), 500


def _run(service: ProxyPoolService, coro, timeout: float):
    try:
        return _to_response(service.call(coro, timeout=timeout)), None
    except Exception as exc:  # noqa: BLE001
        return None, _error_response(exc, service.language)


def _bind_query(service: ProxyPoolService, handler: Callable,
                timeout: float = QUERY_TIMEOUT) -> Callable:
    @wraps(handler)
    def view(**path_params: Any):
        try:
            params = {**_query_params(handler), **path_params}
        except Exception as exc:  # noqa: BLE001
            return _error_response(exc, service.language)

        response, error = _run(service, handler(**params), timeout)
        return error or response

    return view


def _bind_body(service: ProxyPoolService, handler: Callable,
               timeout: float = MUTATION_TIMEOUT) -> Callable:
    @wraps(handler)
    def view(**path_params: Any):
        try:
            params = _body_params(handler, path_params)
        except Exception as exc:  # noqa: BLE001
            return _error_response(exc, service.language)

        response, error = _run(service, handler(**params), timeout)
        return error or response

    return view


def _bind_no_args(service: ProxyPoolService, coro_factory: Callable,
                  timeout: float = MUTATION_TIMEOUT) -> Callable:
    def view():
        response, error = _run(service, coro_factory(), timeout)
        return error or response

    return view


def create_pool_blueprint(service: ProxyPoolService) -> Blueprint:
    blueprint = Blueprint("pool_api", __name__, url_prefix="/api/pool")

    _register_lifecycle_routes(blueprint, service)
    _register_proxy_routes(blueprint, service)
    _register_plugin_routes(blueprint, service)
    _register_batch_routes(blueprint, service)
    _register_database_routes(blueprint, service)
    _register_geo_routes(blueprint, service)

    return blueprint


def _register_geo_routes(blueprint: Blueprint, service: ProxyPoolService) -> None:
    blueprint.add_url_rule(
        "/geo/status", "pool_geo_status",
        _bind_query(service, geo_routes.get_geo_status), methods=["GET"],
    )
    blueprint.add_url_rule(
        "/geo/update", "pool_geo_update",
        _bind_no_args(service, geo_routes.start_geo_update), methods=["POST"],
    )
    blueprint.add_url_rule(
        "/geo/recompute", "pool_geo_recompute",
        _bind_no_args(service, geo_routes.start_geo_recompute), methods=["POST"],
    )


def _register_database_routes(blueprint: Blueprint, service: ProxyPoolService) -> None:
    def backups_view():
        try:
            return _to_response(database_routes.list_backups())
        except Exception as exc:  # noqa: BLE001
            return _error_response(exc, service.language)

    def restore_view():
        try:
            if service.has_live_thread:
                return jsonify({
                    "status": "error",
                    "message": get_message('pool_restore_requires_stop', service.language),
                    "error_code": "pool_running",
                }), 409
            body = request.get_json(silent=True) or {}
            if not isinstance(body, dict) or not str(body.get("filename", "")).strip():
                return jsonify({
                    "status": "error",
                    "message": get_message('pool_backup_filename_required', service.language),
                    "error_code": "invalid_parameter",
                }), 400

            result = asyncio.run(
                database_routes.restore_backup(str(body["filename"]).strip())
            )
            return _to_response(result)
        except Exception as exc:  # noqa: BLE001
            return _error_response(exc, service.language)

    blueprint.add_url_rule("/backups", "pool_backups", backups_view, methods=["GET"])
    blueprint.add_url_rule(
        "/backups/restore", "pool_backup_restore", restore_view, methods=["POST"]
    )
    blueprint.add_url_rule(
        "/database/stats", "pool_db_stats",
        _bind_query(service, database_routes.get_database_stats), methods=["GET"],
    )
    blueprint.add_url_rule(
        "/database/optimize", "pool_db_optimize",
        _bind_no_args(service, database_routes.optimize_database, HEAVY_TIMEOUT),
        methods=["POST"],
    )


def _register_lifecycle_routes(blueprint: Blueprint, service: ProxyPoolService) -> None:
    def status():
        stats = None
        if service.is_running:
            try:
                stats = service.call(proxy_routes.get_stats(), timeout=QUERY_TIMEOUT)
            except Exception as exc:  # noqa: BLE001
                logger.warning(get_message('pool_status_error', service.language, exc))

        return jsonify({
            "status": "success",
            "is_running": service.is_running,
            "last_error": service.last_error,
            "stats": stats,
        })

    blueprint.add_url_rule("/status", "pool_status", status, methods=["GET"])
    blueprint.add_url_rule("/schema", "pool_schema", _make_schema_view(), methods=["GET"])

    for action in _LIFECYCLE_ACTIONS:
        blueprint.add_url_rule(
            f"/{action}", f"pool_{action}", _make_lifecycle_view(service, action),
            methods=["POST"],
        )


def _make_schema_view() -> Callable:
    from modules import pool_config_ini

    def view():
        return jsonify({
            "status": "success",
            "groups": pool_config_ini.describe_pool_schema(get_language()),
        })

    return view


def _make_lifecycle_view(service: ProxyPoolService, action: str) -> Callable:
    def view():
        language = service.language
        ok = getattr(service, action)()
        if not ok:
            detail = service.last_error or get_message('pool_unknown_error', language)
            return jsonify({
                "status": "error",
                "message": get_message(f"pool_{action}_failed", language, detail),
                "is_running": service.is_running,
            }), 500

        return jsonify({
            "status": "success",
            "message": get_message(f"pool_{action}_success", language),
            "is_running": service.is_running,
        })

    return view


def _register_proxy_routes(blueprint: Blueprint, service: ProxyPoolService) -> None:
    blueprint.add_url_rule("/get", "pool_get",
                           _bind_query(service, proxy_routes.get_proxies), methods=["GET"])
    blueprint.add_url_rule("/random", "pool_random",
                           _bind_query(service, proxy_routes.get_random_proxy), methods=["GET"])
    blueprint.add_url_rule("/count", "pool_count",
                           _bind_query(service, proxy_routes.get_proxies_count), methods=["GET"])
    blueprint.add_url_rule("/stats", "pool_stats",
                           _bind_query(service, proxy_routes.get_stats), methods=["GET"])
    blueprint.add_url_rule("/sources", "pool_sources",
                           _bind_query(service, proxy_routes.get_sources), methods=["GET"])
    blueprint.add_url_rule("/export", "pool_export",
                           _bind_query(service, proxy_routes.export_proxies, HEAVY_TIMEOUT),
                           methods=["GET"])
    blueprint.add_url_rule("/import", "pool_import",
                           _bind_body(service, proxy_routes.import_proxies, HEAVY_TIMEOUT),
                           methods=["POST"])
    blueprint.add_url_rule("/proxies/<int:proxy_id>/favorite", "pool_favorite",
                           _bind_query(service, proxy_routes.toggle_favorite), methods=["POST"])


def _register_plugin_routes(blueprint: Blueprint, service: ProxyPoolService) -> None:
    blueprint.add_url_rule("/plugins", "pool_plugins",
                           _bind_query(service, plugin_routes.list_plugins), methods=["GET"])
    blueprint.add_url_rule("/plugins/<plugin_name>/interval", "pool_plugin_interval",
                           _bind_body(service, plugin_routes.set_plugin_interval), methods=["PUT"])
    blueprint.add_url_rule("/plugins/<plugin_name>/test-url", "pool_plugin_test_url",
                           _bind_body(service, plugin_routes.set_plugin_test_url), methods=["PUT"])
    blueprint.add_url_rule("/plugins/<plugin_name>/validation", "pool_plugin_validation",
                           _bind_body(service, plugin_routes.set_plugin_validation),
                           methods=["PUT"])
    blueprint.add_url_rule("/plugins/<plugin_name>/run", "pool_plugin_run",
                           _bind_query(service, plugin_routes.run_plugin, HEAVY_TIMEOUT),
                           methods=["POST"])
    blueprint.add_url_rule("/plugins/<plugin_name>/reload", "pool_plugin_reload",
                           _bind_query(service, plugin_routes.reload_plugin, HEAVY_TIMEOUT),
                           methods=["POST"])

    for enabled, suffix, endpoint in ((True, "enable", "pool_plugin_enable"),
                                      (False, "disable", "pool_plugin_disable")):
        blueprint.add_url_rule(
            f"/plugins/<plugin_name>/{suffix}", endpoint,
            _make_plugin_toggle_view(service, enabled), methods=["POST"],
        )


def _make_plugin_toggle_view(service: ProxyPoolService, enabled: bool) -> Callable:
    def view(plugin_name: str):
        response, error = _run(
            service,
            plugin_routes.set_plugin_enabled(plugin_name, enabled),
            MUTATION_TIMEOUT,
        )
        return error or response

    return view


def _register_batch_routes(blueprint: Blueprint, service: ProxyPoolService) -> None:
    blueprint.add_url_rule("/host-ip", "pool_host_ip",
                           _bind_query(service, validation_routes.get_host_ip),
                           methods=["GET"])
    blueprint.add_url_rule("/validate/all-valid", "pool_validate_valid",
                           _bind_no_args(service, lambda: validation_routes.validate_all_proxies(True)),
                           methods=["POST"])
    blueprint.add_url_rule("/validate/all-invalid", "pool_validate_invalid",
                           _bind_no_args(service, lambda: validation_routes.validate_all_proxies(False)),
                           methods=["POST"])
    blueprint.add_url_rule("/update-geo/all", "pool_update_geo",
                           _bind_no_args(service, validation_routes.update_all_geo),
                           methods=["POST"])
    blueprint.add_url_rule("/delete/invalid", "pool_delete_invalid",
                           _bind_no_args(service, validation_routes.delete_invalid_proxies,
                                         HEAVY_TIMEOUT),
                           methods=["DELETE"])
    blueprint.add_url_rule("/proxies/batch/validate", "pool_batch_validate",
                           _bind_body(service, validation_routes.validate_batch_proxies,
                                      HEAVY_TIMEOUT),
                           methods=["POST"])
    blueprint.add_url_rule("/proxies/batch/delete", "pool_batch_delete",
                           _bind_body(service, validation_routes.delete_batch_proxies,
                                      HEAVY_TIMEOUT),
                           methods=["DELETE"])
    blueprint.add_url_rule("/tasks", "pool_tasks",
                           _bind_query(service, validation_routes.list_all_tasks), methods=["GET"])
    blueprint.add_url_rule("/tasks/<task_id>", "pool_task",
                           _bind_query(service, validation_routes.get_task_status), methods=["GET"])
    blueprint.add_url_rule("/tasks/<task_id>/cancel", "pool_task_cancel",
                           _bind_query(service, validation_routes.cancel_task),
                           methods=["POST"])


__all__ = ["create_pool_blueprint", "QUERY_TIMEOUT", "MUTATION_TIMEOUT", "HEAVY_TIMEOUT"]
