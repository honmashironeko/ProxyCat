"""
模块名称：modules.proxypool.core.application.batch_tasks
功能描述：代理池的后台批量任务与任务状态表：Web 层经本模块 spawn 启动五类批量任务与两类维护任务，执行体把进度写入进程内状态表，供前端按 task_id 轮询。
职责边界：负责：任务登记、取消与状态写入，状态表的 TTL 与条数淘汰，以及各批量与维护任务的执行体；
          不负责：任务的发起与调度（路由层）、单个代理的验证算法（ProxyValidator）、验证结果的入库与落地（ingest、validation_apply）。
关键依赖：core.application.api.dependencies、core.application.ingest、
          core.services.validation_apply、core.services.validation_policy、
          core.services.health_scorer、core.domain.models、
          core.infrastructure.geodb、modules.modules。
已知限制：
1. 取消是协作式的，只在下一个 await 点生效：在跑的一批先收尾（可能已写入），未开始的候选直接丢弃，不保证零写入，且取消状态写出后重新抛出 CancelledError。
2. asyncio.to_thread 中的离线归属地库下载不可取消：等待方退出后下载线程仍会跑完，仍可能完成文件换入。
3. 状态表是进程内内存态：进程重启即丢；被 TTL 淘汰的 id 再查是「不存在」而非「已完成」；终态（含 cancelled）保留 1 小时，条数上限 200，运行中的任务不参与淘汰。
4. 状态表只在池的事件循环线程内读写，跨线程进度更新必须经 loop.call_soon_threadsafe 回投事件循环。
5. 未经 spawn 登记的任务在关闭流程中无法定向取消，只能落到兜底的 cancel-all。
6. status.message 按写入时的界面语言渲染：切换语言只影响之后的写入，已写出的快照不会回溯翻译。
7. 终态集合必须包含 cancelled：漏掉它，取消过的条目既过不了 TTL、也进不了条数淘汰，状态表只增不减。
8. 验证任务入参 targets 必须保持 (proxy_id, proxy_url) 成对：调用方会跳过已删除的 id，拆成两个平行列表会错位，验证结果会写到别的代理头上。
"""

import asyncio
import logging
import uuid
from datetime import datetime
from typing import Optional

from core.services.validation_apply import (
    APPLY_APPLIED,
    build_update_operation,
    dispatch_validation_action,
)
from core.application.ingest import IngestProgress, ingest_proxies
from modules.modules import sanitize_proxy


def _message(key: str, *args) -> str:
    from core.application.api.dependencies import get_language
    from modules.modules import get_message

    return get_message(key, get_language(), *args)


def _language() -> str:
    from core.application.api.dependencies import get_language

    return get_language()


_STAGE_MESSAGE_KEYS = {
    "prescreen": "task_stage_prescreen_text",
    "validate": "task_stage_validate_text",
    "ingest": "task_stage_ingest_text",
}

logger = logging.getLogger(__name__)


background_tasks_status: dict[str, dict] = {}
_MAX_TASK_STATUS = 200

_TERMINAL_TASK_STATUSES = ('completed', 'failed', 'cancelled')

_running_tasks: set = set()

_task_handles: dict = {}

def spawn(coro, task_id: Optional[str] = None):
    task = asyncio.create_task(coro)
    _running_tasks.add(task)
    if task_id:
        _task_handles[task_id] = task

    def _forget(finished):
        _running_tasks.discard(finished)
        if task_id and _task_handles.get(task_id) is finished:
            del _task_handles[task_id]

    task.add_done_callback(_forget)
    return task


async def cancel_task(task_id: str) -> bool:
    task = _task_handles.get(task_id)
    if task is None or task.done():
        return False

    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, Exception):
        pass
    return True


async def cancel_running_tasks() -> None:
    tasks = [task for task in _running_tasks if not task.done()]
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    logger.info("已取消 %d 个在跑的后台任务", len(tasks))

_TASK_STATUS_TTL_SECONDS = 3600


def new_task_id() -> str:
    cleanup_task_status()
    return str(uuid.uuid4())


def cleanup_task_status():
    now = datetime.now()

    expired_keys = []
    for task_id, status_info in background_tasks_status.items():
        if status_info.get('status') not in _TERMINAL_TASK_STATUSES:
            continue
        completed_at_str = status_info.get('completed_at')
        if not completed_at_str:
            continue
        try:
            completed_at = datetime.fromisoformat(completed_at_str)
            if (now - completed_at).total_seconds() > _TASK_STATUS_TTL_SECONDS:
                expired_keys.append(task_id)
        except (ValueError, TypeError):
            continue

    for key in expired_keys:
        del background_tasks_status[key]

    if len(background_tasks_status) > _MAX_TASK_STATUS:
        settled = [
            (k, v) for k, v in background_tasks_status.items()
            if v.get('status') in _TERMINAL_TASK_STATUSES
        ]
        settled.sort(key=lambda item: item[1].get('completed_at', ''))
        for k, _ in settled[:len(settled) // 2]:
            del background_tasks_status[k]


async def validate_and_save_proxies_task(
    task_id: str, plugin_name: str, unique_proxies: list[str]
):
    total = len(unique_proxies)
    background_tasks_status[task_id] = {
        "status": "running",
        "message": _message(_STAGE_MESSAGE_KEYS["prescreen"]),
        "stage": "prescreen",
        "progress": 0,
        "total": total,
        "stage_done": 0,
        "stage_total": total,
        "rate": 0.0,
        "eta_seconds": None,
        "started_at": datetime.now().isoformat(),
        "valid_count": 0,
        "invalid_count": 0,
        "inconclusive_count": 0,
        "prescreened_out": 0,
        "incomplete_count": 0,
        "failed_count": 0,
    }

    def _on_progress(snapshot: IngestProgress) -> None:
        status = background_tasks_status.get(task_id)
        if status is None:
            return
        stats = snapshot.stats
        status["stage"] = snapshot.stage
        stage_key = _STAGE_MESSAGE_KEYS.get(snapshot.stage)
        if stage_key:
            status["message"] = _message(stage_key)
        status["stage_done"] = snapshot.done
        status["stage_total"] = snapshot.total
        status["in_flight"] = snapshot.in_flight
        status["rate"] = round(snapshot.rate, 1)
        status["eta_seconds"] = (
            round(snapshot.eta_seconds) if snapshot.eta_seconds is not None else None
        )
        status["progress"] = (
            stats.prescreened_out + stats.saved + stats.invalid
            + stats.incomplete + stats.inconclusive + stats.failed
        )
        status["valid_count"] = stats.saved
        status["invalid_count"] = stats.invalid
        status["inconclusive_count"] = stats.inconclusive
        status["prescreened_out"] = stats.prescreened_out
        status["incomplete_count"] = stats.incomplete
        status["failed_count"] = stats.failed

    try:
        stats = await ingest_proxies(
            unique_proxies, source_plugin=plugin_name, on_progress=_on_progress
        )
    except asyncio.CancelledError:
        status = background_tasks_status.get(task_id, {})
        background_tasks_status[task_id] = {
            **status,
            "status": "cancelled",
            "message": _message('task_cancelled_with_counts', _counts_text(status)),
            "completed_at": datetime.now().isoformat(),
        }
        logger.info("验证并保存代理任务被取消: %s", task_id)
        raise
    except Exception as e:
        logger.error(f"验证并保存代理任务失败: {e}", exc_info=True)
        background_tasks_status[task_id] = {
            **background_tasks_status.get(task_id, {}),
            "status": "failed",
            "message": _message('task_failed', str(e)),
            "total": total,
            "completed_at": datetime.now().isoformat(),
        }
        return

    background_tasks_status[task_id] = {
        "status": "completed",
        "message": _message(
            'task_plugin_run_done', plugin_name, stats.summary(_language())
        ),
        "stage": "done",
        "progress": stats.total,
        "total": stats.total,
        "completed_at": datetime.now().isoformat(),
        "started_at": background_tasks_status.get(task_id, {}).get("started_at"),
        "valid_count": stats.saved,
        "invalid_count": stats.invalid,
        "inconclusive_count": stats.inconclusive,
        "prescreened_out": stats.prescreened_out,
        "incomplete_count": stats.incomplete,
        "failed_count": stats.failed,
    }


def _counts_text(status: dict) -> str:
    return _message(
        'task_counts_saved_unusable',
        status.get('valid_count', 0), status.get('invalid_count', 0),
    )


async def validate_selected_proxies_task(
    task_id: str, targets: list[tuple[int, str]], mode: str = "auto"
):
    from core.application.api.dependencies import (
        get_geo_resolver, get_proxy_repository, get_proxy_validator, get_config_manager,
        get_plugin_manager,
    )
    from core.domain.models import ValidationMode
    from core.services.validation_policy import pick_validation_mode

    try:
        background_tasks_status[task_id] = {
            "status": "running",
            "message": _message('task_validating'),
            "progress": 0,
            "total": len(targets),
        }

        repository = get_proxy_repository()
        validator = get_proxy_validator()
        geo_resolver = get_geo_resolver()
        config_manager = get_config_manager()

        completed_count = 0
        valid_count = 0
        inconclusive_count = 0

        async def validate_and_update(proxy_id: int, proxy_url: str) -> None:
            nonlocal completed_count, valid_count, inconclusive_count
            try:
                config = config_manager.get_config()
                proxy = await repository.get_by_id(proxy_id)
                validation_mode = (
                    pick_validation_mode(proxy, config)
                    if mode == "auto" else ValidationMode(mode)
                )
                test_url = get_plugin_manager().resolve_test_url(proxy.source_plugin)
                result = await validator.validate_proxy(
                    proxy_url, validation_mode, test_url=test_url
                )

                action, applied = await dispatch_validation_action(
                    result, mode=validation_mode, proxy=proxy,
                    geo_sink=geo_resolver.schedule,
                    sink=lambda applied: repository.update(proxy_id, dict(applied.fields)),
                )
                if action != APPLY_APPLIED:
                    inconclusive_count += 1
                    return

                if result.is_valid:
                    valid_count += 1

            except Exception as e:
                logger.warning(f"验证代理 {sanitize_proxy(proxy_url)} 失败: {e}")
            finally:
                completed_count += 1
                background_tasks_status[task_id]["progress"] = completed_count

        tasks = [
            validate_and_update(proxy_id, proxy_url)
            for proxy_id, proxy_url in targets
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

        background_tasks_status[task_id] = {
            "status": "completed",
            "message": _message(
                'task_validate_selected_done', valid_count, len(targets),
            ) + (_message('task_inconclusive_suffix', inconclusive_count)
                 if inconclusive_count else ""),
            "progress": len(targets),
            "total": len(targets),
            "inconclusive_count": inconclusive_count,
            "completed_at": datetime.now().isoformat(),
        }

    except asyncio.CancelledError:
        status = background_tasks_status.get(task_id, {})
        background_tasks_status[task_id] = {
            **status,
            "status": "cancelled",
            "message": _message('task_cancelled_with_counts', _counts_text(status)),
            "completed_at": datetime.now().isoformat(),
        }
        logger.info("验证选中代理的任务被取消: %s", task_id)
        raise
    except Exception as e:
        logger.error(f"批量验证任务失败: {e}", exc_info=True)
        background_tasks_status[task_id] = {
            "status": "failed",
            "message": _message('task_failed', str(e)),
            "progress": 0,
            "total": len(targets),
            "completed_at": datetime.now().isoformat(),
        }


async def validate_all_proxies_task(task_id: str, is_valid_filter: bool):
    from core.application.api.dependencies import (
        get_proxy_repository, get_proxy_validator, get_plugin_manager,
        get_write_queue, get_geo_resolver, get_config_manager
    )
    from core.domain.models import ProxyFilter, DBOperation
    from core.services.health_scorer import HealthScorer
    from core.services.validation_policy import pick_validation_mode

    try:
        background_tasks_status[task_id] = {
            "status": "running",
            "message": _message('task_validating'),
            "progress": 0,
            "total": 0,
        }

        repository = get_proxy_repository()
        validator = get_proxy_validator()
        write_queue = get_write_queue()
        geo_resolver = get_geo_resolver()
        config_manager = get_config_manager()
        scorer = HealthScorer()

        filter_obj = ProxyFilter(is_valid=is_valid_filter)

        all_proxies = []
        page = 1
        page_size = 5000
        while True:
            batch = await repository.find(filter_obj, page=page, page_size=page_size)
            if not batch:
                break
            all_proxies.extend(batch)
            if len(batch) < page_size:
                break
            page += 1

        proxies = all_proxies

        if not proxies:
            background_tasks_status[task_id] = {
                "status": "completed",
                "message": _message('task_no_proxies_to_validate'),
                "progress": 0,
                "total": 0,
                "completed_at": datetime.now().isoformat(),
            }
            return

        total = len(proxies)
        background_tasks_status[task_id]["total"] = total

        completed_count = 0
        inconclusive_count = 0

        async def validate_and_update(proxy) -> None:
            nonlocal completed_count, inconclusive_count

            try:
                proxy_url = proxy.proxy_url
                config = config_manager.get_config()
                mode = pick_validation_mode(proxy, config)
                test_url = get_plugin_manager().resolve_test_url(proxy.source_plugin)

                result = await validator.validate_proxy(proxy_url, mode, test_url=test_url)

                action, applied = await dispatch_validation_action(
                    result, mode=mode, proxy=proxy, scorer=scorer,
                    geo_sink=geo_resolver.schedule,
                    sink=lambda applied: write_queue.enqueue(
                        build_update_operation(proxy, applied)),
                )
                if action != APPLY_APPLIED:
                    inconclusive_count += 1
                    return
            except Exception as e:
                logger.warning(f"验证代理 {proxy.ip}:{proxy.port} 失败: {e}")
            finally:
                completed_count += 1
                background_tasks_status[task_id]["progress"] = completed_count

        tasks = [validate_and_update(proxy) for proxy in proxies]
        await asyncio.gather(*tasks, return_exceptions=True)

        background_tasks_status[task_id] = {
            "status": "completed",
            "message": _message('task_validate_all_done', total)
            + (_message('task_inconclusive_among_suffix', inconclusive_count)
               if inconclusive_count else ""),
            "progress": total,
            "total": total,
            "inconclusive_count": inconclusive_count,
            "completed_at": datetime.now().isoformat(),
        }

    except asyncio.CancelledError:
        status = background_tasks_status.get(task_id, {})
        background_tasks_status[task_id] = {
            **status,
            "status": "cancelled",
            "message": _message('task_cancelled_with_counts', _counts_text(status)),
            "completed_at": datetime.now().isoformat(),
        }
        logger.info("批量验证任务被取消: %s", task_id)
        raise
    except Exception as e:
        logger.error(f"批量验证任务失败: {e}", exc_info=True)
        background_tasks_status[task_id] = {
            "status": "failed",
            "message": _message('task_validate_failed', str(e)),
            "progress": 0,
            "total": 0,
            "completed_at": datetime.now().isoformat(),
        }


async def update_all_geo_task(task_id: str):
    from core.application.api.dependencies import (
        get_geo_resolver, get_proxy_repository, get_write_queue, get_proxy_validator,
        get_plugin_manager,
    )
    from core.domain.models import DBOperation, ProxyFilter
    from core.services.health_scorer import HealthScorer

    try:
        background_tasks_status[task_id] = {
            "status": "running",
            "message": _message('task_checking'),
            "progress": 0,
            "total": 0,
        }

        repository = get_proxy_repository()
        write_queue = get_write_queue()
        geo_resolver = get_geo_resolver()
        validator = get_proxy_validator()
        scorer = HealthScorer()

        proxies = []
        page = 1
        page_size = 5000
        while True:
            batch = await repository.find(ProxyFilter(), page=page, page_size=page_size)
            if not batch:
                break
            proxies.extend(batch)
            if len(batch) < page_size:
                break
            page += 1

        if not proxies:
            background_tasks_status[task_id] = {
                "status": "completed",
                "message": _message('task_pool_empty'),
                "progress": 0,
                "total": 0,
                "completed_at": datetime.now().isoformat(),
            }
            return

        total = len(proxies)
        background_tasks_status[task_id]["total"] = total
        inconclusive_count = 0
        completed_count = 0

        async def validate_and_update(proxy) -> None:
            nonlocal completed_count, inconclusive_count

            from core.domain.models import ValidationMode
            try:
                test_url = get_plugin_manager().resolve_test_url(proxy.source_plugin)
                result = await validator.validate_proxy(
                    proxy.proxy_url, ValidationMode.FULL, test_url=test_url
                )

                action, applied = await dispatch_validation_action(
                    result, mode=ValidationMode.FULL, proxy=proxy, scorer=scorer,
                    geo_sink=geo_resolver.schedule,
                    sink=lambda applied: write_queue.enqueue(
                        build_update_operation(proxy, applied)),
                )
                if action != APPLY_APPLIED:
                    inconclusive_count += 1
                    return

            except Exception as e:
                logger.warning(f"检测代理 {proxy.ip}:{proxy.port} 失败: {e}")
            finally:
                completed_count += 1
                background_tasks_status[task_id]["progress"] = completed_count

        tasks = [validate_and_update(proxy) for proxy in proxies]
        await asyncio.gather(*tasks, return_exceptions=True)

        background_tasks_status[task_id] = {
            "status": "completed",
            "message": _message('task_check_done', total)
            + (_message('task_inconclusive_among_suffix', inconclusive_count)
               if inconclusive_count else ""),
            "progress": total,
            "total": total,
            "inconclusive_count": inconclusive_count,
            "completed_at": datetime.now().isoformat(),
        }

    except asyncio.CancelledError:
        status = background_tasks_status.get(task_id, {})
        background_tasks_status[task_id] = {
            **status,
            "status": "cancelled",
            "message": _message('task_cancelled_with_counts', _counts_text(status)),
            "completed_at": datetime.now().isoformat(),
        }
        logger.info("代理检测任务被取消: %s", task_id)
        raise
    except Exception as e:
        logger.error(f"代理检测任务失败: {e}", exc_info=True)
        background_tasks_status[task_id] = {
            "status": "failed",
            "message": _message('task_check_failed', str(e)),
            "progress": 0,
            "total": 0,
            "completed_at": datetime.now().isoformat(),
        }


async def run_plugin_task(task_id: str, plugin_name: str):
    from core.application.api.dependencies import (
        get_plugin_manager, get_config_manager,
    )

    manager = get_plugin_manager()
    try:
        fetch_timeout = get_config_manager().get_config().plugins.execution_timeout_seconds
        background_tasks_status[task_id] = {
            "status": "running",
            "message": _message(
                'task_plugin_fetching', plugin_name, max(1, fetch_timeout // 60)
            ),
            "progress": 0,
            "total": 0,
            "started_at": datetime.now().isoformat(),
        }

        proxies = await manager.execute_plugin(plugin_name)

        if not proxies:
            background_tasks_status[task_id] = {
                "status": "completed",
                "message": _message('task_plugin_no_new_proxies', plugin_name),
                "progress": 0,
                "total": 0,
                "completed_at": datetime.now().isoformat(),
            }
            return

        unique_proxies = await manager.deduplicate_proxies(proxies)

        await validate_and_save_proxies_task(task_id, plugin_name, unique_proxies)

    except asyncio.CancelledError:
        status = background_tasks_status.get(task_id, {})
        background_tasks_status[task_id] = {
            **status,
            "status": "cancelled",
            "message": _message(
                'task_plugin_fetch_cancelled', plugin_name, _counts_text(status)
            ),
            "completed_at": datetime.now().isoformat(),
        }
        raise
    except Exception as e:
        logger.error(f"插件抓取任务失败 {plugin_name}: {e}", exc_info=True)
        background_tasks_status[task_id] = {
            "status": "failed",
            "message": _message('task_plugin_failed', plugin_name, e),
            "completed_at": datetime.now().isoformat(),
        }


async def update_geo_databases_task(task_id: str, live=None) -> None:
    from core.infrastructure.geodb import update_databases

    loop = asyncio.get_running_loop()
    background_tasks_status[task_id] = {
        "status": "running",
        "message": _message('task_geo_downloading'),
        "progress": 0,
        "total": 0,
    }

    def report(name: str, done: int, total: int) -> None:
        def apply() -> None:
            status = background_tasks_status.get(task_id)
            if status is None:
                return
            pct = int(done * 100 / total) if total else 0
            status["message"] = _message('task_geo_downloading_file', name, pct)
            status["progress"] = done
            status["total"] = total or 0

        loop.call_soon_threadsafe(apply)

    try:
        results = await asyncio.to_thread(update_databases, None, progress=report, live=live)
    except asyncio.CancelledError:
        background_tasks_status[task_id] = {
            "status": "cancelled",
            "message": _message('task_geo_update_cancelled'),
            "completed_at": datetime.now().isoformat(),
        }
        raise
    except Exception as e:
        logger.error(f"更新离线归属地库失败: {e}", exc_info=True)
        background_tasks_status[task_id] = {
            "status": "failed",
            "message": _message('task_geo_update_failed', e),
            "completed_at": datetime.now().isoformat(),
        }
        return

    failed = [name for name, outcome in results.items() if outcome.startswith("失败")]
    background_tasks_status[task_id] = {
        "status": "completed",
        "message": (
            _message('task_geo_update_done')
            if not failed
            else _message('task_geo_update_partial', '、'.join(failed))
        ),
        "results": results,
        "completed_at": datetime.now().isoformat(),
    }


_RECOMPUTE_POLL_SECONDS = 1.0


async def recompute_geo_task(task_id: str) -> None:
    from core.application.api.dependencies import get_geo_resolver, get_proxy_repository

    resolver = get_geo_resolver()
    if resolver is None:
        background_tasks_status[task_id] = {
            "status": "failed",
            "message": _message('task_geo_recompute_disabled'),
            "completed_at": datetime.now().isoformat(),
        }
        return

    background_tasks_status[task_id] = {
        "status": "running",
        "message": _message('task_geo_picking'),
        "progress": 0,
        "total": 0,
    }

    try:
        repository = get_proxy_repository()
        ips = await repository.get_ips_missing_geo_codes()
        if not ips:
            background_tasks_status[task_id] = {
                "status": "completed",
                "message": _message('task_geo_nothing_to_recompute'),
                "progress": 0,
                "total": 0,
                "completed_at": datetime.now().isoformat(),
            }
            return

        accepted = sum(1 for ip in ips if resolver.schedule(ip))
        background_tasks_status[task_id] = {
            "status": "running",
            "message": _message('task_geo_queued', accepted),
            "progress": 0,
            "total": accepted,
        }

        while resolver.stats().get("pending", 0) > 0:
            await asyncio.sleep(_RECOMPUTE_POLL_SECONDS)
            snapshot = resolver.stats()
            done = max(0, accepted - snapshot.get("pending", 0))
            background_tasks_status[task_id]["progress"] = done
            background_tasks_status[task_id]["message"] = _message(
                'task_geo_resolving', done, accepted
            )
    except asyncio.CancelledError:
        background_tasks_status[task_id] = {
            "status": "cancelled",
            "message": _message('task_geo_recompute_cancelled'),
            "completed_at": datetime.now().isoformat(),
        }
        raise
    except Exception as e:
        logger.error(f"重算归属地失败: {e}", exc_info=True)
        background_tasks_status[task_id] = {
            "status": "failed",
            "message": _message('task_geo_recompute_failed', e),
            "completed_at": datetime.now().isoformat(),
        }
        return

    background_tasks_status[task_id] = {
        "status": "completed",
        "message": _message('task_geo_recompute_done', accepted),
        "progress": accepted,
        "total": accepted,
        "completed_at": datetime.now().isoformat(),
    }
