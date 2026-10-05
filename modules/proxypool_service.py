"""
模块名称：modules.proxypool_service
功能描述：代理池在 ProxyCat 进程内的宿主：用专用线程承载池的 asyncio 事件循环，对外只暴露同步门面方法，
          供 Flask 同步路由与 CLI 调用，另提供进程内事件循环使用的异步取用入口（取一个 / 取一批出口代理）。
职责边界：负责：事件循环线程的创建与销毁、Application 初始化与关闭、跨线程调用的桥接与超时/异常转换、配置推送；
          不负责：HTTP 路由与请求解析（见 proxypool_api）、配置文件读写（见 ProxyCat 配置接口）、池业务逻辑（见 core.services）。
关键依赖：core.application（app / api.dependencies）、core.config.Config、core.logger、
          modules.pool_config_ini、modules.logging_setup、modules.loop_noise_filter、modules.modules。
已知限制：
  1. from modules.proxypool import POOL_DIR 仅靠导入副作用注入 sys.path，必须早于 core.* 导入且不可删除。
  2. 在池事件循环线程内调用 call() 会死锁；call() 有线程守卫，池线程内调用直接抛 RuntimeError。
  3. 调用超时必须大于池内部最长超时（aiohttp 30 秒）；DEFAULT_CALL_TIMEOUT 取 35 秒，超时后调用方放弃而池仍在跑。
  4. stop() 默认 35 秒预算等于池内各段最坏耗时之和（插件停止 10 秒 + 配置落库 5 秒 + 写队列排空 15 秒 + 余量），改动任一段都要重算。
  5. 上一次 stop() 超时未让线程退出时 start() 拒绝启动，避免两个 Application 并存并同写 proxies.db。
  6. stop 超时后 _stopping 常置：is_running 为假而线程可能仍在写库，退出与恢复路径须按 has_live_thread 判断。
  7. 语言提供者须在构造期注册（池未启动时面板仍按当前语言渲染池设置文案），不可因初始化阶段会重复注册而删除。
"""

import asyncio
import concurrent.futures
import logging
import os
import random
import threading
from pathlib import Path
from typing import Any, Callable, Coroutine, Optional

from modules.proxypool import POOL_DIR  # noqa: F401
from core.application.app import Application
from core.application.api.dependencies import (
    set_container, set_dedup_cache, set_language_provider,
)
from core.config import Config
from core.logger import attach_pool_log_handlers

from modules import pool_config_ini
from modules.logging_setup import LogCategory, classify_record
from modules.loop_noise_filter import install_loop_noise_filter
from modules.modules import get_message

logger = logging.getLogger(__name__)

DEFAULT_CALL_TIMEOUT = 35.0

CONFIG_WATCH_INTERVAL = 3.0


class _PoolLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return classify_record(record) == LogCategory.POOL


class PoolUnavailableError(RuntimeError):
    pass


class PoolTimeoutError(RuntimeError):
    pass


class ProxyPoolService:
    def __init__(self, config: Config, config_ini_path: str | Path,
                 language_provider: Optional[Callable[[], str]] = None):
        self._config = config
        self._config_ini_path = Path(config_ini_path)
        self._language_provider = language_provider
        set_language_provider(language_provider)

        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._application: Optional[Application] = None

        self._ready = threading.Event()
        self._stopping = threading.Event()
        self._startup_ok = False
        self._lifecycle_lock = threading.RLock()

        self._last_error: Optional[str] = None
        self._last_mtime: float = 0.0
        self._watch_task: Optional[asyncio.Task] = None

    @property
    def is_running(self) -> bool:
        thread = self._thread
        return bool(
            thread is not None
            and thread.is_alive()
            and self._startup_ok
            and self._ready.is_set()
            and not self._stopping.is_set()
        )

    @property
    def has_live_thread(self) -> bool:
        thread = self._thread
        return thread is not None and thread.is_alive()

    @property
    def last_error(self) -> Optional[str]:
        return self._last_error

    @property
    def language(self) -> str:
        if self._language_provider is None:
            return 'cn'
        return self._language_provider() or 'cn'

    def start(self, timeout: float = 30.0) -> bool:
        with self._lifecycle_lock:
            if self.is_running:
                return True

            previous = self._thread
            if previous is not None and previous.is_alive():
                self._last_error = get_message('pool_previous_stop_incomplete', self.language)
                logger.error(self._last_error)
                return False

            self._ready.clear()
            self._stopping.clear()
            self._startup_ok = False
            self._last_error = None
            self._remember_config_mtime()

            self._thread = threading.Thread(
                target=self._run_loop, name="proxypool-loop", daemon=True
            )
            self._thread.start()

        if not self._ready.wait(timeout):
            self._last_error = get_message('pool_start_timeout', self.language, f"{timeout:.0f}")
            logger.error(self._last_error)
            return False

        return self.is_running

    def stop(self, timeout: float = 35.0) -> bool:
        with self._lifecycle_lock:
            thread = self._thread
            if thread is None or not thread.is_alive():
                self._thread = None
                return True

            logger.info(get_message('pool_stopping', self.language))
            self._stopping.set()

            loop = self._loop
            if loop is not None:
                try:
                    loop.call_soon_threadsafe(loop.stop)
                except RuntimeError:
                    pass

        thread.join(timeout)

        if thread.is_alive():
            self._last_error = get_message('pool_stop_timeout', self.language, f"{timeout:.0f}")
            logger.error(self._last_error)
            return False

        with self._lifecycle_lock:
            self._thread = None
            self._loop = None
            self._stopping.clear()

        logger.info(get_message('pool_stop_success', self.language))
        return True

    def restart(self, timeout: float = 30.0) -> bool:
        with self._lifecycle_lock:
            self.stop(timeout=timeout)
            return self.start(timeout=timeout)

    def _run_loop(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        install_loop_noise_filter(loop)

        initialized = False
        try:
            loop.run_until_complete(self._initialize_application())
            initialized = True
            self._startup_ok = True
            logger.info(get_message('pool_start_success', self.language))
        except Exception as e:
            self._startup_ok = False
            self._last_error = f"{type(e).__name__}: {e}"
            logger.error(get_message('pool_start_failed', self.language, e), exc_info=True)
        finally:
            self._ready.set()

        if initialized:
            try:
                loop.run_forever()
            except Exception as e:
                self._last_error = f"{type(e).__name__}: {e}"
                logger.error(get_message('pool_loop_crashed', self.language, e), exc_info=True)

        self._shutdown_application(loop)

    async def _initialize_application(self) -> None:
        application = Application(self._config)
        try:
            await application.initialize()
        except BaseException:
            try:
                await application.shutdown()
            except Exception as e:
                logger.warning("初始化失败后的收尾也失败了（不影响报错）: %s", e)
            raise

        self._application = application
        set_container(application.get_container())
        set_dedup_cache(application.dedup_cache)
        set_language_provider(self._language_provider)

        attach_pool_log_handlers(
            self._config.logging,
            logging.getLogger().level or logging.INFO,
            record_filter=_PoolLogFilter(),
        )

        self._watch_task = asyncio.create_task(self._watch_config_file())

    def _shutdown_application(self, loop: asyncio.AbstractEventLoop) -> None:
        application = self._application
        self._application = None
        set_container(None)
        set_dedup_cache(None)

        if application is None:
            self._close_loop(loop)
            return

        try:
            loop.run_until_complete(application.shutdown())
        except Exception as e:
            logger.error("关闭代理池时出错: %s", e, exc_info=True)

        self._close_loop(loop)

    @staticmethod
    def _close_loop(loop: asyncio.AbstractEventLoop) -> None:
        try:
            pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
            for task in pending:
                task.cancel()
            if pending:
                loop.run_until_complete(
                    asyncio.gather(*pending, return_exceptions=True)
                )
        except Exception as e:
            logger.debug("清理残留任务时出错（忽略）: %s", e)
        finally:
            try:
                loop.close()
            except Exception as e:
                logger.debug("关闭事件循环时出错（忽略）: %s", e)

    def call(self, coro: Coroutine, timeout: float = DEFAULT_CALL_TIMEOUT) -> Any:
        if threading.current_thread() is self._thread:
            coro.close()
            raise RuntimeError("禁止在代理池事件循环线程内同步等待池调用（会死锁）")

        if not self.is_running or self._loop is None:
            coro.close()
            raise PoolUnavailableError(
                self._last_error or get_message('pool_not_running', self.language))

        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        try:
            return future.result(timeout)
        except concurrent.futures.TimeoutError:
            future.cancel()
            raise PoolTimeoutError(
                get_message('pool_call_timeout', self.language, f"{timeout:.0f}")) from None
        except concurrent.futures.CancelledError:
            raise PoolUnavailableError(
                get_message('pool_stopped', self.language)) from None

    def submit(self, coro: Coroutine) -> concurrent.futures.Future:
        if not self.is_running or self._loop is None:
            coro.close()
            raise PoolUnavailableError(
                self._last_error or get_message('pool_not_running', self.language))

        return asyncio.run_coroutine_threadsafe(coro, self._loop)

    async def _run_route(self, coro, timeout: float):
        future = self.submit(coro)
        return await asyncio.wait_for(asyncio.wrap_future(future), timeout=timeout)

    @staticmethod
    def _text_content(result) -> str:
        from core.application.api.http_types import RawResponse

        return result.content if isinstance(result, RawResponse) else str(result)

    async def fetch_random_proxy_url(self, timeout: float = 10.0) -> Optional[str]:
        from core.application.api.routes import proxies as proxy_routes

        if not self.is_running:
            return None

        result = await self._run_route(
            proxy_routes.get_random_proxy(status='valid', format='text'), timeout
        )
        return self._text_content(result).strip() or None

    async def fetch_proxy_entries(self, limit: int, timeout: float = 10.0) -> list:
        from core.application.api.routes import proxies as proxy_routes

        limit = int(limit)
        if not self.is_running or limit <= 0:
            return []

        counted = await self._run_route(
            proxy_routes.get_proxies_count(status='valid'), timeout
        )
        total = int((counted or {}).get('count', 0))
        if total <= 0:
            return []

        pages = max(1, (total + limit - 1) // limit)
        page = random.randint(1, pages)
        result = await self._run_route(
            proxy_routes.get_proxies(
                status='valid', page=page, page_size=limit, format='json'
            ),
            timeout,
        )
        return [entry for entry in (result or [])
                if isinstance(entry, dict)][:limit]

    async def fetch_proxy_urls(self, limit: int, timeout: float = 10.0) -> list:
        entries = await self.fetch_proxy_entries(limit, timeout)
        urls = [(entry.get('proxy_url') or '').strip() for entry in entries]
        return [url for url in urls if url]

    async def report_proxy_use(self, ip: str, port: int, ok: bool,
                               test_url: str = "", timeout: float = 5.0) -> None:
        from core.application.api.routes import validation as validation_routes

        if not self.is_running:
            return

        try:
            future = self.submit(
                validation_routes.report_proxy_use(ip, port, ok, test_url)
            )
            await asyncio.wait_for(asyncio.wrap_future(future), timeout=timeout)
        except Exception as e:
            logger.debug("使用期反馈上报失败（已忽略）: %s: %s", type(e).__name__, e)

    def apply_config(self, config: Config, timeout: float = 15.0) -> None:
        if not self.is_running or self._application is None:
            raise PoolUnavailableError(
                self._last_error or get_message('pool_not_running', self.language))

        self.call(self._application.apply_config(config), timeout=timeout)
        attach_pool_log_handlers(
            config.logging,
            logging.getLogger().level or logging.INFO,
            record_filter=_PoolLogFilter(),
        )

    def reload_config_from_file(self, timeout: float = 15.0) -> None:
        config = pool_config_ini.load_pool_config(self._config_ini_path)
        self._config = config
        self.apply_config(config, timeout=timeout)

    def note_config_saved(self) -> None:
        self._remember_config_mtime()

    def _remember_config_mtime(self) -> None:
        try:
            self._last_mtime = os.path.getmtime(self._config_ini_path)
        except OSError:
            self._last_mtime = 0.0

    async def _watch_config_file(self) -> None:
        while True:
            try:
                await asyncio.sleep(CONFIG_WATCH_INTERVAL)
                mtime = os.path.getmtime(self._config_ini_path)
                if mtime <= self._last_mtime:
                    continue

                config = pool_config_ini.reload_pool_config(self._config_ini_path)
                if config is None:
                    logger.warning(get_message('pool_config_unreadable', self.language))
                    continue

                logger.info(get_message('config_file_changed', self.language))
                self._config = config
                if self._application is not None:
                    await self._application.apply_config(config)
                self._last_mtime = mtime
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning("配置文件兜底轮询出错（不影响运行）: %s", e)


__all__ = ["ProxyPoolService", "PoolUnavailableError", "PoolTimeoutError"]
