"""
模块名称：modules.proxypool.core.services.plugin_manager
功能描述：抓取插件的发现、加载与周期调度：扫描 plugins/ 目录并热加载，按各插件配置的周期并行执行，
          抓取到的地址去重后交统一入库流水线入库；插件配置 skip_validation 时该流水线不经验证直接写库。
职责边界：负责：插件扫描与热重载、周期调度与失败退避重试、并行限流、插件配置与验证策略的持久化、
          错误记录；不负责：抓取结果的验证与写库（见 core.application.ingest）、代理质量判定。
关键依赖：core.paths、modules.modules（sanitize_proxy）、core.services.validation_policy（resolve_test_url）、
          core.interfaces 契约、core.domain 模型与异常、core.application.ingest（函数内导入）、
          Config（仅类型标注）、注入的 DedupCache。
已知限制：
  1. 插件模块以 plugin.<文件名> 注册进 sys.modules；若改用裸文件名，plugins/ 内的同名文件会顶掉同名标准库模块；模块加载执行抛错时立即撤回注册。
  2. skip_validation 由本模块持久化并按插件生效，为真时 ingest_proxies 走直接入库路径，不做验证与初筛。
  3. 去重判据是 ip:port 而非仅 ip，同一 IP 的不同端口是两个代理；DedupCache 未就绪时回落到全表扫描，整体去重失败时原样返回输入。
  4. 执行返回值不是 list 时不推进 next_run，下一轮扫描会立即重试；已禁用的插件执行返回空列表而不抛异常。
  5. 并发上限为 max(1, plugins.max_parallel_plugins)，start() 不做幂等保护；stop() 等待在跑任务至多 10 秒。
  6. stop() 等待配置落库的上限 5 秒必须保留：外层 ProxyPoolService.stop 的 35 秒预算按段累加。
  7. 配置写库是异步的，方法返回时磁盘可能仍是旧值，stop() 靠持有任务引用等待落库；错误记录是进程内内存态，重启即清零。
  8. 热重载先摘除旧实例再加载新版本，失败时放回旧实例，避免一次加载错误导致插件从面板上消失。
"""

import asyncio
import importlib.util
import inspect
import logging
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional, TYPE_CHECKING
from urllib.parse import urlparse

from core.paths import resolve_pool_path
from modules.modules import sanitize_proxy
from core.interfaces.services import IPluginManager
from core.interfaces.repository import IPluginConfigRepository, IProxyRepository
from core.interfaces.infrastructure import IWriteQueue, IHttpClient

if TYPE_CHECKING:
    from core.config import Config
from core.interfaces.services import IProxyPlugin, PluginContext
from core.domain.models import PluginConfig, PluginStatus, Proxy
from core.services.validation_policy import resolve_test_url
from core.domain.exceptions import (
    InvalidParameterException,
    PluginException,
    PluginExecutionException
)

logger = logging.getLogger(__name__)


def _is_http_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)

_PLUGIN_MODULE_PREFIX = "plugin."


class LegacyPluginAdapter(IProxyPlugin):
    def __init__(self, legacy_module: Any):
        self._module = legacy_module
        self._name = legacy_module.__name__

    async def fetch_proxies(self, context: PluginContext) -> list[str]:
        try:
            fetch_func = getattr(self._module, 'fetch_proxies')

            if inspect.iscoroutinefunction(fetch_func):
                return await fetch_func()
            else:
                loop = asyncio.get_running_loop()
                return await loop.run_in_executor(None, fetch_func)
        except Exception as e:
            raise PluginExecutionException(f"旧插件执行失败: {str(e)}") from e

    @property
    def name(self) -> str:
        return self._name

    @property
    def version(self) -> str:
        return "1.0.0"


class PluginManager(IPluginManager):
    def __init__(
        self,
        plugin_config_repo: IPluginConfigRepository,
        proxy_repo: IProxyRepository,
        http_client: IHttpClient,
        config: 'Config',
        dedup_cache: 'DedupCache' = None,
        plugins_dir: Optional[str] = None,
    ):
        self._plugin_config_repo = plugin_config_repo
        self._proxy_repo = proxy_repo
        self._http_client = http_client
        self._config = config
        self._dedup_cache = dedup_cache

        self._plugins: dict[str, IProxyPlugin] = {}
        self._plugin_configs: dict[str, PluginConfig] = {}
        self._plugin_errors: dict[str, dict] = {}
        self._plugins_dir = resolve_pool_path(plugins_dir or "plugins")
        self._scheduler_task: Optional[asyncio.Task] = None
        self._pending_save_tasks = set()
        self._running = False
        self._execution_semaphore: Optional[asyncio.Semaphore] = None
        self._running_plugin_tasks: set[asyncio.Task] = set()

    def _schedule_save(self, coro):
        task = asyncio.create_task(coro)
        self._pending_save_tasks.add(task)
        task.add_done_callback(self._pending_save_tasks.discard)

    async def start(self) -> None:
        try:
            await self._load_plugin_configs()

            await self.scan_plugins()

            max_parallel = max(1, getattr(
                self._config.plugins, 'max_parallel_plugins', 3
            ))
            self._execution_semaphore = asyncio.Semaphore(max_parallel)
            logger.info(f"插件并行调度信号量已初始化: 最大并行数={max_parallel}")

            self._scheduler_task = asyncio.create_task(self._schedule_plugins())

            logger.info("插件管理器已启动")
        except Exception as e:
            raise PluginException(f"插件管理器启动失败: {str(e)}") from e

    async def stop(self) -> None:
        try:
            self._running = False

            if self._scheduler_task:
                self._scheduler_task.cancel()
                try:
                    await self._scheduler_task
                except asyncio.CancelledError:
                    pass

            if self._running_plugin_tasks:
                logger.info(
                    f"等待 {len(self._running_plugin_tasks)} 个正在运行的插件任务完成..."
                )
                try:
                    await asyncio.wait_for(
                        asyncio.gather(
                            *self._running_plugin_tasks, return_exceptions=True
                        ),
                        timeout=10.0
                    )
                except asyncio.TimeoutError:
                    logger.warning(
                        "插件任务等待超时，取消剩余任务"
                    )
                    for task in self._running_plugin_tasks:
                        task.cancel()
                self._running_plugin_tasks.clear()

            if self._pending_save_tasks:
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*self._pending_save_tasks, return_exceptions=True),
                        timeout=5.0
                    )
                except asyncio.TimeoutError:
                    logger.warning("等待插件配置落库超时（5 秒），放弃剩余写入")
                self._pending_save_tasks.clear()

            logger.info("插件管理器已停止")
        except Exception as e:
            raise PluginException(f"插件管理器停止失败: {str(e)}") from e

    async def scan_plugins(self) -> None:
        if not self._plugins_dir.exists():
            logger.error(
                f"插件目录不存在: {self._plugins_dir} —— 将创建空目录，"
                f"不会加载任何抓取插件，请检查配置中的路径"
            )
            self._plugins_dir.mkdir(parents=True, exist_ok=True)
            return

        plugin_files = [
            f for f in self._plugins_dir.glob("*.py")
            if f.name != "__init__.py" and not f.name.startswith("_")
        ]

        for plugin_file in plugin_files:
            plugin_name = plugin_file.stem

            if plugin_name in self._plugins:
                continue

            await self._load_plugin(str(plugin_file))

    async def execute_plugin(self, plugin_name: str) -> list[str]:
        if plugin_name not in self._plugins:
            raise PluginExecutionException(f"插件 {plugin_name} 未加载")

        config = self._plugin_configs.get(plugin_name)
        if config and not config.enabled:
            logger.warning(f"插件 {plugin_name} 已禁用，跳过执行")
            return []

        try:
            context = PluginContext(
                http_client=self._http_client,
                logger=logging.getLogger(f"plugin.{plugin_name}"),
                config=self._config
            )

            plugin = self._plugins[plugin_name]
            proxies = await asyncio.wait_for(
                plugin.fetch_proxies(context),
                timeout=self._config.plugins.execution_timeout_seconds
            )

            if not isinstance(proxies, list):
                error_msg = f"插件 {plugin_name} 返回值类型错误，期望 list，实际 {type(proxies)}"
                logger.error(error_msg)
                self._record_plugin_error(
                    plugin_name, "返回值类型错误", 'plugin_error_bad_return_type')
                return []

            await self._advance_schedule(plugin_name, config)

            if plugin_name in self._plugin_errors:
                del self._plugin_errors[plugin_name]

            logger.info(f"插件 {plugin_name} 执行成功，获取 {len(proxies)} 个代理")
            return proxies

        except asyncio.TimeoutError:
            error_msg = f"插件 {plugin_name} 执行超时"
            logger.error(error_msg)
            self._record_plugin_error(
                plugin_name, "执行超时", 'plugin_error_timeout')
            await self._advance_schedule(plugin_name, config)
            raise PluginExecutionException(error_msg)

        except Exception as e:
            error_msg = f"插件 {plugin_name} 执行失败: {e}"
            logger.error(error_msg, exc_info=True)
            self._record_plugin_error(plugin_name, str(e))
            await self._advance_schedule(plugin_name, config)
            raise PluginExecutionException(error_msg) from e

    async def _advance_schedule(self, plugin_name: str, config) -> None:
        if not config:
            return
        try:
            config.last_run = datetime.now()
            config.next_run = datetime.now() + timedelta(minutes=config.interval_minutes)
            await self._plugin_config_repo.save(config)
        except Exception as e:
            logger.warning("更新插件 %s 的调度时间失败: %s", plugin_name, e)

    def enable_plugin(self, plugin_name: str) -> None:
        if plugin_name not in self._plugin_configs:
            config = PluginConfig(
                name=plugin_name,
                enabled=True,
                interval_minutes=self._config.plugins.default_interval_minutes
            )
            self._plugin_configs[plugin_name] = config
        else:
            self._plugin_configs[plugin_name].enabled = True

        self._schedule_save(
            self._plugin_config_repo.save(self._plugin_configs[plugin_name])
        )
        logger.info(f"插件 {plugin_name} 已启用")

    def disable_plugin(self, plugin_name: str) -> None:
        if plugin_name not in self._plugin_configs:
            config = PluginConfig(
                name=plugin_name,
                enabled=False,
                interval_minutes=self._config.plugins.default_interval_minutes
            )
            self._plugin_configs[plugin_name] = config
        else:
            self._plugin_configs[plugin_name].enabled = False

        self._schedule_save(
            self._plugin_config_repo.save(self._plugin_configs[plugin_name])
        )
        logger.info(f"插件 {plugin_name} 已禁用")

    def set_plugin_interval(self, plugin_name: str, minutes: int) -> None:
        if minutes < 1:
            raise InvalidParameterException(
                'param_interval_must_be_positive', minutes)

        if plugin_name not in self._plugin_configs:
            config = PluginConfig(
                name=plugin_name,
                enabled=True,
                interval_minutes=minutes
            )
            self._plugin_configs[plugin_name] = config
        else:
            self._plugin_configs[plugin_name].interval_minutes = minutes

        self._schedule_save(
            self._plugin_config_repo.save(self._plugin_configs[plugin_name])
        )
        logger.info(f"插件 {plugin_name} 运行周期已设置为 {minutes} 分钟")

    def set_plugin_test_url(self, plugin_name: str, test_url: str) -> None:
        url = (test_url or "").strip()
        if url and not _is_http_url(url):
            raise ValueError(f"测试地址必须是 http/https 绝对地址: {test_url}")

        if plugin_name not in self._plugin_configs:
            config = PluginConfig(
                name=plugin_name,
                enabled=True,
                interval_minutes=self._config.plugins.default_interval_minutes,
            )
            self._plugin_configs[plugin_name] = config
        self._plugin_configs[plugin_name].test_url = url

        self._schedule_save(
            self._plugin_config_repo.save(self._plugin_configs[plugin_name])
        )
        logger.info(
            "插件 %s 的测试地址已设置为 %s", plugin_name, url or "（继承全局）"
        )

    def set_plugin_validation(
        self, plugin_name: str, reval_enabled: bool, reval_interval_minutes: int,
        skip_validation: bool,
    ) -> None:
        if reval_interval_minutes < 0:
            raise InvalidParameterException(
                'pool_field_reval_interval_invalid', reval_interval_minutes)

        if plugin_name not in self._plugin_configs:
            self._plugin_configs[plugin_name] = PluginConfig(
                name=plugin_name,
                enabled=True,
                interval_minutes=self._config.plugins.default_interval_minutes,
            )

        config = self._plugin_configs[plugin_name]
        config.reval_enabled = bool(reval_enabled)
        config.reval_interval_minutes = int(reval_interval_minutes)
        config.skip_validation = bool(skip_validation)

        self._schedule_save(self._plugin_config_repo.save(config))
        logger.info(
            "插件 %s 的验证策略已更新: 重验证 %s（间隔 %d 分钟），入库验证 %s",
            plugin_name,
            "开启" if config.reval_enabled else "关闭",
            config.reval_interval_minutes,
            "跳过" if config.skip_validation else "照常",
        )

    def should_skip_validation(self, plugin_name: str) -> bool:
        config = self._plugin_configs.get(plugin_name)
        return bool(config.skip_validation) if config else False

    def resolve_test_url(self, plugin_name: str) -> str:
        return resolve_test_url(
            self._plugin_configs.get(plugin_name),
            self._config.validator.target_url,
        )

    def get_plugin_status(self) -> dict[str, PluginStatus]:
        status_dict = {}

        for plugin_name in self._plugins.keys():
            config = self._plugin_configs.get(plugin_name)
            error_record = self._plugin_errors.get(plugin_name)
            last_error = error_record.get("message") if error_record else None
            last_error_key = error_record.get("message_key") if error_record else None

            if config:
                status = PluginStatus(
                    name=plugin_name,
                    enabled=config.enabled,
                    interval_minutes=config.interval_minutes,
                    last_run=config.last_run,
                    next_run=config.next_run,
                    last_error=last_error,
                    last_error_key=last_error_key,
                    is_loaded=True,
                    test_url=config.test_url,
                    reval_enabled=config.reval_enabled,
                    reval_interval_minutes=config.reval_interval_minutes,
                    skip_validation=config.skip_validation,
                )
            else:
                status = PluginStatus(
                    name=plugin_name,
                    enabled=True,
                    interval_minutes=self._config.plugins.default_interval_minutes,
                    last_run=None,
                    next_run=None,
                    last_error=last_error,
                    last_error_key=last_error_key,
                    is_loaded=True,
                )

            status_dict[plugin_name] = status

        return status_dict

    def apply_config(self, config: 'Config') -> None:
        old_scan_interval = self._config.plugins.scan_interval_seconds
        old_default_interval = self._config.plugins.default_interval_minutes
        old_timeout = self._config.plugins.execution_timeout_seconds
        old_max_parallel = self._config.plugins.max_parallel_plugins

        self._config = config

        if self._execution_semaphore is not None and \
                config.plugins.max_parallel_plugins != old_max_parallel:
            self._execution_semaphore = asyncio.Semaphore(
                max(1, config.plugins.max_parallel_plugins)
            )

        logger.info(
            f"插件管理器配置已更新: "
            f"scan_interval={old_scan_interval}->{config.plugins.scan_interval_seconds}s, "
            f"default_interval={old_default_interval}->{config.plugins.default_interval_minutes}min, "
            f"timeout={old_timeout}->{config.plugins.execution_timeout_seconds}s, "
            f"max_parallel={old_max_parallel}->{config.plugins.max_parallel_plugins}"
        )

    async def _load_plugin_configs(self) -> None:
        try:
            configs = await self._plugin_config_repo.get_all()
            for config in configs:
                self._plugin_configs[config.name] = config
            logger.info(f"加载了 {len(configs)} 个插件配置")
        except Exception as e:
            logger.error(f"加载插件配置失败: {e}", exc_info=True)

    async def _load_plugin(self, plugin_path: str) -> Optional[IProxyPlugin]:
        plugin_file = Path(plugin_path)
        plugin_name = plugin_file.stem

        if plugin_name in self._plugins:
            return self._plugins[plugin_name]

        try:
            module_name = f"{_PLUGIN_MODULE_PREFIX}{plugin_name}"
            spec = importlib.util.spec_from_file_location(module_name, plugin_file)
            if spec is None or spec.loader is None:
                logger.error(f"无法加载插件 {plugin_name}: 无效的模块规范")
                self._record_plugin_error(
                    plugin_name, "无效的模块规范", 'plugin_error_bad_spec')
                return None

            module = importlib.util.module_from_spec(spec)

            sys.modules[module_name] = module
            try:
                spec.loader.exec_module(module)
            except BaseException:
                sys.modules.pop(module_name, None)
                raise

            plugin_instance = None

            for item_name in dir(module):
                item = getattr(module, item_name)
                if (inspect.isclass(item) and
                    issubclass(item, IProxyPlugin) and
                    item is not IProxyPlugin):
                    plugin_instance = item()
                    logger.info(f"插件 {plugin_name} 实现了新接口 IProxyPlugin")
                    break

            if plugin_instance is None:
                if hasattr(module, 'fetch_proxies'):
                    plugin_instance = LegacyPluginAdapter(module)
                    logger.info(f"插件 {plugin_name} 使用旧接口，已通过适配器加载")
                else:
                    logger.error(f"插件 {plugin_name} 未实现 IProxyPlugin 接口或 fetch_proxies 函数")
                    self._record_plugin_error(
                        plugin_name, "未实现必需的接口", 'plugin_error_missing_interface')
                    return None

            self._plugins[plugin_name] = plugin_instance

            if plugin_name in self._plugin_errors:
                del self._plugin_errors[plugin_name]

            if plugin_name not in self._plugin_configs:
                config = PluginConfig(
                    name=plugin_name,
                    enabled=True,
                    interval_minutes=self._config.plugins.default_interval_minutes
                )
                self._plugin_configs[plugin_name] = config
                await self._plugin_config_repo.save(config)

            logger.info(f"插件 {plugin_name} 加载成功")
            return plugin_instance

        except Exception as e:
            logger.error(f"加载插件 {plugin_name} 失败: {e}", exc_info=True)
            self._record_plugin_error(plugin_name, str(e))
            return None

    async def deduplicate_proxies(self, proxies: list[str]) -> list[str]:
        if not proxies:
            return []

        try:
            use_cache = self._dedup_cache and self._dedup_cache.is_initialized
            if not use_cache:
                existing_keys = await self._proxy_repo.get_existing_ip_ports()

            unique_proxies = []
            seen_hosts = set()

            for proxy_url in proxies:
                try:
                    proxy = Proxy.from_url(proxy_url, "_dedup")
                    host_key = f"{proxy.ip}:{proxy.port}"

                    if host_key in seen_hosts:
                        continue

                    if use_cache:
                        if self._dedup_cache.contains(proxy.ip, proxy.port):
                            continue
                    else:
                        if host_key in existing_keys:
                            continue

                    seen_hosts.add(host_key)
                    unique_proxies.append(proxy_url)

                except Exception as e:
                    logger.warning(f"解析代理 URL 失败 {sanitize_proxy(proxy_url)}: {e}")
                    continue

            logger.info(f"去重前: {len(proxies)} 个代理，去重后: {len(unique_proxies)} 个代理")
            return unique_proxies
        except Exception as e:
            logger.error(f"代理去重失败: {e}", exc_info=True)
            return proxies

    async def _schedule_plugins(self) -> None:
        self._running = True

        while self._running:
            try:
                current_time = datetime.now()

                for plugin_name, config in self._plugin_configs.items():
                    if not config.enabled:
                        continue

                    if plugin_name not in self._plugins:
                        continue

                    should_execute = False

                    if config.next_run is None:
                        should_execute = True
                    elif current_time >= config.next_run:
                        should_execute = True

                    if should_execute:
                        already_running = any(
                            getattr(t, '_plugin_name', None) == plugin_name
                            and not t.done()
                            for t in self._running_plugin_tasks
                        )
                        if already_running:
                            logger.debug(
                                f"插件 {plugin_name} 仍在执行中，跳过本轮调度"
                            )
                            continue

                        logger.info(f"调度执行插件: {plugin_name}")
                        task = asyncio.create_task(
                            self._execute_plugin_task(plugin_name)
                        )
                        task._plugin_name = plugin_name
                        self._running_plugin_tasks.add(task)
                        task.add_done_callback(
                            self._running_plugin_tasks.discard
                        )

                await asyncio.sleep(self._config.plugins.scan_interval_seconds)

            except asyncio.CancelledError:
                logger.info("插件调度器被取消")
                break
            except Exception as e:
                logger.error(f"插件调度器错误: {e}", exc_info=True)
                await asyncio.sleep(self._config.plugins.scan_interval_seconds)

    async def _execute_plugin_task(self, plugin_name: str) -> None:
        try:
            async with self._execution_semaphore:
                logger.debug(f"插件 {plugin_name} 获取到执行信号量")

                max_retries = self._config.plugins.max_retries_on_failure
                base_delay = self._config.plugins.retry_base_delay_seconds
                proxies = None

                for attempt in range(max_retries + 1):
                    try:
                        proxies = await self.execute_plugin(plugin_name)
                        break
                    except Exception as e:
                        if attempt < max_retries:
                            delay = base_delay * (2 ** attempt)
                            logger.warning(
                                f"插件 {plugin_name} 执行失败，"
                                f"第 {attempt + 1}/{max_retries} 次重试"
                                f"（{delay:.0f}s 后）: {e}"
                            )
                            await asyncio.sleep(delay)
                        else:
                            logger.error(
                                f"插件 {plugin_name} 执行失败，"
                                f"已达最大重试次数 {max_retries}: {e}"
                            )
                            return

                if proxies:
                    unique_proxies = await self.deduplicate_proxies(proxies)
                    logger.info(
                        f"插件 {plugin_name} 去重后获得 {len(unique_proxies)} 个待验证代理"
                    )

                    from core.application.ingest import ingest_proxies

                    stats = await ingest_proxies(
                        unique_proxies, source_plugin=plugin_name
                    )
                    logger.info(f"插件 {plugin_name} 抓取入库完成: {stats.summary()}")
        except asyncio.CancelledError:
            logger.info(f"插件 {plugin_name} 执行任务被取消")
        except Exception as e:
            logger.error(
                f"调度执行插件 {plugin_name} 失败: {e}", exc_info=True
            )

    async def reload_plugin(self, plugin_name: str) -> bool:
        plugin_path = self._plugins_dir / f"{plugin_name}.py"
        if not plugin_path.exists():
            logger.error(f"插件文件不存在: {plugin_path}")
            return False

        is_running = any(
            getattr(t, '_plugin_name', None) == plugin_name
            and not t.done()
            for t in self._running_plugin_tasks
        )
        if is_running:
            logger.warning(
                f"插件 {plugin_name} 正在执行中，无法热重载。"
                f"请等待执行完成后重试。"
            )
            return False

        logger.info(f"开始热重载插件: {plugin_name}")

        module_name = f"{_PLUGIN_MODULE_PREFIX}{plugin_name}"
        if module_name in sys.modules:
            del sys.modules[module_name]
            logger.debug(f"已从 sys.modules 移除旧模块: {module_name}")

        old_plugin = self._plugins.pop(plugin_name, None)
        if old_plugin is not None:
            logger.debug(f"已从插件注册表摘下旧实例: {plugin_name}")

        new_plugin = None
        try:
            new_plugin = await self._load_plugin(str(plugin_path))
        except Exception as e:
            logger.error(f"插件 {plugin_name} 热重载异常: {e}", exc_info=True)

        if new_plugin is not None:
            logger.info(f"插件 {plugin_name} 热重载成功")
            if plugin_name in self._plugin_errors:
                del self._plugin_errors[plugin_name]
            return True

        logger.error(f"插件 {plugin_name} 热重载失败：新版本未加载成功")
        if old_plugin is not None:
            self._plugins[plugin_name] = old_plugin
            logger.warning(f"插件 {plugin_name} 已保留重载前的版本继续运行")
        return False

    def _record_plugin_error(self, plugin_name: str, message: str,
                             message_key: str = "") -> None:
        self._plugin_errors[plugin_name] = {
            "message": message,
            "message_key": message_key,
            "timestamp": datetime.now(),
        }

        if len(self._plugin_errors) > 100:
            sorted_by_time = sorted(
                self._plugin_errors.items(),
                key=lambda item: item[1].get("timestamp", datetime.min)
            )
            oldest_keys = [key for key, _ in sorted_by_time[:50]]
            for key in oldest_keys:
                del self._plugin_errors[key]
            logger.debug(
                f"插件错误记录超限，已清理最旧的 {len(oldest_keys)} 条"
            )
