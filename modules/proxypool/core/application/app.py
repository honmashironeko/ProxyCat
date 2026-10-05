"""
模块名称：modules.proxypool.core.application.app
功能描述：代理池的应用编排层：装配 DI 容器，按依赖顺序启动与关闭全部核心服务，并把配置热更新推送给各服务。
职责边界：负责：DI 容器装配与解析、服务生命周期编排、配置变更扇出；不负责：API 路由（core.application.api）、配置读写（config_manager）、各服务内部逻辑。
关键依赖：core.infrastructure（DI 容器、配置管理器、连接池、去重缓存、HTTP 客户端、离线库）、core.services、core.data、
          core.database、core.config、core.paths、core.interfaces、core.application.batch_tasks、
          core.application.api.dependencies（全局访问点 set_backup_manager、set_data_cleaner、
          set_geo_resolver）、core.backup 与 core.data_cleaner（均在方法内延迟导入）。
已知限制：
1. 一个进程只应创建一个 Application 实例并只 initialize() 一次，重复初始化会让旧实例已启动的服务继续运行并与新实例并行。
2. 启动顺序不可调整（后启动者依赖前者已就绪），关闭是启动的逆序；批量任务与归属地流水线必须先于写队列停止，否则结果会写向已停止的队列。
3. 关闭时单个服务失败只记 error 后继续，正常返回不代表资源都已释放；initialize() 中途失败不回滚已启动服务，未初始化时 shutdown() 安全。
4. 服务与后台任务绑定在 initialize() 调用方的事件循环上，跨线程必须用 loop.call_soon_threadsafe 调度回来。
5. 数据库路径锚定在池子项目根，不随宿主工作目录变化；配置路径不存在时按需建出目录使用，仅当目录无法创建且默认库存在时才回退默认库。
6. 可选服务（备份、维护器）启动失败只记 warning、不阻断初始化；shutdown() 不清空容器、连接池、去重缓存、备份管理器等引用。
7. 配置热更新停用备份时，须先摘掉全局访问点（set_backup_manager(None)）再停实例，避免接口层在停止过程中取到正在关闭的实例。
"""

import asyncio
import logging
from typing import Optional
from core.config import Config
from core.paths import POOL_BASE_DIR, resolve_pool_path
from core.application import batch_tasks
from core.application.api.dependencies import (
    set_backup_manager,
    set_data_cleaner,
    set_geo_resolver,
)
from core.infrastructure.di_container import DIContainer
from core.interfaces.infrastructure import IConfigManager, IWriteQueue, IHttpClient
from core.interfaces.services import IGeoIPService, IPluginManager, IProxyValidator
from core.interfaces.repository import IProxyRepository, IPluginConfigRepository
from core.infrastructure.config_manager import ConfigManager
from core.infrastructure.http_client import AioHttpClient
from core.infrastructure.connection_pool import ConnectionPool
from core.infrastructure.dedup_cache import DedupCache
from core.infrastructure.geodb import GeoDatabase
from core.data.repositories import ProxyRepository, PluginConfigRepository
from core.data.write_queue import AsyncWriteQueue
from core.services.geoip import GeoIPService
from core.services.geo_resolver import GeoResolver
from core.services.validator import ProxyValidator
from core.services.validation_endpoints import ValidationEndpoints
from core.services.plugin_manager import PluginManager
from core.services.auto_revalidator import AutoRevalidator
from core.services.health_scorer import HealthScorer
from core.database import init_database
from core.domain.exceptions import ApplicationException

logger = logging.getLogger(__name__)


class Application:
    def __init__(self, config: Optional[Config] = None):
        self._config: Config = config if config is not None else Config()
        self._container: Optional[DIContainer] = None
        self._config_manager: Optional[IConfigManager] = None
        self._auto_revalidator: Optional[AutoRevalidator] = None
        self._geo_resolver: Optional[GeoResolver] = None
        self._connection_pool: Optional[ConnectionPool] = None
        self._dedup_cache: Optional[DedupCache] = None
        self._backup_manager = None
        self._data_cleaner = None

    async def initialize(
        self,
        enable_backup: bool = True,
        enable_cleaner: bool = True,
    ) -> None:
        try:
            logger.info("开始初始化应用...")

            logger.info("初始化配置管理器...")
            config_manager = ConfigManager(self._config)
            self._config_manager = config_manager
            config = config_manager.get_config()

            db_path = self._resolve_database_path(config.database.path)
            config.database.path = str(db_path)

            logger.info("初始化数据库: %s", db_path)
            await init_database(str(db_path))

            logger.info("初始化连接池...")
            pool = ConnectionPool(
                db_path=str(db_path),
                max_readers=config.database.pool_max_readers,
            )
            await pool.initialize()
            self._connection_pool = pool

            logger.info("初始化去重缓存...")
            dedup_cache = DedupCache()
            await dedup_cache.load_from_db(pool)
            self._dedup_cache = dedup_cache

            logger.info("配置依赖注入容器...")
            self._container = self._configure_container(
                config_manager, config, pool, dedup_cache
            )

            config_manager.subscribe(self._on_config_changed)

            logger.info("启动核心服务...")

            write_queue = self._container.resolve(IWriteQueue)
            await write_queue.start()
            logger.info("写入队列已启动")

            geoip_service = self._container.resolve(IGeoIPService)
            geoip_service.load_database()
            geodb = self._container.resolve(GeoDatabase)
            logger.info(
                "GeoIP 服务已初始化（离线归属地库: %s）",
                "可用" if geodb.available else "不可用，归属地将一律为未知",
            )

            self._geo_resolver = GeoResolver(
                geoip_service,
                write_queue,
                proxy_repository=self._container.resolve(IProxyRepository),
                geodb=geodb,
            )
            await self._geo_resolver.start()
            set_geo_resolver(self._geo_resolver)

            plugin_manager = self._container.resolve(IPluginManager)
            await plugin_manager.start()
            logger.info("插件管理器已启动")

            logger.info("启动自动重新验证服务...")
            proxy_repo = self._container.resolve(IProxyRepository)
            validator = self._container.resolve(IProxyValidator)

            scorer = HealthScorer()

            self._auto_revalidator = AutoRevalidator(
                repository=proxy_repo,
                validator=validator,
                geo_resolver=self._geo_resolver,
                write_queue=write_queue,
                config_manager=self._config_manager,
                health_scorer=scorer,
                dedup_cache=self._dedup_cache,
                plugin_config_repo=self._container.resolve(IPluginConfigRepository),
            )
            await self._auto_revalidator.start()
            logger.info("自动重新验证服务已启动")

            await self._start_optional_services(config, enable_backup, enable_cleaner)

            logger.info("应用初始化完成")

        except Exception as e:
            logger.error(f"应用初始化失败: {e}", exc_info=True)
            raise ApplicationException(f"应用初始化失败: {str(e)}") from e

    async def _start_backup_manager(self, config) -> None:
        try:
            from core.backup import DatabaseBackup
            self._backup_manager = DatabaseBackup(
                config.database.path,
                backup_interval_hours=config.database.backup_interval_hours,
                retention_days=config.database.backup_retention_days,
            )
            await self._backup_manager.start()
            set_backup_manager(self._backup_manager)
            logger.info("数据库备份管理器已启动")
        except Exception as e:
            self._backup_manager = None
            set_backup_manager(None)
            logger.warning(f"启动备份管理器失败（非致命）: {e}")

    async def _stop_backup_manager(self) -> None:
        manager, self._backup_manager = self._backup_manager, None
        set_backup_manager(None)
        if manager is None:
            return
        try:
            await manager.stop()
            logger.info("数据库备份管理器已停止（配置里关掉了自动备份）")
        except Exception as e:
            logger.error(f"停止备份管理器失败: {e}")

    async def _start_optional_services(
        self, config, enable_backup: bool, enable_cleaner: bool
    ) -> None:
        if enable_backup and config.database.backup_enabled:
            await self._start_backup_manager(config)

        if enable_cleaner and self._connection_pool is not None:
            try:
                from core.data_cleaner import DataCleaner
                self._data_cleaner = DataCleaner(self._connection_pool)
                set_data_cleaner(self._data_cleaner)
                logger.info("数据库维护器已就绪")
            except Exception as e:
                logger.warning(f"启动数据清理器失败（非致命）: {e}")

    async def shutdown(self) -> None:
        try:
            logger.info("开始关闭应用...")

            if self._container:
                if self._auto_revalidator:
                    try:
                        logger.info("停止自动重新验证服务...")
                        await self._auto_revalidator.stop()
                    except Exception as e:
                        logger.error(f"停止自动重新验证服务失败: {e}", exc_info=True)

                try:
                    logger.info("停止插件管理器...")
                    plugin_manager = self._container.resolve(IPluginManager)
                    await plugin_manager.stop()
                except Exception as e:
                    logger.error(f"停止插件管理器失败: {e}", exc_info=True)

                try:
                    logger.info("取消在跑的后台批量任务...")
                    await batch_tasks.cancel_running_tasks()
                except Exception as e:
                    logger.error(f"取消后台批量任务失败: {e}", exc_info=True)

                try:
                    logger.info("停止归属地解析流水线...")
                    if self._geo_resolver:
                        await self._geo_resolver.stop()
                except Exception as e:
                    logger.error(f"停止归属地解析流水线失败: {e}", exc_info=True)

                try:
                    logger.info("停止写入队列...")
                    write_queue = self._container.resolve(IWriteQueue)
                    await write_queue.stop()
                    logger.info("写入队列已停止")
                except Exception as e:
                    logger.error(f"停止写入队列失败: {e}", exc_info=True)

                try:
                    logger.info("关闭 GeoIP 服务...")
                    geoip_service = self._container.resolve(IGeoIPService)
                    geoip_service.close()
                    logger.info("GeoIP 服务已关闭")
                except Exception as e:
                    logger.error(f"关闭 GeoIP 服务失败: {e}", exc_info=True)

                try:
                    logger.info("关闭 HTTP 客户端...")
                    http_client = self._container.resolve(IHttpClient)
                    await http_client.close()
                    logger.info("HTTP 客户端已关闭")
                except Exception as e:
                    logger.error(f"关闭 HTTP 客户端失败: {e}", exc_info=True)

            await self._stop_optional_services()

            if self._connection_pool:
                try:
                    logger.info("关闭连接池...")
                    await self._connection_pool.close()
                    logger.info("连接池已关闭")
                except Exception as e:
                    logger.error(f"关闭连接池失败: {e}", exc_info=True)

            logger.info("应用已关闭")

        except Exception as e:
            logger.error(f"应用关闭失败: {e}", exc_info=True)
            raise ApplicationException(f"应用关闭失败: {str(e)}") from e

    async def _stop_optional_services(self) -> None:
        if self._backup_manager is not None:
            try:
                logger.info("停止备份管理器...")
                await self._backup_manager.stop()
                logger.info("备份管理器已停止")
            except Exception as e:
                logger.error(f"停止备份管理器失败: {e}", exc_info=True)

    def get_container(self) -> DIContainer:
        if self._container is None:
            raise RuntimeError("容器未初始化，请先调用 initialize()")
        return self._container

    async def apply_config(self, config: Config) -> None:
        if self._config_manager is None:
            raise RuntimeError("配置管理器未初始化，请先调用 initialize()")
        await self._config_manager.apply(config)

    @staticmethod
    def _resolve_database_path(configured_path: str):
        resolved = resolve_pool_path(configured_path)
        if resolved.exists():
            return resolved

        try:
            resolved.parent.mkdir(parents=True, exist_ok=True)
            return resolved
        except OSError as e:
            fallback = POOL_BASE_DIR / "data" / "proxies.db"
            if fallback.exists() and fallback != resolved:
                logger.error(
                    "配置的数据库路径不可用（%s，%s），已回退到默认库 %s —— 请检查配置",
                    resolved, e, fallback,
                )
                return fallback
            return resolved

    @property
    def connection_pool(self) -> Optional[ConnectionPool]:
        return self._connection_pool

    @property
    def dedup_cache(self) -> Optional[DedupCache]:
        return self._dedup_cache

    def _configure_container(
        self,
        config_manager: ConfigManager,
        config,
        pool: ConnectionPool,
        dedup_cache: DedupCache,
    ) -> DIContainer:
        container = DIContainer()

        container.register_instance(IConfigManager, config_manager)

        http_client = AioHttpClient(
            default_timeout=config.plugins.request_timeout_seconds
        )
        container.register_instance(IHttpClient, http_client)

        proxy_repo = ProxyRepository(pool)
        plugin_config_repo = PluginConfigRepository(pool)
        container.register_instance(IProxyRepository, proxy_repo)
        container.register_instance(IPluginConfigRepository, plugin_config_repo)

        write_queue = AsyncWriteQueue(
            proxy_repository=proxy_repo,
            batch_size=config.write_queue.batch_size,
            dedup_cache=dedup_cache,
            max_queue_size=config.write_queue.max_queue_size,
            max_retries=config.write_queue.max_retries,
        )
        container.register_instance(IWriteQueue, write_queue)

        geodb = GeoDatabase()
        container.register_instance(GeoDatabase, geodb)

        geoip_service = GeoIPService(geodb=geodb)
        container.register_instance(IGeoIPService, geoip_service)

        validator = ProxyValidator(
            http_client, config_manager, ValidationEndpoints(http_client, config_manager)
        )
        container.register_instance(IProxyValidator, validator)

        plugin_manager = PluginManager(
            plugin_config_repo=plugin_config_repo,
            proxy_repo=proxy_repo,
            http_client=http_client,
            config=config,
            dedup_cache=dedup_cache,
        )
        container.register_instance(IPluginManager, plugin_manager)

        logger.info("依赖注入容器配置完成")
        return container

    async def _apply_backup_config(self, new_config) -> None:
        if new_config.database.backup_enabled:
            if self._backup_manager is None:
                await self._start_backup_manager(new_config)
            else:
                try:
                    self._backup_manager.apply_config(new_config)
                except Exception as e:
                    logger.error(f"备份管理器应用配置失败: {e}")
        elif self._backup_manager is not None:
            await self._stop_backup_manager()

    async def _on_config_changed(self, new_config) -> None:
        logger.info("检测到配置变更，应用新配置...")

        try:
            if self._container:
                try:
                    write_queue = self._container.resolve(IWriteQueue)
                    write_queue.apply_config(new_config)
                except Exception as e:
                    logger.error(f"写入队列应用配置失败: {e}")

                try:
                    validator = self._container.resolve(IProxyValidator)
                    validator.apply_config(new_config)
                except Exception as e:
                    logger.error(f"验证器应用配置失败: {e}")

                try:
                    plugin_manager = self._container.resolve(IPluginManager)
                    plugin_manager.apply_config(new_config)
                except Exception as e:
                    logger.error(f"插件管理器应用配置失败: {e}")

                try:
                    http_client = self._container.resolve(IHttpClient)
                    http_client.apply_config(new_config)
                except Exception as e:
                    logger.error(f"HTTP 客户端应用配置失败: {e}")

            await self._apply_backup_config(new_config)

            logger.info("新配置已应用到所有服务")

        except Exception as e:
            logger.error(f"应用新配置失败: {e}", exc_info=True)
