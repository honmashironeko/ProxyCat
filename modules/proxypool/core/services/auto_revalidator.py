"""
模块名称：modules.proxypool.core.services.auto_revalidator
功能描述：对已入库代理的定时重验证：按插件分组把到期代理重新验证一遍，更新可用性、延迟、真实 IP、匿名度、HTTPS 支持与健康评分，命中清理判据的代理会被删除。
职责边界：负责：重验证调度、质量字段更新、三判据择一自动清理、每轮重建去重缓存；
          不负责：单代理验证算法（ProxyValidator）、健康分计算（HealthScorer）、代理抓取
          （PluginManager）、归属地解析本身（只入队，见 GeoResolver）。
关键依赖：IProxyRepository、IProxyValidator、IWriteQueue、IConfigManager、IPluginConfigRepository、
          GeoResolver（鸭子类型注入，仅调用 schedule）、DedupCache、validation_apply、validation_policy。
已知限制：
  1. 每轮重读全局配置与数据库 plugin_configs 表；关闭时循环不退出而是每 60 秒复查，轮间隔取全局与插件周期的最小值。
  2. 测试地址必须按插件用 resolve_test_url 解析；与入库判定口径不一致会把好代理计入自动清理。
  3. 结论不可用（inconclusive）时一个字段都不写；基础设施故障不推进自动清理的删除条件。
  4. 归属地入队必须用 applied.effective_real_ip 而非 result.real_ip，否则只缺地区的代理永远补不上。
  5. 自动清理是唯一无人值守且不可逆的删除路径；only_valid_proxies 决定验谁、auto_cleanup.enabled 决定删不删，从未验证过的记录必须另行追加。
  6. 单轮重验证完成后重建去重缓存，失败只记警告；单轮异常等 60 秒重试；未验证记录须走 find_without_checks，自查 SQL 会绕过行到领域对象映射。
  7. 构造参数 health_scorer 仅被存储、不被读取，健康分由 validation_apply 自行构造 scorer 计算，传入该参数不影响行为。
"""

import asyncio
import logging
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from core.interfaces.repository import IProxyRepository, IPluginConfigRepository
from core.interfaces.services import IProxyValidator
from core.interfaces.infrastructure import IWriteQueue, IConfigManager
from core.domain.models import ProxyFilter
from core.services.health_scorer import HealthScorer
from core.services.validation_apply import (
    APPLY_APPLIED,
    APPLY_INCONCLUSIVE,
    build_delete_operation,
    build_update_operation,
    dispatch_validation_action,
)
from core.services.validation_policy import pick_validation_mode, resolve_test_url

if TYPE_CHECKING:
    from core.infrastructure.dedup_cache import DedupCache

logger = logging.getLogger(__name__)

_DISABLED_RECHECK_SECONDS = 60.0


def cleanup_reason_for(config, proxy, result, update_data: dict) -> Optional[str]:
    if proxy.is_favorite:
        return None

    cleanup = getattr(config, "auto_cleanup", None)
    if cleanup is None or not cleanup.enabled:
        return None
    if result.is_valid:
        return None

    new_total_checks = update_data.get("total_checks", 0)
    new_health_score = update_data.get("health_score", 0.0)
    new_failure_count = update_data.get("failure_count", 0)

    if (new_health_score < cleanup.min_health_score
            and new_total_checks >= cleanup.min_checks_before_cleanup):
        return f"健康评分 {new_health_score:.1f} < {cleanup.min_health_score}"

    if new_failure_count >= cleanup.max_failures:
        return f"连续失败 {new_failure_count} >= {cleanup.max_failures}"

    last_check = last_known_check(proxy)
    if last_check is not None:
        days = (datetime.now() - last_check).days
        if days >= cleanup.max_age_days_if_invalid:
            return f"失效后已 {cleanup.max_age_days_if_invalid} 天未被验证成功"

    return None


def needs_region(proxy, updates: dict) -> bool:
    region = updates.get("region", proxy.region)
    region_en = updates.get("region_en", proxy.region_en)
    zh_known = bool(region) and region != "未知"
    en_known = bool(region_en) and region_en != "未知"
    return not (zh_known and en_known)


def last_known_check(proxy) -> Optional[datetime]:
    return getattr(proxy, "validated_at", None) or getattr(proxy, "created_at", None)


class AutoRevalidator:

    def __init__(
        self,
        repository: IProxyRepository,
        validator: IProxyValidator,
        geo_resolver,
        write_queue: IWriteQueue,
        config_manager: IConfigManager,
        health_scorer: Optional[HealthScorer] = None,
        dedup_cache: Optional['DedupCache'] = None,
        plugin_config_repo: Optional[IPluginConfigRepository] = None,
    ):
        self.repository = repository
        self.validator = validator
        self.geo_resolver = geo_resolver
        self.write_queue = write_queue
        self.config_manager = config_manager
        self._scorer = health_scorer or HealthScorer()
        self._dedup_cache = dedup_cache
        self._plugin_config_repo = plugin_config_repo
        self.running = False
        self.task: Optional[asyncio.Task] = None

    async def _get_plugin_config_map(self) -> dict:
        if self._plugin_config_repo is None:
            return {}

        try:
            configs = await self._plugin_config_repo.get_all()
        except Exception as e:
            logger.warning(f"读取插件配置失败，本次全部按全局配置处理: {e}")
            return {}

        return {c.name: c for c in configs}

    async def start(self) -> None:
        if self.running:
            logger.warning("自动重新验证服务已经在运行")
            return

        config = self.config_manager.get_config()
        if not config.auto_revalidation.enabled:
            logger.info("自动重新验证功能已禁用（可在面板中随时打开）")

        self.running = True
        self.task = asyncio.create_task(self._revalidation_loop())
        logger.info("自动重新验证服务已启动")

    async def stop(self) -> None:
        if not self.running:
            return

        self.running = False

        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass

        logger.info("自动重新验证服务已停止")

    async def _revalidation_loop(self) -> None:
        first_run = True

        while self.running:
            try:
                config = self.config_manager.get_config()

                if not config.auto_revalidation.enabled:
                    await asyncio.sleep(_DISABLED_RECHECK_SECONDS)
                    continue

                min_interval_minutes = config.auto_revalidation.interval_minutes

                plugin_configs = await self._get_plugin_config_map()
                for plugin_config in plugin_configs.values():
                    if plugin_config.reval_enabled and plugin_config.reval_interval_minutes > 0:
                        min_interval_minutes = min(
                            min_interval_minutes, plugin_config.reval_interval_minutes
                        )

                interval_seconds = min_interval_minutes * 60

                if first_run:
                    first_run = False
                    if config.auto_revalidation.run_on_start:
                        logger.info(
                            "run_on_start 已启用，立即执行首轮代理验证"
                        )
                    else:
                        logger.info(
                            f"自动重新验证服务将在 {min_interval_minutes} 分钟后首次检查代理"
                        )
                        await asyncio.sleep(interval_seconds)
                        if not self.running:
                            break
                else:
                    logger.info(
                        f"自动重新验证服务将在 {min_interval_minutes} 分钟后检查代理"
                    )
                    await asyncio.sleep(interval_seconds)
                    if not self.running:
                        break

                logger.info("开始自动重新验证代理...")
                await self._revalidate_proxies()
                logger.info("自动重新验证完成")

                if self._dedup_cache is not None:
                    try:
                        await self._dedup_cache.rebuild(self._get_connection_pool())
                        logger.debug("验证后去重缓存已重建")
                    except Exception as e:
                        logger.warning(f"验证后重建去重缓存失败（非致命）: {e}")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"自动重新验证错误: {e}", exc_info=True)
                await asyncio.sleep(60)

    def _get_connection_pool(self):
        if hasattr(self.repository, '_pool'):
            return self.repository._pool
        return None

    async def _revalidate_proxies(self) -> None:
        config = self.config_manager.get_config()

        endpoints = getattr(self.validator, "endpoints", None)
        if endpoints is not None:
            await endpoints.ensure_ready()
            if not endpoints.network_available():
                logger.warning(
                    "本机网络不可用（所有检测端点直连失败），本轮重新验证已跳过"
                )
                return

        all_proxies = []
        page = 1
        page_size = 5000

        if config.auto_revalidation.only_valid_proxies:
            filter_obj = ProxyFilter(is_valid=True)
            logger.info("只重验证当前有效的代理")
        else:
            filter_obj = ProxyFilter(is_valid=None)

        while True:
            batch = await self.repository.find(filter_obj, page=page, page_size=page_size)
            if not batch:
                break
            all_proxies.extend(batch)
            if len(batch) < page_size:
                break
            page += 1

        unvalidated = await self._fetch_unvalidated_proxies()
        if unvalidated:
            existing_ids = {p.id for p in all_proxies}
            appended = [p for p in unvalidated if p.id not in existing_ids]
            for p in appended:
                all_proxies.append(p)
            if appended:
                logger.info(f"追加 {len(appended)} 个从未验证过的历史记录")

        proxies = all_proxies

        if not proxies:
            logger.info("没有需要重新验证的代理")
            return

        logger.info(f"找到 {len(proxies)} 个代理需要重新验证")

        proxies_by_plugin = {}
        for proxy in proxies:
            plugin_name = proxy.source_plugin
            if plugin_name not in proxies_by_plugin:
                proxies_by_plugin[plugin_name] = []
            proxies_by_plugin[plugin_name].append(proxy)

        plugin_configs = await self._get_plugin_config_map()

        for plugin_name, plugin_proxies in proxies_by_plugin.items():
            plugin_config = plugin_configs.get(plugin_name)
            reval_enabled = plugin_config.reval_enabled if plugin_config else True
            reval_interval = plugin_config.reval_interval_minutes if plugin_config else 0

            if not reval_enabled:
                logger.info(f"插件 {plugin_name} 的自动验证已禁用，跳过")
                continue

            plugin_interval_minutes = (
                reval_interval if reval_interval > 0
                else config.auto_revalidation.interval_minutes
            )

            test_url = resolve_test_url(plugin_config, config.validator.target_url)

            now = datetime.now()
            proxies_to_validate = []

            for proxy in plugin_proxies:
                if proxy.validated_at is None:
                    proxies_to_validate.append(proxy)
                else:
                    time_since_validation = now - proxy.validated_at
                    if time_since_validation.total_seconds() >= plugin_interval_minutes * 60:
                        proxies_to_validate.append(proxy)

            if not proxies_to_validate:
                logger.info(f"插件 {plugin_name} 的代理暂时不需要验证（未到验证间隔）")
                continue

            logger.info(
                f"开始验证插件 {plugin_name} 的 {len(proxies_to_validate)} 个代理"
                f"（间隔：{plugin_interval_minutes}分钟）"
            )

            tasks = [
                self._validate_and_update(proxy, test_url)
                for proxy in proxies_to_validate
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _fetch_unvalidated_proxies(self) -> list:
        try:
            return await self.repository.find_without_checks()
        except Exception as e:
            logger.warning(f"获取未验证代理失败（非致命）: {e}")
            return []

    def _pick_mode(self, proxy):
        return pick_validation_mode(proxy, self.config_manager.get_config())

    async def _validate_and_update(self, proxy, test_url: str) -> None:
        try:
            proxy_url = proxy.proxy_url
            mode = self._pick_mode(proxy)

            result = await self.validator.validate_proxy(
                proxy_url, mode, test_url=test_url
            )

            action, applied = await dispatch_validation_action(
                result, mode=mode, proxy=proxy,
                cleanup=lambda res, fields: cleanup_reason_for(
                    self.config_manager.get_config(), proxy, res, fields),
                sink=lambda applied: self.write_queue.enqueue(
                    build_update_operation(proxy, applied)),
                cleanup_sink=lambda applied: self.write_queue.enqueue(
                    build_delete_operation(proxy)),
                geo_predicate=lambda proxy, fields: needs_region(proxy, fields),
                geo_sink=self.geo_resolver.schedule,
            )
            if action == APPLY_INCONCLUSIVE:
                logger.debug(
                    "代理 %s:%s 本轮结论不可用（%s），跳过更新",
                    proxy.ip, proxy.port, result.error_reason or result.outcome.value,
                )
                return

            if action != APPLY_APPLIED:
                logger.debug(
                    f"自动清理代理 {proxy.ip}:{proxy.port}: {action}"
                )
                return

        except Exception as e:
            logger.warning(f"验证代理失败 {proxy.ip}:{proxy.port}: {e}")
