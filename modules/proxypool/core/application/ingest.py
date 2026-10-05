"""
模块名称：modules.proxypool.core.application.ingest
功能描述：代理入库流水线：URL 解析 → TCP 初筛 → FULL 验证 → 只写可用记录，并把出口 IP 交给归属地调度。
职责边界：负责：解析、初筛、逐条 FULL 验证、写库、跳过验证的直接入库、分阶段进度上报；不负责：抓取（plugin_manager）、
          验证算法（validator）、归属地查询与写回（geo_resolver）、任务状态与前端展示（batch_tasks）、去重（调用方）。
关键依赖：core.application.api.dependencies（函数内延迟导入）、core.domain.models、
          core.services.validation_apply、core.services.health_scorer、modules.modules。
已知限制：
 1. 入库判据为本轮确认可用；解析失败、初筛淘汰、不可用与无结论均不写库；活下来但拿不到出口 IP 时，可归因于代理的不入库，不可归因（我方回显端点不可达）的仍入库待重验证。
 2. skip_validation 插件直接入库且跳过初筛；upsert 命中已有 ip:port 时不覆盖出口 IP、延迟与匿名度，但会覆盖验证状态并使成功/失败/总检测计数归零。
 3. 初筛只回答端口是否可连，黑洞代理能过关；初筛并发按验证并发 ×4 推导并在 [64, 2000] 截断，超时取 connect_timeout_seconds，非正数退化为 2 秒。
 4. 进度为当前阶段口径：done/total 仅描述本阶段；速率取 20 秒窗口，跨度不足 3 秒或无完成样本时报 0；回调按 0.25 秒节流且异常被吞。
 5. 本模块不做去重，调用方负责；归属地按 real_ip 调度，不依赖刚插入行的 id。
 6. 验证链路的意外异常计入 failed 并继续处理其余候选；每条候选恰好落一个分支，计数须闭合。
"""

import asyncio
import logging
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Optional, Sequence

from core.domain.models import DBOperation, ProbeKind, Proxy, ValidationMode
from modules.modules import sanitize_proxy
from core.services.validation_apply import (
    APPLY_INCONCLUSIVE,
    decide_validation_action,
)

logger = logging.getLogger(__name__)

STAGE_PRESCREEN = "prescreen"
STAGE_VALIDATE = "validate"
STAGE_INGEST = "ingest"

_PRESCREEN_CONCURRENCY_FACTOR = 4

_PRESCREEN_MIN_CONCURRENCY = 64

_PRESCREEN_MAX_CONCURRENCY = 2000

_PRESCREEN_DEFAULT_TIMEOUT = 2.0

_PROGRESS_INTERVAL_SECONDS = 0.25


@dataclass
class IngestStats:
    total: int = 0
    prescreened_out: int = 0
    validated: int = 0
    saved: int = 0
    invalid: int = 0
    incomplete: int = 0
    inconclusive: int = 0
    failed: int = 0

    def summary(self, language: str = "cn") -> str:
        from modules.modules import get_message

        parts = [get_message('ingest_summary_candidates', language, self.total)]
        if self.prescreened_out:
            parts.append(get_message(
                'ingest_summary_prescreened_out', language, self.prescreened_out))
        parts.append(get_message('ingest_summary_validated', language, self.validated))
        parts.append(get_message('ingest_summary_saved', language, self.saved))
        if self.invalid:
            parts.append(get_message('ingest_summary_invalid', language, self.invalid))
        if self.incomplete:
            parts.append(get_message(
                'ingest_summary_incomplete', language, self.incomplete))
        if self.inconclusive:
            parts.append(get_message(
                'ingest_summary_inconclusive', language, self.inconclusive))
        if self.failed:
            parts.append(get_message('ingest_summary_failed', language, self.failed))
        return get_message('list_separator', language).join(parts)


@dataclass(frozen=True)
class IngestProgress:
    stage: str
    done: int
    total: int
    rate: float
    eta_seconds: Optional[float]
    in_flight: int
    stats: IngestStats


ProgressCallback = Callable[[IngestProgress], None]


class _RateMeter:
    WINDOW = 20.0

    MIN_SPAN = 3.0

    def __init__(self):
        self._samples: list[tuple[float, int]] = []
        self._warmup = 1

    def set_warmup(self, completions: int) -> None:
        self._warmup = max(1, completions)

    def mark(self, done: int, now: float) -> None:
        self._samples.append((now, done))
        cutoff = now - self.WINDOW
        while len(self._samples) > 2 and self._samples[0][0] < cutoff:
            self._samples.pop(0)

    def rate(self, now: float) -> float:
        if len(self._samples) < 2:
            return 0.0
        if self._samples[-1][1] < self._warmup:
            return 0.0
        first_at, first_done = self._samples[0]
        elapsed = now - first_at
        if elapsed < self.MIN_SPAN:
            return 0.0
        return max(0.0, (self._samples[-1][1] - first_done) / elapsed)

    def eta(self, done: int, total: int, now: float) -> Optional[float]:
        rate = self.rate(now)
        if rate <= 0:
            return None
        return max(0.0, (total - done) / rate)

    def reset(self) -> None:
        self._samples.clear()


async def ingest_proxies(
    proxies: Sequence[str],
    *,
    source_plugin: str,
    on_progress: Optional[ProgressCallback] = None,
) -> IngestStats:
    from core.application.api.dependencies import (
        get_config_manager,
        get_geo_resolver,
        get_plugin_manager,
        get_proxy_validator,
        get_write_queue,
    )

    stats = IngestStats(total=len(proxies))
    if not proxies:
        return stats

    plugin_manager = get_plugin_manager()

    candidates: list[Proxy] = []
    for proxy_url in proxies:
        try:
            candidates.append(Proxy.from_url(proxy_url, source_plugin))
        except Exception as e:
            logger.debug("跳过无法解析的代理 %s: %s", sanitize_proxy(proxy_url), e)
            stats.failed += 1

    if plugin_manager.should_skip_validation(source_plugin):
        return await _ingest_without_validation(
            candidates, source_plugin, stats, on_progress
        )

    validator = get_proxy_validator()
    write_queue = get_write_queue()
    geo_resolver = get_geo_resolver()
    test_url = plugin_manager.resolve_test_url(source_plugin)

    config = get_config_manager().get_config()
    prescreen_concurrency = min(
        _PRESCREEN_MAX_CONCURRENCY,
        max(
            _PRESCREEN_MIN_CONCURRENCY,
            int(config.validator.max_concurrent) * _PRESCREEN_CONCURRENCY_FACTOR,
        ),
    )
    prescreen_timeout = float(config.validator.connect_timeout_seconds)
    if prescreen_timeout <= 0:
        prescreen_timeout = _PRESCREEN_DEFAULT_TIMEOUT

    reporter = _ProgressReporter(on_progress)

    reporter.start_stage(STAGE_PRESCREEN, len(candidates), prescreen_concurrency, stats)
    prescreen_sem = asyncio.Semaphore(prescreen_concurrency)
    survivors: list[Proxy] = []

    async def prescreen(proxy: Proxy) -> None:
        async with prescreen_sem:
            if await _tcp_reachable(proxy.ip, proxy.port, prescreen_timeout):
                survivors.append(proxy)
            else:
                stats.prescreened_out += 1
        reporter.tick(stats)

    if candidates:
        await asyncio.gather(*(prescreen(p) for p in candidates), return_exceptions=True)

    reporter.finish_stage(stats)
    logger.info(
        "初筛完成: %d 个候选 -> %d 个端口可达（并发 %d，超时 %.1fs）",
        len(candidates), len(survivors), prescreen_concurrency, prescreen_timeout,
    )

    stats.validated = len(survivors)
    validate_concurrency = max(1, int(config.validator.max_concurrent))
    reporter.start_stage(
        STAGE_VALIDATE, len(survivors), validate_concurrency, stats
    )

    async def validate_one(proxy: Proxy) -> None:
        try:
            result = await validator.validate_proxy(
                proxy.proxy_url, ValidationMode.FULL, test_url=test_url
            )

            action, applied = decide_validation_action(
                result, mode=ValidationMode.FULL,
                skip=_skip_reason_for_new_record,
            )
            if action == APPLY_INCONCLUSIVE:
                stats.inconclusive += 1
                return
            if action == SKIP_INVALID:
                stats.invalid += 1
                return
            if action == SKIP_INCOMPLETE:
                stats.incomplete += 1
                logger.debug(
                    "代理 %s:%s 通过存活检测但拿不到出口 IP，不入库",
                    proxy.ip, proxy.port,
                )
                return

            proxy_data = {
                'protocol': proxy.protocol,
                'ip': proxy.ip,
                'port': proxy.port,
                'username': proxy.username,
                'password': proxy.password,
                'source_plugin': source_plugin,
                'created_at': datetime.now().isoformat(),
            }
            proxy_data.update(applied.fields)

            await write_queue.enqueue(DBOperation(
                operation_type="insert",
                table="proxies",
                data=proxy_data,
            ))
            stats.saved += 1

            if result.real_ip and geo_resolver is not None:
                geo_resolver.schedule(result.real_ip)
        except Exception as e:
            logger.warning("处理代理 %s:%s 失败: %s", proxy.ip, proxy.port, e)
            stats.failed += 1
        finally:
            reporter.tick(stats)

    if survivors:
        await asyncio.gather(*(validate_one(p) for p in survivors))

    reporter.finish_stage(stats)
    logger.info("入库完成（来源 %s）: %s", source_plugin, stats.summary())
    return stats


class _ProgressReporter:
    def __init__(self, callback: Optional[ProgressCallback]):
        self._callback = callback
        self._stage = ""
        self._stage_total = 0
        self._concurrency = 1
        self._done = 0
        self._last_emit = 0.0
        self._meter = _RateMeter()

    def start_stage(
        self, stage: str, total: int, concurrency: int, stats: IngestStats
    ) -> None:
        self._stage = stage
        self._stage_total = total
        self._concurrency = max(1, concurrency)
        self._done = 0
        self._meter.reset()
        self._meter.set_warmup(min(self._concurrency, total))
        self._meter.mark(0, time.monotonic())
        self._emit(stats, force=True)

    def tick(self, stats: IngestStats) -> None:
        self._done += 1
        self._meter.mark(self._done, time.monotonic())
        self._emit(stats)

    def finish_stage(self, stats: IngestStats) -> None:
        self._emit(stats, force=True)

    def _emit(self, stats: IngestStats, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._last_emit < _PROGRESS_INTERVAL_SECONDS:
            return
        self._last_emit = now

        if self._callback is None:
            return
        try:
            self._callback(IngestProgress(
                stage=self._stage,
                done=self._done,
                total=self._stage_total,
                rate=self._meter.rate(now),
                eta_seconds=self._meter.eta(self._done, self._stage_total, now),
                in_flight=min(
                    max(0, self._stage_total - self._done), self._concurrency
                ),
                stats=stats,
            ))
        except Exception as e:
            logger.debug("入库进度回调异常（忽略）: %s", e)


async def _ingest_without_validation(
    candidates: Sequence[Proxy],
    source_plugin: str,
    stats: IngestStats,
    on_progress: Optional[ProgressCallback] = None,
) -> IngestStats:
    from core.application.api.dependencies import get_write_queue
    from core.services.health_scorer import HealthScorer

    reporter = _ProgressReporter(on_progress)
    reporter.start_stage(STAGE_INGEST, len(candidates), 1, stats)

    if not candidates:
        reporter.finish_stage(stats)
        return stats

    write_queue = get_write_queue()
    scorer = HealthScorer()
    now = datetime.now()

    for proxy in candidates:
        try:
            proxy_data = {
                'protocol': proxy.protocol,
                'ip': proxy.ip,
                'port': proxy.port,
                'username': proxy.username,
                'password': proxy.password,
                'source_plugin': source_plugin,
                'created_at': now.isoformat(),
                'is_valid': 1,
                'validated_at': now.isoformat(),
                'total_checks': 0,
                'success_count': 0,
                'failure_count': 0,
                'anonymity_level': 'unverified',
                'health_score': scorer.calculate(proxy),
            }
            await write_queue.enqueue(DBOperation(
                operation_type="insert",
                table="proxies",
                data=proxy_data,
            ))
            stats.saved += 1
        except Exception as e:
            logger.warning("直接入库代理 %s:%s 失败: %s", proxy.ip, proxy.port, e)
            stats.failed += 1
        finally:
            reporter.tick(stats)

    reporter.finish_stage(stats)
    logger.info("直接入库完成（来源 %s，未做任何验证）: %s", source_plugin, stats.summary())
    return stats


SKIP_INVALID = "invalid"
SKIP_INCOMPLETE = "incomplete"


def _skip_reason_for_new_record(result) -> str:
    if not result.is_valid:
        return SKIP_INVALID
    if not result.real_ip and _identity_attributable(result):
        return SKIP_INCOMPLETE
    return ""

def _identity_attributable(result) -> bool:
    return any(
        probe.kind is ProbeKind.TUNNEL and probe.ok is not None
        for probe in result.probes
    )


async def _tcp_reachable(ip: str, port: int, timeout: float) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
    except (asyncio.TimeoutError, OSError):
        return False
    except Exception as e:
        logger.debug("初筛异常 %s:%s: %s", ip, port, e)
        return False

    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    return True
