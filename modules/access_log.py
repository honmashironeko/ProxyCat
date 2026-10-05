"""
模块名称：modules.access_log
功能描述：描述并记录一次代理请求的客户端、上游出口（含真实出口 IP）、目标、成败与耗时，
          写入 access 类别日志与内存环形缓冲，并转交 modules.domain_stats 做域名累计、modules.access_records 存逐条流水。
职责边界：负责：请求记录对象的结果标记与落盘、转交域名统计与逐条记录、两者间的格式转换；
          不负责：目标解析与转发（modules.proxyserver）、域名聚合与持久化（modules.domain_stats）、
          逐条记录的缓冲、查询与清理（modules.access_records）、日志装配（modules.logging_setup）。
关键依赖：modules.logging_setup（日志与环形缓冲）、modules.domain_stats、modules.access_records、modules.modules。
已知限制：
  1. 耗时从建记录计时到 close 落盘为止：长连接覆盖整段连接时长，结果（成败）确定时刻可能早于落盘；进程强杀会丢未落库的记录。
  2. track() 是收口保证：抛异常的记为失败并写入原因后继续抛出；无结论则默认记为「中断」，非直连隧道已建立、客户端发过数据且上游先断开时归为失败（隧道无数据）；协程取消重抛后归类相同。
  3. 「中断」不算成功也不算失败：不写域名统计，但逐条流水照常落库；逐条记录不跟随 emit_log，有独立开关。
  4. AccessRecord 不是线程安全的，只在请求所属事件循环线程内使用；close() 的幂等靠 _closed 标记，重复调用只生效第一次。
  5. 结果首次写入即定，之后 succeeded/failed 不再改写 outcome；failed() 仍无条件覆盖 status_code，避免留下「失败…状态 200」的矛盾记录。
  6. retry_tunnel() 会清空 outcome、原因与归因标记，只有确实要重开时才可调用，调用后必须有结论补上。
"""

import asyncio
import logging
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import NamedTuple

from modules.access_records import TIME_FORMAT, RequestRecord, RequestRecordStore
from modules.domain_stats import UPSTREAM_DIRECT, UPSTREAM_UNKNOWN, DomainStatsStore
from modules.logging_setup import LogCategory, get_category_logger
from modules.modules import get_message, sanitize_proxy

logger = get_category_logger(LogCategory.ACCESS)

OUTCOME_SUCCESS = 'success'
OUTCOME_FAILURE = 'failure'
OUTCOME_ABORTED = 'aborted'

KIND_CONNECT = 'connect'
KIND_HTTP = 'http'
KIND_SOCKS5 = 'socks5'

_REASON_MAX_LENGTH = 200

_LEVEL_BY_OUTCOME = {
    OUTCOME_SUCCESS: logging.INFO,
    OUTCOME_FAILURE: logging.WARNING,
    OUTCOME_ABORTED: logging.INFO,
}


class ClientIdentity(NamedTuple):

    ip: str = '-'
    username: str = ''

    def display(self) -> str:
        if self.username:
            return f"{self.ip}/{self.username}"
        return self.ip or '-'


@dataclass
class AccessRecord:

    kind: str
    method: str
    client: ClientIdentity
    host: str = ''
    port: int = 0
    language: str = 'cn'

    upstream: str = ''
    real_ip: str = ''
    direct: bool = False
    attempts: int = 0
    status_code: int | None = None
    reason: str = ''
    outcome: str | None = None

    tunnel_established: bool = False
    client_data_seen: bool = False
    upstream_data_seen: bool = False
    last_activity_at: float = 0.0
    tunnel_ended_by: str = ''
    proxy_failure_reported: bool = False
    swept_as_dead: bool = False
    swept_as_idle: bool = False

    started_at: float = field(default_factory=time.monotonic, repr=False)
    started_wall: float = field(default_factory=time.time, repr=False)

    @property
    def target(self) -> str:
        if not self.host:
            return '-'
        return f"{self.host}:{self.port}" if self.port else self.host

    @property
    def upstream_key(self) -> str:
        if self.upstream:
            return self.upstream
        return UPSTREAM_DIRECT if self.direct else UPSTREAM_UNKNOWN

    @property
    def elapsed_ms(self) -> int:
        return int((time.monotonic() - self.started_at) * 1000)

    def use_proxy(self, proxy: str, real_ip: str = '') -> None:
        if self.outcome is not None:
            return
        self.attempts += 1
        self.upstream = sanitize_proxy(proxy)
        self.real_ip = real_ip or ''
        self.direct = False

    def use_direct(self) -> None:
        self.upstream = ''
        self.real_ip = ''
        self.direct = True

    def succeeded(self, status_code: int | None = None) -> None:
        if self.outcome is not None:
            return
        self.outcome = OUTCOME_SUCCESS
        if status_code is not None:
            self.status_code = status_code

    def failed(self, reason: str, status_code: int | None = None) -> None:
        if self.outcome is not None:
            return
        self.outcome = OUTCOME_FAILURE
        self.reason = sanitize_reason(reason)
        self.status_code = status_code


    def tunnel_ready(self, status_code: int | None = None) -> None:
        if status_code is not None:
            self.status_code = status_code
        self.tunnel_established = True

    def tunnel_client_data(self) -> None:
        self.client_data_seen = True
        self.last_activity_at = time.monotonic()

    def retry_tunnel(self) -> None:
        self.outcome = None
        self.reason = ''
        self.tunnel_ended_by = ''
        self.proxy_failure_reported = False
        self.swept_as_dead = False
        self.swept_as_idle = False

    def tunnel_relayed(self) -> None:
        self.upstream_data_seen = True
        self.last_activity_at = time.monotonic()
        self.succeeded(self.status_code)

    def tunnel_ended(self, side: str) -> None:
        if not self.tunnel_ended_by:
            self.tunnel_ended_by = side

    def render(self) -> str:
        status = self.status_code if self.status_code is not None else '-'
        if self.upstream:
            upstream = self.upstream
        else:
            upstream = get_message(
                'access_direct' if self.direct else 'access_unknown', self.language
            )
        if self.outcome == OUTCOME_SUCCESS:
            return get_message(
                'access_ok', self.language,
                self.client.display(), upstream, self.target, self.method,
                self.elapsed_ms, status,
            )
        key = 'access_aborted' if self.outcome == OUTCOME_ABORTED else 'access_failed'
        return get_message(
            key, self.language,
            self.client.display(), upstream, self.target, self.method,
            self.elapsed_ms, status, self.reason or '-',
        )


class AccessTracker:

    def __init__(self, language: str = 'cn', stats: DomainStatsStore | None = None,
                 emit_log: bool = True, records: RequestRecordStore | None = None):
        self.language = language
        self.stats = stats
        self.emit_log = emit_log
        self.records = records

    @contextmanager
    def track(self, kind: str, method: str, client: ClientIdentity,
              host: str = '', port: int = 0):
        record = AccessRecord(
            kind=kind, method=method, client=client,
            host=host, port=port, language=self.language,
        )
        try:
            yield record
        except asyncio.CancelledError:
            raise
        except Exception as e:
            record.failed(str(e))
            raise
        finally:
            self.close(record)

    def close(self, record: AccessRecord) -> None:
        if getattr(record, '_closed', False):
            return
        record._closed = True

        if record.outcome is None:
            self._settle_tunnel(record)

        if record.outcome is None:
            record.outcome = OUTCOME_ABORTED
            if not record.reason:
                record.reason = get_message('access_incomplete', self.language)

        if self.emit_log:
            self._emit(record)

        if self.records is not None and self.records.enabled:
            self.records.append(entry_from_record(record))

        if self.stats is not None and record.outcome != OUTCOME_ABORTED:
            self.stats.record(
                record.host,
                record.upstream_key,
                succeeded=record.outcome == OUTCOME_SUCCESS,
                status_code=record.status_code,
                error=record.reason,
                port=record.port,
            )

    def _settle_tunnel(self, record: AccessRecord) -> None:
        if not record.tunnel_established:
            return

        if (record.client_data_seen and record.tunnel_ended_by == 'upstream'
                and not record.direct):
            record.failed(get_message('access_tunnel_no_data', self.language))
            return

        record.outcome = OUTCOME_ABORTED
        if not record.reason:
            if record.tunnel_ended_by == 'upstream':
                key = 'access_tunnel_closed_by_upstream'
            elif record.client_data_seen:
                key = 'access_tunnel_client_left'
            else:
                key = 'access_tunnel_idle'
            record.reason = get_message(key, self.language)

    def _emit(self, record: AccessRecord) -> None:
        try:
            logger.log(_LEVEL_BY_OUTCOME.get(record.outcome, logging.INFO), record.render())
        except Exception:
            logger.exception("写访问日志失败")


def entry_from_record(record: AccessRecord) -> RequestRecord:
    return RequestRecord(
        ts=datetime.fromtimestamp(record.started_wall).strftime(TIME_FORMAT),
        kind=record.kind,
        method=record.method,
        client_ip=record.client.ip or '-',
        client_user=record.client.username,
        host=record.host,
        port=record.port,
        upstream=record.upstream_key,
        outcome=record.outcome or OUTCOME_ABORTED,
        status_code=record.status_code,
        elapsed_ms=record.elapsed_ms,
        reason=record.reason,
        real_ip=record.real_ip,
    )


def sanitize_reason(reason) -> str:
    text = ' '.join(str(reason).split())
    if len(text) > _REASON_MAX_LENGTH:
        return text[:_REASON_MAX_LENGTH] + '...'
    return text
