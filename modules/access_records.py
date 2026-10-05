"""
模块名称：modules.access_records
功能描述：代理请求的逐条事件流水存储：热路径把记录投入内存缓冲，后台线程按间隔批量落库；
          提供按时间与维度分页查询、导出取数，以及保留期与行数上限清理。
职责边界：负责：内存缓冲、增量落库、查询与导出取数、过期与超限清理；不负责：请求解析与转发（见
          modules.proxyserver）、记录内容组装（见 modules.access_log）、HTTP 接口与导出序列化（见 app）。
关键依赖：modules.modules 的 parse_int_lenient / parse_bool_lenient、modules.spool_store 的
          FlushBackedSqliteStore；其余为标准库（含 sqlite3、threading、collections）。
已知限制：
  1. 查询与导出只读数据库，最近一个 flush_interval 内的记录还看不到（pending 计数即该窗口）；读取时把 failure 行状态码置空，库里旧行保持原值。
  2. 缓冲满时丢弃最老的记录并计入 dropped，不阻塞写入；落库失败整批并回缓冲队首，空间不足时同样丢弃；buffer_size 调小仅下次 start() 生效。
  3. max_rows 在每次落库后裁剪，retention_days 清理限频 3600 秒且失败不推进计时；两者取 <= 0 表示关闭对应清理。
  4. 查询、导出与写入都走短连接，不跨线程共享连接；导出先取最新的 EXPORT_LIMIT 条再反转为升序。
  5. 数据库不开 WAL、不设 auto_vacuum：删除后的页会被复用，文件大小停在历史高水位，不随清理回落。
  6. real_ip 对已有库由 PRAGMA + ALTER 补列；
     _COLUMNS、_row_to_dict 解包、_write_batch 值元组与 INSERT 列名四处须同名同序同步改。
  7. _OUTCOME_FAILURE 取值须与 modules.access_log.OUTCOME_FAILURE 一致，改字面量时两处同步（反向导入成环）。
  8. real_ip 补列标记只在 ALTER 成功后才置位；失败时保持 False，下一次连接重试补列。
"""

import logging
import os
import sqlite3
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import NamedTuple, Optional

from modules.modules import parse_bool_lenient, parse_int_lenient
from modules.spool_store import FlushBackedSqliteStore

logger = logging.getLogger(__name__)

DB_FILENAME = "access_records.db"

_TABLE = "request_records"

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

EXPORT_LIMIT = 50000

_PURGE_MIN_INTERVAL_SECONDS = 3600.0

_DROP_WARN_INTERVAL_SECONDS = 60.0

_OUTCOME_FAILURE = "failure"

_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS {_TABLE} (
    id          INTEGER PRIMARY KEY,
    ts          TEXT    NOT NULL,
    kind        TEXT    NOT NULL,
    method      TEXT    NOT NULL,
    client_ip   TEXT    NOT NULL DEFAULT '-',
    client_user TEXT    NOT NULL DEFAULT '',
    host        TEXT    NOT NULL DEFAULT '',
    port        INTEGER NOT NULL DEFAULT 0,
    upstream    TEXT    NOT NULL,
    outcome     TEXT    NOT NULL,
    status_code INTEGER,
    elapsed_ms  INTEGER NOT NULL DEFAULT 0,
    reason      TEXT    NOT NULL DEFAULT '',
    real_ip     TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_request_records_ts
    ON {_TABLE}(ts DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_request_records_upstream
    ON {_TABLE}(upstream, ts);
CREATE INDEX IF NOT EXISTS idx_request_records_host
    ON {_TABLE}(host, ts);
"""

_COLUMNS = ("id, ts, kind, method, client_ip, client_user, host, port, "
            "upstream, outcome, status_code, elapsed_ms, reason, real_ip")


class RequestRecord(NamedTuple):

    ts: str
    kind: str
    method: str
    client_ip: str
    client_user: str
    host: str
    port: int
    upstream: str
    outcome: str
    status_code: Optional[int]
    elapsed_ms: int
    reason: str
    real_ip: str = ''


@dataclass
class RecordFilter:

    since: Optional[str] = None
    until: Optional[str] = None
    upstream: Optional[str] = None
    host: Optional[str] = None
    outcome: Optional[str] = None
    search: str = ""


class RequestRecordStore(FlushBackedSqliteStore):

    def __init__(self, config, base_dir: str):
        self._init_flush_state(os.path.join(base_dir, 'logs', DB_FILENAME))

        self._config = None
        self.enabled = False
        self.flush_interval = 5
        self.retention_days = 7
        self.max_rows = 200000
        self.buffer_size = 20000
        self.apply_config(config)

        self._buffer: deque[RequestRecord] = deque(maxlen=self.buffer_size)
        self._dropped = 0
        self._real_ip_schema_ready = False
        self._schema_lock = threading.Lock()
        self._row_count = 0
        self._last_purge_at = 0.0
        self._last_drop_warn_at = 0.0



    def append(self, entry: RequestRecord) -> None:
        if not self.enabled:
            return

        with self._lock:
            overflowed = len(self._buffer) == self._buffer.maxlen
            self._buffer.append(entry)
            if overflowed:
                self._dropped += 1
                should_warn = self._mark_drop_warn_locked()
            else:
                should_warn = False

        if should_warn:
            self._warn_dropped()

    def _mark_drop_warn_locked(self) -> bool:
        now = time.monotonic()
        if now - self._last_drop_warn_at < _DROP_WARN_INTERVAL_SECONDS:
            return False
        self._last_drop_warn_at = now
        return True

    def _warn_dropped(self) -> None:
        with self._lock:
            dropped = self._dropped
            capacity = self._buffer.maxlen
        logger.warning(
            "访问记录缓冲已满（上限 %d 条），开始丢弃最老的记录，累计已丢 %d 条；"
            "落库跟不上时请调大 access_records_buffer_size 或加快落库间隔",
            capacity, dropped,
        )


    def query(self, flt: RecordFilter, limit: int = 100, offset: int = 0,
              order: str = "desc") -> tuple[list[dict], int, dict]:
        where, params = _build_where(flt)
        order_sql = "ASC" if order == "asc" else "DESC"

        try:
            with self._session() as conn:
                total = conn.execute(
                    f"SELECT COUNT(*) FROM {_TABLE}{where}", params
                ).fetchone()[0]
                counts = {
                    row[0]: row[1] for row in conn.execute(
                        f"SELECT outcome, COUNT(*) FROM {_TABLE}{where} GROUP BY outcome",
                        params,
                    )
                }
                rows = conn.execute(
                    f"SELECT {_COLUMNS} FROM {_TABLE}{where}"
                    f" ORDER BY ts {order_sql}, id {order_sql} LIMIT ? OFFSET ?",
                    (*params, limit, offset),
                ).fetchall()
        except (sqlite3.Error, OSError) as e:
            logger.error("查询访问记录失败: %s", e)
            return [], 0, {}

        return [_row_to_dict(row) for row in rows], total, counts

    def export_rows(self, flt: RecordFilter) -> list[dict]:
        where, params = _build_where(flt)
        try:
            with self._session() as conn:
                rows = conn.execute(
                    f"SELECT {_COLUMNS} FROM {_TABLE}{where}"
                    f" ORDER BY ts DESC, id DESC LIMIT ?",
                    (*params, EXPORT_LIMIT),
                ).fetchall()
        except (sqlite3.Error, OSError) as e:
            logger.error("读取导出用的访问记录失败: %s", e)
            return []

        return [_row_to_dict(row) for row in reversed(rows)]

    def distinct_options(self, limit: int = 200) -> dict:
        options = {"upstreams": [], "hosts": []}
        try:
            with self._session() as conn:
                options["upstreams"] = [
                    {"value": row[0], "count": row[1]} for row in conn.execute(
                        f"SELECT upstream, COUNT(*) AS n FROM {_TABLE}"
                        f" GROUP BY upstream ORDER BY n DESC LIMIT ?", (limit,)
                    )
                ]
                options["hosts"] = [
                    {"value": row[0], "count": row[1]} for row in conn.execute(
                        f"SELECT host, COUNT(*) AS n FROM {_TABLE}"
                        f" WHERE host <> '' GROUP BY host ORDER BY n DESC LIMIT ?",
                        (limit,),
                    )
                ]
        except (sqlite3.Error, OSError) as e:
            logger.error("读取访问记录的筛选项失败: %s", e)
        return options

    def stats(self) -> dict:
        with self._lock:
            pending = len(self._buffer)
            dropped = self._dropped

        oldest = ""
        try:
            with self._session() as conn:
                row = conn.execute(f"SELECT MIN(ts) FROM {_TABLE}").fetchone()
                oldest = (row[0] or "") if row else ""
        except (sqlite3.Error, OSError) as e:
            logger.error("读取访问记录时间范围失败: %s", e)

        return {"pending": pending, "dropped": dropped, "oldest_ts": oldest}


    def apply_config(self, config) -> bool:
        was_enabled = self.enabled
        self._config = config
        self.enabled = parse_bool_lenient(
            config.get('access_records_enabled', 'true'), default=True
        )
        self.flush_interval = parse_int_lenient(
            config.get('access_records_flush_interval', '5'), default=5, low=1
        )
        self.retention_days = parse_int_lenient(
            config.get('access_records_retention_days', '7'), default=7, low=0
        )
        self.max_rows = parse_int_lenient(
            config.get('access_records_max_rows', '200000'), default=200000, low=0
        )
        self.buffer_size = parse_int_lenient(
            config.get('access_records_buffer_size', '20000'), default=20000, low=100
        )
        return was_enabled

    def start(self) -> bool:
        if not self.enabled:
            logger.info("访问记录已禁用，跳过启动")
            return False
        if self._started:
            return True

        with self._lock:
            shrunk = len(self._buffer) - self.buffer_size
            self._buffer = deque(self._buffer, maxlen=self.buffer_size)
            if shrunk > 0:
                self._dropped += shrunk

        with self._db_lock:
            try:
                with self._session() as conn:
                    loaded_rows = conn.execute(
                        f"SELECT COUNT(*) FROM {_TABLE}"
                    ).fetchone()[0]
            except (sqlite3.Error, OSError) as e:
                logger.error("访问记录行数载入失败，按 0 起算: %s", e)
                loaded_rows = 0
            with self._lock:
                self._row_count = loaded_rows

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._flush_loop, name='access-records-flush', daemon=True
        )
        self._thread.start()
        self._started = True
        logger.info(
            "访问记录已启动: %s（每 %d 秒落库，保留 %d 天 / 最多 %d 行）",
            self.db_path, self.flush_interval, self.retention_days, self.max_rows,
        )
        return True



    _table = _TABLE
    _log_label = '访问记录'

    def _ensure_schema(self, conn):
        conn.executescript(_SCHEMA)
        if self._real_ip_schema_ready:
            return
        with self._schema_lock:
            if self._real_ip_schema_ready:
                return
            columns = [row[1] for row in
                       conn.execute(f"PRAGMA table_info({_TABLE})").fetchall()]
            if columns and 'real_ip' not in columns:
                conn.execute(f"ALTER TABLE {_TABLE} "
                             f"ADD COLUMN real_ip TEXT NOT NULL DEFAULT ''")
                logger.info("访问记录表已迁移：新增列 real_ip")
            self._real_ip_schema_ready = True

    def _take_batch(self):
        with self._lock:
            if not self._buffer:
                return None, self._flush_generation
            batch = list(self._buffer)
            self._buffer.clear()
            return batch, self._flush_generation

    def _on_write_succeeded(self, batch):
        with self._lock:
            self._row_count += len(batch)

    def _after_flush(self):
        self._trim_rows()

    def _clear_memory(self, deleted_rows):
        removed = deleted_rows + len(self._buffer)
        self._buffer.clear()
        self._row_count = 0
        return removed

    def _restore_batch(self, batch: list[RequestRecord]) -> None:
        drop_warned = False
        with self._lock:
            buffered = len(self._buffer)
            to_drop = min(max(0, buffered + len(batch) - self._buffer.maxlen), buffered)
            for _ in range(to_drop):
                self._buffer.popleft()
                self._dropped += 1

            keep = len(batch) if len(batch) <= self._buffer.maxlen else self._buffer.maxlen
            discarded = len(batch) - keep
            if discarded:
                self._dropped += discarded
            self._buffer.extendleft(reversed(batch[-keep:]))

            if to_drop or discarded:
                drop_warned = self._mark_drop_warn_locked()

        if drop_warned:
            self._warn_dropped()





    def _write_batch(self, batch: list[RequestRecord]) -> bool:
        rows = [
            (entry.ts, entry.kind, entry.method, entry.client_ip, entry.client_user,
             entry.host, entry.port, entry.upstream, entry.outcome,
             entry.status_code, entry.elapsed_ms, entry.reason, entry.real_ip)
            for entry in batch
        ]
        try:
            with self._session() as conn:
                conn.executemany(
                    f"""
                    INSERT INTO {_TABLE}
                        (ts, kind, method, client_ip, client_user, host, port,
                         upstream, outcome, status_code, elapsed_ms, reason, real_ip)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )
            return True
        except (sqlite3.Error, OSError) as e:
            logger.error("访问记录批量写入失败（将退回缓冲重试）: %s", e)
            return False


    def _purge_expired(self) -> None:
        if self.retention_days <= 0:
            return

        now = time.monotonic()
        if now - self._last_purge_at < _PURGE_MIN_INTERVAL_SECONDS:
            return

        cutoff = (datetime.now() - timedelta(days=self.retention_days)).strftime(
            TIME_FORMAT
        )
        with self._db_lock:
            try:
                with self._session() as conn:
                    cursor = conn.execute(
                        f"DELETE FROM {_TABLE} WHERE ts < ?", (cutoff,)
                    )
                    removed = cursor.rowcount
            except (sqlite3.Error, OSError) as e:
                logger.error("清理过期访问记录失败: %s", e)
                return

            self._last_purge_at = now
            with self._lock:
                self._row_count = max(0, self._row_count - removed)

        if removed:
            logger.info(
                "已清理 %d 条超过 %d 天的访问记录", removed, self.retention_days
            )

    def _trim_rows(self) -> None:
        if self.max_rows <= 0:
            return

        with self._lock:
            excess = self._row_count - self.max_rows
        if excess <= 0:
            return

        with self._db_lock:
            try:
                with self._session() as conn:
                    actual = conn.execute(f"SELECT COUNT(*) FROM {_TABLE}").fetchone()[0]
                    excess = actual - self.max_rows
                    if excess <= 0:
                        with self._lock:
                            self._row_count = actual
                        return
                    cursor = conn.execute(
                        f"DELETE FROM {_TABLE} WHERE id IN ("
                        f"  SELECT id FROM {_TABLE} ORDER BY id ASC LIMIT ?)",
                        (excess,),
                    )
                    removed = cursor.rowcount
                    remaining = actual - removed
            except (sqlite3.Error, OSError) as e:
                logger.error("按行数上限裁剪访问记录失败: %s", e)
                return

            with self._lock:
                self._row_count = remaining

        logger.info(
            "访问记录已达上限 %d 行，删除了最老的 %d 条", self.max_rows, removed
        )


def _build_where(flt: RecordFilter) -> tuple[str, tuple]:
    clauses: list[str] = []
    params: list = []

    if flt.since:
        clauses.append("ts >= ?")
        params.append(flt.since)
    if flt.until:
        clauses.append("ts <= ?")
        params.append(flt.until)
    if flt.upstream:
        clauses.append("upstream = ?")
        params.append(flt.upstream)
    if flt.host:
        clauses.append("host = ?")
        params.append(flt.host)
    if flt.outcome:
        clauses.append("outcome = ?")
        params.append(flt.outcome)
    if flt.search:
        clauses.append(
            "(host LIKE ? ESCAPE '\\' OR client_ip LIKE ? ESCAPE '\\'"
            " OR client_user LIKE ? ESCAPE '\\' OR reason LIKE ? ESCAPE '\\')"
        )
        needle = f"%{_escape_like(flt.search)}%"
        params.extend([needle] * 4)

    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    return where, tuple(params)


def _escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _row_to_dict(row) -> dict:
    (record_id, ts, kind, method, client_ip, client_user, host, port,
     upstream, outcome, status_code, elapsed_ms, reason, real_ip) = row

    if outcome == _OUTCOME_FAILURE and status_code:
        status_code = None

    client = f"{client_ip}/{client_user}" if client_user else (client_ip or "-")
    target = f"{host}:{port}" if port else (host or "-")

    return {
        "id": record_id,
        "ts": ts,
        "kind": kind,
        "method": method,
        "client": client,
        "client_ip": client_ip,
        "client_user": client_user,
        "host": host,
        "port": port,
        "target": target,
        "upstream": upstream,
        "real_ip": real_ip,
        "outcome": outcome,
        "status_code": status_code,
        "elapsed_ms": elapsed_ms,
        "reason": reason,
    }


__all__ = [
    "DB_FILENAME",
    "TIME_FORMAT",
    "EXPORT_LIMIT",
    "RecordFilter",
    "RequestRecord",
    "RequestRecordStore",
]
