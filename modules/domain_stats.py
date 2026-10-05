"""
模块名称：modules.domain_stats
功能描述：按「目标域名 × 上游代理」累计代理请求的成功/失败次数并持久化到 SQLite，
          供面板查询哪个代理访问过哪些域名、何时、成功还是失败。
职责边界：负责：内存聚合、增量批量落库、启动载入历史基线、过期清理、按上游代理与按域名查询。
          不负责：日志文案与文件（modules.access_log）、代理请求解析（modules.proxyserver）。
关键依赖：modules.modules 的 parse_int_lenient / parse_bool_lenient、modules.spool_store 的
          FlushBackedSqliteStore；其余为标准库（含 sqlite3、threading、os、datetime、logging、dataclasses）。
已知限制：
  1. 聚合键是「域名 × 上游代理」，不区分同域名的路径、端口与方法；last_port 只记最近一次且不落库。
  2. record() 只更新内存（_totals 查询口径、_pending 待落库），后台线程每 flush_interval 秒落库，强杀丢未落库增量，stop() 补最终 flush。
  3. 锁顺序固定为 _db_lock → _lock，不得反向；_lock 只保护内存结构，_db_lock 保证落库与清空不互相穿插。
  4. start() 载入失败只记日志并退化为「仅本次运行」统计；历史与内存合并时计数取较大值，不整体替换。
  5. retention_days <= 0 为永久保留；清理以内存 last_seen 为准，内存侧连 _pending 一起清。
  6. enabled=false 时 record() 直接返回；apply_config 只改内存参数并返回更新前的启用状态；载入时直接删除遗留表 domain_stats（不迁移）。
"""

import logging
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta

from modules.modules import parse_bool_lenient, parse_int_lenient
from modules.spool_store import FlushBackedSqliteStore

logger = logging.getLogger(__name__)

DB_FILENAME = "domain_stats.db"

UPSTREAM_DIRECT = "direct"
UPSTREAM_UNKNOWN = "unknown"

_TABLE = "access_stats"

_LEGACY_TABLE = "domain_stats"

_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS {_TABLE} (
    host        TEXT NOT NULL,
    upstream    TEXT NOT NULL,
    success     INTEGER NOT NULL DEFAULT 0,
    failure     INTEGER NOT NULL DEFAULT 0,
    first_seen  TEXT,
    last_seen   TEXT,
    last_status INTEGER,
    last_error  TEXT,
    PRIMARY KEY (host, upstream)
);
"""

_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

_SORT_KEYS = {
    'host': lambda row: row.get('host'),
    'upstream': lambda row: row.get('upstream'),
    'success': lambda row: row.get('success', 0),
    'failure': lambda row: row.get('failure', 0),
    'total': lambda row: (row.get('success') or 0) + (row.get('failure') or 0),
    'last_seen': lambda row: row.get('last_seen') or '',
}


@dataclass
class AccessCounters:

    success: int = 0
    failure: int = 0
    first_seen: str = ''
    last_seen: str = ''
    last_status: int | None = None
    last_error: str = ''
    last_port: int | None = None

    def as_dict(self, host: str, upstream: str) -> dict:
        return {
            'host': host,
            'upstream': upstream,
            'success': self.success,
            'failure': self.failure,
            'total': self.success + self.failure,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'last_status': self.last_status,
            'last_error': self.last_error,
            'last_port': self.last_port,
        }


class DomainStatsStore(FlushBackedSqliteStore):

    def __init__(self, config, base_dir: str):
        self.enabled = _as_bool(config.get('domain_stats_enabled', 'true'))
        self.flush_interval = _as_int(
            config.get('domain_stats_flush_interval', '15'), default=15, low=1
        )
        self.retention_days = _as_int(
            config.get('domain_stats_retention_days', '30'), default=30, low=0
        )
        self._init_flush_state(os.path.join(base_dir, 'logs', DB_FILENAME))
        self._totals: dict[tuple[str, str], AccessCounters] = {}
        self._pending: dict[tuple[str, str], AccessCounters] = {}


    def record(self, host: str, upstream: str, succeeded: bool,
               status_code: int | None = None, error: str = '',
               port: int | None = None) -> None:
        if not self.enabled or not host:
            return

        key = (host, upstream or UPSTREAM_UNKNOWN)
        stamp = datetime.now().strftime(_TIME_FORMAT)
        with self._lock:
            for table in (self._totals, self._pending):
                counters = table.get(key)
                if counters is None:
                    counters = AccessCounters(first_seen=stamp)
                    table[key] = counters
                if succeeded:
                    counters.success += 1
                else:
                    counters.failure += 1
                counters.last_seen = stamp
                counters.last_status = status_code
                counters.last_error = error
                counters.last_port = port


    def snapshot(self) -> list[dict]:
        with self._lock:
            return [c.as_dict(*key) for key, c in self._totals.items()]

    def query_proxies(self, search: str = '', sort: str = 'last_seen',
                      order: str = 'desc', limit: int = 100,
                      offset: int = 0) -> tuple[list[dict], int]:
        groups: dict[str, dict] = {}
        for row in self.snapshot():
            group = groups.get(row['upstream'])
            if group is None:
                group = groups[row['upstream']] = {
                    'upstream': row['upstream'], 'hosts': set(),
                    'success': 0, 'failure': 0, 'first_seen': '', 'last_seen': '',
                    'last_error': '', 'last_error_time': '',
                }
            group['hosts'].add(row['host'])
            group['success'] += row['success']
            group['failure'] += row['failure']
            if not group['first_seen'] or row['first_seen'] < group['first_seen']:
                group['first_seen'] = row['first_seen']
            if row['last_seen'] > group['last_seen']:
                group['last_seen'] = row['last_seen']
            if row['last_error'] and row['last_seen'] >= group['last_error_time']:
                group['last_error'] = row['last_error']
                group['last_error_time'] = row['last_seen']

        rows = []
        for group in groups.values():
            total = group['success'] + group['failure']
            rows.append({
                'upstream': group['upstream'],
                'host_count': len(group['hosts']),
                'success': group['success'],
                'failure': group['failure'],
                'total': total,
                'rate': round(group['success'] * 100 / total) if total else 0,
                'first_seen': group['first_seen'],
                'last_seen': group['last_seen'],
                'last_error': group['last_error'],
            })
        return self._paginate(rows, search, sort, order, limit, offset,
                              searchable=('upstream',))

    def query_domains(self, upstream: str, search: str = '', sort: str = 'last_seen',
                      order: str = 'desc', limit: int = 100,
                      offset: int = 0) -> tuple[list[dict], int]:
        rows = [row for row in self.snapshot() if row['upstream'] == upstream]
        return self._paginate(rows, search, sort, order, limit, offset,
                              searchable=('host', 'last_error'))

    def _paginate(self, rows: list[dict], search: str, sort: str, order: str,
                  limit: int, offset: int, searchable: tuple[str, ...]):
        if search:
            needle = search.lower()
            rows = [
                row for row in rows
                if any(needle in str(row.get(field) or '').lower() for field in searchable)
            ]

        primary = 'upstream' if rows and 'upstream' in rows[0] else 'host'
        rows.sort(key=lambda row: (row.get(primary) or ''))

        key_func = _SORT_KEYS.get(sort, _SORT_KEYS['last_seen'])
        if rows and all(key_func(row) is None for row in rows):
            key_func = _SORT_KEYS['last_seen']
        rows.sort(key=lambda row: key_func(row) or '', reverse=order != 'asc')

        total = len(rows)
        return rows[offset:offset + limit], total

    def summary(self) -> dict:
        rows = self.snapshot()
        return {
            'pairs': len(rows),
            'hosts': len({row['host'] for row in rows}),
            'upstreams': len({row['upstream'] for row in rows}),
            'success': sum(row['success'] for row in rows),
            'failure': sum(row['failure'] for row in rows),
        }


    def apply_config(self, config) -> bool:
        was_enabled = self.enabled
        self.enabled = _as_bool(config.get('domain_stats_enabled', 'true'))
        self.flush_interval = _as_int(
            config.get('domain_stats_flush_interval', '15'), default=15, low=1
        )
        self.retention_days = _as_int(
            config.get('domain_stats_retention_days', '30'), default=30, low=0
        )
        return was_enabled

    def start(self) -> bool:
        if not self.enabled:
            logger.info("域名统计已禁用，跳过启动")
            return False
        if self._started:
            return True

        try:
            self._load()
        except (sqlite3.Error, OSError) as e:
            logger.error("访问统计历史载入失败，本次运行从零开始: %s", e)

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._flush_loop, name='domain-stats-flush', daemon=True
        )
        self._thread.start()
        self._started = True
        logger.info("访问统计已启动: %s（每 %d 秒落库）", self.db_path, self.flush_interval)
        return True





    _table = _TABLE
    _log_label = '访问统计'

    def _ensure_schema(self, conn):
        conn.execute(_SCHEMA)

    def _take_batch(self):
        with self._lock:
            pending, self._pending = self._pending, {}
            return pending, self._flush_generation

    def _clear_memory(self, deleted_rows):
        removed = len(self._totals)
        self._totals.clear()
        self._pending.clear()
        return removed

    def _restore_batch(self, pending: dict[tuple[str, str], AccessCounters]) -> None:
        with self._lock:
            for key, counters in pending.items():
                target = self._pending.setdefault(key, AccessCounters())
                target.success += counters.success
                target.failure += counters.failure
                if counters.last_seen >= (target.last_seen or ''):
                    target.last_seen = counters.last_seen
                    target.last_status = counters.last_status
                    target.last_error = counters.last_error
                    target.last_port = counters.last_port
                if not target.first_seen or (
                    counters.first_seen and counters.first_seen < target.first_seen
                ):
                    target.first_seen = counters.first_seen


    def _write_batch(self, pending: dict[tuple[str, str], AccessCounters]) -> bool:
        rows = [
            (host, upstream, c.success, c.failure, c.first_seen, c.last_seen,
             c.last_status, c.last_error)
            for (host, upstream), c in pending.items()
        ]
        try:
            with self._session() as conn:
                conn.executemany(
                    f"""
                    INSERT INTO {_TABLE}
                        (host, upstream, success, failure, first_seen, last_seen,
                         last_status, last_error)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(host, upstream) DO UPDATE SET
                        success     = success + excluded.success,
                        failure     = failure + excluded.failure,
                        last_seen   = excluded.last_seen,
                        last_status = excluded.last_status,
                        last_error  = excluded.last_error
                    """,
                    rows,
                )
            return True
        except (sqlite3.Error, OSError) as e:
            logger.error("访问统计批量写入失败（将在下一轮重试）: %s", e)
            return False

    def _load(self) -> None:
        cutoff = self._retention_cutoff()
        with self._session() as conn:
            conn.execute(f"DROP TABLE IF EXISTS {_LEGACY_TABLE}")
            if cutoff:
                conn.execute(f"DELETE FROM {_TABLE} WHERE last_seen < ?", (cutoff,))
            loaded = {
                (row[0], row[1]): AccessCounters(
                    success=row[2], failure=row[3], first_seen=row[4] or '',
                    last_seen=row[5] or '', last_status=row[6], last_error=row[7] or '',
                )
                for row in conn.execute(
                    f"SELECT host, upstream, success, failure, first_seen, last_seen, "
                    f"last_status, last_error FROM {_TABLE}"
                )
            }

        with self._lock:
            for key, counters in loaded.items():
                existing = self._totals.get(key)
                if existing is None:
                    self._totals[key] = counters
                    continue
                existing.success = max(existing.success, counters.success)
                existing.failure = max(existing.failure, counters.failure)
                if counters.last_seen > existing.last_seen:
                    existing.last_seen = counters.last_seen
                    existing.last_status = counters.last_status
                    existing.last_error = counters.last_error
                if not existing.first_seen or (
                    counters.first_seen and counters.first_seen < existing.first_seen
                ):
                    existing.first_seen = counters.first_seen
        logger.info("已载入 %d 条域名×代理访问记录", len(loaded))

    def _purge_expired(self) -> int:
        cutoff = self._retention_cutoff()
        if not cutoff:
            return 0

        with self._session() as conn:
            candidates = [
                (row[0], row[1]) for row in conn.execute(
                    f"SELECT host, upstream FROM {_TABLE} WHERE last_seen < ?", (cutoff,)
                )
            ]

        if not candidates:
            return 0

        with self._lock:
            expired = [
                key for key in candidates
                if (counters := self._totals.get(key)) is None
                or counters.last_seen < cutoff
            ]

        if not expired:
            return 0

        with self._db_lock:
            with self._lock:
                purged = []
                for key in expired:
                    counters = self._totals.get(key)
                    if counters is not None and counters.last_seen >= cutoff:
                        continue
                    self._totals.pop(key, None)
                    self._pending.pop(key, None)
                    purged.append(key)

            with self._session() as conn:
                conn.executemany(
                    f"DELETE FROM {_TABLE} WHERE host = ? AND upstream = ?", purged
                )

        logger.info(
            "已清理 %d 条超过 %d 天未访问的记录", len(purged), self.retention_days
        )
        return len(purged)

    def _retention_cutoff(self) -> str:
        if self.retention_days <= 0:
            return ''
        return (datetime.now() - timedelta(days=self.retention_days)).strftime(_TIME_FORMAT)


def _as_int(value, *, default: int, low: int) -> int:
    return parse_int_lenient(value, default, low=low)


def _as_bool(value) -> bool:
    return parse_bool_lenient(value)
