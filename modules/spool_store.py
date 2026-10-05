"""
模块名称：modules.spool_store
功能描述：为「内存缓冲 + 后台线程批量落 SQLite」的存储提供共用骨架：热路径只写内存，
          后台线程按 flush_interval 定时把攒下的一批写进库，并管理 flush/clear/stop。
职责边界：负责：flush/clear/stop 骨架、后台循环、清空与在途落库的竞态门（generation）、
          批量落库的执行顺序、clear 的整表删除语句、写入失败时调用回退钩子的编排、
          连接获取与建表钩子的调用时机；不负责：内存数据结构、批量写入 SQL 与回退钩子
          的实现、过期清理与读路径，均由 modules.domain_stats / modules.access_records 子类实现。
关键依赖：仅标准库 sqlite3、threading、os、contextlib、logging；无第三方组件。
已知限制：
  1. 子类须实现 _ensure_schema、_take_batch、_write_batch、_restore_batch、_clear_memory、_purge_expired 钩子。
  2. _take_batch 须在 _lock 内取批并返回 (batch, generation)，无数据时返回 falsy（None 或空容器），generation 原样带回。
  3. flush_interval 与 start() 由子类提供，_init_flush_state 不设默认值；stop() 未启动时为空操作。
  4. 锁顺序固定为 _db_lock → _lock，_lock 只保护内存结构，落库 I/O 不得占着它执行。
  5. clear() 自增 generation 作废已取出未落库的那批；该批被丢弃且不回调 _restore_batch。
  6. stop() 只等后台线程 5 秒，最终 flush 失败仅记日志、不再抛出。
"""

import logging
import os
import sqlite3
import threading
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class FlushBackedSqliteStore:
    _table = ''
    _log_label = '记录'

    def _init_flush_state(self, db_path: str) -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        self._db_lock = threading.Lock()
        self._flush_generation = 0
        self._thread = None
        self._stop_event = threading.Event()
        self._started = False

    def stop(self) -> None:
        if not self._started:
            return
        self._started = False
        self._stop_event.set()
        thread, self._thread = self._thread, None
        if thread is not None and thread.is_alive():
            thread.join(timeout=5)
        try:
            self.flush()
        except Exception as e:
            logger.error("%s最终落库失败: %s", self._log_label, e)

    def flush(self) -> int:
        batch, generation = self._take_batch()
        if not batch:
            return 0

        with self._db_lock:
            if generation != self._flush_generation:
                return 0
            if not self._write_batch(batch):
                self._restore_batch(batch)
                return 0
            self._on_write_succeeded(batch)

        self._after_flush()
        return len(batch)

    def clear(self) -> int:
        with self._db_lock:
            try:
                with self._session() as conn:
                    cursor = conn.execute(f"DELETE FROM {self._table}")
            except (sqlite3.Error, OSError) as e:
                logger.error("清空%s数据库失败: %s", self._log_label, e)
                return 0

            with self._lock:
                self._flush_generation += 1
                return self._clear_memory(cursor.rowcount)

    def _flush_loop(self) -> None:
        while not self._stop_event.wait(self.flush_interval):
            try:
                self.flush()
                self._purge_expired()
            except Exception as e:
                logger.error("%s后台落库异常: %s", self._log_label, e)

    @contextmanager
    def _session(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=10)
        try:
            self._ensure_schema(conn)
            with conn:
                yield conn
        finally:
            conn.close()

    def _ensure_schema(self, conn):
        raise NotImplementedError

    def _take_batch(self):
        raise NotImplementedError

    def _write_batch(self, batch) -> bool:
        raise NotImplementedError

    def _restore_batch(self, batch) -> None:
        raise NotImplementedError

    def _clear_memory(self, deleted_rows: int) -> int:
        raise NotImplementedError

    def _purge_expired(self) -> None:
        raise NotImplementedError

    def _on_write_succeeded(self, batch) -> None:
        pass

    def _after_flush(self) -> None:
        pass
