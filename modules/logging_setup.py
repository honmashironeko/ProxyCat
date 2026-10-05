"""
模块名称：modules.logging_setup
功能描述：ProxyCat 的统一日志装配与分类路由：把主程序、代理请求与代理生命周期记录按
          logger 名前缀分流到 logs/ 下独立文件，ERROR 及以上汇总到 error.log，同时写入内存环形缓冲供面板实时查看。
职责边界：负责：handler 创建与挂载、按 logger 名分类、日志级别应用、环形缓冲读写、logs/ 下日志路径解析与列举清空；
          以及面板错误句（LogFileError.localized）与折叠后缀（log_suppressed）的界面语言渲染（语言由 Web 层传入）；
          不负责：文件正文文案翻译、控制台配色（ColoredFormatter）、代理池自身落盘（modules.proxypool.core.logger）。
关键依赖：modules.modules（NoPoolConsoleFilter、ColoredFormatter、get_message、parse_int_lenient）；
          标准库 logging、queue、threading、logging.handlers。
已知限制：
1. 分类依赖 logger 名前缀最长优先匹配，未命中一律归入 main；扩展日志类别必须同步维护 LOGGER_NAMES 与 ALL_CATEGORIES。
2. 文件写入异步：记录进有界队列由写线程落盘，读文件、清空与关停前必须先排空（read_log_file 与 truncate_log_file 内部会先排空），崩溃会丢队列里未落盘的记录。
3. 队列满时丢最旧的普通记录、保留控制帧（排空栅栏与停止哨兵），控制帧被丢会让排空或停止一直等到超时。
4. [Server] log_max_bytes / log_backup_count 只管宿主类别文件与 error.log；池 proxy_pool.log 轮转另由池配置控制，不进历史列表。
5. 读取只认白名单文件名（三个类别文件、error.log 及数字轮转份），非法名抛 LogFileError；清空对非法名不触碰文件却按成功返回，文件不存在时读取空列表、清空成功。
6. setup_logging 幂等：重复装配先摘除旧的 handler；文件 handler 创建失败只警告并降级；控制台默认 INFO，命令行入口传 WARNING 以免干扰 tqdm。
7. _FileQueueHandler.prepare 必须保持恒等覆写：stdlib 预格式化会清掉 exc_info/stack_info，error.log 会丢 traceback。
8. 装配顺序固定：先停写线程并排空，再关它持有的文件 handler；未停写线程就关 handler 会让旧写线程重开文件与新装配双写。
"""

import atexit
import itertools
import logging
import os
import queue
import sys
import threading
import time
from collections import deque
from datetime import datetime
from logging.handlers import QueueHandler, QueueListener, RotatingFileHandler

from modules.modules import (
    ColoredFormatter,
    NoPoolConsoleFilter,
    get_message,
    parse_int_lenient,
)


class LogFileError(ValueError):

    def __init__(self, key: str, *args):
        self.message_key = key
        self.message_args = args
        super().__init__(self.localized('cn'))

    def localized(self, language: str) -> str:
        return get_message(self.message_key, language, *self.message_args)


class LogCategory:

    MAIN = "main"
    ACCESS = "access"
    PROXY = "proxy"
    POOL = "pool"


ALL_CATEGORIES: tuple[str, ...] = (
    LogCategory.ACCESS,
    LogCategory.PROXY,
    LogCategory.MAIN,
    LogCategory.POOL,
)

FILED_CATEGORIES: tuple[str, ...] = (
    LogCategory.MAIN,
    LogCategory.ACCESS,
    LogCategory.PROXY,
)

LOGGER_NAMES: dict[str, str] = {
    LogCategory.MAIN: "proxycat.main",
    LogCategory.ACCESS: "proxycat.access",
    LogCategory.PROXY: "proxycat.proxy",
}

CATEGORY_FILES: dict[str, str] = {
    LogCategory.MAIN: "main.log",
    LogCategory.ACCESS: "access.log",
    LogCategory.PROXY: "proxy.log",
}

ERROR_LOG_FILENAME = "error.log"

ERROR_LOG_CATEGORY = "error"

LEVEL_IMPORTANT = "IMPORTANT"
_IMPORTANT_LEVELNO = logging.WARNING

_RING_SIZE = 20000
_ACCESS_RING_SIZE = 5000

_DEFAULT_MAX_BYTES = 10 * 1024 * 1024
_DEFAULT_BACKUP_COUNT = 3

_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
_FILE_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"


def _build_category_prefixes() -> tuple[tuple[str, str], ...]:
    table = [(prefix, LogCategory.POOL) for prefix in NoPoolConsoleFilter.POOL_LOGGER_PREFIXES]
    table += [(name, category) for category, name in LOGGER_NAMES.items()]
    normalized = [(prefix.rstrip('.'), category) for prefix, category in table]
    return tuple(sorted(normalized, key=lambda item: len(item[0]), reverse=True))


_CATEGORY_PREFIXES = _build_category_prefixes()

_CACHE_ATTR = "_proxycat_category"


def classify_record(record: logging.LogRecord) -> str:
    cached = getattr(record, _CACHE_ATTR, None)
    if cached is not None:
        return cached

    name = record.name or ""
    category = LogCategory.MAIN
    for prefix, candidate in _CATEGORY_PREFIXES:
        if name == prefix or name.startswith(prefix + "."):
            category = candidate
            break
    setattr(record, _CACHE_ATTR, category)
    return category


def get_category_logger(category: str) -> logging.Logger:
    return logging.getLogger(LOGGER_NAMES[category])


class CategoryFilter(logging.Filter):

    def __init__(self, category: str):
        super().__init__()
        self.category = category

    def filter(self, record: logging.LogRecord) -> bool:
        return classify_record(record) == self.category


class MinLevelFilter(logging.Filter):

    def __init__(self, levelno: int):
        super().__init__()
        self.levelno = levelno

    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno >= self.levelno


class ConsoleFilter(logging.Filter):

    def __init__(self):
        super().__init__()
        self._pool_filter = NoPoolConsoleFilter()

    def filter(self, record: logging.LogRecord) -> bool:
        if not self._pool_filter.filter(record):
            return False
        return classify_record(record) != LogCategory.ACCESS


class LogRingHandler(logging.Handler):

    def __init__(self, rings: dict, lock: threading.Lock, counter):
        super().__init__()
        self._rings = rings
        self._lock = lock
        self._counter = counter

    def emit(self, record: logging.LogRecord) -> None:
        try:
            category = classify_record(record)
            entry = {
                'seq': next(self._counter),
                'time': datetime.fromtimestamp(record.created).strftime(_TIME_FORMAT),
                'level': record.levelname,
                'message': self.format(record),
                'category': category,
                'logger': record.name or '',
            }
            with self._lock:
                ring = self._rings.get(category)
                if ring is not None:
                    ring.append(entry)
        except Exception:
            self.handleError(record)

_LOG_QUEUE_SIZE = 20000
_DRAIN_TIMEOUT = 5.0

_file_write_lock = threading.RLock()
_file_queue: "queue.Queue | None" = None
_queue_listener: "_FileQueueListener | None" = None
_file_targets: list[logging.Handler] = []


class _QueueControl:
    pass

class _FileQueueHandler(QueueHandler):
    def prepare(self, record):
        return record

    def enqueue(self, record) -> None:
        try:
            self.queue.put_nowait(record)
            return
        except queue.Full:
            pass
        try:
            oldest = self.queue.get_nowait()
        except queue.Empty:
            oldest = None
        if isinstance(oldest, _QueueControl):
            try:
                self.queue.put_nowait(oldest)
            except queue.Full:
                pass
            return
        try:
            self.queue.put_nowait(record)
        except queue.Full:
            pass


class _DrainBarrier(_QueueControl):
    __slots__ = ('event',)

    def __init__(self):
        self.event = threading.Event()


class _FileQueueListener(QueueListener):
    def __init__(self, log_queue, *handlers):
        super().__init__(log_queue, *handlers)
        self._sentinel = _QueueControl()

    def handle(self, record) -> None:
        if isinstance(record, _DrainBarrier):
            record.event.set()
            return
        with _file_write_lock:
            super().handle(record)

    def stop(self, timeout: float = _DRAIN_TIMEOUT) -> bool:
        if self._thread is None:
            return True
        try:
            self.queue.put(self._sentinel, timeout=timeout)
        except queue.Full:
            return False
        self._thread.join(timeout)
        drained = not self._thread.is_alive()
        if drained:
            self._thread = None
        return drained


def flush_log_queue(timeout: float = _DRAIN_TIMEOUT) -> bool:
    listener, log_queue = _queue_listener, _file_queue
    if listener is None or log_queue is None:
        return True
    barrier = _DrainBarrier()
    try:
        log_queue.put(barrier, timeout=timeout)
    except queue.Full:
        return False
    return barrier.event.wait(timeout)


def shutdown_logging(timeout: float = _DRAIN_TIMEOUT) -> bool:
    if _queue_listener is None:
        return True
    return _stop_file_queue(timeout)


def _start_file_queue(targets: list) -> None:
    global _file_queue, _queue_listener, _file_targets
    _file_queue = queue.Queue(maxsize=_LOG_QUEUE_SIZE)
    _queue_listener = _FileQueueListener(_file_queue, *targets)
    _queue_listener.start()
    _file_targets = list(targets)


def _stop_file_queue(timeout: float = _DRAIN_TIMEOUT) -> bool:
    global _file_queue, _queue_listener
    listener = _queue_listener
    _queue_listener = None
    _file_queue = None
    if listener is None:
        return True
    return listener.stop(timeout)


atexit.register(shutdown_logging)


def _ring_size(category: str) -> int:
    return _ACCESS_RING_SIZE if category == LogCategory.ACCESS else _RING_SIZE


def _new_rings() -> dict:
    return {category: deque(maxlen=_ring_size(category)) for category in ALL_CATEGORIES}


_rings = _new_rings()
_log_lock = threading.Lock()
_seq_counter = itertools.count(1)
_owned_handlers: list[logging.Handler] = []
_file_handlers: dict[str, logging.Handler] = {}
_config_lock = threading.Lock()


def _resolve_level(level_name) -> int:
    level = logging.getLevelName(str(level_name or '').strip().upper())
    if isinstance(level, int):
        return level
    logging.getLogger(__name__).warning("无法识别的日志级别 %r，回退为 INFO", level_name)
    return logging.INFO


def _make_file_handler(path, rotation, formatter, filters) -> logging.Handler | None:
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        handler = RotatingFileHandler(
            path,
            maxBytes=rotation['max_bytes'],
            backupCount=rotation['backup_count'],
            encoding='utf-8',
        )
    except OSError as e:
        print(f"警告: 创建日志文件失败 {path}: {e}", file=sys.stderr)
        return None
    handler.setFormatter(formatter)
    for log_filter in filters:
        handler.addFilter(log_filter)
    return handler


def setup_logging(config, base_dir: str, console_level: int = logging.INFO) -> None:
    rotation = {
        'max_bytes': _as_int(config, 'log_max_bytes', _DEFAULT_MAX_BYTES, low=1024),
        'backup_count': _as_int(config, 'log_backup_count', _DEFAULT_BACKUP_COUNT, low=1),
    }

    logs_dir = os.path.join(base_dir, 'logs')
    file_formatter = logging.Formatter(_FILE_FORMAT, datefmt=_TIME_FORMAT)

    with _config_lock:
        _detach_owned_handlers()

        root_logger = logging.getLogger()
        root_logger.setLevel(_resolve_level(config.get('log_level', 'INFO')))

        file_targets = []
        for category in FILED_CATEGORIES:
            filename = CATEGORY_FILES[category]
            handler = _make_file_handler(
                os.path.join(logs_dir, filename),
                rotation,
                file_formatter,
                [CategoryFilter(category)],
            )
            if handler is not None:
                _file_handlers[filename] = handler
                file_targets.append(handler)

        error_filename = ERROR_LOG_FILENAME
        error_handler = _make_file_handler(
            os.path.join(logs_dir, error_filename),
            rotation,
            file_formatter,
            [MinLevelFilter(logging.ERROR)],
        )
        if error_handler is not None:
            _file_handlers[error_filename] = error_handler
            file_targets.append(error_handler)

        if file_targets:
            _start_file_queue(file_targets)
            _attach(root_logger, _FileQueueHandler(_file_queue))

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(ColoredFormatter(_FILE_FORMAT, datefmt=_TIME_FORMAT))
        console_handler.setLevel(console_level)
        console_handler.addFilter(ConsoleFilter())
        _attach(root_logger, console_handler)

        ring_handler = LogRingHandler(_rings, _log_lock, _seq_counter)
        ring_handler.setFormatter(logging.Formatter('%(message)s'))
        _attach(root_logger, ring_handler)


def _attach(root_logger: logging.Logger, handler: logging.Handler) -> None:
    root_logger.addHandler(handler)
    _owned_handlers.append(handler)


def _detach_owned_handlers() -> None:
    drained = _stop_file_queue()
    if drained:
        for handler in _file_targets:
            try:
                handler.close()
            except Exception:
                pass
    elif _file_targets:
        print("警告: 日志写线程未能在超时内停下，保留其文件句柄以免双写", file=sys.stderr)
    _file_targets.clear()

    root_logger = logging.getLogger()
    for handler in _owned_handlers:
        root_logger.removeHandler(handler)
        try:
            handler.close()
        except Exception:
            pass
    _owned_handlers.clear()
    _file_handlers.clear()


def _as_int(config, key, default: int, *, low: int) -> int:
    try:
        raw = config.get(key, default)
    except AttributeError:
        return default
    return parse_int_lenient(raw, default, low=low)


class ThrottledLogger:
    def __init__(self, logger, language_provider=None, interval=5.0):
        self._logger = logger
        self._language_provider = language_provider
        self._interval = max(0.0, float(interval or 0))
        self._last = {}
        self._lock = threading.Lock()

    def set_interval(self, interval) -> None:
        self._interval = max(0.0, float(interval or 0))

    def warning(self, key, message) -> None:
        now = time.monotonic()
        with self._lock:
            last, suppressed = self._last.get(key, (0.0, 0))
            if last and now - last < self._interval:
                self._last[key] = (last, suppressed + 1)
                return
            self._last[key] = (now, 0)

        if suppressed:
            language = self._language_provider() if self._language_provider else 'cn'
            message = f"{message}{get_message('log_suppressed', language, suppressed)}"
        self._logger.warning(message)


def apply_log_level(level_name) -> int:
    level = _resolve_level(level_name)
    logging.getLogger().setLevel(level)
    return level


def query_log_ring(category: str | None = None,
                   level: str | None = None,
                   search: str | None = None) -> list[dict]:
    with _log_lock:
        if category and category != 'all':
            entries = list(_rings.get(category, ()))
        else:
            entries = []
            for ring in _rings.values():
                entries.extend(ring)
            entries.sort(key=lambda e: e['seq'])

    if level and level != 'ALL':
        if level == LEVEL_IMPORTANT:
            entries = [e for e in entries if _levelno(e) >= _IMPORTANT_LEVELNO]
        else:
            entries = [e for e in entries if e.get('level') == level]

    if search:
        needle = search.lower()
        entries = [
            e for e in entries
            if needle in e.get('message', '').lower()
            or needle in e.get('level', '').lower()
            or needle in e.get('time', '').lower()
            or needle in e.get('logger', '').lower()
        ]
    return entries


def _levelno(entry: dict) -> int:
    level = logging.getLevelName(entry.get('level', 'INFO'))
    return level if isinstance(level, int) else logging.INFO


def log_ring_stats() -> dict:
    with _log_lock:
        entries = []
        for ring in _rings.values():
            entries.extend(ring)

    levels: dict[str, int] = {}
    categories: dict[str, int] = {}
    for entry in entries:
        levels[entry['level']] = levels.get(entry['level'], 0) + 1
        category = entry.get('category', LogCategory.MAIN)
        categories[category] = categories.get(category, 0) + 1

    stats = {'total': len(entries), 'levels': levels, 'categories': categories}
    for category, ring in _rings.items():
        stats.setdefault('capacity', {})[category] = ring.maxlen
    if entries:
        stats['first_time'] = min(entries, key=lambda e: e['seq'])['time']
        stats['last_time'] = max(entries, key=lambda e: e['seq'])['time']
    return stats


def clear_log_ring(category: str | None = None) -> int:
    with _log_lock:
        if not category or category == 'all':
            removed = sum(len(ring) for ring in _rings.values())
            for ring in _rings.values():
                ring.clear()
            return removed

        ring = _rings.get(category)
        if ring is None:
            return 0
        removed = len(ring)
        ring.clear()
        return removed


def log_file_path(filename: str, base_dir: str) -> str | None:
    if os.path.basename(filename) != filename:
        return None
    if not _is_known_log_filename(filename):
        return None
    return os.path.join(base_dir, 'logs', filename)


def _is_known_log_filename(filename: str) -> bool:
    for name in _known_filenames():
        if filename == name:
            return True
        if filename.startswith(name + '.') and filename[len(name) + 1:].isdigit():
            return True
    return False


def _known_filenames() -> list[str]:
    return list(CATEGORY_FILES.values()) + [ERROR_LOG_FILENAME]


def _rotation_index(filename: str) -> int:
    head, _, suffix = filename.rpartition('.')
    if head and suffix.isdigit():
        return int(suffix)
    return -1


def iter_log_files(base_dir: str) -> list[dict]:
    logs_dir = os.path.join(base_dir, 'logs')
    if not os.path.isdir(logs_dir):
        return []

    files = []
    for filename in os.listdir(logs_dir):
        path = os.path.join(logs_dir, filename)
        if not os.path.isfile(path) or not _is_known_log_filename(filename):
            continue
        try:
            stat = os.stat(path)
        except OSError:
            continue
        is_current = filename in _known_filenames()
        files.append({
            'name': filename,
            'category': _filename_category(filename),
            'size': stat.st_size,
            'modified': datetime.fromtimestamp(stat.st_mtime).strftime(_TIME_FORMAT),
            'current': is_current,
            'rotated': not is_current,
        })

    files.sort(key=lambda f: (
        ALL_CATEGORIES.index(f['category']) if f['category'] in ALL_CATEGORIES else 99,
        not f['current'],
        _rotation_index(f['name']),
        f['name'],
    ))
    return files


def _filename_category(filename: str) -> str:
    for category, name in CATEGORY_FILES.items():
        if filename == name or filename.startswith(name + '.'):
            return category
    return ERROR_LOG_CATEGORY


def truncate_log_file(filename: str, base_dir: str) -> bool:
    if not flush_log_queue():
        return False

    handler = _file_handlers.get(filename)
    if handler is not None:
        with _file_write_lock:
            handler.acquire()
            try:
                stream = getattr(handler, 'stream', None)
                if stream is not None:
                    stream.seek(0)
                    stream.truncate()
                    stream.flush()
                    return True
            except (OSError, ValueError):
                return False
            finally:
                handler.release()
        return False

    path = log_file_path(filename, base_dir)
    if path is None or not os.path.exists(path):
        return True
    try:
        with open(path, 'w', encoding='utf-8'):
            pass
        return True
    except OSError:
        return False


def current_log_filenames(category: str | None = None) -> list[str]:
    if category and category != 'all':
        name = CATEGORY_FILES.get(category)
        return [name] if name else []
    return _known_filenames()


def read_log_file(filename: str, base_dir: str, lines: int = 500) -> tuple[list[str], bool]:
    path = log_file_path(filename, base_dir)
    if path is None:
        raise LogFileError('log_file_name_invalid', filename)

    flush_log_queue()

    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as handle:
            tail = deque(handle, maxlen=lines)
            truncated = handle.tell() > 0 and len(tail) == lines
    except FileNotFoundError:
        return [], False
    except OSError as e:
        raise LogFileError('log_file_read_failed', e) from e

    return [line.rstrip('\n') for line in tail], truncated
