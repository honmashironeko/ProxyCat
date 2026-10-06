"""
模块名称：modules.version_check
功能描述：版本检查的调度、取数与状态持久化：决定何时比对版本、从哪些地址取、结果放在哪、给谁读。
          启动后由后台线程立即做一次到期判定，之后每 24 小时至多检查一次；时间与结果落盘，内存中缓存结果。
          取数时并发请求多个 GitHub 地址（官方发布源、镜像、官方 API），谁先返回可用的版本号就用谁。
职责边界：负责：到期判定、并发取数并解析版本号、持久化最近一次检查的时间与结果、在内存中缓存结果
          供只读查询；不负责：HTTP 路由（见 app）、控制台输出与用户可见文案渲染（入口文件与
          modules.modules.get_message 负责），本模块只回调。
关键依赖：modules.modules（CURRENT_VERSION、get_message、read_config_text、write_text_atomic）、
          asyncio、json 与 xml.etree.ElementTree（标准库）、httpx（异步客户端）、packaging。
已知限制：
  1. 内存时间戳是准绳，状态文件只是尽力而为的写穿：写盘失败只记日志，不影响 24 小时内不再检查的判定。
  2. 检查失败时保留上一次成功的版本号，result_payload() 仍返回成功形态，失败只体现在日志与状态文件；
     本次是否成功要看 check_now() 的返回，它用 status 直接表达本次结果。
  3. 时钟回拨时时间戳落到未来，按到期处理，检查一次即以新时间自愈；tick 只用 Event.wait，不按剩余时间计算睡眠。
  4. _in_flight 提供互斥，_in_flight_done 提供「等正在跑的那一次」；两者总在 _lock 下成对读写，
     等待事件必须在锁外进行（_lock 是叶子锁）。多进程共用状态文件时仍可能各查一次。
  5. write_text_atomic 的临时文件名为 .config-*.tmp，进程被强杀时可能在状态文件目录留下残留。
  6. 竞速以「最先返回的成功源」为准，不跨源比对最大值；第三方镜像可能返回缓存的旧响应，
     因而理论上存在「镜像先返回、报出的版本偏旧」的窗口。
  7. api.github.com 未认证限额为每 IP 每小时 60 次，共享出口 IP 下更少；它在默认源里，
     但失败不影响另外两个源。
  8. asyncio.run() 要求调用线程当前没有事件循环；本模块的全部调用点（后台检查线程、
     阻塞启动路径、Web 请求线程）都满足，新增调用点时需保持这一前提。
  9. 自定义地址按响应体形状择一解析（JSON → Atom → 整文正则）；能解析成 JSON/Atom 时不再退回整文正则，
     以免把发布说明正文里的版本号当成发布版本。
  10. 版本号只取 ProxyCat[-_]v?数字.数字[.数字] 这一段前缀，测试版等后缀被丢弃
      （否则同一版本的每个测试版都会被当成一个新版本）。
  11. 请求全部经由 httpx，httpx 默认读取 HTTP(S)_PROXY 环境变量，这是既有的对外行为。
"""

import asyncio
import json
import logging
import os
import re
import threading
import time
import xml.etree.ElementTree as ElementTree
from datetime import datetime

import httpx
from packaging.version import InvalidVersion, Version

from modules.loop_noise_filter import install_loop_noise_filter
from modules.modules import (
    CURRENT_VERSION,
    get_message,
    read_config_text,
    write_text_atomic,
)

logger = logging.getLogger(__name__)

BUILTIN_SOURCES = (
    "https://github.com/honmashironeko/ProxyCat/releases.atom",
    "https://gh-proxy.com/https://api.github.com/repos/honmashironeko/ProxyCat/releases?per_page=10",
    "https://api.github.com/repos/honmashironeko/ProxyCat/releases?per_page=10",
)

CHECK_INTERVAL_SECONDS = 24 * 60 * 60

CHECK_TICK_SECONDS = 600.0

REQUEST_TIMEOUT_SECONDS = 10.0

RACE_TIMEOUT_SECONDS = 15.0

_CONNECT_TIMEOUT_SECONDS = 4.0

_WRITE_TIMEOUT_SECONDS = 4.0

_STATE_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

_ATOM_NAMESPACE = "{http://www.w3.org/2005/Atom}"

_TAG_PATTERN = re.compile(r'ProxyCat[-_]v?(\d+(?:\.\d+){1,2})', re.IGNORECASE)

_JSON_TAG_KEYS = ('tag_name',)

_JSON_LABEL_KEYS = ('name',)


def _parse_version(label):
    match = _TAG_PATTERN.search(str(label))
    if not match:
        return None
    try:
        return Version(match.group(1))
    except InvalidVersion:
        return None


def _match_versions(labels):
    matched = []
    for label in labels:
        for match in _TAG_PATTERN.finditer(str(label)):
            if match.group(0) not in matched:
                matched.append(match.group(0))
    return matched


def _json_labels(text):
    try:
        payload = json.loads(text)
    except (ValueError, UnicodeDecodeError):
        return None

    labels = []

    def collect(node, nested):
        if isinstance(node, dict):
            for key, value in node.items():
                if key in _JSON_TAG_KEYS and isinstance(value, str):
                    labels.append(value)
                elif nested and key in _JSON_LABEL_KEYS and isinstance(value, str):
                    labels.append(value)
                else:
                    collect(value, True)
        elif isinstance(node, list):
            for item in node:
                collect(item, nested)

    collect(payload, False)
    return labels


def _atom_labels(text):
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return None

    if root.tag != _ATOM_NAMESPACE + 'feed':
        return None

    labels = []
    for entry in root.findall(_ATOM_NAMESPACE + 'entry'):
        for name in ('id', 'title'):
            element = entry.find(_ATOM_NAMESPACE + name)
            if element is not None and element.text:
                labels.append(element.text.rsplit('/', 1)[-1])
    return labels


def _extract_versions(text):
    stripped = text.lstrip()
    if stripped[:1] in ('{', '['):
        labels = _json_labels(text)
        if labels is not None:
            return _match_versions(labels)
    elif stripped[:1] == '<':
        labels = _atom_labels(text)
        if labels is not None:
            return _match_versions(labels)
    return _match_versions([text])


def _latest_of(versions):
    best = None
    best_parsed = None
    for label in versions:
        parsed = _parse_version(label)
        if parsed is None:
            continue
        if best_parsed is None or parsed > best_parsed:
            best = label
            best_parsed = parsed
    return best


def _not_newer(latest_version, current_version):
    latest = _parse_version(latest_version)
    current = _parse_version(current_version)
    if latest is None or current is None:
        return True
    return latest <= current


def _host_of(url):
    without_scheme = str(url).split('://', 1)[-1]
    return without_scheme.split('/', 1)[0] or str(url)


def _error_detail(error):
    if isinstance(error, httpx.HTTPStatusError):
        return f"HTTP {error.response.status_code}"
    return type(error).__name__


class VersionChecker:
    def __init__(self, state_path, language_provider=None, on_result=None, url_provider=None):
        self.state_path = str(state_path)
        self._language_provider = language_provider
        self._on_result = on_result
        self._url_provider = url_provider

        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._started = False
        self._loaded = False

        self._checked_at: float | None = None
        self._latest_version: str | None = None
        self._source: str | None = None
        self._error_key: str | None = None
        self._error_args: list = []
        self._in_flight = False
        self._in_flight_done: threading.Event | None = None

    def start(self, blocking: bool = False) -> bool:
        with self._lock:
            if self._started:
                return False
            self._started = True
            self._ensure_loaded_locked()
            due = self._due_locked()

        logging.getLogger('httpx').setLevel(logging.WARNING)

        if blocking and due:
            self.check_if_due()

        self._thread = threading.Thread(
            target=self._tick_loop, name="version-check", daemon=True
        )
        self._thread.start()
        return due

    def stop(self, wait: bool = False) -> None:
        if not self._started:
            return
        self._stop_event.set()
        thread = self._thread
        if wait and thread is not None and thread.is_alive():
            thread.join(timeout=5)

    def check_if_due(self, notify: bool = True) -> bool:
        with self._lock:
            self._ensure_loaded_locked()
            if not self._due_locked():
                return False

        done = self._acquire_check()
        if done is None:
            return False

        self._execute_check(notify=notify, done=done)
        return True

    def check_now(self) -> dict:
        with self._lock:
            self._ensure_loaded_locked()
            running = self._in_flight_done

        if running is None:
            done = self._acquire_check()
            if done is not None:
                self._execute_check(notify=False, done=done)
            else:
                with self._lock:
                    running = self._in_flight_done

        if running is not None:
            running.wait(RACE_TIMEOUT_SECONDS + _CONNECT_TIMEOUT_SECONDS)

        with self._lock:
            return self._check_result_locked()

    def result_payload(self) -> dict:
        with self._lock:
            self._ensure_loaded_locked()
            return self._payload_locked()

    def _acquire_check(self):
        with self._lock:
            if self._in_flight:
                return None
            done = threading.Event()
            self._in_flight = True
            self._in_flight_done = done
            return done

    def _release_check(self, done) -> None:
        with self._lock:
            self._in_flight = False
            self._in_flight_done = None
            done.set()

    def _execute_check(self, notify: bool, done) -> None:
        notify_payload = None
        try:
            started_at = time.time()
            latest_version, source, error_key, error_args = self._fetch_latest()

            with self._lock:
                self._checked_at = started_at
                if latest_version:
                    self._latest_version = latest_version
                    self._source = source
                    self._error_key = None
                    self._error_args = []
                elif error_key:
                    self._error_key = error_key
                    self._error_args = error_args

                self._persist_locked()

                if notify and self._on_result is not None:
                    notify_payload = self._payload_locked()
        finally:
            self._release_check(done)

        if notify_payload is not None:
            try:
                self._on_result(notify_payload)
            except Exception as e:
                logger.warning(f"版本检查的结果回调执行失败（已忽略）: {e}")

    def _sources(self) -> tuple:
        if self._url_provider is None:
            return BUILTIN_SOURCES
        try:
            custom = str(self._url_provider() or '').strip()
        except Exception:
            return BUILTIN_SOURCES
        return (custom,) if custom else BUILTIN_SOURCES

    def _fetch_latest(self) -> tuple:
        try:
            return asyncio.run(self._race_sources(self._sources()))
        except Exception as e:
            logger.warning(f"版本检查失败（本次已记账，24 小时内不再重试）: {e}")
            return None, None, 'update_check_error', [str(e)]

    async def _race_sources(self, sources) -> tuple:
        install_loop_noise_filter(asyncio.get_running_loop())

        deadline = time.monotonic() + RACE_TIMEOUT_SECONDS
        timeouts = httpx.Timeout(
            REQUEST_TIMEOUT_SECONDS,
            connect=_CONNECT_TIMEOUT_SECONDS,
            read=REQUEST_TIMEOUT_SECONDS,
            write=_WRITE_TIMEOUT_SECONDS,
        )
        failures: list = []

        async with httpx.AsyncClient(
            transport=httpx.AsyncHTTPTransport(retries=1),
            timeout=timeouts,
            follow_redirects=True,
        ) as client:
            order = {}
            pending = set()
            for index, url in enumerate(sources):
                task = asyncio.create_task(self._fetch_source(client, url))
                order[task] = index
                pending.add(task)

            try:
                while pending:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    completed, pending = await asyncio.wait(
                        pending, timeout=remaining, return_when=asyncio.FIRST_COMPLETED
                    )
                    if not completed:
                        break
                    for task in sorted(completed, key=lambda item: order[item]):
                        version, source, error_key, detail = task.result()
                        if version:
                            return version, source, None, []
                        failures.append((source, detail, error_key))
            finally:
                for task in pending:
                    task.cancel()
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)

        if not failures:
            return None, None, 'update_check_error', ['timeout']

        logger.warning(f"版本检查失败（本次已记账，24 小时内不再重试）: {_failure_text(failures)}")
        return None, None, _failure_key(failures), [_failure_text(failures)]

    async def _fetch_source(self, client, url) -> tuple:
        source = _host_of(url)
        try:
            response = await client.get(url)
            response.raise_for_status()
        except Exception as e:
            return None, source, 'update_check_error', _error_detail(e)

        latest_version = _latest_of(_extract_versions(response.text))
        if not latest_version:
            return None, source, 'version_info_not_found', 'no version found'
        return latest_version, source, None, None

    def _language(self) -> str:
        if self._language_provider is None:
            return 'cn'
        try:
            return self._language_provider() or 'cn'
        except Exception:
            return 'cn'

    def _payload_locked(self) -> dict:
        language = self._language()
        if self._latest_version:
            return {
                'status': 'success',
                'is_latest': _not_newer(self._latest_version, CURRENT_VERSION),
                'current_version': CURRENT_VERSION,
                'latest_version': self._latest_version,
            }
        if self._error_key:
            return {
                'status': 'error',
                'message': get_message(self._error_key, language, *self._error_args),
            }
        return {
            'status': 'error',
            'message': get_message('version_not_checked', language),
        }

    def _check_result_locked(self) -> dict:
        language = self._language()
        payload = {
            'current_version': CURRENT_VERSION,
            'checked_at': self._checked_at_text(),
        }
        if self._latest_version:
            payload['latest_version'] = self._latest_version
            payload['is_latest'] = _not_newer(self._latest_version, CURRENT_VERSION)

        if self._error_key:
            payload['status'] = 'error'
            payload['message'] = get_message(self._error_key, language, *self._error_args)
        elif self._latest_version:
            payload['status'] = 'success'
            payload['source'] = self._source
        else:
            payload['status'] = 'error'
            payload['message'] = get_message('version_not_checked', language)
        return payload

    def _checked_at_text(self):
        if self._checked_at is None:
            return None
        return datetime.fromtimestamp(self._checked_at).strftime(_STATE_TIME_FORMAT)

    def _tick_loop(self) -> None:
        while True:
            try:
                self.check_if_due()
            except Exception as e:
                logger.warning(f"版本检查的后台轮询出错（已忽略，下个周期继续）: {e}")
            if self._stop_event.wait(CHECK_TICK_SECONDS):
                return

    def _due_locked(self) -> bool:
        if self._checked_at is None:
            return True
        elapsed = time.time() - self._checked_at
        if elapsed < 0:
            return True
        return elapsed >= CHECK_INTERVAL_SECONDS

    def _persist_locked(self) -> None:
        payload = {
            'checked_at': self._checked_at,
            'checked_at_text': self._checked_at_text(),
            'current_version': CURRENT_VERSION,
            'latest_version': self._latest_version,
            'source': self._source,
            'error_key': self._error_key,
            'error_args': self._error_args,
        }
        try:
            directory = os.path.dirname(os.path.abspath(self.state_path))
            os.makedirs(directory, exist_ok=True)
            write_text_atomic(
                self.state_path,
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            )
        except OSError as e:
            logger.warning(
                f"版本检查状态写入 {self.state_path} 失败（本次结果仍在本进程内生效）: {e}"
            )

    def _ensure_loaded_locked(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        self._load_state()

    def _load_state(self) -> None:
        try:
            raw = json.loads(read_config_text(self.state_path))
        except FileNotFoundError:
            return
        except (OSError, ValueError, UnicodeDecodeError) as e:
            logger.warning(f"版本检查状态文件不可用，按未检查处理: {e}")
            return

        if not isinstance(raw, dict):
            logger.warning("版本检查状态文件不是对象，按未检查处理")
            return

        checked_at = raw.get('checked_at')
        if not isinstance(checked_at, (int, float)) or isinstance(checked_at, bool):
            logger.warning("版本检查状态文件缺少可用的 checked_at，按未检查处理")
            return

        if raw.get('current_version') != CURRENT_VERSION:
            logger.info(
                f"版本已从 {raw.get('current_version')} 变为 {CURRENT_VERSION}，"
                "立即重新检查"
            )
            return

        latest_version = raw.get('latest_version')
        source = raw.get('source')
        error_key = raw.get('error_key')
        error_args = raw.get('error_args')

        self._checked_at = float(checked_at)
        self._latest_version = latest_version if isinstance(latest_version, str) else None
        self._source = source if isinstance(source, str) else None
        self._error_key = error_key if isinstance(error_key, str) else None
        self._error_args = list(error_args) if isinstance(error_args, list) else []


def _failure_key(failures) -> str:
    for _, _, error_key in failures:
        if error_key == 'update_check_error':
            return 'update_check_error'
    return 'version_info_not_found'


def _failure_text(failures) -> str:
    parts = []
    for source, detail, _ in failures:
        text = f"{source}: {detail}"
        if text not in parts:
            parts.append(text)
    return '; '.join(parts)


__all__ = [
    "VersionChecker",
    "BUILTIN_SOURCES",
    "CHECK_INTERVAL_SECONDS",
    "CHECK_TICK_SECONDS",
]
