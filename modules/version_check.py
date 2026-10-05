"""
模块名称：modules.version_check
功能描述：版本检查的调度与状态持久化：决定何时比对版本、结果放在哪、给谁读。启动后由后台
          线程立即做一次到期判定，之后每 24 小时至多请求一次；时间与结果落盘，内存中缓存结果。
职责边界：负责：到期判定、发起远端请求并解析版本号、持久化最近一次检查的时间与结果、
          在内存中缓存结果供只读查询；不负责：HTTP 路由（见 app）、控制台输出与用户
          可见文案渲染（入口文件与 modules.modules.get_message 负责），本模块只回调。
关键依赖：modules.modules（CURRENT_VERSION、get_message、read_config_text、
          write_text_atomic）、httpx、packaging。
已知限制：
  1. 内存时间戳是准绳，状态文件只是尽力而为的写穿：写盘失败只记日志，不影响 24 小时内不再检查的判定。
  2. 检查失败时保留上一次成功的版本号，result_payload() 仍返回成功形态，失败只体现在日志。
  3. 时钟回拨时时间戳落到未来，按到期处理，检查一次即以新时间自愈；tick 只用 Event.wait，不按剩余时间计算睡眠。
  4. 远端请求在锁外发起，_in_flight 只防同进程重入，多进程共用状态文件时仍可能各查一次。
  5. write_text_atomic 的临时文件名为 .config-*.tmp，进程被强杀时可能在状态文件目录留下残留。
"""

import json
import logging
import os
import re
import threading
import time
from datetime import datetime

import httpx
from packaging import version

from modules.modules import (
    CURRENT_VERSION,
    get_message,
    read_config_text,
    write_text_atomic,
)

logger = logging.getLogger(__name__)

VERSION_URL = "https://y.shironekosan.cn/1.html"

CHECK_INTERVAL_SECONDS = 24 * 60 * 60

CHECK_TICK_SECONDS = 600.0

REQUEST_TIMEOUT_SECONDS = 10.0

_STATE_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

_VERSION_PATTERN = re.compile(r'<p>(ProxyCat-V\d+\.\d+\.\d+)</p>')


class VersionChecker:
    def __init__(self, state_path, language_provider=None, on_result=None):
        self.state_path = str(state_path)
        self._language_provider = language_provider
        self._on_result = on_result

        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._started = False
        self._loaded = False

        self._checked_at: float | None = None
        self._latest_version: str | None = None
        self._error_key: str | None = None
        self._error_args: list = []
        self._in_flight = False

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
            if not self._due_locked() or self._in_flight:
                return False
            self._in_flight = True

        try:
            started_at = time.time()
            latest_version, error_key, error_args = self._fetch_latest()
        finally:
            with self._lock:
                self._in_flight = False

        notify_payload = None
        with self._lock:
            self._checked_at = started_at
            if latest_version:
                self._latest_version = latest_version
                self._error_key = None
                self._error_args = []
            elif error_key:
                self._error_key = error_key
                self._error_args = error_args

            self._persist_locked()

            if notify and self._on_result is not None:
                notify_payload = self._payload_locked()

        if notify_payload is not None:
            try:
                self._on_result(notify_payload)
            except Exception as e:
                logger.warning(f"版本检查的结果回调执行失败（已忽略）: {e}")
        return True

    def _fetch_latest(self) -> tuple:
        latest_version = None
        error_key = None
        error_args: list = []
        try:
            with httpx.Client(transport=httpx.HTTPTransport(retries=3)) as client:
                response = client.get(VERSION_URL, timeout=REQUEST_TIMEOUT_SECONDS)
                response.raise_for_status()
                match = _VERSION_PATTERN.search(response.text)

            if match:
                latest_version = match.group(1)
            else:
                error_key = 'version_info_not_found'
        except Exception as e:
            error_key = 'update_check_error'
            error_args = [str(e)]
            logger.warning(f"版本检查失败（本次已记账，24 小时内不再重试）: {e}")
        return latest_version, error_key, error_args

    def result_payload(self) -> dict:
        with self._lock:
            self._ensure_loaded_locked()
            return self._payload_locked()

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
            'checked_at_text': datetime.fromtimestamp(self._checked_at).strftime(
                _STATE_TIME_FORMAT
            ),
            'current_version': CURRENT_VERSION,
            'latest_version': self._latest_version,
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
        error_key = raw.get('error_key')
        error_args = raw.get('error_args')

        self._checked_at = float(checked_at)
        self._latest_version = latest_version if isinstance(latest_version, str) else None
        self._error_key = error_key if isinstance(error_key, str) else None
        self._error_args = list(error_args) if isinstance(error_args, list) else []


def _not_newer(latest_version: str, current_version: str) -> bool:
    try:
        return (
            version.parse(latest_version.split('-V')[1])
            <= version.parse(current_version.split('-V')[1])
        )
    except (IndexError, ValueError):
        return True


__all__ = [
    "VersionChecker",
    "VERSION_URL",
    "CHECK_INTERVAL_SECONDS",
    "CHECK_TICK_SECONDS",
]
