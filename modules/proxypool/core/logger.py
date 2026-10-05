"""
模块名称：modules.proxypool.core.logger
功能描述：把池的高频日志（插件抓取、批量验证）写入 logs/proxy_pool.log 轮转文件以免淹没主日志，经 propagate 只汇入面板「运行日志」的内存环形缓冲，不进控制台。
职责边界：负责：挂载或重挂池的轮转文件 handler、压低第三方库日志级别；不负责：主日志装配与 root 级别设置（见 modules.logging_setup）。
关键依赖：core.config.LoggingConfig、core.paths.resolve_pool_path、标准库 logging 与 logging.handlers。
已知限制：
1. 与 ProxyCat 共用同一个 root logger，不清空已有 handler 也不设 root 级别，否则主程序日志面板失效。
2. handler 与配置签名存为 logger 属性而非模块级变量，保证模块多次导入也只挂一份。
3. 幂等依据是四项配置签名（文件路径、单文件上限、保留份数、级别）：签名未变时直接返回，签名变化时函数内部先摘旧 handler 再挂新，调用方无需先摘后挂。
4. record_filter 由宿主注入，本模块不反向依赖主程序分类规则；不传时主程序的访问日志会被整份复制进来。
5. 创建日志目录或文件抛出 OSError 时仅向 stderr 打印警告并放弃挂载，不向上抛出。
"""

import logging
import sys
from logging.handlers import RotatingFileHandler

from core.config import LoggingConfig
from core.paths import resolve_pool_path

_HANDLER_ATTR = "_proxy_pool_handler"
_SIGNATURE_ATTR = "_proxy_pool_handler_signature"


def _detach_pool_log_handler(root_logger: logging.Logger) -> None:
    handler = getattr(root_logger, _HANDLER_ATTR, None)
    if handler is None:
        return
    root_logger.removeHandler(handler)
    try:
        handler.close()
    except Exception:
        pass
    setattr(root_logger, _HANDLER_ATTR, None)


def attach_pool_log_handlers(log_config: LoggingConfig, level: int,
                            record_filter: logging.Filter | None = None) -> None:
    root_logger = logging.getLogger()
    log_path = resolve_pool_path(log_config.file_path)
    signature = (str(log_path), log_config.max_bytes, log_config.backup_count, level)

    if getattr(root_logger, _SIGNATURE_ATTR, None) == signature:
        logging.getLogger(__name__).debug("池日志 handler 的配置未变，跳过重挂")
        return

    _detach_pool_log_handler(root_logger)

    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print(f"警告: 创建池日志目录失败 {log_path.parent}: {e}", file=sys.stderr)
        return

    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    try:
        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=log_config.max_bytes,
            backupCount=log_config.backup_count,
            encoding="utf-8",
        )
    except OSError as e:
        print(f"警告: 创建池日志文件失败 {log_path}: {e}", file=sys.stderr)
        return

    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    if record_filter is not None:
        file_handler.addFilter(record_filter)
    root_logger.addHandler(file_handler)
    setattr(root_logger, _HANDLER_ATTR, file_handler)
    setattr(root_logger, _SIGNATURE_ATTR, signature)

    for noisy in ("aiohttp", "asyncio", "urllib3", "aiosqlite"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    logging.getLogger(__name__).info("池日志已挂载: %s", log_path)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
