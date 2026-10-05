"""
模块名称：modules.loop_noise_filter
功能描述：抑制 Windows 上 asyncio 传输层收尾对已重置连接抛出的 ConnectionResetError：仅把该已知异常降级为 DEBUG，其余 context 交回原处理器。
职责边界：负责：判定该已知噪声并安装事件循环异常过滤器；不负责：修复 CPython 传输层缺陷，也不代替业务代码捕获其自身应处理的 ConnectionResetError。
关键依赖：仅标准库 asyncio、logging、os。
已知限制：
  1. 只对调用过 install_loop_noise_filter() 的循环生效，新增承载网络 I/O 的常驻循环需自行安装。
  2. 只在 Windows 安装；其它平台出现同类异常说明另有原因，应让它照常报错。
  3. 判定要求回调名、宿主类名后缀、异常类型三者同时成立；CPython 若重命名该私有方法，失效方向是噪声重现而不会误吞真实错误。
  4. 只认 ConnectionResetError，同一位置上成因不同的其它 OSError 不会被一并吞掉。
  5. 幂等检测依赖本模块处理器仍是循环当前处理器；被第三方替换后再次安装会再包一层。
"""

import asyncio
import logging
import os

logger = logging.getLogger(__name__)

_IS_WINDOWS = os.name == 'nt'

_INSTALLED_FLAG = '_proxycat_loop_noise_filter'

_CLOSE_CALLBACK_NAME = '_call_connection_lost'

_CLOSE_CALLBACK_OWNER_SUFFIX = 'Transport'


def is_proactor_close_noise(context: dict) -> bool:
    if not _IS_WINDOWS:
        return False

    if not isinstance(context.get('exception'), ConnectionResetError):
        return False

    callback = getattr(context.get('handle'), '_callback', None)
    owner, _, method = getattr(callback, '__qualname__', '').rpartition('.')
    return method == _CLOSE_CALLBACK_NAME and owner.endswith(_CLOSE_CALLBACK_OWNER_SUFFIX)


def install_loop_noise_filter(loop: asyncio.AbstractEventLoop) -> bool:
    if not _IS_WINDOWS:
        return False

    previous = loop.get_exception_handler()
    if getattr(previous, _INSTALLED_FLAG, False):
        return False

    def _handler(active_loop, context):
        if is_proactor_close_noise(context):
            logger.debug(
                "已抑制 Proactor 关闭噪声（连接此前已关闭，此异常无后续影响）: %s",
                context.get('exception'),
            )
            return
        if previous is not None:
            previous(active_loop, context)
        else:
            active_loop.default_exception_handler(context)

    setattr(_handler, _INSTALLED_FLAG, True)
    loop.set_exception_handler(_handler)
    return True
