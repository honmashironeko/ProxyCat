"""
模块名称：modules.proxypool.core.domain.exceptions
功能描述：代理池全域的异常类型定义：所有异常源于 ProxyPoolException，按出错层次分族，覆盖数据访问、依赖注入、插件、参数、验证、HTTP 客户端、写队列与应用编排。
职责边界：负责：异常类型定义及少数类型携带的结构化信息（reason 失败分类、文案键与实参）；不负责：抛出的时机与捕获策略（各业务模块自定）、错误文案的渲染（由 Web 边界完成）。
关键依赖：无
已知限制：
  1. 异常不携带 HTTP 状态码，路由层要映射状态码只能另行判断。
  2. message_key 为空时按普通异常处理，message 原样透出。
  3. InvalidParameterException 同时继承 ValueError 是有意的：适配层按 ValueError 映射成 400 invalid_parameter。
  4. HttpClientException.reason 是机器可读的失败分类（proxy_connect / connect_timeout 等），调用方按它分支，不要解析 message。
  5. ProxyValidationException 无任何抛出点，仅登记在 Web 适配层异常映射表；验证结论（含无结论）均由结果对象表达，不抛异常。
  6. WriteQueueFullException 是背压信号而非故障；WriteQueueException 也用于启停失败，批次重试用尽后由消费者丢弃并计数、不向写入方抛出；队列不做重投。
"""

from typing import Any


class ProxyPoolException(Exception):
    message_key: str = ""
    message_args: tuple = ()

    def with_message_key(self, key: str, *args) -> "ProxyPoolException":
        self.message_key = key
        self.message_args = args
        return self


class RepositoryException(ProxyPoolException):
    pass


class DataValidationException(RepositoryException):
    pass


class DatabaseConnectionException(RepositoryException):
    pass


class InvalidParameterException(ProxyPoolException, ValueError):
    def __init__(self, key: str, *args: Any):
        self.message_key = key
        self.message_args = args
        super().__init__(f"{key} {args}" if args else key)


class QueryBuildException(RepositoryException):
    pass


class DependencyInjectionException(ProxyPoolException):
    pass


class DependencyNotRegisteredError(DependencyInjectionException):
    pass


class PluginException(ProxyPoolException):
    pass


class PluginExecutionException(PluginException):
    pass


class ProxyValidationException(ProxyPoolException):
    pass


class HttpClientException(ProxyPoolException):
    def __init__(self, message: str = "", reason: str = "unknown"):
        super().__init__(message)
        self.reason = reason


class HttpRequestException(HttpClientException):
    pass


class HttpTimeoutException(HttpClientException):
    pass


class WriteQueueException(ProxyPoolException):
    pass


class WriteQueueFullException(WriteQueueException):
    pass


class ApplicationException(ProxyPoolException):
    pass
