"""
模块名称：modules.proxypool.core.application.api.http_types
功能描述：路由层与 Web 适配层之间的响应契约：路由函数返回普通字典（转 JSON）或
          RawResponse（按原样输出，filename 非空时作为附件下载），出错抛 ApiError，
          由适配层统一翻译成 HTTP 响应；json_download 用于生成 JSON 附件下载响应。
职责边界：负责：定义上述返回与异常类型；不负责：把 ApiError 翻译成 HTTP 响应（见
          modules.proxypool_api）；除 json_download 外，正文序列化由调用方完成。
关键依赖：仅标准库 json、dataclasses、typing。
已知限制：
  1. RawResponse.content 必须是已序列化好的文本，适配层按原样写出。
  2. RawResponse.filename 非空时才作为附件下载，空字符串不会触发下载响应头。
  3. ApiError 只携带状态码与文案，适配层固定以 error_code=api_error 返回。
  4. RawResponse.mimetype 默认 text/plain，返回 JSON 正文时需显式指定。
"""

import json
from dataclasses import dataclass
from typing import Optional


class ApiError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
        super().__init__(message)


@dataclass
class RawResponse:
    content: str
    mimetype: str = "text/plain"
    filename: Optional[str] = None


def json_download(data, filename: str) -> RawResponse:
    return RawResponse(
        content=json.dumps(data, ensure_ascii=False, indent=2),
        mimetype="application/json",
        filename=filename,
    )


__all__ = ["ApiError", "RawResponse", "json_download"]
