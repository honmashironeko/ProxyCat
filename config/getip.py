"""
模块名称：config.getip
功能描述：按 config.ini 的 api_proxy_url 请求一次，每次调用重新读配置；把响应每一行当作代理地址，清洗去重后补全协议与凭证，返回可直接使用的代理 URL 列表，不做缓存。
职责边界：负责：读取接口地址与凭证、发起请求、逐行清洗去重、协议推断与凭证拼接、把失败统一翻译成 RuntimeError（响应无可用地址时原样抛 ProxyResponseError）。
          不负责：代理可用性验证与轮换（modules.proxyserver）、配置读写与校验（modules.modules）、失败日志落盘（由调用方记录）。
关键依赖：requests；modules.modules（load_config、get_message、parse_proxy_url、format_proxy_url）；tqdm（可选）。
已知限制：
  1. 请求超时固定 15 秒，不可通过调用参数调整。
  2. 凭证仅在用户名与密码同时非空时注入，缺一则保留地址行自带的认证。
  3. 统一抛 RuntimeError；ProxyResponseError（空响应、清洗后无地址）为无前缀中文消息，其余形如「类型: 详情」（request/config/unknown）。
  4. api_proxy_url 为空或响应首行为 error000x-13 时按 config 类错误抛出；配置文件缺失时回落默认值（请求 example.com），不算 config 错误。
  5. 畸形行会被跳过并记一条 warning，不会让整批失败；未写协议的行按 http 补全。
  6. 单次返回条数受 _MAX_BATCH=500 封顶，limit 只在该上限内进一步裁剪（传 0 返回空列表）。
"""

import os
from modules.modules import format_proxy_url, get_message, load_config, parse_proxy_url
import requests
import logging

_GETIP_DIR = os.path.dirname(os.path.abspath(__file__))
_BASE_DIR = os.path.dirname(_GETIP_DIR)

_MAX_BATCH = 500

_ERROR_CODE_SENTINEL = "error000x-13"


def _console_write(message: str) -> None:
    try:
        from tqdm import tqdm
        tqdm.write(message)
    except Exception:
        print(message)


class ProxyResponseError(RuntimeError):
    pass

def _clean_line(raw_line, username, password):
    text = raw_line.strip()
    if not text:
        return None
    if '://' not in text:
        text = f"http://{text}"

    try:
        protocol, auth, host, port = parse_proxy_url(text)
    except ValueError:
        return None
    if not protocol or not host:
        return None

    if username and password:
        auth = f"{username}:{password}"
    return format_proxy_url(protocol, host, port, auth)


def newip_list(limit=None):
    config = load_config(os.path.join(_BASE_DIR, 'config', 'config.ini'))
    language = config.get('language', 'cn')

    def handle_error(error_type, details=None):
        error_msg = {
            'request': 'proxy_get_error',
            'config': 'proxy_config_error',
            'unknown': 'proxy_get_error',
        }.get(error_type, 'proxy_file_not_found')
        _console_write(get_message(error_msg, language, str(details)))
        raise RuntimeError(f"{error_type}: {details}")

    try:
        url = config.get('api_proxy_url', '')
        username = config.get('proxy_username', '')
        password = config.get('proxy_password', '')

        if not url:
            raise ValueError('api_proxy_url')

        def fetch_body():
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            return response.text

        lines = fetch_body().replace('\r\n', '\n').replace('\r', '\n').split('\n')
        entries = [line.strip() for line in lines if line.strip()]

        if not entries:
            raise ProxyResponseError("接口返回内容为空，没有可用的代理地址")

        if entries[0] == _ERROR_CODE_SENTINEL:
            raise ValueError(get_message('getip_api_error_code', language))

        proxies = []
        seen = set()
        for entry in entries:
            proxy = _clean_line(entry, username, password)
            if proxy is None:
                logging.warning(f"跳过形态非法的代理地址: {entry[:100]}")
                continue
            if proxy in seen:
                continue
            seen.add(proxy)
            proxies.append(proxy)

        if not proxies:
            raise ProxyResponseError(f"接口返回的 {len(entries)} 行里没有一个可用的代理地址")

        cap = _MAX_BATCH if limit is None else max(0, min(int(limit), _MAX_BATCH))
        return proxies[:cap]

    except requests.RequestException as e:
        handle_error('request', e)
    except ValueError as e:
        handle_error('config', e)
    except ProxyResponseError:
        raise
    except Exception as e:
        handle_error('unknown', e)


def newip():
    return newip_list(1)[0]
