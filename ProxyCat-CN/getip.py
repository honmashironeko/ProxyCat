import requests
from typing import List


def newip() -> List[str]:
    """
    自定义获取新的代理IP池

    :return: 返回代理IP池列表，形如：['http://127.0.0.1:10809', 'socks5://127.0.0.1:10808']
    """
    print("正在获取新的代理IP")

    proxy = ['http://127.0.0.1:10809', 'socks5://127.0.0.1:10808', 'http://127.0.0.1:1089', 'socks5://127.0.0.1:1088']

    return proxy
