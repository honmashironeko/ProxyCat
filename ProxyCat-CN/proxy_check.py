import httpx
import socket
import re
import asyncio
import logging

async def check_proxy(proxy):
    proxy_type = proxy.split('://')[0]
    check_funcs = {
        'http': check_http_proxy,
        'https': check_https_proxy,
        'socks5': check_socks_proxy
    }
    
    if proxy_type not in check_funcs:
        return False
    
    try:
        return await check_funcs[proxy_type](proxy)
    except Exception as e:
        logging.error(f"{proxy_type.upper()}代理 {proxy} 检测失败: {e}")
        return False

async def check_http_proxy(proxy):
    async with httpx.AsyncClient(proxies={'http://': proxy}, timeout=10) as client:
        response = await client.get('http://www.baidu.com')
        return response.status_code == 200

async def check_https_proxy(proxy):
    async with httpx.AsyncClient(proxies={'https://': proxy}, timeout=10) as client:
        response = await client.get('https://www.baidu.com')
        return response.status_code == 200

async def check_socks_proxy(proxy):
    proxy_type, proxy_addr = proxy.split('://')
    proxy_host, proxy_port = proxy_addr.split(':')
    proxy_port = int(proxy_port)
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(proxy_host, proxy_port), timeout=5)
        writer.write(b'\x05\x01\x00')
        await writer.drain()
        response = await asyncio.wait_for(reader.readexactly(2), timeout=5)
        writer.close()
        await writer.wait_closed()
        return response == b'\x05\x00'
    except Exception:
        return False

async def check_proxies(proxies):
    valid_proxies = []
    for proxy in proxies:
        if await check_proxy(proxy):
            valid_proxies.append(proxy)
    return valid_proxies
