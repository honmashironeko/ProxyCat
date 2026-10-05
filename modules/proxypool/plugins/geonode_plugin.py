"""
模块名称：modules.proxypool.plugins.geonode_plugin
功能描述：经 GeoNode 公开 REST API 分页抓取代理：逐页请求 JSON，把记录的 ip / port / protocols 转为代理 URL，批次内去重后交插件管理器验证入库。
职责边界：负责：分页遍历、单页响应解析、协议挑选、记录合法性校验、批次内去重；不负责：与池内
          已有代理的去重（PluginManager.deduplicate_proxies）、验证与入库（application.ingest）、
          HTTP 客户端构造与超时（由 context.http_client 承担）。
关键依赖：core.interfaces.services（IProxyPlugin / PluginContext）、core.domain.models
          （Proxy、SUPPORTED_PROTOCOLS）、core.domain.exceptions（PluginExecutionException）；
          请求经 context 注入的 http_client 发出，数据源自 GeoNode 公开 REST API。
已知限制：1. 页数上限 _MAX_PAGES=20、每页 500 条，最多约 1 万条原始记录即停止，不保证抓全整个列表。
2. 单页请求异常、非 200、JSON 解析失败或缺 data 数组均按「本页无数据」返回 None 并终止分页，不重试；空列表同样是终止信号。
3. 首页失败向上抛 PluginExecutionException，整次抓取按失败上报，调度器据此退避重试；后续页失败保留已取得部分并记 warning。
4. 协议仅在 http / https / socks5 中按 _PROTOCOL_PRIORITY（socks5 > https > http）取最高优先级，全不匹配时按 http 兜底。
5. ip / port 为空、port 非整数或越界、URL 通不过 Proxy.from_url 的记录按单条丢弃，基本无日志（仅部分记 debug）。
6. ip / port 非字符串（含 null）、protocols 为 null 或含非字符串、条目非对象时，异常不受单条防护、冒泡到页级 except，整页作废。
7. 去重只覆盖本批次；跨批次与池内重复由 PluginManager.deduplicate_proxies 处理；注册键取文件名 stem geonode_plugin，而非 name。
"""

import json
from typing import List, Optional

from core.interfaces.services import IProxyPlugin, PluginContext
from core.domain.exceptions import PluginExecutionException
from core.domain.models import SUPPORTED_PROTOCOLS, Proxy


class GeoNodePlugin(IProxyPlugin):

    _API_TEMPLATE = (
        "https://proxylist.geonode.com/api/proxy-list"
        "?limit=500&page={page}&sort_by=lastChecked&sort_type=desc"
    )

    _MAX_PAGES = 20

    _PROTOCOL_PRIORITY = {"socks5": 0, "https": 1, "http": 2}

    @property
    def name(self) -> str:
        return "geonode"

    @property
    def version(self) -> str:
        return "2.0.0"

    async def fetch_proxies(self, context: PluginContext) -> List[str]:
        logger = context.logger
        logger.info("正在从 GeoNode API 分页抓取代理...")

        seen_hosts: set = set()
        proxy_list: List[str] = []

        for page in range(1, self._MAX_PAGES + 1):
            page_proxies = await self._fetch_page(context, page)

            if page_proxies is None:
                if page == 1:
                    raise PluginExecutionException(
                        "GeoNode 首页抓取失败，本次未取得任何代理"
                    )
                logger.warning(
                    f"GeoNode 第 {page} 页抓取失败，本次提前结束，"
                    f"已取得 {len(proxy_list)} 个代理"
                )
                break

            if len(page_proxies) == 0:
                logger.info(f"GeoNode 第 {page} 页返回空列表，终止分页")
                break

            page_new_count = 0
            for proxy_url in page_proxies:
                try:
                    proxy_obj = Proxy.from_url(proxy_url, source_plugin="geonode")
                    host_key = f"{proxy_obj.ip}:{proxy_obj.port}"
                    if host_key not in seen_hosts:
                        seen_hosts.add(host_key)
                        proxy_list.append(proxy_url)
                        page_new_count += 1
                except ValueError:
                    continue

            logger.debug(f"GeoNode 第 {page} 页贡献 {page_new_count} 个新代理")

        logger.info(f"GeoNode 插件共获取 {len(proxy_list)} 个去重代理")
        return proxy_list

    async def _fetch_page(
        self, context: PluginContext, page: int
    ) -> Optional[List[str]]:
        logger = context.logger
        url = self._API_TEMPLATE.format(page=page)

        try:
            response = await context.http_client.get(url)

            if response.status != 200:
                logger.warning(f"GeoNode 第 {page} 页返回 HTTP {response.status}")
                return None

            try:
                payload = json.loads(response.text)
            except json.JSONDecodeError as e:
                logger.error(f"GeoNode 第 {page} 页 JSON 解析失败: {e}")
                return None

            data_list = payload.get("data")
            if not isinstance(data_list, list):
                logger.warning(f"GeoNode 第 {page} 页响应中缺少 data 数组")
                return None

            proxies: List[str] = []
            for item in data_list:
                proxy_url = self._parse_item(item, logger)
                if proxy_url:
                    proxies.append(proxy_url)

            logger.info(f"GeoNode 第 {page} 页解析出 {len(proxies)} 个代理")
            return proxies

        except Exception as e:
            logger.error(f"请求 GeoNode 第 {page} 页异常: {e}", exc_info=True)
            return None

    def _parse_item(self, item: dict, logger) -> Optional[str]:
        ip = item.get("ip", "").strip()
        port_str = item.get("port", "").strip()
        protocols_raw = item.get("protocols", [])

        if not ip or not port_str:
            return None

        try:
            port = int(port_str)
        except (ValueError, TypeError):
            logger.debug(f"GeoNode 数据中端口非法: ip={ip}, port={port_str}")
            return None

        if not (1 <= port <= 65535):
            return None

        supported_protocols = set(SUPPORTED_PROTOCOLS)
        valid_protocols = [
            p.lower() for p in protocols_raw if p.lower() in supported_protocols
        ]

        if not valid_protocols:
            valid_protocols = ["http"]

        valid_protocols.sort(key=lambda p: self._PROTOCOL_PRIORITY.get(p, 99))
        protocol = valid_protocols[0]

        raw_url = f"{protocol}://{ip}:{port}"

        try:
            proxy_obj = Proxy.from_url(raw_url, source_plugin="geonode")
            return proxy_obj.proxy_url
        except ValueError as e:
            logger.debug(f"GeoNode 代理格式校验失败: {raw_url}, 原因: {e}")
            return None
