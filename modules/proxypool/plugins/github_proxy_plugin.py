"""
模块名称：modules.proxypool.plugins.github_proxy_plugin
功能描述：对 SOURCES 中硬编码的 GitHub 代理清单源并发抓取纯文本清单，逐行解析为代理 URL，按 ip:port 在批次内去重后返回；单源失败只记日志，不影响其余源。
职责边界：负责：各源的并发抓取、文本行到代理 URL 的解析、批次内去重；不负责：代理可用性验证与入库
          （见 application.ingest）、抓取间隔与测试地址（由 PluginManager 的插件配置控制）、网络会话与超时（由
          PluginContext 注入的 http_client 承担）。
关键依赖：core.interfaces.services（IProxyPlugin、PluginContext）、core.domain.models.Proxy；
          core.domain.exceptions（PluginExecutionException）。
已知限制：
  1. 源清单硬编码在 SOURCES：12 个源（6 个 http、5 个 socks5、1 个 https），增删源必须改代码。
  2. 单源失败只记日志并跳过，非 200 也按失败抛出；返回非空只代表至少一个源有产出，全部源失败才抛 PluginExecutionException。
  3. 空行与 # 开头行跳过，行内无 :// 时补该源默认协议，单行解析失败只记 debug 并丢弃。
  4. 去重只覆盖本批次（按 Proxy.from_url 解析出的 ip:port），跨批次与池内重复由 PluginManager 处理。
  5. 只解析每行一个 ip:port 或完整 URL；带多余列的行解析失败被丢弃，清单格式变化只会让产出静默减少。
  6. 调度键、配置键与入库来源取文件名 stem（github_proxy_plugin）；文件内 source_plugin 字面量不决定入库来源，name/version 无调用方读取。
"""

import asyncio
from typing import List, Tuple

from core.interfaces.services import IProxyPlugin, PluginContext
from core.domain.exceptions import PluginExecutionException
from core.domain.models import Proxy


class GitHubProxyPlugin(IProxyPlugin):

    SOURCES: List[Tuple[str, str]] = [
        (
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "http",
        ),
        (
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
            "socks5",
        ),
        (
            "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
            "http",
        ),
        (
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
            "http",
        ),
        (
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
            "socks5",
        ),
        (
            "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
            "socks5",
        ),
        (
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
            "http",
        ),
        (
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
            "socks5",
        ),
        (
            "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
            "http",
        ),
        (
            "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
            "socks5",
        ),
        (
            "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
            "https",
        ),
        (
            "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt",
            "http",
        ),
    ]

    @property
    def name(self) -> str:
        return "github_proxy"

    @property
    def version(self) -> str:
        return "2.0.0"

    async def fetch_proxies(self, context: PluginContext) -> List[str]:
        logger = context.logger
        logger.info(f"正在从 {len(self.SOURCES)} 个 GitHub 代理源并发抓取...")

        tasks = [
            self._fetch_single_source(context, url, default_protocol)
            for url, default_protocol in self.SOURCES
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        seen_hosts: set = set()
        proxy_list: List[str] = []
        failed_sources = []

        for idx, result in enumerate(results):
            source_url = self.SOURCES[idx][0]

            if isinstance(result, Exception):
                logger.error(f"源 {source_url} 抓取失败: {result}")
                failed_sources.append(source_url)
                continue

            if not isinstance(result, list):
                logger.warning(f"源 {source_url} 返回非列表类型: {type(result)}")
                continue

            source_count = 0
            for proxy_url in result:
                try:
                    proxy_obj = Proxy.from_url(proxy_url, source_plugin="github_proxy")
                    host_key = f"{proxy_obj.ip}:{proxy_obj.port}"
                    if host_key not in seen_hosts:
                        seen_hosts.add(host_key)
                        proxy_list.append(proxy_url)
                        source_count += 1
                except ValueError:
                    continue

            logger.debug(f"源 {source_url} 贡献 {source_count} 个新代理")

        if failed_sources and len(failed_sources) == len(self.SOURCES):
            raise PluginExecutionException(
                f"GitHub 代理插件全部 {len(self.SOURCES)} 个源都抓取失败"
            )

        logger.info(f"GitHub 代理插件共获取 {len(proxy_list)} 个去重代理")
        return proxy_list

    async def _fetch_single_source(
        self,
        context: PluginContext,
        url: str,
        default_protocol: str,
    ) -> List[str]:
        logger = context.logger
        proxies: List[str] = []

        try:
            response = await context.http_client.get(url)

            if response.status != 200:
                raise PluginExecutionException(
                    f"请求源 {url} 失败，HTTP 状态码: {response.status}"
                )

            lines = response.text.strip().split("\n")

            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                if "://" not in line:
                    line = f"{default_protocol}://{line}"

                try:
                    proxy_obj = Proxy.from_url(line, source_plugin="github_proxy")
                    proxies.append(proxy_obj.proxy_url)
                except ValueError as e:
                    logger.debug(f"解析代理行失败 '{line}': {e}")
                    continue

            logger.info(f"从 {url} 获取了 {len(proxies)} 个代理")

        except Exception as e:
            logger.warning(f"抓取源 {url} 发生异常: {e}")
            raise

        return proxies
