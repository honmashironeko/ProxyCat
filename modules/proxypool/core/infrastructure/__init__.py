"""
模块名称：modules.proxypool.core.infrastructure
功能描述：基础设施层的包入口：连接池、去重缓存、配置管理器、依赖注入容器、归属地库、HTTP 客户端等实现分别定义在各自子模块；本文件不含代码，仅作包标记。
职责边界：负责：作为 core.infrastructure 包的标记存在；不负责：任何再导出，使用方按子模块路径导入
          （如 core.infrastructure.http_client 的 AioHttpClient）。
关键依赖：无。
已知限制：无。
"""
