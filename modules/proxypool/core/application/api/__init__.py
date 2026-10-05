"""
模块名称：modules.proxypool.core.application.api
功能描述：代理池 HTTP 适配层的包标记，不含代码；依赖装配见 dependencies，响应与
          异常类型见 http_types，各资源的路由函数见 routes。
职责边界：负责：作为适配层各子模块的包入口；不负责：路由注册与请求解析（由
          modules.proxypool_api 承担）以及业务逻辑（见 routes 下的各功能域）。
关键依赖：无。
已知限制：导入本包不会连带加载 dependencies、http_types 或 routes。
"""
