"""
模块名称：modules.proxypool.core.application.api.routes
功能描述：代理池业务操作层的功能域包：database、geo、proxies、plugins、validation 子模块按功能域实现业务逻辑；本文件不含代码，仅作包标记。
职责边界：负责：作为 routes 包的标记存在，不聚合也不转发子模块的处理函数。
          不负责：HTTP 路由注册与请求解析（见 modules.proxypool_api）、服务实例的装配与解析
          （见 core.application.api.dependencies）。
关键依赖：无。
已知限制：
  1. 子模块不依赖 Web 框架：返回值是普通 JSON 数据（字典/列表）或 http_types.RawResponse（原始文本/附件）。
  2. 参数错误抛 InvalidParameterException（ValueError 子类）或 http_types.ApiError(400)，两者均由适配层转换为 HTTP 响应。
  3. 新增功能域须在 modules/proxypool_api.py 中导入并注册 URL 才能访问；服务访问器由 core.application.api.dependencies 提供。
"""
