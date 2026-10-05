"""
模块名称：modules.proxypool.core.application
功能描述：代理池应用层的包标记，不含代码；装配入口 Application 定义在子模块
          core.application.app 中。
职责边界：负责：作为应用层包的标记存在；不负责：任何再导出与初始化逻辑。
关键依赖：无。
已知限制：导入本包不会连带加载 core.application.app，也不触发任何装配流程。
"""
