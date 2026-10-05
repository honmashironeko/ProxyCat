"""
模块名称：modules.proxypool.core.interfaces
功能描述：代理池抽象接口（端口）所在包的入口，本文件仅为包标记，不含任何代码。
职责边界：负责：标记 core.interfaces 包；不负责：接口声明与再导出，接口按基础设施、仓储、服务三册声明在对应子模块。
关键依赖：无。
已知限制：
1. 从 core.interfaces 直接导入接口会失败，须按册从子模块导入，例如 core.interfaces.repository 里的 IProxyRepository。
"""
