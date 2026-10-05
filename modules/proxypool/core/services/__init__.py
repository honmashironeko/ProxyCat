"""
模块名称：modules.proxypool.core.services
功能描述：服务层所在包的入口，本文件仅为包标记，不含任何代码；各服务类定义在自己的子模块里。
职责边界：负责：标记 core.services 包；不负责：服务实现与再导出，服务类（GeoIP、验证器、插件管理器、重验证、归属地解析等）定义在对应子模块。
关键依赖：无。
已知限制：
1. 从 core.services 直接导入服务类会失败，须从具体子模块导入，例如 core.services.validator 里的 ProxyValidator。
"""
