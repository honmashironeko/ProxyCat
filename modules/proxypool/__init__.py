"""
模块名称：modules.proxypool
功能描述：代理池子项目的包入口，导入时把池根目录插入 sys.path 首位，使子项目内部
          不带上层包名的绝对导入（from core.xxx import ...）能够解析。
职责边界：负责：模块搜索路径的注入；不负责：子项目内部的一切业务逻辑（见 core.*）。
关键依赖：标准库 os、sys。
已知限制：
  1. POOL_DIR 依赖本文件固定位于池根包目录这一层级。
  2. 注入使 core 等成为进程级顶层包名，进程内若已有同名包会发生冲突。
  3. 路径插在 sys.path 首位，池内同名模块优先于仓库根下的模块被导入。
"""

import os
import sys

POOL_DIR = os.path.dirname(os.path.abspath(__file__))

if POOL_DIR not in sys.path:
    sys.path.insert(0, POOL_DIR)

__all__ = ["POOL_DIR"]
