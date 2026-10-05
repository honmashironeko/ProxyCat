"""
模块名称：modules.proxypool.core.paths
功能描述：代理池子项目的路径锚点：定位池根目录 modules/proxypool，并把池内相对路径解析为绝对路径。
职责边界：负责：池根目录定位与相对路径拼接；不负责：校验路径是否存在、按需创建目录，由调用方自行处理。
关键依赖：标准库 pathlib。
已知限制：
1. POOL_BASE_DIR 依赖本文件固定位于池根/core/paths.py 这一层级。
2. resolve_pool_path 对绝对路径原样返回，不做规范化与存在性检查。
3. 池内代码直接使用相对路径会以进程工作目录为基准，须经 resolve_pool_path 锚定到池根。
"""

from pathlib import Path

POOL_BASE_DIR: Path = Path(__file__).resolve().parents[1]


def resolve_pool_path(path: str | Path) -> Path:
    candidate = Path(path)
    if candidate.is_absolute():
        return candidate
    return POOL_BASE_DIR / candidate
