"""
模块名称：modules.proxypool.core.infrastructure.geodb
功能描述：离线归属地库的读取与更新：GeoLite2 提供国家/行政区的 ISO 代码与多语言名字，纯真库在国家判为中国时补齐缺失的中文名，查询结果统一为 GeoRecord。
职责边界：负责：加载两个库、规范化查询结果为 GeoRecord、下载更新数据文件；不负责：选词翻译（geo_names）、按 IP 缓存（geoip 服务）、写库（geo_resolver）。
关键依赖：maxminddb、ipdb、requests；内部依赖 core.paths.resolve_pool_path 与 core.domain.models.GeoRecord。
已知限制：
1. 两个数据文件任一缺失或打不开即整体不可用，查询一律返回 None，不做「缺谁用谁」的部分降级，也没有在线兜底。
2. 国家结论只由 GeoLite2 决定；纯真库仅在国家为中国、且 GeoLite2 缺对应 zh-CN 名字时才补，region_name 原样作为中文省名。
3. .mmdb 打开先试 C 扩展再降级纯 Python 版：C 扩展在非 ASCII 路径下打不开（默认路径含中文），纯 Python 版 get() 不接受默认值参数。
4. 查询是同步的内存映射调用；close() 只关 mmdb，ipdb 无 close、丢引用即释放占用，关库窗口内的并发查询表现为「查不到」。
5. Windows 上被内存映射占用的文件无法 os.replace，故 update_databases() 把关库窗口压到两次换入之间，下载期间不关库。
6. 数据文件不入库，由 update_databases() 从带 @latest 的 CDN 地址拉取；下载低于体积下限即判失败，原文件保持不动。
"""

import gzip
import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import Optional

from core.domain.models import GeoRecord

logger = logging.getLogger(__name__)

GEOLITE2_FILENAME = "GeoLite2-City.mmdb"
QQWRY_FILENAME = "qqwry.ipdb"

GEODB_SUBDIR = "data/geodb"

_GEOLITE2_URL = (
    "https://cdn.jsdelivr.net/npm/geolite2-city@latest/GeoLite2-City.mmdb.gz"
)
_QQWRY_URL = "https://cdn.jsdelivr.net/npm/qqwry.ipdb@latest/qqwry.ipdb"

_DOWNLOAD_TIMEOUT = 600

_MIN_PLAUSIBLE_SIZE = 1024 * 1024

LANG_ZH = "zh-CN"
LANG_EN = "en"

SOURCE_GEOLITE2 = "geolite2"
SOURCE_GEOLITE2_QQWRY = "geolite2+qqwry"


def default_data_dir() -> Path:
    from core.paths import resolve_pool_path

    return resolve_pool_path(GEODB_SUBDIR)


class GeoDatabase:
    def __init__(self, data_dir: Optional[Path] = None):
        self._data_dir = Path(data_dir) if data_dir else default_data_dir()
        self._geolite2 = None
        self._qqwry = None
        self._load()

    def _load(self) -> None:
        mmdb_path = self._data_dir / GEOLITE2_FILENAME
        ipdb_path = self._data_dir / QQWRY_FILENAME

        missing = [p.name for p in (mmdb_path, ipdb_path) if not p.is_file()]
        if missing:
            logger.info(
                "离线归属地库不可用（缺少 %s），归属地查询将一律返回未知；"
                "可用 update_databases() 或面板的更新入口拉取",
                "、".join(missing),
            )
            return

        self._geolite2 = self._open_mmdb(mmdb_path)
        if self._geolite2 is None:
            return

        try:
            import ipdb

            self._qqwry = ipdb.City(str(ipdb_path))
        except Exception as e:
            logger.warning(f"打开纯真库失败，离线归属地整体不可用: {e}")
            self._close_geolite2()
            return

    @staticmethod
    def _open_mmdb(mmdb_path: Path):
        try:
            import maxminddb
        except ImportError as e:
            logger.warning(f"未安装 maxminddb，离线归属地不可用: {e}")
            return None

        try:
            return maxminddb.open_database(str(mmdb_path))
        except Exception as e:
            logger.info(f"C 扩展打开 GeoLite2 失败（{type(e).__name__}），改用纯 Python 读取器")

        try:
            return maxminddb.open_database(str(mmdb_path), maxminddb.MODE_MMAP)
        except Exception as e:
            logger.warning(f"打开 GeoLite2 失败，离线归属地整体不可用: {e}")
            return None

    @property
    def available(self) -> bool:
        return self._geolite2 is not None and self._qqwry is not None

    def lookup(self, ip: str) -> Optional[GeoRecord]:
        if not self.available:
            return None

        base = self._lookup_geolite2(ip)
        if base is None:
            return None
        if not base.is_china or self._qqwry is None:
            return base
        return self._overlay_qqwry(ip, base)

    def _lookup_geolite2(self, ip: str) -> Optional[GeoRecord]:
        try:
            data = self._geolite2.get(ip)
        except Exception as e:
            logger.debug(f"GeoLite2 查询异常 {ip}: {e}")
            return None
        if not data:
            return None

        country = data.get("country") or {}
        country_code = country.get("iso_code") or ""
        if not country_code:
            return None

        subdivision = (data.get("subdivisions") or [{}])[0]
        city = data.get("city") or {}

        return GeoRecord(
            country_code=country_code,
            subdivision_code=subdivision.get("iso_code") or "",
            country_names=dict(country.get("names") or {}),
            subdivision_names=dict(subdivision.get("names") or {}),
            city_names=dict(city.get("names") or {}),
            source=SOURCE_GEOLITE2,
        )

    def _overlay_qqwry(self, ip: str, base: GeoRecord) -> GeoRecord:
        try:
            info = self._qqwry.find_map(ip, "CN") or {}
        except Exception as e:
            logger.debug(f"纯真库查询异常 {ip}: {e}")
            return base

        region = str(info.get("region_name") or "").strip()
        city = str(info.get("city_name") or "").strip()
        if not region and not city:
            return base

        country_names = dict(base.country_names)
        country_names.setdefault(LANG_ZH, str(info.get("country_name") or "中国"))

        subdivision_names = dict(base.subdivision_names)
        if region and LANG_ZH not in subdivision_names:
            subdivision_names[LANG_ZH] = region

        city_names = dict(base.city_names)
        if city and LANG_ZH not in city_names:
            city_names[LANG_ZH] = city

        return GeoRecord(
            country_code=base.country_code,
            subdivision_code=base.subdivision_code,
            country_names=country_names,
            subdivision_names=subdivision_names,
            city_names=city_names,
            source=SOURCE_GEOLITE2_QQWRY,
        )

    def _close_geolite2(self) -> None:
        if self._geolite2 is None:
            return
        try:
            self._geolite2.close()
        except Exception:
            pass
        self._geolite2 = None

    def close(self) -> None:
        self._close_geolite2()
        self._qqwry = None

    def reload(self) -> None:
        self.close()
        self._load()


def _download(url: str, dest: Path, *, progress=None) -> None:
    import requests

    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(dir=str(dest.parent), prefix=".geo-", suffix=".tmp")
    downloaded = 0
    try:
        with os.fdopen(fd, "wb") as handle:
            with requests.get(url, stream=True, timeout=_DOWNLOAD_TIMEOUT) as response:
                if response.status_code != 200:
                    raise RuntimeError(f"HTTP {response.status_code}")
                total = int(response.headers.get("Content-Length") or 0)
                for chunk in response.iter_content(chunk_size=1 << 16):
                    if not chunk:
                        continue
                    handle.write(chunk)
                    downloaded += len(chunk)
                    if progress is not None:
                        progress(downloaded, total)
            handle.flush()
            os.fsync(handle.fileno())

        if downloaded < _MIN_PLAUSIBLE_SIZE:
            raise RuntimeError(f"下载体积异常（{downloaded} 字节），疑为中途断开")

        os.replace(temp_path, str(dest))
    except BaseException:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise


def _decompress_gz(gz_path: Path, dest: Path) -> None:
    fd, temp_path = tempfile.mkstemp(dir=str(dest.parent), prefix=".geo-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            with gzip.open(str(gz_path), "rb") as source:
                shutil.copyfileobj(source, handle, length=1 << 20)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, str(dest))
    except BaseException:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise


def describe_databases(data_dir: Optional[Path] = None) -> list:
    import datetime

    target = Path(data_dir) if data_dir else default_data_dir()
    entries = []
    for filename in (GEOLITE2_FILENAME, QQWRY_FILENAME):
        path = target / filename
        try:
            stat = path.stat()
            entries.append({
                "filename": filename,
                "exists": True,
                "size": stat.st_size,
                "modified_at": datetime.datetime.fromtimestamp(stat.st_mtime)
                .strftime("%Y-%m-%d %H:%M:%S"),
            })
        except OSError:
            entries.append({
                "filename": filename,
                "exists": False,
                "size": 0,
                "modified_at": None,
            })
    return entries


def update_databases(data_dir: Optional[Path] = None, *, progress=None,
                     live: Optional["GeoDatabase"] = None) -> dict:
    target = Path(data_dir) if data_dir else default_data_dir()
    target.mkdir(parents=True, exist_ok=True)
    results: dict = {}

    def _cb(name):
        if progress is None:
            return None
        return lambda done, total: progress(name, done, total)

    def _stage(filename, fetch) -> None:
        fd, temp_path = tempfile.mkstemp(dir=str(target), prefix=".geo-", suffix=".tmp")
        os.close(fd)
        try:
            fetch(Path(temp_path))
        except Exception as e:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
            results[filename] = f"失败: {e}"
            logger.warning(f"更新 {filename} 失败: {e}")
            return
        staged.append((Path(temp_path), target / filename, filename))

    def _fetch_geolite2(dest: Path) -> None:
        gz_path = target / (GEOLITE2_FILENAME + ".gz")
        try:
            _download(_GEOLITE2_URL, gz_path, progress=_cb(GEOLITE2_FILENAME))
            _decompress_gz(gz_path, dest)
        finally:
            try:
                gz_path.unlink()
            except OSError:
                pass

    staged: list = []
    _stage(GEOLITE2_FILENAME, _fetch_geolite2)
    _stage(QQWRY_FILENAME,
           lambda dest: _download(_QQWRY_URL, dest, progress=_cb(QQWRY_FILENAME)))

    if not staged:
        return results

    if live is not None:
        live.close()
    try:
        for temp_path, final_path, filename in staged:
            try:
                os.replace(str(temp_path), str(final_path))
                results[filename] = "已更新"
            except OSError as e:
                results[filename] = f"失败: {e}"
                logger.warning(f"换入 {filename} 失败: {e}")
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass
    finally:
        if live is not None:
            live.reload()

    return results


def main(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="拉取/更新离线归属地库")
    parser.add_argument("--dir", default=None, help="数据目录（默认子项目 data/geodb）")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    target = Path(args.dir) if args.dir else default_data_dir()

    last = {}

    def report(name, done, total):
        pct = int(done * 100 / total) if total else 0
        if last.get(name) != pct and pct % 10 == 0:
            last[name] = pct
            print(f"  {name}: {pct}% ({done / 1048576:.1f} MB)", flush=True)

    print(f"更新目录: {target}")
    results = update_databases(target, progress=report)
    print()
    failed = False
    for name, outcome in results.items():
        print(f"  {name:<24}{outcome}")
        failed = failed or outcome.startswith("失败")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
