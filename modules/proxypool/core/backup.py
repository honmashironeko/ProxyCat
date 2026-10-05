"""
模块名称：modules.proxypool.core.backup
功能描述：SQLite 数据库的定时备份、过期备份清理与从备份文件恢复；备份文件位于池根目录 data/backups/ 下，按保留天数自动淘汰。
职责边界：负责：按间隔创建一致性备份、清理超期备份、列出备份、从备份文件恢复数据库；不负责：数据库连接管理、备份间隔与保留天数的来源（见 core.config）。
关键依赖：核心模块 core.paths.resolve_pool_path、第三方 aiosqlite；标准库 asyncio、sqlite3、shutil、os。
已知限制：
  1. apply_config 只改内存中的间隔与保留天数，下一次循环复查时生效，不会立刻补做备份；stop() 不回滚已开始的单次备份。
  2. restore 只返回布尔值，失败原因与分类码通过 last_restore_error、last_restore_error_code 读取。
  3. 换库前必须删净原库的 -wal 与 -shm 边车，主路径删不掉则以 wal_locked 放弃恢复；回滚路径为尽力而为，不因边车删除失败中止：旧 WAL 帧会污染新库。
  4. restore_backup_file 只接受备份目录下的纯文件名，含路径分隔符的名称被拒绝。
  5. _is_backup_due 在无备份文件或目录读取失败时返回 True（宁可多备份），循环异常后等待 300 秒重试。
  6. db_path 与 backup_dir 按池根目录解析；备份目录在构造时创建，创建失败抛 OSError。
"""

import asyncio
import logging
import shutil
import time
from datetime import datetime, timedelta
import os
from pathlib import Path
from typing import Optional

from core.paths import resolve_pool_path

logger = logging.getLogger(__name__)

_DUE_CHECK_INTERVAL = 60.0


class DatabaseBackup:
    def __init__(
        self,
        db_path: str,
        backup_dir: str = "data/backups",
        backup_interval_hours: int = 24,
        retention_days: int = 7
    ):
        self._db_path = resolve_pool_path(db_path)
        self._backup_dir = resolve_pool_path(backup_dir)
        self._backup_interval_hours = backup_interval_hours
        self._retention_days = retention_days
        self._backup_task: Optional[asyncio.Task] = None
        self._running = False
        self._last_restore_error: Optional[str] = None
        self._last_restore_error_code: str = ""

        self._backup_dir.mkdir(parents=True, exist_ok=True)

        logger.info(
            f"数据库备份管理器已初始化: db={db_path}, "
            f"backup_dir={backup_dir}, interval={backup_interval_hours}h, "
            f"retention={retention_days}d"
        )

    async def start(self) -> None:
        if self._running:
            logger.warning("数据库备份任务已经在运行")
            return

        self._running = True
        self._backup_task = asyncio.create_task(self._auto_backup_loop())
        logger.info("数据库自动备份任务已启动")

    async def stop(self) -> None:
        if not self._running:
            return

        self._running = False

        if self._backup_task:
            self._backup_task.cancel()
            try:
                await self._backup_task
            except asyncio.CancelledError:
                pass

        logger.info("数据库自动备份任务已停止")

    async def _auto_backup_loop(self) -> None:
        while self._running:
            try:
                if not self._is_backup_due():
                    await asyncio.sleep(_DUE_CHECK_INTERVAL)
                    continue

                await self.backup()

                await self.cleanup_old_backups()

                await asyncio.sleep(self._backup_interval_hours * 3600)

            except asyncio.CancelledError:
                logger.info("自动备份任务被取消")
                break
            except Exception as e:
                logger.error(f"自动备份任务错误: {e}", exc_info=True)
                await asyncio.sleep(300)

    def _is_backup_due(self) -> bool:
        try:
            latest_mtime = max(
                (
                    f.stat().st_mtime
                    for f in self._backup_dir.glob("proxies_backup_*.db")
                ),
                default=None,
            )
        except OSError:
            return True

        if latest_mtime is None:
            return True

        return time.time() - latest_mtime >= self._backup_interval_hours * 3600

    async def backup(self) -> Optional[Path]:
        if not self._db_path.exists():
            logger.error(f"数据库文件不存在: {self._db_path}")
            return None

        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_filename = f"proxies_backup_{timestamp}.db"
            backup_path = self._backup_dir / backup_filename

            def _sqlite_backup():
                import sqlite3
                src = sqlite3.connect(str(self._db_path))
                try:
                    dst = sqlite3.connect(str(backup_path))
                    try:
                        src.backup(dst)
                    finally:
                        dst.close()
                finally:
                    src.close()

            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, _sqlite_backup)

            if not backup_path.exists():
                logger.error(f"备份文件创建失败: {backup_path}")
                return None

            backup_size = backup_path.stat().st_size
            logger.info(
                f"数据库备份成功: {backup_path} "
                f"(大小: {backup_size / 1024:.2f} KB)"
            )

            return backup_path

        except Exception as e:
            logger.error(f"数据库备份失败: {e}", exc_info=True)
            return None

    async def cleanup_old_backups(self) -> int:
        try:
            cutoff_time = datetime.now() - timedelta(days=self._retention_days)

            backup_files = list(self._backup_dir.glob("proxies_backup_*.db"))

            deleted_count = 0

            for backup_file in backup_files:
                try:
                    file_mtime = datetime.fromtimestamp(backup_file.stat().st_mtime)

                    if file_mtime < cutoff_time:
                        backup_file.unlink()
                        deleted_count += 1
                        logger.info(f"已删除过期备份: {backup_file}")

                except Exception as e:
                    logger.warning(f"删除备份文件失败 {backup_file}: {e}")
                    continue

            if deleted_count > 0:
                logger.info(f"清理完成，删除了 {deleted_count} 个过期备份")

            return deleted_count

        except Exception as e:
            logger.error(f"清理过期备份失败: {e}", exc_info=True)
            return 0

    def list_backups(self) -> list[dict]:
        try:
            backup_files = list(self._backup_dir.glob("proxies_backup_*.db"))

            backups = []
            for backup_file in backup_files:
                try:
                    stat = backup_file.stat()
                    backups.append({
                        'path': str(backup_file),
                        'filename': backup_file.name,
                        'size': stat.st_size,
                        'created_at': datetime.fromtimestamp(stat.st_mtime)
                    })
                except Exception as e:
                    logger.warning(f"获取备份文件信息失败 {backup_file}: {e}")
                    continue

            backups.sort(key=lambda x: x['created_at'], reverse=True)

            return backups

        except Exception as e:
            logger.error(f"列出备份文件失败: {e}", exc_info=True)
            return []

    def apply_config(self, config) -> None:
        old_interval = self._backup_interval_hours
        old_retention = self._retention_days

        self._backup_interval_hours = config.database.backup_interval_hours
        self._retention_days = config.database.backup_retention_days

        logger.info(
            f"备份管理器配置已更新: "
            f"interval={old_interval}->{self._backup_interval_hours}h, "
            f"retention={old_retention}->{self._retention_days}d"
        )

    async def restore_backup_file(self, filename: str) -> bool:
        self._last_restore_error = None
        self._last_restore_error_code = ""
        name = str(filename).strip()
        if (
            not name
            or not name.endswith(".db")
            or Path(name).name != name
            or "/" in name
            or "\\" in name
        ):
            logger.warning("拒绝非法的备份文件名: %r", filename)
            return False

        backup_path = self._backup_dir / name
        if not backup_path.is_file():
            logger.warning("备份文件不存在: %s", backup_path)
            return False

        return await self.restore(str(backup_path))

    def _drop_wal_sidecars(self) -> bool:
        remaining: list[str] = []
        for suffix in ('-wal', '-shm'):
            sidecar = Path(str(self._db_path) + suffix)
            try:
                sidecar.unlink()
            except FileNotFoundError:
                pass
            except OSError as e:
                logger.warning("删除 %s 失败: %s", sidecar, e)
                remaining.append(sidecar.name)
        return not remaining

    @property
    def last_restore_error(self) -> Optional[str]:
        return self._last_restore_error or ""

    @property
    def last_restore_error_code(self) -> str:
        return self._last_restore_error_code

    async def restore(self, backup_path: str) -> bool:
        self._last_restore_error = None
        self._last_restore_error_code = ""
        backup_file = Path(backup_path)
        staged = self._db_path.with_suffix('.db.restoring')
        temp_backup: Optional[Path] = None

        def fail(reason: str, code: str) -> bool:
            self._last_restore_error = reason
            self._last_restore_error_code = code
            logger.error(reason)
            return False

        if not backup_file.exists():
            return fail(f"备份文件不存在: {backup_path}", "invalid_backup")

        loop = asyncio.get_running_loop()

        try:
            if not await self._verify_database(backup_file):
                return fail(
                    f"备份文件不是有效的 SQLite 数据库: {backup_path}",
                    "invalid_backup",
                )

            if self._db_path.exists():
                temp_backup = self._db_path.with_suffix('.db.temp')
                await loop.run_in_executor(
                    None, shutil.copy2, str(self._db_path), str(temp_backup)
                )
                logger.info(f"已创建临时备份: {temp_backup}")

            await loop.run_in_executor(
                None, shutil.copy2, str(backup_file), str(staged)
            )
            if not self._drop_wal_sidecars():
                return fail(
                    "无法删除原数据库的 WAL 边车文件（可能仍有进程持有数据库），"
                    "带着旧 WAL 换库会损坏新库，已放弃恢复",
                    "wal_locked",
                )
            await loop.run_in_executor(
                None, os.replace, str(staged), str(self._db_path)
            )

            if not await self._verify_database(self._db_path):
                logger.error("恢复后的数据库验证失败，回滚到原数据库")

                if temp_backup and temp_backup.exists():
                    await loop.run_in_executor(
                        None, shutil.copy2, str(temp_backup), str(staged)
                    )
                    self._drop_wal_sidecars()
                    await loop.run_in_executor(
                        None, os.replace, str(staged), str(self._db_path)
                    )

                return fail("恢复后的数据库验证失败，已回滚到原数据库", "verify_failed")

            logger.info(f"数据库恢复成功: {backup_path} -> {self._db_path}")
            return True

        except Exception as e:
            self._last_restore_error = str(e)
            self._last_restore_error_code = "error"
            logger.error(f"数据库恢复失败: {e}", exc_info=True)
            return False
        finally:
            for leftover in (staged, temp_backup):
                if leftover is None:
                    continue
                try:
                    leftover.unlink()
                except FileNotFoundError:
                    pass
                except OSError as e:
                    logger.warning("清理临时文件 %s 失败: %s", leftover, e)

    async def _verify_database(self, db_path: Path) -> bool:
        try:
            import aiosqlite

            async with aiosqlite.connect(str(db_path)) as db:
                async with db.execute("PRAGMA integrity_check") as cursor:
                    result = await cursor.fetchone()
                    if result and result[0] != 'ok':
                        logger.error(f"数据库完整性检查失败: {result[0]}")
                        return False

                async with db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ) as cursor:
                    tables = [row[0] for row in await cursor.fetchall()]

                    required_tables = ['proxies', 'plugin_configs']
                    for table in required_tables:
                        if table not in tables:
                            logger.error(f"数据库缺少必需的表: {table}")
                            return False

                async with db.execute("SELECT COUNT(*) FROM proxies") as cursor:
                    count = (await cursor.fetchone())[0]
                    logger.info(f"数据库验证成功，包含 {count} 条代理记录")

            return True

        except Exception as e:
            logger.error(f"数据库验证失败: {e}", exc_info=True)
            return False
