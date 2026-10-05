"""
模块名称：modules.proxypool.core.database
功能描述：SQLite 建表、建索引与幂等的列迁移，应用启动初始化时调用一次，确保库结构与当前代码期望的字段一致。
职责边界：负责：创建 proxies 与 plugin_configs 表及索引、为旧库补新增列、按谓词收敛
  废弃取值；不负责：数据读写（见 core.data.repositories）与连接生命周期管理
  （见 core.infrastructure.connection_pool）。
关键依赖：aiosqlite。
已知限制：
  1. 迁移只做新增列与按谓词收敛既有取值，不支持改类型或删列；收敛谓词必须幂等。
  2. 建表、建索引或末尾提交失败会抛出；补列与取值收敛一段的失败只记 warning，缺列由后续查询的失败暴露。
  3. 列默认值承载语义：anonymity_level='unverified' 表示从未检测过，anonymity_fallback=0 表示历史行或未验证行。
  4. 英文归属地列与 country_code / subdivision_code / geo_source 刻意不带 DEFAULT，NULL 表示尚未查询。
  5. 历史行由 'unknown' 收敛为 'transparent' 时须同时置 anonymity_fallback=1 并清空 quality_assessed_at，否则不会被重新检测。
  6. plugin_configs 默认值是契约：reval_interval_minutes=0 与 test_url='' 表示继承全局值，skip_validation=0 表示照常验证。
"""

import aiosqlite
import logging

logger = logging.getLogger(__name__)


async def init_database(db_path: str) -> None:
    async with aiosqlite.connect(db_path) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS proxies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                protocol TEXT NOT NULL,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                username TEXT,
                password TEXT,
                region TEXT DEFAULT '未知',
                country TEXT DEFAULT '未知',
                province TEXT DEFAULT '未知',
                city TEXT DEFAULT '未知',
                region_en TEXT,
                country_en TEXT,
                province_en TEXT,
                city_en TEXT,
                delay_ms REAL,
                is_valid BOOLEAN DEFAULT 1,
                real_ip TEXT,
                source_plugin TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                validated_at TIMESTAMP,
                failure_count INTEGER DEFAULT 0,
                UNIQUE(ip, port)
            )
        """)

        try:
            cursor = await db.execute("PRAGMA table_info(proxies)")
            columns = await cursor.fetchall()
            column_names = [col[1] for col in columns]

            if 'failure_count' not in column_names:
                await db.execute("ALTER TABLE proxies ADD COLUMN failure_count INTEGER DEFAULT 0")

            if 'is_favorite' not in column_names:
                await db.execute("ALTER TABLE proxies ADD COLUMN is_favorite INTEGER DEFAULT 0")

            if 'username' not in column_names:
                await db.execute("ALTER TABLE proxies ADD COLUMN username TEXT")

            if 'password' not in column_names:
                await db.execute("ALTER TABLE proxies ADD COLUMN password TEXT")

            migration_columns = {
                'health_score':    'REAL DEFAULT 0.0',
                'success_count':   'INTEGER DEFAULT 0',
                'total_checks':    'INTEGER DEFAULT 0',
                'anonymity_level': "TEXT DEFAULT 'unverified'",
                'anonymity_fallback': 'INTEGER DEFAULT 0',
                'supports_https':  'INTEGER DEFAULT 0',
                'avg_delay_ms':    'REAL',
                'supports_http':   'INTEGER DEFAULT 0',
                'quality_assessed_at': 'TIMESTAMP',
                'delay_variance':       'REAL',
                'last_valid_at':        'TIMESTAMP',
                'total_valid_seconds':  'REAL DEFAULT 0.0',
                'probe_success_count':  'INTEGER DEFAULT 0',
                'probe_total_count':    'INTEGER DEFAULT 0',
                'region_en':      'TEXT',
                'country_en':     'TEXT',
                'province_en':    'TEXT',
                'city_en':        'TEXT',
                'country_code':     'TEXT',
                'subdivision_code': 'TEXT',
                'geo_source':       'TEXT',
            }
            for col_name, col_def in migration_columns.items():
                if col_name not in column_names:
                    await db.execute(f"ALTER TABLE proxies ADD COLUMN {col_name} {col_def}")
                    logger.info(f"数据库迁移: 新增列 {col_name}")

            cursor = await db.execute(
                "UPDATE proxies SET anonymity_level = 'transparent',"
                " anonymity_fallback = 1, quality_assessed_at = NULL"
                " WHERE anonymity_level = 'unknown'"
            )
            if cursor.rowcount:
                logger.info(
                    "数据库迁移: %d 条历史记录的匿名度由 unknown 收敛为 transparent"
                    "（已清空完整评估时间，下轮将重新检测）", cursor.rowcount
                )

        except Exception as e:
            logger.warning(f"数据库迁移检查失败（非致命）: {e}")

        await db.execute("CREATE INDEX IF NOT EXISTS idx_ip ON proxies(ip)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_protocol ON proxies(protocol)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_is_valid ON proxies(is_valid)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_region ON proxies(region)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_delay ON proxies(delay_ms)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_source ON proxies(source_plugin)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_failure_count ON proxies(failure_count)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_is_favorite ON proxies(is_favorite)")

        await db.execute("CREATE INDEX IF NOT EXISTS idx_health_score ON proxies(health_score)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_anonymity ON proxies(anonymity_level)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_supports_https ON proxies(supports_https)")

        await db.execute("""
            CREATE TABLE IF NOT EXISTS plugin_configs (
                name TEXT PRIMARY KEY,
                enabled BOOLEAN DEFAULT 1,
                interval_minutes INTEGER DEFAULT 60,
                last_run TIMESTAMP,
                next_run TIMESTAMP,
                reval_enabled BOOLEAN DEFAULT 1,
                reval_interval_minutes INTEGER DEFAULT 0,
                test_url TEXT DEFAULT '',
                skip_validation BOOLEAN DEFAULT 0
            )
        """)

        try:
            cursor = await db.execute("PRAGMA table_info(plugin_configs)")
            plugin_columns = [col[1] for col in await cursor.fetchall()]

            plugin_migration_columns = {
                'reval_enabled':          'BOOLEAN DEFAULT 1',
                'reval_interval_minutes': 'INTEGER DEFAULT 0',
                'test_url':               "TEXT DEFAULT ''",
                'skip_validation':        'BOOLEAN DEFAULT 0',
            }
            for col_name, col_def in plugin_migration_columns.items():
                if col_name not in plugin_columns:
                    await db.execute(
                        f"ALTER TABLE plugin_configs ADD COLUMN {col_name} {col_def}"
                    )
                    logger.info(f"数据库迁移: plugin_configs 新增列 {col_name}")

        except Exception as e:
            logger.warning(f"plugin_configs 迁移检查失败（非致命）: {e}")

        await db.commit()


__all__ = ['init_database']
