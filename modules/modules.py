"""
模块名称：modules.modules
功能描述：宿主侧公共基础层，集中提供跨模块复用的基础能力：配置读写与键迁移、国际化文案、
          启动与运行期终端展示、代理可用性检测，以及 IP 名单与绕过名单的加载、匹配和变更监视。
职责边界：负责：配置读写与迁移、国际化文案、终端展示、代理检测、IP 名单和变更监视等公共能力；
          不负责：出口转发与轮换调度（modules.proxyserver）、代理池内部业务（modules.proxypool_service
          与 modules/proxypool/）、日志装配（modules.logging_setup）、Web 路由（app 与 modules.proxypool_api）。
关键依赖：标准库 configparser / socket / fnmatch / threading / asyncio / locale、colorama（终端着色）、
          httpx（HTTP 代理检测）。
已知限制：
1. ini 写助手整文件读入、改写后原子替换，不做并发合并，两个写者同时保存时后写者胜。
2. 临时文件由 mkstemp 创建（固定 0600），换入前用 _copy_file_mode 复制原文件权限位，源文件不存在时保持默认。
3. read_config_text 先按 utf-8-sig 再按系统本地代码页解码，两级都失败才抛 UnicodeDecodeError，命中本地代码页回退会 warning。
4. 代理检测结果缓存是进程内的，键为 (代理 URL, 目标地址)，TTL 10 秒、上限约 1000 条；检测抛意外异常时不写缓存，本次仍返回 False。
5. load_config 出错只记日志并回退默认配置副本；IP 名单读取失败返回空集合，均不向上抛出。
6. 文案表 cn / en 的键必须一一对应，缺键或语言未知时按「目标语言 → 中文 → 键名」回退，键名会被原样显示。
7. HTTP 出口探测客户端固定 trust_env=False（与转发侧客户端同口径），不继承系统代理环境变量；否则探测会绕经本机系统代理，测得的不是该出口的真实连通性。
8. SOCKS5 应答长度随 atyp 变（IPv4 10、IPv6 22、域名 7+len 字节），解析须按 atyp 变长读取，固定长度会把域名与 IPv6 代理误判为坏。
"""

import asyncio, logging, httpx, os, re, sys, time, fnmatch, threading, socket, locale
from configparser import ConfigParser
from typing import Any
from colorama import Fore, Style

CURRENT_VERSION = "ProxyCat-V3.0.0"

logger = logging.getLogger(__name__)

class ColoredFormatter(logging.Formatter):

    COLORS = {
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT,
    }

    def format(self, record):
        log_color = self.COLORS.get(record.levelno, Fore.WHITE)
        colored = logging.makeLogRecord(record.__dict__)
        colored.msg = f"{log_color}{record.getMessage()}{Style.RESET_ALL}"
        colored.args = None
        return super().format(colored)

MESSAGES = {
    'cn': {
        'proxy_check_disabled': '代理检测已禁用',
        'valid_proxies': '检测完成，有效出口: {} 个',
        'no_valid_proxies': '没有有效的代理地址',
        'proxy_check_failed': '代理 {} 检测失败: {}',
        'proxy_switch': '出口批次已更换: {} 个（原 {} 个）',
        'proxy_invalid': '代理 {} 不可达，已从本批出口中剔除',
        'proxy_check_error': '代理检查时发生错误: {}',
        'server_closing': '服务器正在关闭...',
        'current_proxy': '最近分配出口',
        'next_switch': '最近到期',
        'seconds': '秒',
        'proxy_file_not_found': '代理文件不存在: {}',
        'auth_not_set': '未设置 (无需认证)',
        'public_account': '公众号',
        'blog': '博客',
        'proxy_mode': '运行模式',
        'cycle': '按顺序使用',
        'loadbalance': '负载均衡',
        'continuous': '持续更换',
        'request': '触发更换',
        'single_round': '单轮',
        'proxy_interval': '出口刷新间隔',
        'default_auth': '默认账号密码',
        'local_http': '本地监听地址 (HTTP)',
        'local_socks5': '本地监听地址 (SOCKS5)',
        'star_project': '开源项目求 Star',
        'client_handle_error': '客户端处理错误: {}',
        'user_interrupt': '用户中断程序',
        'latest_version': '当前已是最新版本',
        'new_version_available': '发现新版本：{}（当前 {}）',
        'version_not_checked': '尚未完成版本检查',
        'version_info_not_found': '未找到版本信息',
        'update_check_error': '检查更新失败: {}',
        'unauthorized_ip': '未授权的IP尝试访问: {}',
        'socks5_connection_error': 'SOCKS5连接错误: {}',
        'connect_timeout': '连接超时',
        'client_request_error': '客户端请求错误: {}',
        'request_retry': '请求失败，重试中 (剩余{}次)',
        'log_suppressed': '（窗口内另有 {} 条同类消息已折叠）',
        'whitelist_error': '添加白名单失败: {}',
        'api_mode_notice': '当前为API模式，收到请求将自动批量获取上游出口',
        'server_running': '代理服务器运行在 {}:{}',
        'server_start_error': '服务器启动错误: {}',
        'server_shutting_down': '正在关闭服务器...',
        'status_update_error': '状态更新出错',
        'display_level_notice': '当前显示级别: {}',
        'display_level_desc': '''显示级别说明:
0: 仅显示出口名册变化和错误信息
1: 显示出口名册、各出口状态、倒计时和错误信息
2: 显示所有详细信息''',
        'new_client_connect': '新客户端连接 - IP: {}, 用户: {}',
        'port_changed': '端口已更改: {} -> {}，需要重启服务器生效',
        'load_proxy_file_error': '加载代理文件失败: {}',
        'proxy_check_result': '代理检查完成，有效代理：{}个',
        'no_proxy': '无代理',
        'proxy_check_start': '开始检查代理...',
        'proxy_save_success': '代理保存成功',
        'proxy_save_failed': '代理保存失败: {}',
        'ip_list_save_success': 'IP名单保存成功',
        'ip_list_save_failed': 'IP名单保存失败: {}',
        'switch_success': '出口批次已刷新',
        'switch_failed': '刷新出口批次失败: {}',
        'switch_cooldown_msg': '刷新冷却中，请等待 {} 秒后再试',
        'switch_in_progress': '出口批次刷新正在进行中，请稍后再试',
        'service_start_success': '服务启动成功',
        'service_already_running': '服务已在运行',
        'service_stop_success': '服务停止成功',
        'service_not_running': '服务未在运行',
        'service_restart_success': '服务重启成功',
        'invalid_action': '无效的操作',
        'operation_failed': '操作失败: {}',
        'logs_cleared': '日志已清除',
        'clear_logs_failed': '清除日志失败: {}',
        'unsupported_language': '不支持的语言',
        'service_start_failed': '服务启动失败',
        'service_restart_failed': '服务重启失败：{}',
        'invalid_token': '无效的访问令牌',
        'config_file_changed': '检测到配置文件更改，正在重新加载...',
        'proxy_file_changed': '代理文件已更改，正在重新加载...',
        'ip_lists_reloaded': '访问名单已重新加载：白名单 {} 条、黑名单 {} 条、绕过名单 {} 条',
        'users_save_success': '用户保存成功',
        'users_save_failed': '用户保存失败：{}',
        'users_load_failed': '用户列表读取失败：{}',
        'web_panel_url': '网页控制面板地址: {}',
        'web_panel_notice': '请使用浏览器访问上述地址来管理代理服务器',
        'all_retries_failed': '所有重试均已失败，最后错误: {}',
        'proxy_get_failed': '获取代理失败',
        'proxy_get_error': '获取代理错误: {}',
        'proxy_config_error': '代理配置有误: {}',
        'proxy_source_error_request': '取代理接口请求失败（网络不通、接口地址不可达或对方拒绝）',
        'proxy_source_error_config': '取代理接口的配置有误（接口地址缺失，或接口返回了错误码）',
        'proxy_source_error_unknown': '取代理接口失败',
        'proxy_switch_error': '刷新出口批次出错: {}',
        'proxy_allocate_error': '获取上游出口出错: {}',
        'proxy_get_timeout': '获取上游出口超时，等待下次补货',
        'pool_mode_notice': '当前为维护池模式，收到请求将自动批量获取上游出口',
        'pool_no_proxy': '维护池中无可用代理',
        'pool_unavailable': '维护池接口不可用: {}',
        'pool_fetch_failed': '从维护池获取代理失败: {}',
        'proxy_workers_ready': '已就绪 {} 个上游出口',
        'elastic_expanded': '出口池已扩容至 {} 个出口（高峰后自动收回）',
        'elastic_capacity_boosted': '来源暂时拿不出新出口，单出口并发额度已临时放宽至 {} 倍',
        'elastic_released': '出口池已停止扩容，多出的出口将在寿命到期后逐个撤下（当前 {} 个出口）',
        'exit_pool_drained': '没有任务在跑，已到寿命的出口直接移除（当前 {} 个出口，下次请求会重新取货）',
        'exit_pool_trimmed': '出口池已按容量收回多余的出口，当前 {} 个出口',
        'proxy_exit_added': '新增出口 {}',
        'proxy_exit_rotated': '轮换出口 {} -> {}',
        'proxy_worker_retired': '上游出口 {} 近期失败占比过高，已停用并等待补货',
        'proxy_batch_fetch_failed': '批量获取代理失败: {}',
        'proxy_batch_partial': '批量获取到 {} 个代理，期望 {} 个',
        'exits_summary': '上游出口: {}/{}',
        'exits_summary_expanded': '上游出口: {}/{}（高峰期扩容中）',
        'exit_line': '  {}  在用 {}  剩余 {}',
        'exit_load_no_cap': '{}（不限）',
        'exit_left_requests': '{} 次',
        'exit_left_none': '不换',
        'pool_start_success': '维护池启动成功',
        'pool_start_failed': '维护池启动失败: {}',
        'pool_stop_success': '维护池停止成功',
        'pool_stop_failed': '维护池停止失败: {}',
        'pool_restart_success': '维护池重启成功',
        'pool_restart_failed': '维护池重启失败: {}',
        'pool_status_error': '获取维护池状态失败: {}',
        'pool_starting': '正在启动代理池...',
        'pool_stopping': '正在停止代理池...',
        'pool_unknown_error': '未知原因',
        'pool_start_timeout': '维护池初始化超时（{} 秒）',
        'pool_stop_timeout': '维护池未能在 {} 秒内停止',
        'pool_previous_stop_incomplete': (
            '上一次停止未完成，旧线程仍在运行；为避免两个池实例共用同一数据库，'
            '本次启动已拒绝。请重启进程。'
        ),
        'pool_loop_crashed': '维护池事件循环异常退出: {}',
        'pool_config_unreadable': '配置文件暂时读不出来，保持当前池配置，下一轮重试',
        'pool_invalid_parameters': '维护池请求参数错误: {}',
        'pool_request_failed': '维护池请求处理失败: {}',
        'pool_internal_error': '维护池内部错误',
        'pool_restore_requires_stop': '恢复备份前请先停止代理池（正在关闭中也需等它完全退出）',
        'pool_backup_filename_required': '缺少备份文件名',
        'pool_db_backup_disabled': '数据库备份功能未启用',
        'pool_db_maintenance_disabled': '数据库维护功能不可用',
        'pool_db_optimize_done': '数据库优化完成',
        'pool_db_optimize_failed': '数据库优化失败，请查看日志',
        'pool_backup_restore_success': '备份恢复成功，请重启代理池以加载恢复后的数据',
        'pool_backup_restore_bad_name': '备份恢复失败：文件不存在或名称非法',
        'pool_backup_restore_invalid_backup': '备份恢复失败：该文件不是有效的 SQLite 数据库',
        'pool_backup_restore_wal_locked': '备份恢复失败：无法删除原数据库的 WAL 边车文件，可能仍有进程持有数据库',
        'pool_backup_restore_verify_failed': '备份恢复失败：恢复后的数据库校验未通过，已回滚到原数据库',
        'pool_backup_restore_error': '备份恢复失败：{}',
        'pool_autostart_source_switched': '代理来源已切换为维护池，自动启动代理池',
        'pool_autostart_required': '配置要求使用内置代理池，自动启动代理池',
        'pool_autostart_skipped': '当前代理来源不使用内置代理池，跳过启动池',
        'pool_error_http_status': '维护池返回异常状态码: {}',
        'pool_error_connect': '无法连接到维护池: {}',
        'pool_error_timeout': '维护池请求超时',
        'pool_error_invalid_format': '维护池返回的代理格式无效: {}',
        'port_in_use': '端口 {} 已被其他程序占用，请更换其他端口后重试',
        'web_port_in_use': 'Web 面板端口 {} 已被其他程序占用，请修改 config.ini 的 web_port 后重新启动',
        'access_ok': '[成功] 客户端 {} 上游 {} 目标 {} {} {}ms 状态 {}',
        'access_failed': '[失败] 客户端 {} 上游 {} 目标 {} {} {}ms 状态 {} 原因 {}',
        'access_aborted': '[中断] 客户端 {} 上游 {} 目标 {} {} {}ms 状态 {} 原因 {}',
        'access_direct': '直连',
        'access_unknown': '未知',
        'access_incomplete': '请求未完成（客户端断开或请求被取消）',
        'access_tunnel_no_data': '隧道已建立但上游未返回任何数据（客户端等不到响应）',
        'access_tunnel_idle': '隧道已建立，客户端未发送数据即断开',
        'access_tunnel_client_left': '隧道已建立，客户端在收到上游数据前主动断开',
        'access_tunnel_closed_by_upstream': '隧道已建立，上游未发送任何数据即关闭连接',
        'proxy_silent_upstream': '代理 {} 收下 CONNECT 后 {} 秒内未回传任何数据，判定为不可用并触发健康检查',
        'domain_stats_cleared': '已清除 {} 个域名的访问统计',
        'access_outcome_success': '成功',
        'access_outcome_failure': '失败',
        'access_outcome_aborted': '中断',
        'access_records_cleared': '已清除 {} 条访问记录',
        'access_records_bad_outcome': '结果筛选取值非法（只能是 success、failure、aborted 之一）：{}',
        'access_records_bad_format': '导出格式非法（只能是 csv 或 json）：{}',
        'pool_geo_update_task_created': '离线归属地库更新任务已创建',
        'pool_geo_recompute_disabled': '归属地解析服务未启用，无法重算',
        'pool_geo_recompute_task_created': '归属地重算任务已创建',
        'pool_plugin_enabled': '插件 {} 已启用',
        'pool_plugin_disabled': '插件 {} 已禁用',
        'pool_plugin_enable_failed': '启用插件失败: {}',
        'pool_plugin_disable_failed': '禁用插件失败: {}',
        'pool_plugin_not_loaded': '插件 {} 未加载',
        'pool_plugin_interval_set': '插件 {} 运行周期已设置为 {} 分钟',
        'pool_plugin_interval_failed': '设置插件运行周期失败: {}',
        'pool_plugin_test_url_set': '插件 {} 的测试地址已设置为 {}',
        'pool_plugin_test_url_inherited': '插件 {} 的测试地址已恢复为继承全局地址',
        'pool_plugin_test_url_failed': '设置插件测试地址失败: {}',
        'pool_plugin_validation_set': '插件 {} 的验证策略已更新',
        'pool_plugin_validation_failed': '设置插件验证策略失败: {}',
        'pool_plugin_run_task_created': '插件 {} 抓取任务已创建',
        'pool_plugin_reload_success': '插件 {} 热重载成功',
        'pool_plugin_reload_rejected': '插件 {} 热重载失败（可能正在执行中或文件不存在）',
        'pool_plugin_reload_failed': '热重载失败: {}',
        'pool_no_matching_proxies': '没有符合条件的代理',
        'pool_proxy_not_found': '代理不存在',
        'config_option_invalid': '配置项 {} 非法（当前值: {}）：{}',
        'config_reason_expected_int': '期望整数',
        'config_reason_expected_float': '期望小数',
        'config_reason_expected_bool': '期望布尔值（true/false）',
        'config_reason_expected_comma_list': '期望至少一个逗号分隔的取值',
        'config_reason_expected_value': '期望至少一个取值',
        'config_reason_min': '不能小于 {}',
        'config_reason_max': '不能大于 {}',
        'config_reason_expected_choice': '只能是 {} 之一',
        'config_reason_expected_ip': '必须是一到两个合法的 IP 地址（IPv4 与 IPv6 各至多一个，逗号分隔）',
        'config_reason_expected_url': '必须是 http/https 开头的完整地址，留空表示使用内置地址',
        'config_reason_derived_key': '该配置项由 [Server] 段派生，不能单独设置',
        'config_reason_unknown_key': '不是可修改的配置项',
        'config_reason_users_via_api': '用户账号请通过用户管理接口修改',

        'task_stage_prescreen_text': '正在初筛端口连通性...',
        'task_stage_validate_text': '正在验证代理...',
        'task_stage_ingest_text': '正在直接入库（该插件已关闭入库验证）...',
        'task_cancelled_with_counts': '任务已取消，{}',
        'task_failed': '任务失败: {}',
        'task_counts_saved_unusable': '已入库 {} 个，不可用 {} 个',
        'task_plugin_run_done': '插件 {} 执行成功，{}',
        'task_validating': '正在验证代理...',
        'task_validate_selected_done': '验证完成，有效: {}/{}',
        'task_inconclusive_suffix': '，{} 个因检测链路问题未得出结论',
        'task_validate_all_done': '验证完成，共验证 {} 个代理',
        'task_inconclusive_among_suffix': '，其中 {} 个因检测链路问题未得出结论',
        'task_validate_failed': '验证失败: {}',
        'task_no_proxies_to_validate': '没有需要验证的代理',
        'task_checking': '正在检测代理...',
        'task_pool_empty': '池里还没有代理',
        'task_check_done': '检测完成，共处理 {} 个代理',
        'task_check_failed': '检测失败: {}',
        'task_plugin_fetching': '正在抓取插件 {}...（外部源较多时最长约 {} 分钟）',
        'task_plugin_no_new_proxies': '插件 {} 执行完成，未获取到新代理',
        'task_plugin_fetch_cancelled': '插件 {} 抓取任务已取消，{}',
        'task_plugin_failed': '插件 {} 执行失败: {}',
        'task_geo_downloading': '正在下载离线归属地库...',
        'task_geo_downloading_file': '正在下载 {}（{}%）',
        'task_geo_update_cancelled': '离线归属地库更新已取消',
        'task_geo_update_failed': '更新失败: {}',
        'task_geo_update_done': '离线归属地库更新完成',
        'task_geo_update_partial': '部分文件更新失败（{}），其余已更新',
        'task_geo_recompute_disabled': '归属地解析服务未启用，无法重算',
        'task_geo_picking': '正在挑选待重算的记录...',
        'task_geo_nothing_to_recompute': '没有需要重算的记录',
        'task_geo_queued': '已排入 {} 个出口 IP，正在解析...',
        'task_geo_resolving': '正在解析归属地 {}/{}',
        'task_geo_recompute_cancelled': '归属地重算已取消（已解析的部分保留）',
        'task_geo_recompute_failed': '重算失败: {}',
        'task_geo_recompute_done': '归属地重算完成，共处理 {} 个出口 IP',
        'ingest_summary_candidates': '候选 {} 个',
        'ingest_summary_prescreened_out': '初筛淘汰 {} 个',
        'ingest_summary_validated': '验证 {} 个',
        'ingest_summary_saved': '入库 {} 个',
        'ingest_summary_invalid': '不可用 {} 个',
        'ingest_summary_incomplete': '信息不全 {} 个',
        'ingest_summary_inconclusive': '未能判定 {} 个',
        'ingest_summary_failed': '失败 {} 个',
        'list_separator': '，',

        'config_body_must_be_json': '请求体必须是 JSON 对象',
        'proxies_must_be_list': '代理列表必须是数组',
        'config_sections_must_be_json': 'server 与 pool 都必须是 JSON 对象',
        'config_nothing_to_save': '没有需要保存的配置项',
        'ip_list_type_invalid': '类型必须为 whitelist 或 blacklist',
        'log_category_unknown': '未知的日志类别',
        'log_file_missing': '日志文件不存在',
        'log_file_name_invalid': '非法的日志文件名: {}',
        'log_file_read_failed': '读取日志文件失败: {}',
        'credential_name_required': '凭据名称不能为空',
        'credential_saved': '凭据已保存',
        'credential_deleted': '凭据已删除',
        'credential_switched': '已切换凭据',
        'credential_not_found': '凭据不存在: {}',
        'unknown_action': '未知操作',
        'no_current_proxy': '无',
        'service_thread_still_running': '旧服务线程未能在超时时间内退出，请稍后重试',
        'service_stop_timeout': '服务未能在超时时间内停止',

        'param_invalid_protocol': '不支持的协议: {}',
        'param_invalid_status': '不支持的状态: {}',
        'param_negative_min_delay': '最小延迟不能为负数: {}',
        'param_negative_max_delay': '最大延迟不能为负数: {}',
        'param_delay_range_reversed': '最小延迟不能大于最大延迟: {} > {}',
        'param_negative_min_health': '最低健康分不能为负数: {}',
        'param_invalid_anonymity': '不支持的匿名等级: {}',
        'param_invalid_export_format': '不支持的格式: {}，仅支持 {}',
        'param_invalid_validation_mode': '不支持的验证强度: {}（只能是 {} 之一）',
        'param_page_must_be_positive': '页码必须大于 0: {}',
        'param_page_size_must_be_positive': '每页数量必须大于 0: {}',
        'param_page_size_too_large': '每页数量不能大于 {}: {}',
        'param_limit_must_be_positive': 'limit 必须大于 0: {}',
        'param_limit_too_large': 'limit 不能大于 {}: {}',
        'param_proxy_list_empty': '代理列表不能为空',
        'param_proxy_ids_empty': '代理ID列表不能为空',
        'param_body_must_be_json': '请求体必须是 JSON 对象',
        'param_missing_fields': '缺少必需的参数: {}',
        'param_interval_must_be_positive': '运行周期必须大于 0 分钟: {}',
        'param_reval_interval_not_int': '重验证间隔必须是整数: {}',

        'pool_not_running': '代理池未运行',
        'pool_stopped': '代理池已停止',
        'access_reason_bad_target': '非法的目标地址: {}',
        'access_reason_direct_failed': '直连目标失败: {}',
        'pool_call_timeout': '代理池调用超时（{} 秒）',
        'pool_not_enabled': '代理池未启用',

        'getip_api_error_code': 'API返回error000x-13',

        'csv_col_protocol': '协议', 'csv_col_ip': 'IP', 'csv_col_port': '端口',
        'csv_col_username': '用户名', 'csv_col_password': '密码',
        'csv_col_proxy_url': '代理URL', 'csv_col_region': '地区',
        'csv_col_delay_ms': '延迟(ms)', 'csv_col_status': '状态',
        'csv_col_real_ip': '真实IP', 'csv_col_source': '来源',
        'csv_col_validated_at': '验证时间',
        'csv_status_valid': '有效', 'csv_status_invalid': '失效',
        'csv_col_time': '时间', 'csv_col_kind': '类型', 'csv_col_method': '方法',
        'csv_col_client_ip': '客户端IP', 'csv_col_client_user': '客户端用户',
        'csv_col_host': '目标域名', 'csv_col_upstream': '上游代理',
        'csv_col_outcome': '结果', 'csv_col_status_code': '状态码',
        'csv_col_elapsed': '耗时(ms)', 'csv_col_reason': '原因',

        'plugin_error_bad_return_type': '返回值类型错误',
        'plugin_error_timeout': '执行超时',
        'plugin_error_bad_spec': '无效的模块规范',
        'plugin_error_missing_interface': '未实现必需的接口',
        'pool_field_protocol_required': '协议不能为空',
        'pool_field_protocol_unsupported': '不支持的协议: {}',
        'pool_field_ip_required': 'IP 地址不能为空',
        'pool_field_port_invalid': '无效的端口: {}',
        'pool_field_source_required': '来源插件不能为空',
        'pool_field_update_not_allowed': '不允许更新的字段: {}',
        'pool_field_where_not_allowed': '不允许作为更新条件的字段: {}',
        'pool_field_is_valid_invalid': '无效的 is_valid 值: {}',
        'pool_field_anonymity_invalid': '无效的匿名等级: {}',
        'pool_field_plugin_name_required': '插件名称不能为空',
        'pool_field_plugin_interval_invalid': '运行间隔必须大于 0: {}',
        'pool_field_reval_interval_invalid': '重验证间隔不能为负数: {}',
        'pool_repo_integrity_error': '代理数据完整性错误: {}',
        'pool_repo_plugin_integrity_error': '插件配置数据完整性错误: {}',
        'pool_repo_query_build_failed': '查询构建失败: {}',
        'pool_random_proxy_bad_format': 'format 参数必须是 json 或 text',
        'pool_import_no_valid_proxy': '没有有效的代理可导入',
        'pool_import_duplicated': '所有代理已存在，未导入新代理',
        'pool_import_validating': '正在后台验证 {} 个代理，通过后才入库',
        'pool_favorite_added': '代理已收藏',
        'pool_favorite_removed': '代理已取消收藏',
        'pool_validation_task_created': '验证任务已创建',
        'pool_full_check_task_created': '代理全面检测任务已创建',
        'pool_validation_no_valid_proxy': '未找到有效的代理',
        'pool_validating_proxies': '正在验证 {} 个代理',
        'pool_no_invalid_proxies': '没有失效代理需要删除',
        'pool_invalid_proxies_deleted': '成功删除 {} 个失效代理',
        'pool_proxies_deleted': '成功删除 {} 个代理',
        'pool_task_not_found': '任务不存在',
        'pool_task_already_finished': '任务已经结束，无需取消',
        'pool_task_cancelled': '任务已取消',
    },
    'en': {
        'proxy_check_disabled': 'Proxy check is disabled',
        'valid_proxies': 'Check done, valid exits: {}',
        'no_valid_proxies': 'No valid proxies found',
        'proxy_check_failed': 'Proxy {} check failed: {}',
        'proxy_switch': 'Upstream exits replaced: {} (was {})',
        'proxy_invalid': 'Proxy {} unreachable, dropped from this batch',
        'proxy_check_error': 'Error occurred during proxy check: {}',
        'server_closing': 'Server is closing...',
        'current_proxy': 'Last Assigned Exit',
        'next_switch': 'Next expiry',
        'seconds': 's',
        'proxy_file_not_found': 'Proxy file not found: {}',
        'auth_not_set': 'Not set (No authentication required)',
        'public_account': 'WeChat Public Number',
        'blog': 'Blog',
        'proxy_mode': 'Run Mode',
        'cycle': 'In order',
        'loadbalance': 'Least loaded',
        'continuous': 'Continuous rotation',
        'request': 'On-request rotation',
        'single_round': 'Single Round',
        'proxy_interval': 'Exit Refresh Interval',
        'default_auth': 'Default Username and Password',
        'local_http': 'Local Listening Address (HTTP)',
        'local_socks5': 'Local Listening Address (SOCKS5)',
        'star_project': 'Star the Project',
        'client_handle_error': 'Client handling error: {}',
        'user_interrupt': 'User interrupted the program',
        'latest_version': 'You are using the latest version',
        'new_version_available': 'New version available: {} (current {})',
        'version_not_checked': 'Version check has not completed yet',
        'version_info_not_found': 'Version information not found',
        'update_check_error': 'Failed to check for updates: {}',
        'unauthorized_ip': 'Unauthorized IP attempt: {}',
        'socks5_connection_error': 'SOCKS5 connection error: {}',
        'connect_timeout': 'Connection timeout',
        'client_request_error': 'Client request handling error: {}',
        'request_retry': 'Request failed, retrying ({} left)',
        'log_suppressed': ' ({} similar messages suppressed in this window)',
        'whitelist_error': 'Failed to add whitelist: {}',
        'api_mode_notice': 'Currently in API mode, a batch of upstream exits will be fetched on demand',
        'all_retries_failed': 'All retries failed, last error: {}',
        'proxy_get_failed': 'Failed to get proxy',
        'proxy_get_error': 'Error getting proxy: {}',
        'proxy_config_error': 'Invalid proxy configuration: {}',
        'proxy_source_error_request': 'Fetching proxies failed (network unreachable, bad endpoint, or the provider refused)',
        'proxy_source_error_config': 'Proxy-fetch configuration is wrong (endpoint missing, or the provider returned an error code)',
        'proxy_source_error_unknown': 'Fetching proxies failed',
        'proxy_switch_error': 'Error refreshing upstream exits: {}',
        'proxy_allocate_error': 'Error obtaining an upstream exit: {}',
        'proxy_get_timeout': 'Upstream exit fetch timed out; waiting for the next replenish',
        'server_running': 'Proxy server running at {}:{}',
        'server_start_error': 'Server startup error: {}',
        'server_shutting_down': 'Server shutting down...',
        'status_update_error': 'Status update error',
        'display_level_notice': 'Current display level: {}',
        'display_level_desc': '''Display level description:
0: Only show exit roster changes and error messages
1: Show the exit roster, per-exit state, countdown and error messages
2: Show all detailed information''',
        'new_client_connect': 'New client connection - IP: {}, User: {}',
        'port_changed': 'Port changed: {} -> {}, server restart required to take effect',
        'load_proxy_file_error': 'Failed to load proxy file: {}',
        'proxy_check_result': 'Proxy check completed, valid proxies: {}',
        'no_proxy': 'No proxy',
        'proxy_check_start': 'Starting proxy check...',
        'proxy_save_success': 'Proxy saved successfully',
        'proxy_save_failed': 'Failed to save proxy: {}',
        'ip_list_save_success': 'IP list saved successfully',
        'ip_list_save_failed': 'Failed to save IP list: {}',
        'switch_success': 'Upstream exit batch refreshed',
        'switch_failed': 'Failed to refresh upstream exits: {}',
        'switch_cooldown_msg': 'Refresh cooldown, wait {} seconds',
        'switch_in_progress': 'Exit batch refresh in progress, please try again later',
        'service_start_success': 'Service started successfully',
        'service_already_running': 'Service is already running',
        'service_stop_success': 'Service stopped successfully',
        'service_not_running': 'Service is not running',
        'service_restart_success': 'Service restarted successfully',
        'invalid_action': 'Invalid action',
        'operation_failed': 'Operation failed: {}',
        'logs_cleared': 'Logs cleared',
        'clear_logs_failed': 'Failed to clear logs: {}',
        'unsupported_language': 'Unsupported language',
        'service_start_failed': 'Failed to start service',
        'service_restart_failed': 'Failed to restart service: {}',
        'invalid_token': 'Invalid access token',
        'config_file_changed': 'Config file change detected, reloading...',
        'proxy_file_changed': 'Proxy file changed, reloading...',
        'ip_lists_reloaded': 'Access lists reloaded: {} whitelist, {} blacklist, {} bypass entries',
        'users_save_success': 'Users saved successfully',
        'users_save_failed': 'Failed to save users: {}',
        'users_load_failed': 'Failed to load the user list: {}',
        'web_panel_url': 'Web panel URL: {}',
        'web_panel_notice': 'Please use a browser to access the above URL to manage the proxy server',
        'pool_mode_notice': 'Currently in pool mode, a batch of upstream exits will be fetched on demand',
        'pool_no_proxy': 'No proxy available in pool',
        'pool_unavailable': 'Pool API unavailable: {}',
        'pool_fetch_failed': 'Failed to fetch proxy from pool: {}',
        'proxy_workers_ready': '{} upstream exits ready',
        'elastic_expanded': 'Exit pool expanded to {} exits (released automatically after the peak)',
        'elastic_capacity_boosted': 'Source has no new exits right now; per-exit concurrency temporarily raised to {}x',
        'elastic_released': 'Elastic capacity released; surplus exits retire as their lifetime ends ({} exits now)',
        'exit_pool_drained': 'No tasks are running, so expired exits were removed outright ({} exits now; the next request fetches fresh ones)',
        'exit_pool_trimmed': 'Exit pool trimmed back to the configured size; {} exits now',
        'proxy_exit_added': 'Exit added: {}',
        'proxy_exit_rotated': 'Exit rotated: {} -> {}',
        'proxy_worker_retired': 'Upstream exit {} is failing too often; retired and awaiting replacement',
        'proxy_batch_fetch_failed': 'Batch proxy fetch failed: {}',
        'proxy_batch_partial': 'Fetched {} proxies, expected {}',
        'exits_summary': 'Upstream exits: {}/{}',
        'exits_summary_expanded': 'Upstream exits: {}/{} (peak expansion active)',
        'exit_line': '  {}  in use {}  left {}',
        'exit_load_no_cap': '{} (no cap)',
        'exit_left_requests': '{} reqs',
        'exit_left_none': 'kept',
        'pool_start_success': 'Pool started successfully',
        'pool_start_failed': 'Failed to start pool: {}',
        'pool_stop_success': 'Pool stopped successfully',
        'pool_stop_failed': 'Failed to stop pool: {}',
        'pool_restart_success': 'Pool restarted successfully',
        'pool_restart_failed': 'Failed to restart pool: {}',
        'pool_status_error': 'Failed to get pool status: {}',
        'pool_starting': 'Starting proxy pool...',
        'pool_stopping': 'Stopping proxy pool...',
        'pool_unknown_error': 'unknown reason',
        'pool_start_timeout': 'Pool initialization timed out ({}s)',
        'pool_stop_timeout': 'Pool did not stop within {}s',
        'pool_previous_stop_incomplete': (
            'The previous stop did not finish and the old thread is still running; '
            'refusing to start a second pool instance against the same database. '
            'Restart the process.'
        ),
        'pool_loop_crashed': 'Pool event loop exited with an error: {}',
        'pool_config_unreadable': 'Config file is temporarily unreadable, keeping the current pool config and retrying next round',
        'pool_invalid_parameters': 'Invalid pool request parameters: {}',
        'pool_request_failed': 'Pool request failed: {}',
        'pool_internal_error': 'Pool internal error',
        'pool_restore_requires_stop': 'Stop the pool before restoring a backup (wait for a stopping pool to exit completely)',
        'pool_backup_filename_required': 'Backup file name is required',
        'pool_db_backup_disabled': 'Database backup is not enabled',
        'pool_db_maintenance_disabled': 'Database maintenance is unavailable',
        'pool_db_optimize_done': 'Database optimization completed',
        'pool_db_optimize_failed': 'Database optimization failed, please check the logs',
        'pool_backup_restore_success': 'Backup restored; restart the pool to load the restored data',
        'pool_backup_restore_bad_name': 'Restore failed: the file does not exist or its name is invalid',
        'pool_backup_restore_invalid_backup': 'Restore failed: the file is not a valid SQLite database',
        'pool_backup_restore_wal_locked': 'Restore failed: cannot remove the original database WAL sidecar files (another process may still hold the database)',
        'pool_backup_restore_verify_failed': 'Restore failed: the restored database failed verification and was rolled back',
        'pool_backup_restore_error': 'Restore failed: {}',
        'pool_autostart_source_switched': 'Proxy source switched to the pool, starting it automatically',
        'pool_autostart_required': 'Config requires the built-in pool, starting it automatically',
        'pool_autostart_skipped': 'The current proxy source does not use the built-in pool, skipping pool start',
        'pool_error_http_status': 'Pool returned abnormal status code: {}',
        'pool_error_connect': 'Cannot connect to pool: {}',
        'pool_error_timeout': 'Pool request timeout',
        'pool_error_invalid_format': 'Invalid proxy format from pool: {}',
        'port_in_use': 'Port {} is already in use by another program, please choose a different port and retry',
        'web_port_in_use': 'Web panel port {} is already in use by another program, please change web_port in config.ini and restart',
        'access_ok': '[OK] client {} upstream {} target {} {} {}ms status {}',
        'access_failed': '[FAIL] client {} upstream {} target {} {} {}ms status {} reason {}',
        'access_aborted': '[ABORT] client {} upstream {} target {} {} {}ms status {} reason {}',
        'access_direct': 'direct',
        'access_unknown': 'unknown',
        'access_incomplete': 'request not completed (client disconnected or cancelled)',
        'access_tunnel_no_data': 'tunnel established but upstream returned no data (client got no response)',
        'access_tunnel_idle': 'tunnel established, client disconnected without sending data',
        'access_tunnel_client_left': 'tunnel established, client gave up before any upstream data',
        'access_tunnel_closed_by_upstream': 'tunnel established, upstream closed without sending data',
        'proxy_silent_upstream': 'Proxy {} accepted CONNECT but sent no data within {}s; marked unusable and health-checked',
        'domain_stats_cleared': 'Cleared access statistics for {} domains',
        'access_outcome_success': 'Success',
        'access_outcome_failure': 'Failure',
        'access_outcome_aborted': 'Aborted',
        'access_records_cleared': 'Cleared {} access records',
        'access_records_bad_outcome': 'Invalid outcome filter (must be one of success, failure, aborted): {}',
        'access_records_bad_format': 'Invalid export format (must be csv or json): {}',
        'pool_geo_update_task_created': 'Geo database update task created',
        'pool_geo_recompute_disabled': 'Geo resolver is not enabled, cannot recompute',
        'pool_geo_recompute_task_created': 'Geo recompute task created',
        'pool_plugin_enabled': 'Plugin {} enabled',
        'pool_plugin_disabled': 'Plugin {} disabled',
        'pool_plugin_enable_failed': 'Failed to enable plugin: {}',
        'pool_plugin_disable_failed': 'Failed to disable plugin: {}',
        'pool_plugin_not_loaded': 'Plugin {} is not loaded',
        'pool_plugin_interval_set': 'Plugin {} interval set to {} minutes',
        'pool_plugin_interval_failed': 'Failed to set the plugin interval: {}',
        'pool_plugin_test_url_set': 'Test URL of plugin {} set to {}',
        'pool_plugin_test_url_inherited': 'Test URL of plugin {} restored to inherit the global URL',
        'pool_plugin_test_url_failed': 'Failed to set the plugin test URL: {}',
        'pool_plugin_validation_set': 'Validation policy of plugin {} updated',
        'pool_plugin_validation_failed': 'Failed to set the plugin validation policy: {}',
        'pool_plugin_run_task_created': 'Fetch task created for plugin {}',
        'pool_plugin_reload_success': 'Plugin {} reloaded successfully',
        'pool_plugin_reload_rejected': 'Failed to reload plugin {} (it may be running or the file does not exist)',
        'pool_plugin_reload_failed': 'Hot reload failed: {}',
        'pool_no_matching_proxies': 'No proxies match the filter',
        'pool_proxy_not_found': 'Proxy not found',
        'config_option_invalid': 'Invalid option {} (current value: {}): {}',
        'config_reason_expected_int': 'expected an integer',
        'config_reason_expected_float': 'expected a decimal number',
        'config_reason_expected_bool': 'expected a boolean (true/false)',
        'config_reason_expected_comma_list': 'expected at least one comma-separated value',
        'config_reason_expected_value': 'expected at least one value',
        'config_reason_min': 'must not be less than {}',
        'config_reason_max': 'must not be greater than {}',
        'config_reason_expected_choice': 'must be one of {}',
        'config_reason_expected_ip': 'must be one or two valid IP addresses (at most one IPv4 and one IPv6, comma-separated)',
        'config_reason_expected_url': 'must be a full http/https URL, or empty to use the built-in addresses',
        'config_reason_derived_key': 'this option is derived from the [Server] section and cannot be set separately',
        'config_reason_unknown_key': 'not an editable option',
        'config_reason_users_via_api': 'manage user accounts through the user management API',

        'task_stage_prescreen_text': 'Checking port reachability...',
        'task_stage_validate_text': 'Validating proxies...',
        'task_stage_ingest_text': 'Storing directly (ingest validation is off for this plugin)...',
        'task_cancelled_with_counts': 'Task cancelled, {}',
        'task_failed': 'Task failed: {}',
        'task_counts_saved_unusable': '{} stored, {} unusable',
        'task_plugin_run_done': 'Plugin {} finished, {}',
        'task_validating': 'Validating proxies...',
        'task_validate_selected_done': 'Done, valid: {}/{}',
        'task_inconclusive_suffix': ', {} inconclusive (detection chain issue)',
        'task_validate_all_done': 'Done, {} proxies checked',
        'task_inconclusive_among_suffix': ', {} of them inconclusive (detection chain issue)',
        'task_validate_failed': 'Validation failed: {}',
        'task_no_proxies_to_validate': 'No proxies need validating',
        'task_checking': 'Running a full check...',
        'task_pool_empty': 'The pool has no proxies yet',
        'task_check_done': 'Check finished, {} proxies processed',
        'task_check_failed': 'Check failed: {}',
        'task_plugin_fetching': 'Fetching plugin {}... (up to about {} minutes with many sources)',
        'task_plugin_no_new_proxies': 'Plugin {} finished without new proxies',
        'task_plugin_fetch_cancelled': 'Fetch task for plugin {} cancelled, {}',
        'task_plugin_failed': 'Plugin {} failed: {}',
        'task_geo_downloading': 'Downloading the offline geo databases...',
        'task_geo_downloading_file': 'Downloading {} ({}%)',
        'task_geo_update_cancelled': 'Geo database update cancelled',
        'task_geo_update_failed': 'Update failed: {}',
        'task_geo_update_done': 'Geo databases updated',
        'task_geo_update_partial': 'Some files failed to update ({}), the rest are up to date',
        'task_geo_recompute_disabled': 'The geo resolver is not enabled, cannot recompute',
        'task_geo_picking': 'Picking records to recompute...',
        'task_geo_nothing_to_recompute': 'No records need recomputing',
        'task_geo_queued': '{} exit IPs queued for resolution...',
        'task_geo_resolving': 'Resolving geo {}/{}',
        'task_geo_recompute_cancelled': 'Geo recompute cancelled (already resolved parts are kept)',
        'task_geo_recompute_failed': 'Recompute failed: {}',
        'task_geo_recompute_done': 'Geo recompute finished, {} exit IPs processed',
        'ingest_summary_candidates': '{} candidates',
        'ingest_summary_prescreened_out': '{} unreachable',
        'ingest_summary_validated': '{} validated',
        'ingest_summary_saved': '{} stored',
        'ingest_summary_invalid': '{} unusable',
        'ingest_summary_incomplete': '{} incomplete',
        'ingest_summary_inconclusive': '{} inconclusive',
        'ingest_summary_failed': '{} failed',
        'list_separator': ', ',

        'config_body_must_be_json': 'The request body must be a JSON object',
        'proxies_must_be_list': 'The proxy list must be an array',
        'config_sections_must_be_json': 'Both server and pool must be JSON objects',
        'config_nothing_to_save': 'Nothing to save',
        'ip_list_type_invalid': 'Type must be whitelist or blacklist',
        'log_category_unknown': 'Unknown log category',
        'log_file_missing': 'Log file does not exist',
        'log_file_name_invalid': 'Invalid log file name: {}',
        'log_file_read_failed': 'Failed to read the log file: {}',
        'credential_name_required': 'Credential name is required',
        'credential_saved': 'Credential saved',
        'credential_deleted': 'Credential deleted',
        'credential_switched': 'Credential switched',
        'credential_not_found': 'Credential not found: {}',
        'unknown_action': 'Unknown action',
        'no_current_proxy': 'none',
        'service_thread_still_running': 'the previous service thread did not exit within the timeout, please retry later',
        'service_stop_timeout': 'the service did not stop within the timeout',

        'param_invalid_protocol': 'Unsupported protocol: {}',
        'param_invalid_status': 'Unsupported status: {}',
        'param_negative_min_delay': 'Minimum delay cannot be negative: {}',
        'param_negative_max_delay': 'Maximum delay cannot be negative: {}',
        'param_delay_range_reversed': 'Minimum delay cannot exceed maximum delay: {} > {}',
        'param_negative_min_health': 'Minimum health score cannot be negative: {}',
        'param_invalid_anonymity': 'Unsupported anonymity level: {}',
        'param_invalid_export_format': 'Unsupported format: {}; only {} are supported',
        'param_invalid_validation_mode': 'Unsupported validation mode: {} (must be one of {})',
        'param_page_must_be_positive': 'Page number must be greater than 0: {}',
        'param_page_size_must_be_positive': 'Page size must be greater than 0: {}',
        'param_page_size_too_large': 'Page size cannot exceed {}: {}',
        'param_limit_must_be_positive': 'limit must be greater than 0: {}',
        'param_limit_too_large': 'limit cannot exceed {}: {}',
        'param_proxy_list_empty': 'The proxy list cannot be empty',
        'param_proxy_ids_empty': 'The proxy ID list cannot be empty',
        'param_body_must_be_json': 'The request body must be a JSON object',
        'param_missing_fields': 'Missing required parameters: {}',
        'param_interval_must_be_positive': 'The run interval must be greater than 0 minutes: {}',
        'param_reval_interval_not_int': 'Re-validation interval must be an integer: {}',

        'pool_not_running': 'The proxy pool is not running',
        'pool_stopped': 'The proxy pool has stopped',
        'access_reason_bad_target': 'Invalid target address: {}',
        'access_reason_direct_failed': 'Could not connect directly to the target: {}',
        'pool_call_timeout': 'Pool call timed out ({} s)',
        'pool_not_enabled': 'The proxy pool is not enabled',
        'getip_api_error_code': 'the API returned error000x-13',

        'csv_col_protocol': 'Protocol', 'csv_col_ip': 'IP', 'csv_col_port': 'Port',
        'csv_col_username': 'Username', 'csv_col_password': 'Password',
        'csv_col_proxy_url': 'Proxy URL', 'csv_col_region': 'Region',
        'csv_col_delay_ms': 'Delay (ms)', 'csv_col_status': 'Status',
        'csv_col_real_ip': 'Exit IP', 'csv_col_source': 'Source',
        'csv_col_validated_at': 'Validated at',
        'csv_status_valid': 'valid', 'csv_status_invalid': 'invalid',
        'csv_col_time': 'Time', 'csv_col_kind': 'Kind', 'csv_col_method': 'Method',
        'csv_col_client_ip': 'Client IP', 'csv_col_client_user': 'Client user',
        'csv_col_host': 'Host', 'csv_col_upstream': 'Upstream proxy',
        'csv_col_outcome': 'Outcome', 'csv_col_status_code': 'Status code',
        'csv_col_elapsed': 'Elapsed (ms)', 'csv_col_reason': 'Reason',

        'plugin_error_bad_return_type': 'unexpected return type',
        'plugin_error_timeout': 'execution timed out',
        'plugin_error_bad_spec': 'invalid module spec',
        'plugin_error_missing_interface': 'required interface not implemented',
        'pool_field_protocol_required': 'Protocol is required',
        'pool_field_protocol_unsupported': 'Unsupported protocol: {}',
        'pool_field_ip_required': 'IP address is required',
        'pool_field_port_invalid': 'Invalid port: {}',
        'pool_field_source_required': 'Source plugin is required',
        'pool_field_update_not_allowed': 'Fields that may not be updated: {}',
        'pool_field_where_not_allowed': 'Fields that may not be used as update conditions: {}',
        'pool_field_is_valid_invalid': 'Invalid is_valid value: {}',
        'pool_field_anonymity_invalid': 'Invalid anonymity level: {}',
        'pool_field_plugin_name_required': 'Plugin name is required',
        'pool_field_plugin_interval_invalid': 'Run interval must be greater than 0: {}',
        'pool_field_reval_interval_invalid': 'Re-validation interval cannot be negative: {}',
        'pool_repo_integrity_error': 'Proxy data integrity error: {}',
        'pool_repo_plugin_integrity_error': 'Plugin config data integrity error: {}',
        'pool_repo_query_build_failed': 'Query build failed: {}',
        'pool_random_proxy_bad_format': 'format must be json or text',
        'pool_import_no_valid_proxy': 'No valid proxies to import',
        'pool_import_duplicated': 'All proxies already exist, none imported',
        'pool_import_validating': 'Validating {} proxies in the background; only working ones are saved',
        'pool_favorite_added': 'Proxy added to favorites',
        'pool_favorite_removed': 'Proxy removed from favorites',
        'pool_validation_task_created': 'Validation task created',
        'pool_full_check_task_created': 'Full proxy check task created',
        'pool_validation_no_valid_proxy': 'No valid proxies to validate',
        'pool_validating_proxies': 'Validating {} proxies',
        'pool_no_invalid_proxies': 'No invalid proxies to delete',
        'pool_invalid_proxies_deleted': 'Deleted {} invalid proxies',
        'pool_proxies_deleted': 'Deleted {} proxies',
        'pool_task_not_found': 'Task not found',
        'pool_task_already_finished': 'The task has already finished, nothing to cancel',
        'pool_task_cancelled': 'Task cancelled',
    }
}

class MessageManager:

    def __init__(self, messages=MESSAGES):
        self.messages = messages
        self.default_lang = 'cn'

    def get(self, key, lang='cn', *args):
        try:
            return self.messages[lang][key].format(*args) if args else self.messages[lang][key]
        except KeyError:
            return self.messages[self.default_lang][key] if key in self.messages[self.default_lang] else key

message_manager = MessageManager(MESSAGES)
get_message = message_manager.get


def enable_safe_console_output() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors='replace')
        except (AttributeError, ValueError, OSError):
            continue

MODE_BY_SOURCE = {
    'local': ('cycle', 'loadbalance'),
    'api': ('request', 'continuous'),
    'pool': ('request', 'continuous'),
}


def normalize_rotation_mode(mode, source_mode) -> str:
    allowed = MODE_BY_SOURCE.get(str(source_mode or '').strip().lower(),
                                 MODE_BY_SOURCE['api'])
    text = str(mode or '').strip().lower()
    return text if text in allowed else allowed[0]


def mode_display_text(config, language) -> str:
    source = str(config.get('proxy_source_mode', 'local')).strip().lower()
    return get_message(normalize_rotation_mode(config.get('mode'), source), language)


def print_banner(config):
    language = config.get('language', 'cn').lower()

    users = config.get('Users') or {}
    has_auth = bool(users)
    auth_info = "、".join(users.keys()) if has_auth else get_message('auth_not_set', language)

    http_addr = f"http://<用户>:<密码>@127.0.0.1:{config.get('port')}" if has_auth else f"http://127.0.0.1:{config.get('port')}"
    socks5_addr = f"socks5://<用户>:<密码>@127.0.0.1:{config.get('port')}" if has_auth else f"socks5://127.0.0.1:{config.get('port')}"
    
    banner_info = [
        (get_message('public_account', language), '樱花庄的本间白猫'),
        (get_message('blog', language), 'https://y.shironekosan.cn'),
        (get_message('proxy_mode', language), mode_display_text(config, language)),
        (get_message('proxy_interval', language), f"{config.get('interval')}{get_message('seconds', language)}"),
        (get_message('default_auth', language), auth_info),
        (get_message('local_http', language), http_addr),
        (get_message('local_socks5', language), socks5_addr),
        (get_message('star_project', language), 'https://github.com/honmashironeko/ProxyCat'),
    ]
    print(f"{Fore.MAGENTA}{'=' * 55}")
    for key, value in banner_info:
        print(f"{Fore.YELLOW}{key}: {Fore.GREEN}{value}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}{'=' * 55}\n")

    display_level = config.get('display_level', '1')
    if int(display_level) >= 2:
        print(f"\n{Fore.CYAN}{get_message('display_level_desc', language)}{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.CYAN}{get_message('display_level_notice', language).format(display_level)}{Style.RESET_ALL}")

DEFAULT_CONFIG = {
    'port': '1080',
    'mode': 'cycle',
    'interval': '300',
    'proxy_source_mode': 'local',
    'api_proxy_url': 'http://example.com/getip',
    'pool_remote_url': '',
    'version_check_url': '',

    'proxy_file': 'ip.txt',
    'check_proxies_on_startup': 'True',
    'check_proxies_on_use': 'True',
    'check_concurrency': '50',
    'whitelist_file': 'whitelist.txt',
    'blacklist_file': 'blacklist.txt',
    'ip_auth_priority': 'whitelist',
    'language': 'cn',
    'display_level': '1',

    'log_level': 'INFO',
    'log_max_bytes': '10485760',
    'log_access_enabled': 'true',
    'log_backup_count': '3',

    'domain_stats_enabled': 'true',
    'domain_stats_flush_interval': '15',
    'domain_stats_retention_days': '30',

    'access_records_enabled': 'true',
    'access_records_flush_interval': '5',
    'access_records_retention_days': '7',
    'access_records_max_rows': '200000',
    'access_records_buffer_size': '20000',
    'access_records_real_ip_probe': 'false',

    'web_port': '5001',
    'token': '',
    'proxy_username': '',
    'proxy_password': '',
    'test_url': 'https://www.baidu.com',
    'request_interval': '0',
    'bypass_whitelist_file': 'bypass_whitelist.txt',

    'switch_cooldown': '2',
    'proxy_check_ttl': '60',
    'check_cooldown': '10',
    'proxy_failure_cooldown': '3',
    'tunnel_idle_timeout': '10',
    'buffer_size': '8192',
    'max_concurrent_requests': '1000',
    'max_pool_size': '500',
    'max_concurrent_per_proxy': '0',
    'auto_expand_enabled': 'true',
    'exit_count': '5',
    'exit_wait_timeout': '15',
    'client_max_connections': '1000',
    'client_max_keepalive': '8',
    'client_keepalive_expiry': '30',
    'client_idle_timeout': '300'
}

DEPRECATED_SERVER_KEYS = frozenset({
    'check_proxies',
    'getip_url',
    'pool_autostart',
    'pool_port',
    'pool_proxy_url',
    'pool_web_url',
    'pool_proxy_count',
})


def migrate_pool_proxy_count(config_file: str) -> bool:
    try:
        config = ini_parser()
        config.read_string(read_config_text(os.path.abspath(str(config_file))))
        if not config.has_section('Server'):
            return False
        old_value = config.get('Server', 'pool_proxy_count', fallback='').strip()
        new_value = config.get('Server', 'exit_count', fallback='').strip()
        if not old_value or new_value:
            return False
    except Exception as e:
        logging.warning(f"迁移 pool_proxy_count 时读取配置失败（已跳过）: {e}")
        return False

    if not update_ini_keys(config_file, 'Server', {'exit_count': old_value}):
        return False
    logging.info(f"已把 pool_proxy_count = {old_value} 迁移为 exit_count")
    return True


def migrate_getip_url(config_file: str) -> bool:
    try:
        config = ini_parser()
        config.read_string(read_config_text(os.path.abspath(str(config_file))))
        if not config.has_section('Server'):
            return False
        legacy_value = config.get('Server', 'getip_url', fallback='').strip()
        if not legacy_value:
            return False
    except Exception as e:
        logging.warning(f"迁移 getip_url 时读取配置失败（已跳过）: {e}")
        return False

    if not update_ini_keys(config_file, 'Server',
                           {'api_proxy_url': legacy_value, 'getip_url': ''}):
        return False
    logging.info("已把 getip_url 合并进 api_proxy_url 并清空"
                 "（两者语义相同，合并后不再有「接口与凭据错配」）")
    return True


def strip_deprecated_server_keys(config_file: str) -> bool:
    try:
        removed = remove_ini_keys(config_file, 'Server', DEPRECATED_SERVER_KEYS)
    except OSError as e:
        logging.warning(f"清理废弃配置项时读写配置失败（已跳过）: {e}")
        return False
    except Exception as e:
        logging.warning(f"清理废弃配置项时读取配置失败（已跳过）: {e}")
        return False

    if not removed:
        return False

    logging.info(f"已从 [Server] 段清除 {len(removed)} 个废弃配置项: {', '.join(sorted(removed))}")
    return True


def remove_ini_keys(path, section: str, keys) -> list:
    target = os.path.abspath(str(path))
    original = read_config_text(target)

    lines = original.splitlines(keepends=True)
    span = _ini_section_span(lines, section)
    if span is None:
        return []

    start, end = span
    wanted = {str(key) for key in keys}
    removed = []
    kept = []

    for i, line in enumerate(lines):
        if start < i < end:
            stripped = line.lstrip()
            if stripped and not stripped.startswith(('#', ';')) and '=' in line:
                key = line.split('=', 1)[0].strip()
                if key in wanted:
                    removed.append(key)
                    continue
        kept.append(line)

    if not removed:
        return []

    write_text_atomic(target, ''.join(kept))
    return removed


TRUE_WORDS = frozenset({"1", "true", "yes", "on"})
FALSE_WORDS = frozenset({"0", "false", "no", "off"})


def render_config_error(key: str, value: Any, reason_key: str, reason_args: tuple,
                         language: str) -> str:
    reason = get_message(reason_key, language, *reason_args)
    return get_message('config_option_invalid', language, key, str(value), reason)


def parse_bool_lenient(value, default: bool = False) -> bool:
    text = str(value).strip().lower()
    if text in TRUE_WORDS:
        return True
    if text in FALSE_WORDS:
        return False
    return default


def parse_int_lenient(value, default: int, *, low: int) -> int:
    try:
        parsed = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    return parsed if parsed >= low else default


def write_text_atomic(path, text: str) -> None:
    import tempfile

    directory = os.path.dirname(os.path.abspath(str(path)))
    fd, temp_path = tempfile.mkstemp(dir=directory, prefix='.config-', suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        _copy_file_mode(str(path), temp_path)
        os.replace(temp_path, str(path))
    except BaseException:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise


def _copy_file_mode(source, target) -> None:
    try:
        os.chmod(target, os.stat(source).st_mode & 0o7777)
    except OSError:
        pass


def ini_parser() -> ConfigParser:
    parser = ConfigParser(interpolation=None)
    parser.optionxform = str
    return parser


def read_config_text(path) -> str:
    with open(os.path.abspath(str(path)), 'rb') as handle:
        raw = handle.read()

    try:
        return _universal_newlines(raw.decode('utf-8-sig'))
    except UnicodeDecodeError as utf8_error:
        local = locale.getpreferredencoding(False) or ''
        if local.replace('_', '-').lower() in ('utf-8', 'utf8', 'cp65001', 'ascii'):
            raise
        try:
            text = raw.decode(local)
        except (UnicodeDecodeError, LookupError):
            raise utf8_error
        logging.warning(
            "%s 不是 UTF-8 编码，已按系统代码页 %s 读取；"
            "请用编辑器另存为 UTF-8，避免后续内容被误读",
            path, local,
        )
        return _universal_newlines(text)


def _universal_newlines(text: str) -> str:
    return text.replace('\r\n', '\n').replace('\r', '\n')


_INI_SECTION_HEADER = re.compile(r'^\s*\[[^\]]+\]\s*$')


def _ini_section_span(lines: list, section: str):
    header = re.compile(rf'^\s*\[{re.escape(section)}\]\s*$')
    start = next((i for i, line in enumerate(lines) if header.match(line)), None)
    if start is None:
        return None
    end = len(lines)
    for i in range(start + 1, len(lines)):
        if _INI_SECTION_HEADER.match(lines[i]):
            end = i
            break
    return start, end


def _line_ending(line: str) -> str:
    if line.endswith('\r\n'):
        return '\r\n'
    if line.endswith('\n'):
        return '\n'
    return '\n'


def update_ini_keys(path, section: str, updates) -> bool:
    target = os.path.abspath(str(path))
    original = read_config_text(target)

    lines = original.splitlines(keepends=True)
    span = _ini_section_span(lines, section)

    if span is None:
        block = f'[{section}]\n' + ''.join(
            f'{key} = {value}\n' for key, value in updates.items()
        )
        head = original.rstrip('\n')
        updated = f'{head}\n\n{block}' if head else block
    else:
        start, end = span
        remaining = dict(updates)
        for i in range(start + 1, end):
            line = lines[i]
            if line.lstrip().startswith(('#', ';')) or '=' not in line:
                continue
            key = line.split('=', 1)[0].strip()
            if key in remaining:
                lines[i] = f'{key} = {remaining.pop(key)}{_line_ending(line)}'

        for key, value in remaining.items():
            insert_at = end
            while insert_at > start + 1 and not lines[insert_at - 1].strip():
                insert_at -= 1
            lines.insert(insert_at, f'{key} = {value}\n')
            end += 1

        updated = ''.join(lines)

    if updated == original:
        return False

    write_text_atomic(target, updated)
    return True


def _trim_section_tail(lines: list, start: int, end: int) -> int:
    content_end = end
    while content_end > start + 1:
        stripped = lines[content_end - 1].strip()
        if stripped and not stripped.startswith(('#', ';')):
            break
        content_end -= 1
    return content_end


def write_ini_section(path, section: str, entries) -> bool:
    target = os.path.abspath(str(path))
    original = read_config_text(target)

    lines = original.splitlines(keepends=True)
    span = _ini_section_span(lines, section)

    if not entries:
        if span is None:
            return False
        start, end = span
        del lines[start:_trim_section_tail(lines, start, end)]
        updated = ''.join(lines)
    else:
        block = f'[{section}]\n' + ''.join(
            f'{key} = {value}\n' for key, value in entries.items()
        ) + '\n'
        if span is None:
            head = original.rstrip('\n')
            updated = f'{head}\n\n{block}' if head else block
        else:
            start, end = span
            content_end = _trim_section_tail(lines, start, end)
            updated = ''.join(lines[:start]) + block + ''.join(lines[content_end:])

    if updated == original:
        return False

    write_text_atomic(target, updated)
    return True


class NoPoolConsoleFilter(logging.Filter):

    POOL_LOGGER_PREFIXES = (
        "core.",
        "plugin.",
        "modules.proxypool_service",
        "modules.proxypool_api",
        "modules.pool_config_ini",
    )

    def filter(self, record):
        return not record.name.startswith(self.POOL_LOGGER_PREFIXES)


def port_in_use(port, host='127.0.0.1', timeout=0.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, int(port))) == 0
    except Exception:
        return False


def load_config(config_file='config/config.ini'):
    try:
        config = ini_parser()
        if os.path.exists(config_file):
            config.read_string(read_config_text(config_file))

        if not config.has_section('Server'):
            config.add_section('Server')
            for key, value in DEFAULT_CONFIG.items():
                if not config.has_option('Server', key):
                    config.set('Server', key, str(value))

        result = {key.lower(): value for key, value in config.items('Server')}

        if config.has_section('Users'):
            result['Users'] = dict(config.items('Users'))
        
        return result
    except Exception as e:
        logging.error(f"Error loading config: {e}")
        return DEFAULT_CONFIG.copy()

def load_ip_list(file_path):
    try:
        if os.path.exists(file_path):
            return set(
                line.strip() for line in read_config_text(file_path).splitlines()
                if line.strip() and not line.strip().startswith('#')
            )
    except Exception as e:
        logging.error(f"Error loading IP list: {e}")
    return set()


def load_bypass_whitelist(file_path):
    try:
        if os.path.exists(file_path):
            return set(line.strip() for line in read_config_text(file_path).splitlines()
                       if line.strip() and not line.strip().startswith('#'))
    except Exception as e:
        logging.error(f"加载代理绕过白名单失败: {e}")
    return set()


def check_bypass_match(host, bypass_list):
    if not bypass_list or not host:
        return False
    normalized_host = str(host).strip().lower()
    for pattern in bypass_list:
        pattern = pattern.strip()
        if not pattern:
            continue
        if fnmatch.fnmatchcase(normalized_host, pattern.lower()):
            return True
    return False


def list_files_snapshot(server) -> dict:
    snapshot = {}
    for path in (server.whitelist_file, server.blacklist_file,
                 server.bypass_whitelist_file):
        try:
            snapshot[path] = os.path.getmtime(path)
        except OSError:
            snapshot[path] = 0
    return snapshot


def reload_ip_lists_if_changed(server, snapshot: dict) -> dict:
    current = list_files_snapshot(server)
    if current != snapshot:
        server.reload_ip_lists()
    return current

_proxy_check_cache = {}
_proxy_check_ttl = 10
_proxy_check_max_size = 1000
_proxy_check_cache_lock = threading.Lock()

_proxy_cache_clean_interval = 10.0
_last_proxy_cache_clean = 0.0


def _clean_proxy_cache():
    global _last_proxy_cache_clean
    current_time = time.time()
    if current_time - _last_proxy_cache_clean < _proxy_cache_clean_interval:
        return
    _last_proxy_cache_clean = current_time

    expired_keys = [
        k for k, (cache_time, _) in _proxy_check_cache.items()
        if current_time - cache_time >= _proxy_check_ttl
    ]
    for k in expired_keys:
        del _proxy_check_cache[k]
    if len(_proxy_check_cache) > _proxy_check_max_size:
        excess = len(_proxy_check_cache) - int(_proxy_check_max_size * 0.8)
        oldest_keys = sorted(
            _proxy_check_cache.keys(),
            key=lambda k: _proxy_check_cache[k][0]
        )[:excess]
        for k in oldest_keys:
            del _proxy_check_cache[k]

def split_host_port(value: str, default_port=None):
    text = value.strip()
    port_text = ''
    if text.startswith('['):
        host, closed, rest = text[1:].partition(']')
        if not closed:
            raise ValueError(f'IPv6 字面量缺少闭合方括号: {value}')
        if rest and not rest.startswith(':'):
            raise ValueError(f'IPv6 字面量后只能是端口: {value}')
        port_text = rest[1:]
    else:
        head, sep, tail = text.rpartition(':')
        if not sep or ':' in head:
            host = text
        else:
            host, port_text = head, tail

    if not port_text:
        if default_port is None:
            raise ValueError(f'缺少端口: {value}')
        return host, default_port
    if not port_text.isdigit():
        raise ValueError(f'端口不是数字: {value}')
    return host, int(port_text)

def parse_proxy_url(proxy):
    protocol, separator, remaining = proxy.partition('://')
    if not separator:
        raise ValueError(f'缺少协议: {proxy}')
    auth = None
    if '@' in remaining:
        auth, remaining = remaining.rsplit('@', 1)
    host, port = split_host_port(remaining)
    return protocol, auth, host, port


def parse_proxy(proxy):
    try:
        return parse_proxy_url(proxy)
    except Exception:
        return None, None, None, None

def format_proxy_url(protocol, host, port, auth=None):
    host_text = f'[{host}]' if ':' in host else host
    if auth:
        return f'{protocol}://{auth}@{host_text}:{port}'
    return f'{protocol}://{host_text}:{port}'


def sanitize_proxy(proxy: str) -> str:
    if not proxy:
        return ''
    text = str(proxy)
    if '@' not in text:
        return text

    scheme, _, rest = text.rpartition('://')
    credentials, _, host = rest.rpartition('@')
    if not credentials:
        return text

    user = credentials.split(':', 1)[0]
    masked = f"{user}:***" if ':' in credentials else credentials
    return f"{scheme}://{masked}@{host}" if scheme else f"{masked}@{host}"

async def check_http_proxy(proxy, test_url=None):
    if test_url is None:
        test_url = 'https://www.baidu.com'
    protocol, auth, host, port = parse_proxy(proxy)
    url = format_proxy_url(protocol, host, port, auth)
    proxies = {'http://': url, 'https://': url}

    try:
        async with httpx.AsyncClient(proxies=proxies, timeout=10, verify=False,
                                     trust_env=False) as client:
            try:
                response = await client.get(test_url, follow_redirects=True)
                return response.status_code < 400
            except (httpx.HTTPError, OSError, asyncio.TimeoutError):
                if test_url.startswith('https://'):
                    http_url = 'http://' + test_url[8:]
                    try:
                        response = await client.get(http_url, follow_redirects=True)
                        return response.status_code < 400
                    except (httpx.HTTPError, OSError, asyncio.TimeoutError):
                        pass
                return False
    except (httpx.HTTPError, OSError, asyncio.TimeoutError):
        return False

def build_socks5_auth_packet(username: str, password: str) -> bytes:
    username_bytes = username.encode()
    password_bytes = password.encode()
    for label, raw in (('用户名', username_bytes), ('密码', password_bytes)):
        if not 1 <= len(raw) <= 255:
            raise ValueError(f'SOCKS5 {label}长度须为 1-255 字节，实际 {len(raw)}')
    return (b'\x01' + bytes([len(username_bytes)]) + username_bytes +
            bytes([len(password_bytes)]) + password_bytes)


async def check_socks_proxy(proxy, test_url=None):
    if test_url is None:
        test_url = 'https://www.baidu.com'
    protocol, auth, host, port = parse_proxy(proxy)
    if not all([host, port]):
        return False

    writer = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)

        if auth:
            writer.write(b'\x05\x02\x00\x02')
        else:
            writer.write(b'\x05\x01\x00')

        await writer.drain()

        auth_method = await asyncio.wait_for(reader.readexactly(2), timeout=5)
        if auth_method[0] != 0x05:
            return False

        if auth_method[1] == 0x02 and auth:
            username, password = auth.split(':', 1)
            writer.write(build_socks5_auth_packet(username, password))
            await writer.drain()

            auth_response = await asyncio.wait_for(reader.readexactly(2), timeout=5)
            if auth_response[1] != 0x00:
                return False

        from urllib.parse import urlparse
        parsed = urlparse(test_url)
        domain = (parsed.hostname or test_url).encode()
        target_port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        writer.write(
            b'\x05\x01\x00\x03'
            + bytes([len(domain)])
            + domain
            + target_port.to_bytes(2, 'big')
        )
        await writer.drain()

        head = await asyncio.wait_for(reader.readexactly(4), timeout=5)
        atyp = head[3]
        if atyp == 0x01:
            tail = await asyncio.wait_for(reader.readexactly(6), timeout=5)
        elif atyp == 0x04:
            tail = await asyncio.wait_for(reader.readexactly(18), timeout=5)
        elif atyp == 0x03:
            length = await asyncio.wait_for(reader.readexactly(1), timeout=5)
            tail = length + await asyncio.wait_for(
                reader.readexactly(length[0] + 2), timeout=5)
        else:
            return False

        return head[1] == 0x00

    except Exception:
        return False
    finally:
        await _close_socks_writer(writer)


async def _close_socks_writer(writer) -> None:
    if writer is None:
        return
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass

async def check_proxy(proxy, test_url=None):
    test_url = test_url or 'https://www.baidu.com'
    current_time = time.time()
    cache_key = f"{proxy}:{test_url}"

    with _proxy_check_cache_lock:
        _clean_proxy_cache()
        if cache_key in _proxy_check_cache:
            cache_time, is_valid = _proxy_check_cache[cache_key]
            if current_time - cache_time < _proxy_check_ttl:
                return is_valid

    proxy_type = proxy.split('://')[0]
    check_funcs = {
        'http': check_http_proxy,
        'https': check_http_proxy,
        'socks5': check_socks_proxy
    }

    if proxy_type not in check_funcs:
        return False

    try:
        is_valid = await check_funcs[proxy_type](proxy, test_url)
        with _proxy_check_cache_lock:
            _proxy_check_cache[cache_key] = (current_time, is_valid)
        return is_valid
    except Exception as e:
        logger.debug(f"代理检测异常（不写缓存，下次重试） {sanitize_proxy(proxy)}: {e}")
        return False

DEFAULT_CHECK_CONCURRENCY = 50


async def check_proxies(proxies, test_url=None, concurrency=DEFAULT_CHECK_CONCURRENCY):
    if not proxies:
        return []

    limit = max(1, int(concurrency))
    semaphore = asyncio.Semaphore(limit)

    async def check_one(proxy):
        async with semaphore:
            return proxy if await check_proxy(proxy, test_url) else None

    chunk_size = max(1, limit * 4)
    results = []
    for start in range(0, len(proxies), chunk_size):
        chunk = proxies[start:start + chunk_size]
        results.extend(await asyncio.gather(*(check_one(p) for p in chunk)))
    return [proxy for proxy in results if proxy is not None]
