import asyncio, logging, random, httpx, re, os, time, threading
from collections import deque
from configparser import ConfigParser
from packaging import version
from colorama import Fore, Style

class ColoredFormatter(logging.Formatter):
    COLORS = {
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT,
    }

    def format(self, record):
        log_color = self.COLORS.get(record.levelno, Fore.WHITE)
        record.msg = f"{log_color}{record.msg}{Style.RESET_ALL}"
        return super().format(record)

MESSAGES = {
    'cn': {
        'getting_new_proxy': '正在获取新的代理IP',
        'new_proxy_is': '新的代理IP为: {}',
        'proxy_check_start': '开始检测代理地址...',
        'proxy_check_disabled': '代理检测已禁用',
        'valid_proxies': '有效代理地址: {}',
        'no_valid_proxies': '没有有效的代理地址',
        'proxy_check_failed': '{}代理 {} 检测失败: {}',
        'proxy_switch': '切换代理: {} -> {}',
        'proxy_consecutive_fails': '代理 {} 连续失败 {} 次，正在切换新代理',
        'proxy_invalid': '代理 {} 无效，立即切换代理',
        'proxy_failure': '代理检测失败: {}',
        'proxy_failure_threshold': '代理无效，开始切换',
        'proxy_check_error': '代理检查时发生错误: {}',
        'connection_timeout': '连接超时',
        'data_transfer_timeout': '数据传输超时，正在重试...',
        'connection_reset': '连接被重置',
        'transfer_cancelled': '传输被取消',
        'data_transfer_error': '数据传输错误: {}',
        'unsupported_protocol': '不支持的协议请求: {}',
        'client_error': '客户端处理出错: {}',
        'response_write_error': '响应写入错误: {}',
        'server_closing': '服务器正在关闭...',
        'program_interrupted': '程序被用户中断',
        'multiple_proxy_fail': '多次尝试获取有效代理失败，退出程序',
        'current_proxy': '当前代理',
        'next_switch': '下次切换',
        'seconds': '秒',
        'no_proxies_available': '没有可用的代理',
        'proxy_file_not_found': '代理文件不存在: {}',
        'auth_not_set': '未设置 (无需认证)',
        'public_account': '公众号',
        'blog': '博客',
        'proxy_mode': '代理轮换模式',
        'cycle': '循环',
        'loadbalance': '负载均衡',
        'single_round': '单轮',
        'proxy_interval': '代理更换时间',
        'default_auth': '默认账号密码',
        'local_http': '本地监听地址 (HTTP)',
        'local_socks5': '本地监听地址 (SOCKS5)',
        'star_project': '开源项目求 Star',
        'client_handle_error': '客户端处理错误: {}',
        'proxy_invalid_switch': '代理无效，切换代理',
        'request_fail_retry': '请求失败，重试剩余次数: {}',
        'user_interrupt': '用户中断程序',
        'new_version_found': '发现新版本！',
        'visit_quark': '夸克网盘: https://pan.quark.cn/s/39b4b5674570',
        'visit_github': 'GitHub: https://github.com/honmashironeko/ProxyCat',
        'visit_baidu': '百度网盘: https://pan.baidu.com/s/1C9LVC9aiaQeYFSj_2mWH1w?pwd=13r5',
        'latest_version': '当前已是最新版本',
        'version_info_not_found': '未找到版本信息',
        'update_check_error': '检查更新失败: {}',
        'unauthorized_ip': '未授权的IP尝试访问: {}',
        'client_cancelled': '客户端连接已取消',
        'socks5_connection_error': 'SOCKS5连接错误: {}',
        'connect_timeout': '连接超时',
        'connection_reset': '连接被重置',
        'transfer_cancelled': '传输已取消',
        'client_request_error': '客户端请求错误: {}',
        'unsupported_protocol': '不支持的协议: {}',
        'request_retry': '请求失败，重试中 (剩余{}次)',
        'response_write_error': '写入响应时出错: {}',
        'consecutive_failures': '检测到连续代理失败: {}',
        'invalid_proxy': '当前代理无效: {}',
        'whitelist_error': '添加白名单失败: {}',
        'api_mode_notice': '当前为API模式，收到请求将自动获取代理地址',
        'server_running': '代理服务器运行在 {}:{}',
        'server_start_error': '服务器启动错误: {}',
        'server_shutting_down': '正在关闭服务器...',
        'client_process_error': '处理客户端请求时出错: {}',
        'request_handling_error': '请求处理错误: {}',
        'proxy_forward_error': '代理转发错误: {}',
        'data_transfer_timeout': '{}数据传输超时',
        'data_transfer_error': '{}数据传输错误: {}',
        'status_update_error': '状态更新出错',
        'display_level_notice': '当前显示级别: {}',
        'display_level_desc': '''显示级别说明:
0: 仅显示代理切换和错误信息
1: 显示代理切换、倒计时和错误信息
2: 显示所有详细信息''',
        'new_client_connect': '新客户端连接 - IP: {}, 用户: {}',
        'no_auth': '无认证',
        'connection_error': '连接处理错误: {}',
        'cleanup_error': '清理IP错误: {}',
        'port_changed': '端口已更改: {} -> {}，需要重启服务器生效',
        'config_updated': '服务器配置已更新',
        'load_proxy_file_error': '加载代理文件失败: {}',
        'proxy_check_result': '代理检查完成，有效代理：{}个',
        'no_proxy': '无代理',
        'cycle_mode': '循环模式',
        'loadbalance_mode': '负载均衡模式',
        'proxy_check_start': '开始检查代理...',
        'proxy_check_complete': '代理检查完成',
        'proxy_save_success': '代理保存成功',
        'proxy_save_failed': '代理保存失败: {}',
        'ip_list_save_success': 'IP名单保存成功',
        'ip_list_save_failed': 'IP名单保存失败: {}',
        'switch_success': '代理切换成功',
        'switch_failed': '代理切换失败: {}',
        'service_start_success': '服务启动成功',
        'service_start_failed': '服务启动失败',
        'service_already_running': '服务已在运行',
        'service_stop_success': '服务停止成功',
        'service_not_running': '服务未在运行',
        'service_restart_success': '服务重启成功',
        'service_restart_failed': '服务重启失败',
        'invalid_action': '无效的操作',
        'operation_failed': '操作失败: {}',
        'logs_cleared': '日志已清除',
        'clear_logs_failed': '清除日志失败: {}',
        'unsupported_language': '不支持的语言',
        'language_changed': '语言已切换为{}',
        'loading': '加载中...',
        'get_proxy_failed': '获取新代理失败: {}',
        'log_level_all': '全部',
        'log_level_info': '信息',
        'log_level_warning': '警告',
        'log_level_error': '错误',
        'log_level_critical': '严重错误',
        'confirm_clear_logs': '确定要清除所有日志吗？此操作不可恢复。',
        'language_label': '语言',
        'chinese': '中文',
        'english': 'English',
        'manual_switch_btn': '手动切换',
        'service_control_title': '服务控制',
        'language_switch_success': '',
        'language_switch_failed': '',
        'refresh_failed': '刷新数据失败: {}',
        'auth_username_label': '认证用户名',
        'auth_password_label': '认证密码',
        'proxy_auth_username_label': '代理认证用户名',
        'proxy_auth_password_label': '代理认证密码',
        'progress_bar_label': '切换进度',
        'proxy_settings_title': '代理设置',
        'config_save_success': '配置保存成功',
        'config_save_failed': '配置保存失败：{}',
        'config_restart_required': '配置已更改，需要重启服务器生效',
        'confirm_restart_service': '是否立即重启服务器？',
        'service_status': '服务状态',
        'running': '运行中',
        'stopped': '已停止',
        'restarting': '重启中',
        'unknown': '未知',
        'service_start_failed': '服务启动失败：{}',
        'service_stop_failed': '服务停止失败：{}',
        'service_restart_failed': '服务重启失败：{}',
        'invalid_token': '无效的访问令牌',
        'config_file_changed': '检测到配置文件更改，正在重新加载...',
        'proxy_file_changed': '代理文件已更改，正在重新加载...',
        'test_target_label': '测试目标地址',
        'invalid_test_target': '无效的测试目标地址',
        'users_save_success': '用户保存成功',
        'users_save_failed': '用户保存失败：{}',
        'user_management_title': '用户管理',
        'username_column': '用户名',
        'password_column': '密码',
        'actions_column': '操作',
        'add_user_btn': '添加用户',
        'enter_username': '请输入用户名',
        'enter_password': '请输入密码',
        'confirm_delete_user': '确定要删除该用户吗？',
        'no_logs_found': '未找到匹配的日志',
        'clear_search': '清除搜索',
        'web_panel_url': '网页控制面板地址: {}',
        'web_panel_notice': '请使用浏览器访问上述地址来管理代理服务器',
        'api_proxy_settings_title': 'API代理设置',
        'all_retries_failed': '所有重试均已失败，最后错误: {}',
        'proxy_get_failed': '获取代理失败',
        'proxy_get_error': '获取代理错误: {}',
        'request_error': '请求错误: {}',
        'proxy_switch_error': '代理切换错误: {}',
    },
    'en': {
        'getting_new_proxy': 'Getting new proxy IP',
        'new_proxy_is': 'New proxy IP is: {}',
        'proxy_check_start': 'Starting proxy check...',
        'proxy_check_disabled': 'Proxy check is disabled',
        'valid_proxies': 'Valid proxies: {}',
        'no_valid_proxies': 'No valid proxies found',
        'proxy_check_failed': '{} proxy {} check failed: {}',
        'proxy_switch': 'Switch proxy: {} -> {}',
        'proxy_consecutive_fails': 'Proxy {} failed {} times consecutively, switching to new proxy',
        'proxy_invalid': 'Proxy {} is invalid, switching proxy immediately',
        'proxy_failure': 'Proxy check failed: {}',
        'proxy_failure_threshold': 'Proxy invalid, switching now',
        'proxy_check_error': 'Error occurred during proxy check: {}',
        'connection_timeout': 'Connection timeout',
        'data_transfer_timeout': 'Data transfer timeout, retrying...',
        'connection_reset': 'Connection reset',
        'transfer_cancelled': 'Transfer cancelled',
        'data_transfer_error': 'Data transfer error: {}',
        'unsupported_protocol': 'Unsupported protocol request: {}',
        'client_error': 'Client handling error: {}',
        'response_write_error': 'Response write error: {}',
        'server_closing': 'Server is closing...',
        'program_interrupted': 'Program interrupted by user',
        'multiple_proxy_fail': 'Multiple attempts to get valid proxy failed, exiting',
        'current_proxy': 'Current Proxy',
        'next_switch': 'Next Switch',
        'seconds': 's',
        'no_proxies_available': 'No proxies available',
        'proxy_file_not_found': 'Proxy file not found: {}',
        'auth_not_set': 'Not set (No authentication required)',
        'public_account': 'WeChat Public Number',
        'blog': 'Blog',
        'proxy_mode': 'Proxy Rotation Mode',
        'cycle': 'Cycle',
        'loadbalance': 'Load Balance',
        'single_round': 'Single Round',
        'proxy_interval': 'Proxy Change Interval',
        'default_auth': 'Default Username and Password',
        'local_http': 'Local Listening Address (HTTP)',
        'local_socks5': 'Local Listening Address (SOCKS5)',
        'star_project': 'Star the Project',
        'client_handle_error': 'Client handling error: {}',
        'proxy_invalid_switch': 'Proxy invalid, switching proxy',
        'request_fail_retry': 'Request failed, retrying remaining times: {}',
        'user_interrupt': 'User interrupted the program',
        'new_version_found': 'New version available!',
        'visit_quark': 'Quark Drive: https://pan.quark.cn/s/39b4b5674570',
        'visit_github': 'GitHub: https://github.com/honmashironeko/ProxyCat',
        'visit_baidu': 'Baidu Drive: https://pan.baidu.com/s/1C9LVC9aiaQeYFSj_2mWH1w?pwd=13r5',
        'latest_version': 'You are using the latest version',
        'version_info_not_found': 'Version information not found',
        'update_check_error': 'Failed to check for updates: {}',
        'unauthorized_ip': 'Unauthorized IP attempt: {}',
        'client_cancelled': 'Client connection cancelled',
        'socks5_connection_error': 'SOCKS5 connection error: {}',
        'connect_timeout': 'Connection timeout',
        'connection_reset': 'Connection reset',
        'transfer_cancelled': 'Transfer cancelled',
        'data_transfer_error': 'Data transfer error: {}',
        'client_request_error': 'Client request handling error: {}',
        'unsupported_protocol': 'Unsupported protocol: {}',
        'request_retry': 'Request failed, retrying ({} left)',
        'request_error': 'Error during request: {}',
        'response_write_error': 'Error writing response: {}',
        'consecutive_failures': 'Consecutive proxy failures detected for {}',
        'invalid_proxy': 'Current proxy is invalid: {}',
        'whitelist_error': 'Failed to add whitelist: {}',
        'api_mode_notice': 'Currently in API mode, proxy address will be automatically obtained upon request',
        'all_retries_failed': 'All retries failed, last error: {}',
        'proxy_get_failed': 'Failed to get proxy',
        'proxy_get_error': 'Error getting proxy: {}',
        'proxy_switch_error': 'Error switching proxy: {}',
        'server_running': 'Proxy server running at {}:{}',
        'server_start_error': 'Server startup error: {}',
        'server_shutting_down': 'Server shutting down...',
        'client_process_error': 'Client processing error: {}',
        'request_handling_error': 'Request handling error: {}',
        'proxy_forward_error': 'Proxy forwarding error: {}',
        'data_transfer_timeout': '{}data transfer timeout',
        'status_update_error': 'Status update error',
        'display_level_notice': 'Current display level: {}',
        'display_level_desc': '''Display level description:
0: Only show proxy switch and error messages
1: Show proxy switch, countdown and error messages
2: Show all detailed information''',
        'new_client_connect': 'New client connection - IP: {}, User: {}',
        'no_auth': 'No authentication',
        'connection_error': 'Connection handling error: {}',
        'cleanup_error': 'Cleanup IP error: {}',
        'port_changed': 'Port changed: {} -> {}, server restart required to take effect',
        'config_updated': 'Server configuration updated',
        'load_proxy_file_error': 'Failed to load proxy file: {}',
        'proxy_check_result': 'Proxy check completed, valid proxies: {}',
        'no_proxy': 'No proxy',
        'cycle_mode': 'Cycle mode',
        'loadbalance_mode': 'Load balance mode',
        'proxy_check_start': 'Starting proxy check...',
        'proxy_check_complete': 'Proxy check completed',
        'proxy_save_success': 'Proxy saved successfully',
        'proxy_save_failed': 'Failed to save proxy: {}',
        'ip_list_save_success': 'IP list saved successfully',
        'ip_list_save_failed': 'Failed to save IP list: {}',
        'switch_success': 'Proxy switched successfully',
        'switch_failed': 'Failed to switch proxy: {}',
        'service_start_success': 'Service started successfully',
        'service_start_failed': 'Failed to start service',
        'service_already_running': 'Service is already running',
        'service_stop_success': 'Service stopped successfully',
        'service_not_running': 'Service is not running',
        'service_restart_success': 'Service restarted successfully',
        'service_restart_failed': 'Failed to restart service',
        'invalid_action': 'Invalid action',
        'operation_failed': 'Operation failed: {}',
        'logs_cleared': 'Logs cleared',
        'clear_logs_failed': 'Failed to clear logs: {}',
        'unsupported_language': 'Unsupported language',
        'language_changed': 'Language changed to {}',
        'loading': 'Loading...',
        'get_proxy_failed': 'Failed to get new proxy: {}',
        'log_level_all': 'All',
        'log_level_info': 'Info',
        'log_level_warning': 'Warning',
        'log_level_error': 'Error',
        'log_level_critical': 'Critical',
        'confirm_clear_logs': 'Are you sure you want to clear all logs? This action cannot be undone.',
        'language_label': 'Language',
        'chinese': 'Chinese',
        'english': 'English',
        'manual_switch_btn': 'Switch Manually',
        'service_control_title': 'Service Control',
        'language_switch_success': 'Language switched successfully',
        'language_switch_failed': 'Failed to switch language',
        'refresh_failed': 'Failed to refresh data: {}',
        'auth_username_label': 'Authentication Username',
        'auth_password_label': 'Authentication Password',
        'proxy_auth_username_label': 'Proxy Authentication Username',
        'proxy_auth_password_label': 'Proxy Authentication Password',
        'progress_bar_label': 'Switch Progress',
        'proxy_settings_title': 'Proxy Settings',
        'config_save_success': 'Configuration saved successfully',
        'config_save_failed': 'Failed to save configuration: {}',
        'config_restart_required': 'Configuration changed, server restart required to take effect',
        'confirm_restart_service': 'Restart server now?',
        'service_status': 'Service Status',
        'running': 'Running',
        'stopped': 'Stopped',
        'restarting': 'Restarting',
        'unknown': 'Unknown',
        'service_start_failed': 'Failed to start service: {}',
        'service_stop_failed': 'Failed to stop service: {}',
        'service_restart_failed': 'Failed to restart service: {}',
        'invalid_token': 'Invalid access token',
        'config_file_changed': 'Config file change detected, reloading...',
        'proxy_file_changed': 'Proxy file changed, reloading...',
        'test_target_label': 'Test Target Address',
        'invalid_test_target': 'Invalid test target address',
        'users_save_success': 'Users saved successfully',
        'users_save_failed': 'Failed to save users: {}',
        'user_management_title': 'User Management',
        'username_column': 'Username',
        'password_column': 'Password',
        'actions_column': 'Actions',
        'add_user_btn': 'Add User',
        'enter_username': 'Please enter username',
        'enter_password': 'Please enter password',
        'confirm_delete_user': 'Are you sure you want to delete this user?',
        'no_logs_found': 'No matching logs found',
        'clear_search': 'Clear Search',
        'web_panel_url': 'Web panel URL: {}',
        'web_panel_notice': 'Please use a browser to access the above URL to manage the proxy server',
        'api_proxy_settings_title': 'API Proxy Settings',
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

def print_banner(config):
    language = config.get('language', 'cn').lower()
    has_auth = config.get('username') and config.get('password')
    auth_info = f"{config.get('username')}:{config.get('password')}" if has_auth else get_message('auth_not_set', language)
    
    http_addr = f"http://{auth_info}@127.0.0.1:{config.get('port')}" if has_auth else f"http://127.0.0.1:{config.get('port')}"
    socks5_addr = f"socks5://{auth_info}@127.0.0.1:{config.get('port')}" if has_auth else f"socks5://127.0.0.1:{config.get('port')}"
    
    banner_info = [
        (get_message('public_account', language), '樱花庄的本间白猫'),
        (get_message('blog', language), 'https://y.shironekosan.cn'),
        (get_message('proxy_mode', language), get_message('cycle', language) if config.get('mode') == 'cycle' else get_message('loadbalance', language) if config.get('mode') == 'loadbalance' else get_message('single_round', language)),
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

logo1 = r"""
      |\      _,,,---,,_  by 本间白猫
ZZZzz /,`.-'`'    -.  ;-;;,_
     |,4-  ) )-,_. ,\ (  `'-'
    '---''(_/--'  `-'\_)  ProxyCat 
"""
logo2 = r"""
             *     ,MMM8&&&.            *
                  MMMM88&&&&&    .
                 MMMM88&&&&&&&
     *           MMM88&&&&&&&&
                 MMM88&&&&&&&&
                 'MMM88&&&&&&'
                   'MMM8&&&'      *    
            /\/|_    __/\\
           /    -\  /-   ~\  .              '
           \    =_YT_ =   /
           /==*(`    `\ ~ \         ProxyCat
          /     \     /    `\      by 本间白猫
          |     |     ) ~   (
         /       \   /     ~ \\
         \       /   \~     ~/
  _/\_/\_/\__  _/_/\_/\__~__/_/\_/\_/\_/\_/\_
  |  |  |  | ) ) |  |  | ((  |  |  |  |  |  |
  |  |  |  |( (  |  |  |  \\ |  |  |  |  |  |
  |  |  |  | )_) |  |  |  |))|  |  |  |  |  | 
  |  |  |  |  |  |  |  |  (/ |  |  |  |  |  |
  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |
"""
logo3 = r"""
        /\_/\         _
       /``   \       / )
       |n n   |__   ( (
      =(Y =.'`   `\  \ \\
       {`"`        \  ) ) 
       {       /    |/ /
        \\   ,(     / /
ProxyCat) ) /-'\  ,_.' by 本间白猫
       (,(,/ ((,,/
"""
logo4 = r"""
                   .-o=o-.
               ,  /=o=o=o=\ .--.
              _|\|=o=O=o=O=|    \\
          __.'  a`\=o=o=o=(`\   /
          '.   a 4/`|.-""'`\ \ ;'`)   .---.
            \   .'  /   .--'  |_.'   / .-._)
 by 本间白猫 `)  _.'   /     /`-.__.' /
  ProxyCat  `'-.____;     /'-.___.-'
                       `\"""`
"""

logos_list = [logo1, logo2, logo3, logo4]
def logos():
    selected_logo = random.choice(logos_list)
    print(selected_logo)

DEFAULT_CONFIG = {
    'port': '1080',
    'mode': 'cycle',
    'interval': '300',
    'username': 'neko',
    'password': '123456',
    'use_getip': 'False',
    'proxy_file': 'ip.txt',
    'check_proxies': 'True',
    'proxy_check_timeout_ms': '2000',
    'auto_check_enabled': 'false',
    'auto_check_interval_minutes': '60',
    'auto_disable_failed_proxies': 'false',
    'whitelist_file': '',
    'blacklist_file': '',
    'ip_auth_priority': 'whitelist',
    'language': 'cn'
}

def load_config(config_file='config/config.ini'):
    try:
        config = ConfigParser()
        config.read(config_file, encoding='utf-8')
        
        if not config.has_section('Server'):
            config.add_section('Server')
            for key, value in DEFAULT_CONFIG.items():
                config.set('Server', key, str(value))
            with open(config_file, 'w', encoding='utf-8') as f:
                config.write(f)
        
        result = dict(config.items('Server'))
        
        if config.has_section('Users'):
            result['Users'] = dict(config.items('Users'))
        
        return result
    except Exception as e:
        logging.error(f"Error loading config: {e}")
        return DEFAULT_CONFIG.copy()

def load_ip_list(file_path):
    try:
        config_path = os.path.join('config', os.path.basename(file_path))
        if os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8') as f:
                return set(line.strip() for line in f if line.strip())
    except Exception as e:
        logging.error(f"Error loading IP list: {e}")
    return set()

_proxy_check_cache = {}
_proxy_check_ttl = 10

# Web UI 共享的检测结果 / 日志（多浏览器同步）
_ui_check_lock = threading.RLock()
_ui_check_results = {}  # normalized proxy -> last result
_ui_check_logs = deque(maxlen=500)
_ui_check_log_id = 0
_ui_check_log_clear_id = 0
_ui_check_revision = 0

# 检测超时安全边界
CHECK_TIMEOUT_MS_MIN = 200
CHECK_TIMEOUT_MS_MAX = 60000
CHECK_TIMEOUT_MS_DEFAULT = 2000

def normalized_check_timeout_ms(value):
    """解析并限幅用户设置的检测超时（毫秒），非法值退回默认值。"""
    try:
        ms = int(float(str(value)))
    except (TypeError, ValueError):
        return CHECK_TIMEOUT_MS_DEFAULT
    if ms < CHECK_TIMEOUT_MS_MIN:
        return CHECK_TIMEOUT_MS_MIN
    if ms > CHECK_TIMEOUT_MS_MAX:
        return CHECK_TIMEOUT_MS_MAX
    return ms


def _normalize_ui_check_proxy_key(proxy):
    """规范化代理地址，用作 UI 检测结果字典键。"""
    key = normalize_proxy_address(proxy or '')
    if key.startswith('#'):
        key = key[1:]
    return key


def record_ui_check_result(proxy, detail, source='api'):
    """保存最近一次检测结果，供所有 Web 客户端同步延迟/状态。"""
    global _ui_check_revision
    key = _normalize_ui_check_proxy_key(proxy)
    if not key:
        return None

    if isinstance(detail, dict):
        valid = bool(detail.get('valid'))
        elapsed_ms = detail.get('elapsed_ms', 0)
        error = detail.get('error')
        error_code = detail.get('error_code')
        timed_out = bool(detail.get('timed_out'))
        test_url = detail.get('test_url')
    else:
        valid = bool(detail)
        elapsed_ms = 0
        error = None if valid else 'probe failed'
        error_code = None if valid else 'probe_failed'
        timed_out = False
        test_url = None

    try:
        elapsed_ms = int(elapsed_ms or 0)
    except (TypeError, ValueError):
        elapsed_ms = 0

    entry = {
        'proxy': key,
        'valid': valid,
        'status': 'ok' if valid else 'fail',
        'elapsed_ms': elapsed_ms,
        'error': error,
        'error_code': error_code,
        'timed_out': timed_out,
        'test_url': test_url,
        'checked_at': time.time(),
        'source': source or 'api',
    }
    with _ui_check_lock:
        _ui_check_results[key] = entry
        _ui_check_revision += 1
        return dict(entry)


def get_ui_check_results():
    with _ui_check_lock:
        return {k: dict(v) for k, v in _ui_check_results.items()}


def append_ui_check_log(message, level='info', source='client'):
    """追加一条检测日志；返回带 id 的条目，便于多浏览器增量同步。"""
    global _ui_check_log_id, _ui_check_revision
    text = str(message or '').strip()
    if not text:
        return None
    level = level if level in ('info', 'ok', 'fail') else 'info'
    now = time.time()
    with _ui_check_lock:
        _ui_check_log_id += 1
        _ui_check_revision += 1
        entry = {
            'id': _ui_check_log_id,
            'ts': now,
            'time': time.strftime('%H:%M:%S', time.localtime(now)),
            'message': text,
            'level': level,
            'source': source or 'client',
        }
        _ui_check_logs.append(entry)
        return dict(entry)


def get_ui_check_logs(since_id=0):
    try:
        since_id = int(since_id or 0)
    except (TypeError, ValueError):
        since_id = 0
    with _ui_check_lock:
        if since_id <= 0:
            return [dict(e) for e in _ui_check_logs]
        return [dict(e) for e in _ui_check_logs if e['id'] > since_id]


def clear_ui_check_logs():
    """清空检测日志（所有浏览器可见）。"""
    global _ui_check_log_clear_id, _ui_check_revision
    with _ui_check_lock:
        _ui_check_logs.clear()
        _ui_check_log_clear_id += 1
        _ui_check_revision += 1
        return _ui_check_log_clear_id


def get_ui_check_state(since_log_id=0):
    """返回检测结果 + 增量日志，供 Web 轮询。"""
    try:
        since_log_id = int(since_log_id or 0)
    except (TypeError, ValueError):
        since_log_id = 0
    with _ui_check_lock:
        if since_log_id <= 0:
            logs = [dict(e) for e in _ui_check_logs]
        else:
            logs = [dict(e) for e in _ui_check_logs if e['id'] > since_log_id]
        return {
            'revision': _ui_check_revision,
            'log_clear_id': _ui_check_log_clear_id,
            'latest_log_id': _ui_check_log_id,
            'results': {k: dict(v) for k, v in _ui_check_results.items()},
            'logs': logs,
        }


# 常见代理协议别名 → 内部标准协议
PROXY_SCHEME_ALIASES = {
    'socks5h': 'socks5',  # curl: DNS 也走代理
    'socks5a': 'socks5',
    'socks': 'socks5',
    'socks4a': 'socks5',  # 引擎仅实现 socks5，降级归并避免直接拒收
    'socks4': 'socks5',
    'http': 'http',
    'https': 'https',
    'socks5': 'socks5',
}

def normalize_proxy_address(proxy):
    """规范化代理地址：去空白、补协议、别名归并（socks5h→socks5 等）。"""
    if proxy is None:
        return ''
    s = str(proxy).strip()
    if not s:
        return ''
    # 禁用项以 # 开头时，规范化时先去掉再由调用方决定是否加回
    disabled = False
    if s.startswith('#'):
        disabled = True
        s = re.sub(r'^#+\s*', '', s).strip()
        if not s:
            return ''

    if '://' not in s:
        s = 'http://' + s

    scheme, rest = s.split('://', 1)
    scheme = scheme.strip().lower()
    scheme = PROXY_SCHEME_ALIASES.get(scheme, scheme)
    rest = rest.strip()
    normalized = f'{scheme}://{rest}'
    return f'#{normalized}' if disabled else normalized

def parse_proxy(proxy):
    try:
        proxy = normalize_proxy_address(proxy)
        if proxy.startswith('#'):
            proxy = proxy[1:]
        if '://' not in proxy:
            return None, None, None, None

        protocol, remaining = proxy.split('://', 1)
        protocol = PROXY_SCHEME_ALIASES.get(protocol.lower(), protocol.lower())

        if '@' in remaining:
            # 只按最后一个 @ 分割，兼容密码中含 : 的情况
            auth, address = remaining.rsplit('@', 1)
        else:
            auth, address = None, remaining

        # host:port —— 从右侧拆端口，兼容将来可能的异常主机写法
        host, port_s = address.rsplit(':', 1)
        host = host.strip()
        # 去掉 IPv6 中括号（若有）
        if host.startswith('[') and host.endswith(']'):
            host = host[1:-1]
        port = int(port_s)
        if not host or not (0 < port < 65536):
            return None, None, None, None
        return protocol, auth, host, port
    except Exception:
        return None, None, None, None

def validate_proxy_format(proxy):
    """格式是否可被引擎接受（会先做别名规范化）。"""
    protocol, auth, host, port = parse_proxy(proxy)
    if protocol not in ('http', 'https', 'socks5'):
        return False
    if not host or port is None:
        return False
    return 0 < int(port) < 65536

def _proxy_url_from_parts(protocol, auth, host, port):
    protocol = PROXY_SCHEME_ALIASES.get((protocol or '').lower(), (protocol or '').lower())
    if auth:
        return f'{protocol}://{auth}@{host}:{port}'
    return f'{protocol}://{host}:{port}'

def _httpx_proxy_kwargs(proxy_url):
    """兼容 httpx 0.27(proxies=) 与 0.28+(proxy=)。"""
    try:
        ver = tuple(int(x) for x in httpx.__version__.split('.')[:2])
    except Exception:
        ver = (0, 28)
    if ver >= (0, 28):
        return {'proxy': proxy_url}
    return {'proxies': {'http://': proxy_url, 'https://': proxy_url, 'all://': proxy_url}}

async def check_http_proxy(proxy, test_url=None, timeout_ms=None):
    if test_url is None:
        test_url = 'https://www.baidu.com'
    timeout_ms = normalized_check_timeout_ms(timeout_ms)
    timeout_sec = timeout_ms / 1000.0
    protocol, auth, host, port = parse_proxy(proxy)
    if not all([protocol, host, port]):
        raise ValueError(f'invalid proxy format: {proxy}')

    proxy_url = _proxy_url_from_parts(protocol, auth, host, port)
    client_kwargs = {
        'timeout': timeout_sec,
        'verify': False,
        'follow_redirects': True,
    }
    client_kwargs.update(_httpx_proxy_kwargs(proxy_url))

    async def _probe():
        async with httpx.AsyncClient(**client_kwargs) as client:
            try:
                response = await client.get(test_url)
                if response.status_code == 200:
                    return True
                if test_url.startswith('https://'):
                    http_url = 'http://' + test_url[8:]
                    response = await client.get(http_url)
                    if response.status_code == 200:
                        return True
                raise RuntimeError(f'HTTP {response.status_code} from {test_url}')
            except Exception as first_err:
                if test_url.startswith('https://'):
                    try:
                        http_url = 'http://' + test_url[8:]
                        response = await client.get(http_url)
                        if response.status_code == 200:
                            return True
                        raise RuntimeError(f'HTTP {response.status_code} from {http_url}') from first_err
                    except Exception:
                        raise first_err
                raise

    return await asyncio.wait_for(_probe(), timeout=timeout_sec)

async def check_socks_proxy(proxy, test_url=None, timeout_ms=None):
    if test_url is None:
        test_url = 'https://www.baidu.com'
    timeout_ms = normalized_check_timeout_ms(timeout_ms)
    timeout_sec = timeout_ms / 1000.0
    protocol, auth, host, port = parse_proxy(proxy)
    if not all([host, port]):
        raise ValueError(f'invalid socks proxy format: {proxy}')

    async def _probe():
        # 优先用 httpx 走 socks（若已安装 socks 扩展），失败再回落手工握手
        proxy_url = _proxy_url_from_parts(protocol or 'socks5', auth, host, port)
        try:
            client_kwargs = {
                'timeout': timeout_sec,
                'verify': False,
                'follow_redirects': True,
            }
            client_kwargs.update(_httpx_proxy_kwargs(proxy_url))
            async with httpx.AsyncClient(**client_kwargs) as client:
                response = await client.get(test_url)
                if response.status_code == 200:
                    return True
                if test_url.startswith('https://'):
                    http_url = 'http://' + test_url[8:]
                    response = await client.get(http_url)
                    if response.status_code == 200:
                        return True
                raise RuntimeError(f'HTTP {response.status_code} via socks proxy')
        except ImportError:
            pass
        except Exception:
            pass

        # SOCKS5 手工握手
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout_sec,
        )
        try:
            if auth:
                writer.write(b'\x05\x02\x00\x02')
            else:
                writer.write(b'\x05\x01\x00')
            await writer.drain()

            auth_method = await asyncio.wait_for(reader.readexactly(2), timeout=timeout_sec)
            if auth_method[0] != 0x05:
                raise RuntimeError('invalid SOCKS5 version in response')

            if auth_method[1] == 0x02 and auth:
                username, password = auth.split(':', 1)
                auth_packet = bytes([0x01, len(username)]) + username.encode() + bytes([len(password)]) + password.encode()
                writer.write(auth_packet)
                await writer.drain()
                auth_response = await asyncio.wait_for(reader.readexactly(2), timeout=timeout_sec)
                if auth_response[1] != 0x00:
                    raise RuntimeError('SOCKS5 authentication failed')
            elif auth_method[1] == 0xFF:
                raise RuntimeError('SOCKS5 no acceptable auth method')

            from urllib.parse import urlparse
            domain = urlparse(test_url).netloc if '://' in test_url else test_url
            domain = domain.split(':')[0].encode()

            writer.write(b'\x05\x01\x00\x03' + bytes([len(domain)]) + domain + b'\x00\x50')
            await writer.drain()
            response = await asyncio.wait_for(reader.readexactly(10), timeout=timeout_sec)
            if response[1] != 0x00:
                raise RuntimeError(f'SOCKS5 connect failed, code={response[1]}')
            return True
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    return await asyncio.wait_for(_probe(), timeout=timeout_sec)

async def check_proxy(proxy, test_url=None, force=False, timeout_ms=None):
    result = await check_proxy_detailed(proxy, test_url=test_url, force=force, timeout_ms=timeout_ms)
    return bool(result.get('valid'))

async def check_proxy_detailed(proxy, test_url=None, force=False, timeout_ms=None):
    """返回 {valid, error, elapsed_ms, timed_out, error_code, proxy, test_url}，供 API/UI 展示真实原因。"""
    timeout_ms = normalized_check_timeout_ms(timeout_ms)
    current_time = time.time()
    test_url = test_url or 'https://www.baidu.com'
    original_proxy = proxy
    proxy = normalize_proxy_address(proxy)
    if proxy.startswith('#'):
        proxy = proxy[1:]
    cache_key = f"{proxy}:{test_url}:{timeout_ms}"
    started = time.time()

    if not force and cache_key in _proxy_check_cache:
        cache_time, cached = _proxy_check_cache[cache_key]
        if current_time - cache_time < _proxy_check_ttl:
            if isinstance(cached, dict):
                return {
                    'valid': bool(cached.get('valid')),
                    'error': cached.get('error'),
                    'timed_out': bool(cached.get('timed_out')),
                    'error_code': cached.get('error_code'),
                    'timeout_ms': timeout_ms,
                    'elapsed_ms': cached.get('elapsed_ms', 0),
                    'proxy': proxy,
                    'input_proxy': original_proxy,
                    'test_url': test_url,
                    'cached': True,
                }
            return {
                'valid': bool(cached),
                'error': None if cached else 'cached failure',
                'timed_out': False,
                'error_code': None,
                'timeout_ms': timeout_ms,
                'elapsed_ms': 0,
                'proxy': proxy,
                'input_proxy': original_proxy,
                'test_url': test_url,
                'cached': True,
            }

    proxy_type = proxy.split('://')[0].lower() if '://' in (proxy or '') else ''
    proxy_type = PROXY_SCHEME_ALIASES.get(proxy_type, proxy_type)
    check_funcs = {
        'http': check_http_proxy,
        'https': check_http_proxy,
        'socks5': check_socks_proxy,
    }

    if proxy_type not in check_funcs:
        result = {
            'valid': False,
            'error': f'unsupported scheme: {proxy_type or "(none)"}',
            'timed_out': False,
            'error_code': 'unsupported_scheme',
            'timeout_ms': timeout_ms,
            'elapsed_ms': int((time.time() - started) * 1000),
            'proxy': proxy,
            'input_proxy': original_proxy,
            'test_url': test_url,
            'cached': False,
        }
        _proxy_check_cache[cache_key] = (time.time(), result)
        return result

    try:
        is_valid = await check_funcs[proxy_type](proxy, test_url, timeout_ms=timeout_ms)
        result = {
            'valid': bool(is_valid),
            'error': None if is_valid else 'probe returned false',
            'timed_out': False,
            'error_code': None if is_valid else 'probe_failed',
            'timeout_ms': timeout_ms,
            'elapsed_ms': int((time.time() - started) * 1000),
            'proxy': proxy,
            'input_proxy': original_proxy,
            'test_url': test_url,
            'cached': False,
        }
        _proxy_check_cache[cache_key] = (time.time(), result)
        return result
    except asyncio.TimeoutError:
        err = f'timeout after {timeout_ms}ms'
        logging.warning(f'proxy check timeout: {proxy} -> {err}')
        result = {
            'valid': False,
            'error': err,
            'timed_out': True,
            'error_code': 'timeout',
            'timeout_ms': timeout_ms,
            'elapsed_ms': int((time.time() - started) * 1000),
            'proxy': proxy,
            'input_proxy': original_proxy,
            'test_url': test_url,
            'cached': False,
        }
        _proxy_check_cache[cache_key] = (time.time(), result)
        return result
    except Exception as e:
        err = f'{type(e).__name__}: {e}'
        logging.warning(f'proxy check failed: {proxy} -> {err}')
        result = {
            'valid': False,
            'error': err,
            'timed_out': False,
            'error_code': 'exception',
            'timeout_ms': timeout_ms,
            'elapsed_ms': int((time.time() - started) * 1000),
            'proxy': proxy,
            'input_proxy': original_proxy,
            'test_url': test_url,
            'cached': False,
        }
        _proxy_check_cache[cache_key] = (time.time(), result)
        return result

async def check_proxies(proxies, test_url=None, timeout_ms=None):
    valid_proxies = []
    for proxy in proxies:
        if await check_proxy(proxy, test_url, timeout_ms=timeout_ms):
            valid_proxies.append(proxy)
    return valid_proxies

async def check_for_updates(language='cn'):
    try:
        async with httpx.AsyncClient() as client:
            response = await asyncio.wait_for(client.get("https://y.shironekosan.cn/1.html"), timeout=10)
            response.raise_for_status()
            content = response.text
            match = re.search(r'<p>(ProxyCat-V\d+\.\d+\.\d+)</p>', content)
            if match:
                latest_version = match.group(1)
                CURRENT_VERSION = "ProxyCat-V2.0.4"
                if version.parse(latest_version.split('-V')[1]) > version.parse(CURRENT_VERSION.split('-V')[1]):
                    print(f"{Fore.YELLOW}{get_message('new_version_found', language)} 当前版本: {CURRENT_VERSION}, 最新版本: {latest_version}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}{get_message('visit_quark', language)}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}{get_message('visit_github', language)}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}{get_message('visit_baidu', language)}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}{get_message('latest_version', language)} ({CURRENT_VERSION}){Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}{get_message('version_info_not_found', language)}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}{get_message('update_check_error', language, e)}{Style.RESET_ALL}")