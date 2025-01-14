import asyncio, logging, random, httpx, re, os, time
from configparser import ConfigParser
from packaging import version
from colorama import Fore

MESSAGES = {
    'cn': {
        'getting_new_proxy': '正在获取新的代理IP',
        'new_proxy_is': '新的代理IP为: {}',
        'proxy_check_start': '开始检测代理地址...',
        'proxy_check_disabled': '代理检测已禁用',
        'valid_proxies': '有效代理地址: {}',
        'no_valid_proxies': '没有有效的代理地址',
        'proxy_check_failed': '{}代理 {} 检测失败: {}',
        'proxy_switch': '切换到新的代理: {}',
        'proxy_switch_detail': '已切换代理: {} -> {}',
        'proxy_consecutive_fails': '代理 {} 连续失败 {} 次，正在切换新代理',
        'proxy_invalid': '代理 {} 已失效，立即切换新代理',
        'connection_timeout': '连接超时',
        'proxy_invalid_switching': '代理地址失效，切换代理地址',
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
        'load_balance': '负载均衡',
        'single_round': '单轮',
        'proxy_interval': '代理更换时间',
        'default_auth': '默认账号密码',
        'local_http': '本地监听地址 (HTTP)',
        'local_socks5': '本地监听地址 (SOCKS5)',
        'star_project': '开源项目求 Star',
        'client_request_error': '客户端请求错误: {}',
        'client_handle_error': '客户端处理错误: {}',
        'proxy_invalid_switch': '代理无效，切换代理',
        'request_fail_retry': '请求失败，重试剩余次数: {}',
        'request_error': '请求错误: {}',
        'user_interrupt': '用户中断程序',
        'new_version_found': '发现新版本！',
        'visit_quark': '请访问 https://pan.quark.cn/s/39b4b5674570 获取最新版本。',
        'visit_github': '请访问 https://github.com/honmashironeko/ProxyCat 获取最新版本。',
        'visit_baidu': '请访问 https://pan.baidu.com/s/1C9LVC9aiaQeYFSj_2mWH1w?pwd=13r5 获取最新版本。',
        'latest_version': '当前版本已是最新',
        'version_info_not_found': '无法在响应中找到版本信息',
        'update_check_error': '检查更新时发生错误: {}',
        'unauthorized_ip': '未授权的IP尝试访问: {}',
        'client_cancelled': '客户端连接已取消',
        'socks5_connection_error': 'SOCKS5连接错误: {}',
        'connect_timeout': '连接超时',
        'connection_reset': '连接被重置',
        'transfer_cancelled': '传输已取消',
        'client_request_error': '客户端请求处理错误: {}',
        'unsupported_protocol': '不支持的协议: {}',
        'proxy_invalid_switch': '代理无效，正在切换',
        'request_retry': '请求失败，重试中 (剩余{}次)',
        'request_error': '请求过程中出错: {}',
        'response_write_error': '写入响应时出错: {}',
        'consecutive_failures': '检测到连续代理失败: {}',
        'invalid_proxy': '当前代理无效: {}',
        'proxy_switched': '已从代理 {} 切换到 {}',
        'whitelist_error': '添加白名单失败: {}'
    },
    'en': {
        'getting_new_proxy': 'Getting new proxy IP',
        'new_proxy_is': 'New proxy IP is: {}',
        'proxy_check_start': 'Starting proxy check...',
        'proxy_check_disabled': 'Proxy check is disabled',
        'valid_proxies': 'Valid proxies: {}',
        'no_valid_proxies': 'No valid proxies found',
        'proxy_check_failed': '{} proxy {} check failed: {}',
        'proxy_switch': 'Switching to new proxy: {}',
        'proxy_switch_detail': 'Switched proxy: {} -> {}',
        'proxy_consecutive_fails': 'Proxy {} failed {} times consecutively, switching to new proxy',
        'proxy_invalid': 'Proxy {} is invalid, switching immediately',
        'connection_timeout': 'Connection timeout',
        'proxy_invalid_switching': 'Proxy invalid, switching to new proxy',
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
        'load_balance': 'Load Balance',
        'single_round': 'Single Round',
        'proxy_interval': 'Proxy Change Interval',
        'default_auth': 'Default Username and Password',
        'local_http': 'Local Listening Address (HTTP)',
        'local_socks5': 'Local Listening Address (SOCKS5)',
        'star_project': 'Star the Project',
        'client_request_error': 'Client request error: {}',
        'client_handle_error': 'Client handling error: {}',
        'proxy_invalid_switch': 'Proxy invalid, switching proxy',
        'request_fail_retry': 'Request failed, retrying remaining times: {}',
        'request_error': 'Request error: {}',
        'user_interrupt': 'User interrupted the program',
        'new_version_found': 'New version found!',
        'visit_quark': 'Please visit https://pan.quark.cn/s/39b4b5674570 to get the latest version.',
        'visit_github': 'Please visit https://github.com/honmashironeko/ProxyCat to get the latest version.',
        'visit_baidu': 'Please visit https://pan.baidu.com/s/1C9LVC9aiaQeYFSj_2mWH1w?pwd=13r5 to get the latest version.',
        'latest_version': 'You are using the latest version',
        'version_info_not_found': 'Version information not found in the response',
        'update_check_error': 'Error occurred while checking for updates: {}',
        'unauthorized_ip': 'Unauthorized IP attempt: {}',
        'client_cancelled': 'Client connection cancelled',
        'socks5_connection_error': 'SOCKS5 connection error: {}',
        'connect_timeout': 'Connection timeout',
        'connection_reset': 'Connection reset',
        'transfer_cancelled': 'Transfer cancelled',
        'data_transfer_error': 'Data transfer error: {}',
        'client_request_error': 'Client request handling error: {}',
        'unsupported_protocol': 'Unsupported protocol: {}',
        'proxy_invalid_switch': 'Proxy invalid, switching',
        'request_retry': 'Request failed, retrying ({} left)',
        'request_error': 'Error during request: {}',
        'response_write_error': 'Error writing response: {}',
        'consecutive_failures': 'Consecutive proxy failures detected for {}',
        'invalid_proxy': 'Current proxy is invalid: {}',
        'proxy_switched': 'Switched from proxy {} to {}',
        'whitelist_error': 'Failed to add whitelist: {}'
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
        (get_message('proxy_mode', language), get_message('cycle', language) if config.get('mode') == 'cycle' else get_message('load_balance', language) if config.get('mode') == 'load_balance' else get_message('single_round', language)),
        (get_message('proxy_interval', language), f"{config.get('interval')}{get_message('seconds', language)}"),
        (get_message('default_auth', language), auth_info),
        (get_message('local_http', language), http_addr),
        (get_message('local_socks5', language), socks5_addr),
        (get_message('star_project', language), 'https://github.com/honmashironeko/ProxyCat'),
    ]
    print(f"{Fore.MAGENTA}{'=' * 55}")
    for key, value in banner_info:
        print(f"{Fore.YELLOW}{key}: {Fore.GREEN}{value}")
    print(f"{Fore.MAGENTA}{'=' * 55}\n")

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
    'whitelist_file': '',
    'blacklist_file': '',
    'ip_auth_priority': 'whitelist',
    'language': 'cn'
}

def load_config(config_file='config/config.ini'):
    config = ConfigParser()
    config.read(config_file, encoding='utf-8')
    
    settings = {}
    if config.has_section('SETTINGS'):
        settings.update(dict(config.items('SETTINGS')))

        for key in ['proxy_file', 'whitelist_file', 'blacklist_file']:
            if key in settings and settings[key]:
                config_dir = os.path.dirname(config_file)
                settings[key] = os.path.join(config_dir, settings[key])
            
    return {**DEFAULT_CONFIG, **settings}

def load_ip_list(file_path):
    if not file_path or not os.path.exists(file_path):
        return set()
    
    with open(file_path, 'r') as f:
        return {line.strip() for line in f if line.strip()}

_proxy_check_cache = {}
_proxy_check_ttl = 10

def parse_proxy(proxy):
    try:
        protocol = proxy.split('://')[0]
        remaining = proxy.split('://')[1]
        
        if '@' in remaining:
            auth, address = remaining.split('@')
            host, port = address.split(':')
            return protocol, auth, host, int(port)
        else:
            host, port = remaining.split(':')
            return protocol, None, host, int(port)
    except Exception:
        return None, None, None, None

async def check_proxy(proxy):
    current_time = time.time()
    if proxy in _proxy_check_cache:
        cache_time, is_valid = _proxy_check_cache[proxy]
        if current_time - cache_time < _proxy_check_ttl:
            return is_valid
            
    proxy_type = proxy.split('://')[0]
    check_funcs = {
        'http': check_http_proxy,
        'https': check_https_proxy,
        'socks5': check_socks_proxy
    }
    
    if proxy_type not in check_funcs:
        return False
    
    try:
        is_valid = await check_funcs[proxy_type](proxy)
        _proxy_check_cache[proxy] = (current_time, is_valid)
        return is_valid
    except Exception as e:
        logging.error(f"{proxy_type.upper()}代理 {proxy} 检测失败: {e}")
        _proxy_check_cache[proxy] = (current_time, False)
        return False

async def check_http_proxy(proxy):
    protocol, auth, host, port = parse_proxy(proxy)
    proxies = {}
    if auth:
        proxies['http://'] = f'{protocol}://{auth}@{host}:{port}'
        proxies['https://'] = f'{protocol}://{auth}@{host}:{port}'
    else:
        proxies['http://'] = f'{protocol}://{host}:{port}'
        proxies['https://'] = f'{protocol}://{host}:{port}'
        
    try:
        async with httpx.AsyncClient(proxies=proxies, timeout=10, verify=False) as client:
            try:
                response = await client.get('https://www.baidu.com')
                return response.status_code == 200
            except:
                response = await client.get('http://www.baidu.com')
                return response.status_code == 200
    except:
        return False

async def check_https_proxy(proxy):
    return await check_http_proxy(proxy)

async def check_socks_proxy(proxy):
    protocol, auth, host, port = parse_proxy(proxy)
    if not all([host, port]):
        return False
        
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
            username, password = auth.split(':')
            auth_packet = bytes([0x01, len(username)]) + username.encode() + bytes([len(password)]) + password.encode()
            writer.write(auth_packet)
            await writer.drain()
            
            auth_response = await asyncio.wait_for(reader.readexactly(2), timeout=5)
            if auth_response[1] != 0x00:
                return False
        
        domain = b"www.baidu.com"
        writer.write(b'\x05\x01\x00\x03' + bytes([len(domain)]) + domain + b'\x00\x50')
        await writer.drain()
        
        response = await asyncio.wait_for(reader.readexactly(10), timeout=5)
        writer.close()
        try:
            await writer.wait_closed()
        except:
            pass
        
        return response[1] == 0x00
        
    except Exception:
        return False

async def check_proxies(proxies):
    valid_proxies = []
    for proxy in proxies:
        if await check_proxy(proxy):
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
                CURRENT_VERSION = "ProxyCat-V1.9.4"
                if version.parse(latest_version.split('-V')[1]) > version.parse(CURRENT_VERSION.split('-V')[1]):
                    print(f"{Fore.YELLOW}{get_message('new_version_found', language)} 当前版本: {CURRENT_VERSION}, 最新版本: {latest_version}")
                    print(f"{Fore.YELLOW}{get_message('visit_quark', language)}")
                    print(f"{Fore.YELLOW}{get_message('visit_github', language)}")
                    print(f"{Fore.YELLOW}{get_message('visit_baidu', language)}")
                else:
                    print(f"{Fore.GREEN}{get_message('latest_version', language)} ({CURRENT_VERSION})")
            else:
                print(f"{Fore.RED}{get_message('version_info_not_found', language)}")
    except Exception as e:
        print(f"{Fore.RED}{get_message('update_check_error', language, e)}")