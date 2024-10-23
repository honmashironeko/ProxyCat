from colorama import Fore

def print_banner(config):
    auth_info = f"{config.get('username')}:{config.get('password')}" if config.get('username') and config.get('password') else "未设置 (无需认证)"
    banner_info = [
        ('公众号', '樱花庄的本间白猫'),
        ('博客', 'https://y.shironekosan.cn'),
        ('代理轮换模式', '循环' if config.get('mode') == 'cycle' else '负载均衡' if config.get('mode') == 'load_balance' else '单轮'),
        ('代理更换时间', f"{config.get('interval')}秒"),
        ('默认账号密码', auth_info),
        ('本地监听地址 (HTTP)', f"http://{auth_info + '@' if auth_info else ''}127.0.0.1:{config.get('port')}"),
        ('本地监听地址 (SOCKS5)', f"socks5://{auth_info + '@' if auth_info else ''}127.0.0.1:{config.get('port')}"),
        ('开源项目求 Star', 'https://github.com/honmashironeko/ProxyCat'),
    ]
    print(f"{Fore.MAGENTA}{'=' * 55}")
    for key, value in banner_info:
        print(f"{Fore.YELLOW}{key}: {Fore.GREEN}{value}")
    print(f"{Fore.MAGENTA}{'=' * 55}\n")
