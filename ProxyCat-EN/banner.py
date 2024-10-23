from colorama import Fore

def print_banner(config):
    auth_info = f"{config.get('username')}:{config.get('password')}" if config.get('username') and config.get('password') else "Not set (no authentication required)"
    banner_info = [
        ('Public Account', 'Cherry Blossom Manor\'s Main White Cat'),
        ('Blog', 'https://y.shironekosan.cn'),
        ('Proxy Rotation Mode', 'Cycle' if config.get('mode') == 'cycle' else 'Load Balance' if config.get('mode') == 'load_balance' else 'Single Round'),
        ('Proxy Change Interval', f"{config.get('interval')} seconds"),
        ('Default Username and Password', auth_info),
        ('Local Listening Address (HTTP)', f"http://{auth_info + '@' if auth_info else ''}127.0.0.1:{config.get('port')}"),
        ('Local Listening Address (SOCKS5)', f"socks5://{auth_info + '@' if auth_info else ''}127.0.0.1:{config.get('port')}"),
        ('Open Source Project Seeking Star', 'https://github.com/honmashironeko/ProxyCat'),
    ]
    print(f"{Fore.MAGENTA}{'=' * 55}")
    for key, value in banner_info:
        print(f"{Fore.YELLOW}{key}: {Fore.GREEN}{value}")
    print(f"{Fore.MAGENTA}{'=' * 55}\n")
