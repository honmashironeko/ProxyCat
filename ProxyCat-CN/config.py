import configparser

DEFAULT_CONFIG = {
    'port': 1080,
    'mode': 'cycle',
    'interval': 300,
    'username': '',
    'password': '',
    'use_getip': False,
    'proxy_file': 'ip.txt',
    'check_proxies' : True
}

def load_config(config_file='config.ini'):
    config = configparser.ConfigParser()
    config.read(config_file, encoding='utf-8')
    return {k: v for k, v in config['SETTINGS'].items()}