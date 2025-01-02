from modules.modules import get_message, load_config
import requests

def newip():
    config = load_config()
    language = config.get('language', 'cn')
    print(get_message('getting_new_proxy', language))
    url = f""
    response = requests.get(url)
    response.raise_for_status()
    newip = "socks5://" + response.text.split("\r\n")[0]
    print(get_message('new_proxy_is', language, newip))
    return newip


