from modules.modules import get_message, load_config
import requests

first_run_flag = True

def newip():
    global first_run_flag
    config = load_config()
    language = config.get('language', 'cn')
    try:
        if first_run_flag:
            appKey = ""
            anquanma = ""
            whitelist_url = f"https://sch.shanchendaili.com/api.html?action=addWhiteList&appKey={appKey}&anquanma={anquanma}"
            requests.get(whitelist_url).raise_for_status()
            first_run_flag = False

        url = config.get('getip_url', '')
        if not url:
            raise ValueError('getip_url')
            
        response = requests.get(url)
        response.raise_for_status()
        return "socks5://" + response.text.split("\r\n")[0]
        
    except Exception as e:
        error_msg = 'whitelist_error' if first_run_flag else 'proxy_file_not_found'
        print(get_message(error_msg, language, str(e)))
        raise


