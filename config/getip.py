from modules.modules import get_message, load_config
import requests

first_run_flag = True

def newip():
    global first_run_flag
    config = load_config()
    language = config.get('language', 'cn')

    def handle_error(error_type, details=None):
        error_msg = 'whitelist_error' if error_type == 'whitelist' else 'proxy_file_not_found'
        print(get_message(error_msg, language, str(details)))
        raise ValueError(f"{error_type}: {details}")

    try:
        if first_run_flag:
            appKey = ""
            anquanma = ""
            whitelist_url = f"https://sch.shanchendaili.com/api.html?action=addWhiteList&appKey={appKey}&anquanma={anquanma}"
            requests.get(whitelist_url).raise_for_status()
            first_run_flag = False

        url = config.get('getip_url', '')
        username = config.get('proxy_username', '')
        password = config.get('proxy_password', '')
        
        if not url:
            raise ValueError('getip_url')
            
        response = requests.get(url)
        response.raise_for_status()
        proxy = response.text.split("\r\n")[0]
        
        if username and password:
            return f"socks5://{username}:{password}@{proxy}"
        return f"socks5://{proxy}"
        
    except requests.RequestException as e:
        handle_error('request', e)
    except ValueError as e:
        handle_error('config', e)
    except Exception as e:
        handle_error('unknown', e)


