import requests

def newip():
    print("正在获取新的代理IP")
    url = f""
    response = requests.get(url)
    response.raise_for_status()
    newip = "socks5://"+response.text.split("\n\r")[0]
    print("新的代理IP为:"+newip)
    return newip


