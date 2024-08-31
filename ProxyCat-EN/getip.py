import requests

def newip():
    print("Getting new proxy IP")
    url = f""
    response = requests.get(url)
    response.raise_for_status()
    newip = "socks5://"+response.text.split("\n\r")[0]
    print("The new proxy IP is:"+newip)
    return newip


