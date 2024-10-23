from colorama import Fore
from packaging import version
import httpx, asyncio, re

async def check_for_updates():

    try:
        async with httpx.AsyncClient() as client:
            response = await asyncio.wait_for(client.get("https://y.shironekosan.cn/1.html"), timeout=10)
            response.raise_for_status()
            content = response.text
            match = re.search(r'<p>(ProxyCat-V\d+\.\d+)</p>', content)
            if match:
                latest_version = match.group(1)
                CURRENT_VERSION = "ProxyCat-V1.7"
                if version.parse(latest_version.split('-V')[1]) > version.parse(CURRENT_VERSION.split('-V')[1]):
                    print(f"{Fore.YELLOW}发现新版本！当前版本: {CURRENT_VERSION}, 最新版本: {latest_version}")
                    print(f"{Fore.YELLOW}请访问 https://pan.quark.cn/s/39b4b5674570 获取最新版本。")
                    print(f"{Fore.YELLOW}请访问 https://github.com/honmashironeko/ProxyCat 获取最新版本。")
                    print(f"{Fore.YELLOW}请访问 https://pan.baidu.com/s/1C9LVC9aiaQeYFSj_2mWH1w?pwd=13r5 获取最新版本。")
                else:
                    print(f"{Fore.GREEN}当前版本已是最新 ({CURRENT_VERSION})")
            else:
                print(f"{Fore.RED}无法在响应中找到版本信息")
    except Exception as e:
        print(f"{Fore.RED}检查更新时发生错误: {e}")