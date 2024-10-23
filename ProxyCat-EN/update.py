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
                    print(f"{Fore.YELLOW}New version found! Current version: {CURRENT_VERSION}, Latest version: {latest_version}")
                    print(f"{Fore.YELLOW}Please visit https://pan.quark.cn/s/39b4b5674570 to get the latest version.")
                    print(f"{Fore.YELLOW}Please visit https://github.com/honmashironeko/ProxyCat to get the latest version.")
                    print(f"{Fore.YELLOW}Please visit https://pan.baidu.com/s/1C9LVC9aiaQeYFSj_2mWH1w?pwd=13r5 to get the latest version.")
                else:
                    print(f"{Fore.GREEN}The current version is up to date ({CURRENT_VERSION})")
            else:
                print(f"{Fore.RED}Unable to find version information in the response")
    except Exception as e:
        print(f"{Fore.RED}An error occurred while checking for updates: {e}")
