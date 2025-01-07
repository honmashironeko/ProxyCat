![ProxyCat](https://socialify.git.ci/honmashironeko/ProxyCat/image?description=1&descriptionEditable=A%20lightweight%20and%20excellent%20proxy%20pool%20middleware%20that%20implements%20automatic%20proxy%20rotation&font=Bitter&forks=1&issues=1&language=1&logo=https%3A%2F%2Favatars.githubusercontent.com%2Fu%2F139044047%3Fv%3D4&name=1&owner=1&pattern=Circuit%20Board&pulls=1&stargazers=1&theme=Dark)

<p align="center">
  <a href="/README-EN.md">English</a>
  ·
  <a href="/README.md">简体中文</a>
</p>

## Table of Contents

- [Development Background](#development-background)
- [Features](#features)
- [Installation and Usage](#installation-and-usage)
  - [Dependencies Installation](#dependencies-installation)
  - [Running the Tool](#running-the-tool)
  - [Manual Proxy Entry](#iptxt-manual-proxy-entry)
  - [Configuration File](#configuration-file)
  - [Demo Effect](#demo-effect)
  - [Using API for Automatic Proxy Retrieval](#using-api-for-automatic-proxy-retrieval)
- [Docker Deployment](#docker-deployment)
- [Performance](#performance)
- [Disclaimer](#disclaimer)
- [Change Log](#change-log)
- [Development Plan](#development-plan)
- [Acknowledgments](#acknowledgments)
- [Proxy Recommendations](#proxy-recommendations)

## Development Background

During penetration testing, it's often necessary to hide or change IP addresses to bypass security devices. However, tunnel proxies in the market are expensive, typically costing $3-6 per day, which is unaffordable for many. The author noticed that short-term IPs offer high cost-effectiveness, with each IP costing just a few cents, averaging $0.03-0.4 per day.

Therefore, **ProxyCat** was born! This tool aims to transform short-term IPs (lasting from 1 to 60 minutes) into fixed IPs for other tools to use, creating a proxy pool server that can be used permanently after one deployment.

![Project Principle](./assets/项目原理图.png)

## Features

- **Dual Protocol Support**: Supports both SOCKS5 and HTTP protocol listening, compatible with more tools.
- **Multiple Proxy Protocols**: Supports HTTP/HTTPS/SOCKS5 proxy servers to meet various application needs.
- **Multiple Switching Modes**: Cycles through each proxy in the list sequentially; randomly selects available proxies to distribute traffic load and improve performance. Allows users to customize proxy selection logic for specific needs.
- **Function-based Proxy Retrieval**: Supports dynamic proxy retrieval through GetIP function for real-time availability.
- **Automatic Validity Detection**: Automatically detects proxy availability at startup to filter invalid proxies.
- **Switch Only During Proxy Forwarding**: Changes to new proxy server only when timer reaches zero and new requests arrive.
- **Proxy Failure Switching**: Automatically switches to new proxy if current proxy fails during traffic forwarding.
- **Proxy Pool Authentication**: Supports username/password-based authentication and blacklist/whitelist mechanisms.
- **Real-time Status Updates**: Displays current proxy status and next switch time.
- **Configurable File**: Easily adjust port, mode, authentication info via config.ini.
- **Version Detection**: Built-in version checking for automatic updates.

## Installation and Usage

### Dependencies Installation

The tool is based on Python, recommended version **Python 3.8** or above. Install dependencies using:

```bash
pip install -r requirements.txt
# Or using Chinese mirror:
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple/
```

### Running the Tool

Run the following command in the project directory to view help information:

```bash
python3 ProxyCat.py -h
```

Success is indicated by this response:

```
      |\      _,,,---,,_  by honmashironeko
ZZZzz /,`.-'`'    -.  ;-;;,_
     |,4-  ) )-,_. ,\ (  `'-'
    '---''(_/--'  `-'\_)  ProxyCat

Usage: ProxyCat.py [-h] [-c]

Parameters:
  -h, --help  Show this help message and exit
  -c C        Specify config file name (default: config.ini)
```

### ip.txt Manual Proxy Entry

Add proxies to `ip.txt` in the following format (`socks5://127.0.0.1:7890` or `http://127.0.0.1:7890`), one per line:

```txt
socks5://127.0.0.1:7890
https://127.0.0.1:7890
http://127.0.0.1:7890
...
```

### Configuration File

Configure parameters in `config.ini` (or custom config file):

```ini
[SETTINGS]
# Local server listening port (default: 1080)
port = 1080

# Proxy rotation mode: cycle, custom, or load_balance (default: cycle)
mode = cycle

# Proxy change interval in seconds, 0 means change every request (default: 300)
interval = 300

# Local server authentication username (default: neko) empty means no auth
username = neko

# Local server authentication password (default: 123456) empty means no auth
password = 123456

# Whether to use getip module for proxy retrieval True/False (default: False)
use_getip = False

# Proxy list file (default: ip.txt)
proxy_file = ip.txt

# Enable proxy checking True/False (default: True)
check_proxies = True

# Language setting (cn/en)
language = en

# IP whitelist file path (empty to disable)
whitelist_file = whitelist.txt

# IP blacklist file path (empty to disable)
blacklist_file = blacklist.txt

# IP authentication priority (whitelist/blacklist)
# whitelist: Check whitelist first, allow if in whitelist
# blacklist: Check blacklist first, deny if in blacklist
ip_auth_priority = whitelist
```

After configuration, run:

```bash
python3 ProxyCat.py
```

### Demo Effect

**Fixed proxy address (default)**:

```
http://neko:123456@127.0.0.1:1080
http://127.0.0.1:1080 
socks5://neko:123456@127.0.0.1:1080
socks5://127.0.0.1:1080 
```

If you're deploying on a public network, simply replace `127.0.0.1` with your public IP.

![主界面图](./assets/主界面图.png)

### Using API for Automatic Proxy Retrieval

The tool supports direct API calls to obtain proxy addresses. When you configure `use_getip = True`, the tool will no longer read from local `ip.txt` but instead execute **getip.py** script to obtain new proxy addresses (ensure your IP is whitelisted, and the format should be IP:port, only one proxy address can be used each time).

In this case, you need to modify the content of **getip.py** to your own API, with format `IP:PORT`. Default protocol is `socks5`, manually change to `http` if needed.

### Docker Deployment

Please install Docker and Docker-compose in advance. You can search for installation methods online.

```
# Clone the project source code locally
git clone https://github.com/honmashironeko/ProxyCat.git

# Modify the content in the config.ini file in the config folder

# Enter the ProxyCat folder, build the image and start the container
docker-compose up -d --build

# Stop and start the service (you need to restart the service after modifying the configuration each time)
docker-compose down | docker-compose up -d

# View log information
docker logs proxycat-app-1
```

## Performance

Through actual testing, when proxy server performance is sufficient, ProxyCat can handle **1000** concurrent connections without packet loss, covering most scanning and penetration testing needs.

![性能测试图](./assets/性能测试图.png)

## Disclaimer

- By downloading, installing, using, or modifying this tool and related code, you indicate your trust in this tool.
- We take no responsibility for any form of loss or damage caused to yourself or others while using this tool.
- You are solely responsible for any illegal activities during your use of this tool, and we bear no legal or associated liability.
- Please carefully read and fully understand all terms, especially liability exemption or limitation clauses, and choose to accept or not.
- Unless you have read and accepted all terms of this agreement, you have no right to download, install, or use this tool.
- Your download, installation, and usage actions indicate you have read and agreed to be bound by the above agreement.

## Change Log

### 2025/01/07

- Added caching mechanism to proxy detection module to prevent frequent checks
- Optimized error handling and logging

### 2025/01/03

- Centralized configuration parameters management into config files for better maintenance
- Fixed known bugs and improved stability and concurrency capabilities

### 2025/01/02

- Restructured software architecture for better usability
- Added blacklist/whitelist mechanism for authentication
- GetIP method now only requests proxy after receiving first request to prevent resource waste
- Changed language configuration logic, now controlled via config.ini parameter
- Updated configuration panel, addresses can be copied without username/password
- Added docker deployment support

### 2024/10/23

- Restructured code, split into separate files
- Added automatic proxy switching when current proxy fails during forwarding

### 2024/09/29

- Removed less-used single cycle mode, replaced with custom mode for customizable proxy switching logic
- Changed proxy validity checking to asynchronous for better speed
- Removed problematic SOCKS4 protocol support
- Beautified logging system
- Improved exception handling logic
- Added proxy format validation

### 2024/09/10

- Optimized concurrency efficiency, supporting next request before receiving response
- Added load balancing mode for random proxy selection and concurrent proxy usage
- Changed proxy validity checking to asynchronous for better efficiency

### 2024/09/09

- Added option to validate proxies in ip.txt at startup
- Function downgrade to support lower Python versions

### 2024/09/03

- Added local SOCKS5 listening for wider software compatibility
- Changed some functions to support lower Python versions
- Beautified output display

### 2024/08/31

- Major project structure adjustment
- Beautified display with continuous proxy switch time indication
- Added Ctrl+C support for stopping
- Major adjustment to async requests, improved concurrency efficiency
- Changed from runtime parameters to local ini config file
- Added support for local authentication-free mode
- Added version detection
- Added proxy server authentication
- Added GetIP update only on request feature
- Added proxy protocol auto-detection
- Added HTTPS protocol support
- Changed asyncio.timeout() to asyncio.wait_for() for lower Python version support

[Additional change log entries follow similar pattern...]

## Development Plan

- [x] Added local server authentication
- [x] Added IP change per request feature
- [x] Added static proxy auto-update module
- [x] Added load balancing mode
- [x] Added version detection
- [x] Added proxy authentication support
- [x] Added request-triggered getip updates
- [x] Added initial proxy validity check
- [x] Added SOCKS protocol support
- [ ] Add detailed logging with multi-user support
- [ ] Add Web UI interface
- [x] Add docker deployment
- [ ] Develop babycat module

For feedback or suggestions, please contact via WeChat Official Account: **樱花庄的本间白猫**

## Acknowledgments

In no particular order, thanks to:

- [AabyssZG](https://github.com/AabyssZG)
- [ProbiusOfficial](https://github.com/ProbiusOfficial)
- [gh0stkey](https://github.com/gh0stkey)
- chars6
- qianzai
- ziwindlu

![Star History Chart](https://api.star-history.com/svg?repos=honmashironeko/ProxyCat&type=Date)

## Proxy Recommendations

- [First affordable proxy service - Get 5000 free IPs + ¥10 coupon with invite code](https://h.shanchendaili.com/invite_reg.html?invite=fM6fVG)
- [Various carrier data plans](https://172.lot-ml.com/ProductEn/Index/0b7c9adef5e9648f)
- [Click here to purchase](https://www.ipmart.io?source=Shironeko)
