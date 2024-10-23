![ProxyCat](https://socialify.git.ci/honmashironeko/ProxyCat/image?description=1&descriptionEditable=%E4%B8%80%E6%AC%BE%E8%BD%BB%E9%87%8F%E7%BA%A7%E7%9A%84%E4%BC%98%E7%A7%80%E4%BB%A3%E7%90%86%E6%B1%A0%E4%B8%AD%E9%97%B4%E4%BB%B6%EF%BC%8C%E5%AE%9E%E7%8E%B0%E4%BB%A3%E7%90%86%E7%9A%84%E8%87%AA%E5%8A%A8%E8%BD%AE%E6%8D%A2&font=Bitter&forks=1&issues=1&language=1&logo=https%3A%2F%2Favatars.githubusercontent.com%2Fu%2F139044047%3Fv%3D4&name=1&owner=1&pattern=Circuit%20Board&pulls=1&stargazers=1&theme=Dark)

<p align="center">
  <a href="/ProxyCat-EN/README-EN.md">English</a>
  ·
  <a href="/README.md">简体中文</a>
</p>

## Table of Contents

- [Development Motivation](#development-motivation)
- [Features](#features)
- [Installation and Usage](#installation-and-usage)
  - [Installing Dependencies](#installing-dependencies)
  - [Running the Tool](#running-the-tool)
  - [Manually Entering Proxy Addresses](#manually-entering-proxy-addresses)
  - [Configuration File](#configuration-file)
  - [Demonstration](#demonstration)
  - [Automatically Obtaining Proxy Addresses via API](#automatically-obtaining-proxy-addresses-via-api)
- [Performance](#performance)
- [Disclaimer](#disclaimer)
- [Changelog](#changelog)
- [Development Plan](#development-plan)
- [Acknowledgements](#acknowledgements)
- [Sponsor Open Source](#sponsor-open-source)
- [Recommended Proxies](#recommended-proxies)

## Development Motivation

During penetration testing, it is often necessary to hide or change IP addresses to bypass security devices. However, tunnel proxies available in the market are expensive, typically costing between 20-40 RMB per day, which is unaffordable for many. I noticed that short-lived IPs offer high cost-effectiveness, with each IP costing only a few cents, averaging 0.2-3 RMB per day.

In summary, **ProxyCat** was born! This tool aims to transform short-lived IPs, lasting from 1 minute to 60 minutes, into fixed IPs for use by other tools, forming a proxy pool server that can be deployed once for permanent use.

![项目原理图](./assets/202408260021207-1725093725174-21.png)

## Features

**Upstream multi protocol monitoring**

- **Dual protocol support**: Supports SOCKS5 and HTTP protocol listening, adapts to more tools.

**Multi-Protocol Support**

- **SOCKS5 Proxy**: Supports the SOCKS5 protocol, suitable for various network environments.
- **HTTP/HTTPS Proxy**: Supports HTTP and HTTPS proxies to meet different application scenarios.

**Proxy Rotation Modes**

- **Cycle Mode**: Sequentially cycles through each proxy in the list, ensuring balanced usage.
- **Load Balance Mode**: Randomly selects available proxies to distribute traffic load and enhance performance.
- **Custom Mode**: Allows users to customize proxy selection logic to flexibly meet specific needs.

**Dynamic Proxy Acquisition**

- **Acquire Proxies Using GetIP Function**: Supports dynamically obtaining real-time available proxies through the GetIP function, ensuring the proxies are current and valid.

**Proxy Verification**

- **Automatic Validity Detection**: Automatically checks the availability of proxies at startup, filtering out invalid proxies to ensure the reliability of the proxy list.
- **Supports Multiple Protocols for Verification**: Specifically checks HTTP, HTTPS, and SOCKS5 proxies to improve validation accuracy.
- **Support proxy failure switching**: In the process of forwarding traffic, if the proxy server suddenly fails, it can automatically switch to a new proxy.

**Authentication Mechanism**

- **Username/Password Authentication**: Supports proxy authentication based on username and password to enhance security and prevent unauthorized access.

**High Concurrency Handling**

- **Asynchronous Architecture**: Implements asynchronous processing based on `asyncio`, supporting large-scale concurrent connections suitable for high-traffic demands.

**Logging and Monitoring**

- **Colored Log Output**: Utilizes `colorama` for colored logs, facilitating real-time monitoring and debugging.
- **Real-Time Status Updates**: Displays the current proxy status and the next switch time to help users understand proxy dynamics.

**Flexible Configuration**

- **Configurable Files**: Easily adjust parameters such as port, mode, and authentication information through the `config.ini` file to adapt to different usage scenarios.
- **Command-Line Arguments**: Supports specifying the configuration file path via command-line arguments for increased convenience.

**Automatic Update Checks**

- **Version Detection**: Built-in version detection feature automatically checks for the latest version and notifies users to ensure continuous software optimization.

## Installation and Usage

### Installing Dependencies

The tool is implemented in Python and is recommended to use **Python 3.8** or higher. Before use, configure the dependencies using the following command:

````bash:c:\Users\hoshi\Documents\GitHub\ProxyCat\requirements.txt
pip install -r requirements.txt
# Or recommended to use domestic source:
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple/
````

### Running the Tool

Run the following command in the project directory to view the help information and confirm the configuration is successful:

````bash:c:\Users\hoshi\Documents\GitHub\ProxyCat\ProxyCat.py
python3 ProxyCat.py -h
````

The following output indicates successful configuration:

```
      |\      _,,,---,,_  by Honma Shironeko
ZZZzz /,`.-'`'    -.  ;-;;,_
     |,4-  ) )-,_. ,\ (  `'-'
    '---''(_/--'  `-'\_)  ProxyCat

Usage: ProxyCat.py [-h] [-c]

Parameters:
  -h, --help  Show this help message and exit
  -c C        Specify the configuration file name (default: config.ini)
```

### Manually Entering Proxy Addresses in ip.txt

Enter proxy addresses in the `ip.txt` file in the following format (`socks5://127.0.0.1:7890` or `http://127.0.0.1:7890`), one per line:

````plaintext:c:\Users\hoshi\Documents\GitHub\ProxyCat\ip.txt
socks5://127.0.0.1:7890
https://127.0.0.1:7890
http://127.0.0.1:7890
...
````

### Configuration File

Configure parameters in `config.ini` (or a custom configuration file):

````ini:c:\Users\hoshi\Documents\GitHub\ProxyCat\config.ini
[SETTINGS]
# Local server listening port (default: 1080)
port = 1080

# Proxy rotation mode: cycle for sequential use, custom for custom mode, load_balance for load balancing (default: cycle)
mode = cycle

# Proxy switching interval (seconds). Set to 0 to switch IP on every request (default: 300)
interval = 300

# Username for authenticating the local server port (default: neko). Leave empty if no authentication is required
username = neko

# Password for authenticating the local server port (default: 123456). Leave empty if no authentication is required
password = 123456

# Whether to use the getip module to obtain proxy addresses True or False (default: False)
use_getip = False

# Proxy address list file (default: ip.txt)
proxy_file = ip.txt

# Whether to enable proxy verification feature True or False (default: True)
check_proxies = True
````

After configuring the corresponding parameters, you can use the tool:

````bash:c:\Users\hoshi\Documents\GitHub\ProxyCat\ProxyCat.py
python3 ProxyCat.py
````

### Demonstration

**Fixed Proxy Addresses (Default):**

````plaintext:c:\Users\hoshi\Documents\GitHub\ProxyCat\README.md
http://neko:123456@127.0.0.1:1080
http://127.0.0.1:1080 
socks5://neko:123456@127.0.0.1:1080
socks5://127.0.0.1:1080 
````

If you are deploying on the public network, replace `127.0.0.1` with your public IP.

![Clip_2024-09-30_09-05-17](C:\Users\hoshi\AppData\Local\Programs\PixPin\Temp\Clip_2024-09-30_09-05-17.png)

### Automatically Obtaining Proxy Addresses via API

The tool supports directly calling API interfaces to obtain proxy addresses. When you set `use_getip = True`, the tool will no longer read proxy addresses from the local `ip.txt` but will obtain new proxy addresses by executing the **getip.py** script (ensure your IP is whitelisted).

At this point, you need to modify the content of **getip.py** to your own interface, formatted as `IP:PORT`. The default is the `socks5` protocol. If you need to use `http`, please change it manually.

**Demonstration Result**

> The operator can be obtained from the advertisement area below.

![Clip_2024-08-31_20-44-23](https://github.com/user-attachments/assets/42c1f3ef-0e75-4b07-a901-1c8b76f7f9c3)

## Performance

After actual testing, when the proxy address server has sufficient performance, ProxyCat can handle **1000** concurrent connections without packet loss, covering most scanning and penetration testing needs.

![8e3f79309626ed0e653ba51b6482bff](./assets/8e3f79309626ed0e653ba51b6482bff-1725093725174-23.png)

## Disclaimer

- If you download, install, use, or modify this tool and related code, you indicate your trust in this tool.
- We do not assume any responsibility for any form of loss or damage to you or others caused by using this tool.
- If you engage in any illegal activities while using this tool, you must bear the corresponding consequences yourself. We will not bear any legal or related responsibilities.
- Please read and fully understand all the terms, especially the clauses that exempt or limit liability, and choose to accept or not accept.
- Unless you have read and accepted all the terms of this agreement, you are not authorized to download, install, or use this tool.
- Your actions of downloading, installing, and using this tool are deemed as your agreement to the above terms.

## Changelog

### **2024/10/23**

- Refactor the code structure and split some of the code into separate files.
- During the proxy process, if the proxy server suddenly fails, it will automatically request to replace the proxy server and reset the replacement timer.

### 2024/09/29

- Removed the less-used single cycle mode and replaced it with a custom mode, allowing users to customize the proxy switching logic based on needs.
- Modified proxy validity checks to asynchronous for increased speed.
- Removed support for the problematic SOCKS4 protocol.
- Enhanced the logging system aesthetics.
- Improved exception handling logic.
- Added validation for proxy formats to ensure correctness.

### 2024/09/10

- Optimized concurrency efficiency, supporting initiating the next request before receiving a response to enhance efficiency.
- Added load balancing mode, randomly sending requests to proxy addresses and using concurrent proxies to improve request efficiency.
- Modified proxy validity checks to asynchronous to improve efficiency.

### 2024/09/09

- Added a feature to set whether to perform validity checks on proxy addresses in `ip.txt` during the first startup and use only valid proxies.
- Function downgraded to support lower versions of Python.

### 2024/09/03

- Added local SOCKS5 listening to adapt to more software.
- Replaced some functions to support lower versions of Python.
- Enhanced display content aesthetics.

### 2024/08/31

- Reorganized the project structure.
- Enhanced display, continuously prompting the next proxy switch time.
- Supported stopping the tool with `Ctrl+C`.
- Significantly shifted to asynchronous requests, improving concurrent efficiency. Tested **1000** concurrent connections with a total of **5000** packets, losing about **50** packets, achieving approximately **99%** stability, and **500** concurrent connections with no packet loss.
- Abandoned the runtime parameter specification approach, modified to read from the local `ini` configuration file for higher usability.
- Supported local unauthenticated access to adapt to more software proxy methods.
- Added version detection feature to automatically prompt version information.
- Added identity verification for proxy server addresses, supporting only local reading as most APIs require whitelisting, thus no duplication was provided.
- Added a feature to update using `getip` only upon receiving new requests to reduce IP consumption.
- Added automatic recognition of proxy server address protocols to adapt to more proxy providers.
- Added support for HTTPS and SOCKS4 proxy protocols, currently covering HTTP, HTTPS, SOCKS5, and SOCKS4 protocols.
- Changed `asyncio.timeout()` to `asyncio.wait_for()` to support lower Python versions.

### 2024/08/25

- Automatically skipped empty lines when reading `ip.txt`.
- Replaced `httpx` with a concurrency pool to improve performance.
- Added a buffer dictionary to reduce latency for identical sites.
- Changed the logic of switching IPs on every request to randomly selecting proxies.
- Adopted more efficient structures and algorithms to optimize request handling logic.

### 2024/08/24

- Adopted an asynchronous approach to improve concurrency capabilities and reduce timeouts.
- Encapsulated duplicate code to enhance code reuse.

### 2024/08/23

- Modified concurrency logic.
- Added identity verification feature.
- Added an IP acquisition interface for permanent IP switching.
- Added a feature to switch IPs on every request.

## Development Plan

- [x] Added local server identity verification to prevent unauthorized use during public network deployment.
- [x] Added feature to switch IPs on every request.
- [x] Added a module for automatic acquisition and updating of static proxies for permanent operation.
- [x] Added load balancing mode, using multiple proxy addresses simultaneously to improve concurrency efficiency and reduce single server load.
- [x] Added version detection feature.
- [x] Added support for proxy address identity verification.
- [x] Added a feature to update using `getip` only when receiving new requests to reduce IP consumption.
- [x] Performed batch validity checks on proxy servers in `ip.txt` during the first startup.
- [x] Added local SOCKS protocol listening or fully switched to SOCKS to adapt to more software.
- [ ] Added detailed logging to record the identity of all IPs connecting to ProxyCat and support multiple users.
- [ ] Increase the web UI and provide a more powerful and user-friendly interface.
- [ ] Add Docker one click deployment, simple and easy to use.
- [ ] Develop a babycat module that can run babycat on any server or host, turning it into a proxy server.

If you have good ideas or encounter bugs during use, please contact the author through the following methods to provide feedback!

## Acknowledgements

No particular order is given. Thanks to the mentors who provided help for this project.

- [AabyssZG (曾哥)](https://github.com/AabyssZG)
- [ProbiusOfficial (探姬)](https://github.com/ProbiusOfficial)
- chars6

![Star History Chart](https://api.star-history.com/svg?repos=honmashironeko/ProxyCat&type=Date)

## Proxy Recommendations

- [Click here to purchase](https://www.ipmart.io?source=Shironeko)