![ProxyCat](https://socialify.git.ci/honmashironeko/ProxyCat/image?description=1&descriptionEditable=%E4%B8%80%E6%AC%BE%E8%BD%BB%E9%87%8F%E7%BA%A7%E7%9A%84%E4%BC%98%E7%A7%80%E4%BB%A3%E7%90%86%E6%B1%A0%E4%B8%AD%E9%97%B4%E4%BB%B6%EF%BC%8C%E5%AE%9E%E7%8E%B0%E4%BB%A3%E7%90%86%E7%9A%84%E8%87%AA%E5%8A%A8%E8%BD%AE%E6%8D%A2&font=Bitter&forks=1&issues=1&language=1&logo=https%3A%2F%2Favatars.githubusercontent.com%2Fu%2F139044047%3Fv%3D4&name=1&owner=1&pattern=Circuit%20Board&pulls=1&stargazers=1&theme=Dark)

  <p align="center">
    <a href="/ProxyCat-EN/README-EN.md">English</a>
    ·
    <a href="/README.md">简体中文</a>
  </p>

## Project Overview

During penetration testing, one often encounters situations where hiding or changing the IP address is necessary to bypass security devices. However, commercial tunnel proxies are generally very expensive, ranging from 20 to 40 yuan per day, which can be quite prohibitive. The author has observed that short-lived IPs are much more cost-effective, averaging only 0.2 to 3 yuan per day.

Thus, this tool was developed to transform short-lived IPs (lasting from 1 to 60 minutes) into a stable IP, enabling other tools to utilize them effectively and forming a proxy pool server that can be deployed once for permanent use.

![项目原理图](./assets/202408260021207-1725093725174-21.png)

## Supported Features

```
Local Listening Service: Customizable listening ports, custom authentication for listening ports.
Proxy Address Support: Four protocol types, timed proxy address changes, automatic address change after each request, API for automatic proxy retrieval, supports authenticated proxies.
Service Runtime: Changes proxy addresses only upon receiving requests, supports ultra-high concurrency, supports HTTP and HTTPS protocols, checks for version updates at startup.
System Compatibility: Compatible with Windows, Linux, and MacOS; supports VPS remote deployment and local installation.
```

## Project Usage

### Install Dependencies

This tool is implemented in Python (recommended version 3.8 or higher). Please configure the dependencies using the following commands:

```bash
pip install -r requirements.txt
```

Run the command `python3 ProxyCat.py -h` in the project directory, and if the following output appears, the configuration is successful:

```
# python3 ProxyCat.py -h
      |\      _,,,---,,_  by 本间白猫
ZZZzz /,`.-'`'    -.  ;-;;,_
     |,4-  ) )-,_. ,\ (  `'-'
    '---''(_/--'  `-'\_)  ProxyCat

Usage: ProxyCat.py [-h] [-c]

Arguments:
  -h, --help  Display this help message and exit
  -c C        Specify configuration file name (default: config.ini)
```

### Manually Enter Proxy Addresses in ip.txt

Enter proxy addresses in the following format, one per line, into the `ip.txt` file:

```ip.txt
socks5://127.0.0.1:7890
socks4://127.0.0.1:7890
https://127.0.0.1:7890
http://127.0.0.1:7890
...
```

Configure parameters in `config.ini` (or a custom configuration file):

```
[SETTINGS]
# Local server listening port (default: 1080)
port = 1080

# Proxy address rotation mode: cycle means cyclic use, once means once used up (default is: cycle)
mode = cycle

# Proxy address change time (seconds), when set to 0, the IP will be changed for each request (default: 300)
interval = 300

# Local server port authentication username (default: neko) No authentication is required when it is empty
username = neko

# Local server port authentication password (default: 123456) No authentication is required when it is empty
password = 123456

# Whether to use the getip module to obtain the proxy address True or False (default: False)
use_getip = False

# Proxy address list file (default: ip.txt)
proxy_file = ip.txt
```

Once the corresponding parameters are configured, you may use the following command:

```bash
# python3 ProxyCat.py
```

**Demonstration Result**

Fixed proxy address (default): http://neko:123456@127.0.0.1:1080 or http://127.0.0.1:1080

If deployed publicly, replace `127.0.0.1` with your public IP address.

![Clip_2024-08-31_16-49-22](./assets/Clip_2024-08-31_16-49-22.png)

### Use API to Automatically Retrieve Proxy Addresses

The tool supports directly calling the API for proxy address retrieval. When you set `use_getip = True`, the tool will no longer read from the local `ip.txt` and will instead execute **getip.py** to fetch new proxy addresses.

In this case, you need to modify the contents of **getip.py** to use your own API, formatted as `IP:PORT`. The default is `socks5` protocol; change it manually if using `http`.

**Demonstration Result**

> The operator can be obtained from the advertisement area below.

![Clip_2024-08-31_16-50-59](./assets/Clip_2024-08-31_16-50-59.png)

## Performance

Current testing shows that under adequate server performance for proxy addresses, the tool can support 500 concurrent requests without packet loss, effectively covering most scanning and penetration testing needs.

![8e3f79309626ed0e653ba51b6482bff](./assets/8e3f79309626ed0e653ba51b6482bff-1725093725174-23.png)

## Disclaimer

- By downloading, installing, using, or modifying this tool and its related code, you indicate your trust in this tool.
- We take no responsibility for any loss or damage caused to you or others while using this tool.
- If you engage in any illegal activities while using this tool, you assume all corresponding consequences, and we will not bear any legal or associated liabilities.
- Please read and thoroughly understand each clause, especially those that exempt or limit liability, and choose to accept or decline.
- Unless you have read and accepted all terms of this agreement, you are not entitled to download, install, or use this tool.
- Your actions, including downloading, installing, or using, indicate that you have read and agree to these terms.

## Changelog

**2024/08/31**

- Major structure adjustments for the project.

- UI enhancements to indicate the time remaining until the next proxy address change.
- Support for `ctrl+c` to stop operation.
- Significant adjustments to asynchronous requests; tested at 1000 concurrent requests with 5000 packets sent, resulting in about 50 lost packets, achieving ~99% stability; 500 concurrent requests resulted in no packet loss.
- Changed parameter specification from runtime to reading from local ini configuration file for improved usability.
- Support for local no-authentication, adapting to more software proxy modes.
- Added version detection functionality to automatically prompt version information.
- Introduced authentication for proxy server addresses, but this only applies to local reads due to the need for whitelisting in most APIs, hence not provided repeatedly.
- Implemented a feature that updates via `getip` only upon receiving new requests to reduce IP consumption.
- Enhanced automatic recognition of proxy server address protocols to accommodate more proxy providers.
- Added support for HTTPS and SOCKS4 proxy protocols; now covers HTTP, HTTPS, SOCKS5, and SOCKS4 protocols.

**2024/08/25**

- Automatically skips empty lines when reading from `ip.txt`.

- Replaced `httpx` with a concurrency pool for performance improvement.
- Added a buffering dictionary to reduce latency for the same site.
- Modified the logic for changing IPs on each request to randomly select a proxy.
- Implemented more efficient structures and algorithms to optimize request handling.

**2024/08/24**

- Adopted asynchronous solutions to improve concurrency and reduce timeouts.

- Encapsulated redundant code for increased reusability.

**2024/08/23**

- Adjusted concurrency logic.
- Added authentication features.
- Added IP retrieval interface for permanent IP changes.
- Introduced functionality to change IP on every request.

## Development Plans

- [x] Add local server authentication to prevent malicious use in public.
- [x] Introduce functionality to change IP on every request.
- [x] Create a static proxy automatic retrieval module for permanent operation.
- [ ] Introduce load balancing mode to use multiple proxy addresses simultaneously, effectively increasing concurrency and reducing load on a single server.
- [x] Add version detection functionality.
- [x] Include support for proxy address authentication.
- [x] Implement functionality for updating via `getip` only upon new requests to minimize IP usage.
- [ ] Perform validity checks on all proxy servers in `ip.txt` upon the first startup.

If you have suggestions or encounter bugs during use, please reach out to the author using the contact information provided!

## Acknowledgments

The following individuals are thanked in no particular order for their contributions to this project.

[AabyssZG (曾哥)](https://github.com/AabyssZG)

[ProbiusOfficial (探姬)](https://github.com/ProbiusOfficial)

![Star History Chart](https://api.star-history.com/svg?repos=honmashironeko/ProxyCat&type=Date)

## Proxy Recommendations

- [Click here to purchase](https://www.ipmart.io?source=Shironeko)
