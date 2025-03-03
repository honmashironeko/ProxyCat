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
- [Disclaimer](#disclaimer)
- [Changelog](#changelog)
- [Development Plan](#development-plan)
- [Special Thanks](#special-thanks)
- [Sponsor](#sponsor)
- [Proxy Recommendations](#proxy-recommendations)

## Development Background

During penetration testing, it's often necessary to hide or change IP addresses to bypass security devices. However, tunnel proxies in the market are expensive, typically costing $3-6 per day, which is unaffordable for many. The author noticed that short-term IPs offer high cost-effectiveness, with each IP costing just a few cents, averaging $0.03-0.4 per day.

Therefore, **ProxyCat** was born! This tool aims to transform short-term IPs (lasting from 1 to 60 minutes) into fixed IPs for other tools to use, creating a proxy pool server that can be used permanently after one deployment.

![Project Principle](./assets/项目原理图.png)

## Features

- **Dual Protocol Listening**: Supports HTTP/SOCKS5 protocol listening, compatible with more tools.
- **Triple Proxy Types**: Supports HTTP/HTTPS/SOCKS5 proxy servers with authentication.
- **Flexible Switching Modes**: Supports sequential, random, and custom proxy selection for optimized traffic distribution.
- **Dynamic Proxy Acquisition**: Get available proxies in real-time through GetIP function, supports API interface calls.
- **Proxy Protection**: When using GetIP method, proxies are only fetched upon receiving requests, not at initial startup.
- **Automatic Proxy Detection**: Automatically checks proxy validity at startup, removing invalid ones.
- **Smart Proxy Switching**: Only obtains new proxies during request execution, reducing resource consumption.
- **Invalid Proxy Handling**: Automatically validates and switches to new proxies when current ones fail.
- **Authentication Support**: Supports username/password authentication and IP blacklist/whitelist management.
- **Real-time Status Display**: Shows proxy status and switching times for dynamic monitoring.
- **Dynamic Configuration**: Updates configuration without service restart.
- **Web UI Interface**: Provides web management interface for convenient operation.
- **Docker Deployment**: One-click Docker deployment with unified web management.
- **Bilingual Support**: Supports Chinese and English language switching.
- **Flexible Configuration**: Customize ports, modes, and authentication through config.ini.
- **Version Check**: Automatic software update checking.

## Tool Usage

[ProxyCat Operation Manual](../main/ProxyCat-Manual/Operation%20Manual.md)

## Error Troubleshooting

[ProxyCat Investigation Manual](../main/ProxyCat-Manual/Investigation%20Manual.md)

## Disclaimer

- By downloading, installing, using, or modifying this tool and related code, you indicate your trust in this tool.
- We are not responsible for any form of loss or damage caused to yourself or others while using this tool.
- You are solely responsible for any illegal activities conducted while using this tool.
- Please carefully read and fully understand all terms, especially liability exemption clauses.
- You have no right to download, install, or use this tool unless you have read and accepted all terms.
- Your download, installation, and usage actions indicate your acceptance of this agreement.

## Changelog

[Changelog Records](../main/ProxyCat-Manual/logs.md)

## Development Plan

- [x] Add detailed logging to record all IP identities connecting to ProxyCat, supporting multiple users.
- [x] Add Web UI for a more powerful and user-friendly interface.
- [ ] Develop babycat module that can run on any server or host to turn it into a proxy server.
- [ ] Add request blacklist/whitelist to specify URLs, IPs, or domains to be forcibly dropped or bypassed.
- [ ] Package to PyPi for easier installation and use.

If you have good ideas or encounter bugs during use, please contact the author through:

WeChat Official Account: **樱花庄的本间白猫**

## Special Thanks

In no particular order, thanks to all contributors who helped with this project:

- [AabyssZG (曾哥)](https://github.com/AabyssZG)
- [ProbiusOfficial (探姬)](https://github.com/ProbiusOfficial)
- [gh0stkey (EvilChen)](https://github.com/gh0stkey)
- [huangzheng2016(HydrogenE7)](https://github.com/huangzheng2016)
- chars6
- qianzai（千载）
- ziwindlu

## Sponsor

Open source development isn't easy. If you find this tool helpful, consider sponsoring the author's development!

---
| Rank |         ID          | Amount (CNY) |
| :--: | :-----------------: | :----------: |
|  1   |      **陆沉**       |   1266.62    |
|  2   | **柯林斯.民间新秀** |     696      |
|  3   |      **taffy**      |     150      |
|  [Sponsor List](https://github.com/honmashironeko/Thanks-for-sponsorship)   |     Every sponsorship is a motivation for the author!      |      (´∀｀)♡      |

---
![Sponsor](./assets/赞助.png)

## Proxy Recommendations

- [First affordable proxy service - Get 5000 free IPs + ¥10 coupon with invite code](https://h.shanchendaili.com/invite_reg.html?invite=fM6fVG)
- [Various carrier data plans](https://172.lot-ml.com/ProductEn/Index/0b7c9adef5e9648f)
- [Click here to purchase](https://www.ipmart.io?source=Shironeko)
