![ProxyCat](https://socialify.git.ci/honmashironeko/ProxyCat/image?custom_description=%E4%B8%80%E6%AC%BE%E6%94%AF%E6%8C%81%E5%A4%9A%E5%8D%8F%E8%AE%AE%E7%9A%84%E9%9A%A7%E9%81%93%E4%BB%A3%E7%90%86%E6%B1%A0%E4%B8%AD%E9%97%B4%E4%BB%B6%E6%9C%8D%E5%8A%A1%EF%BC%8C%E5%AE%9E%E7%8E%B0%E4%BD%8E%E6%88%90%E6%9C%AC%E4%BB%A3%E7%90%86%E7%9A%84%E8%87%AA%E5%8A%A8%E8%BD%AE%E6%8D%A2&description=1&font=Bitter&forks=1&issues=1&language=1&logo=https%3A%2F%2Favatars.githubusercontent.com%2Fu%2F139044047%3Fv%3D4%26size%3D1080&name=1&owner=1&pattern=Circuit+Board&pulls=1&stargazers=1&theme=Dark)

<p align="center">
  <a href="/README-EN.md">English</a>
  ·
  <a href="/README.md">简体中文</a>
</p>

## 目录

- [开发缘由](#开发缘由)
- [功能特点](#功能特点)
- [安装与使用](#安装与使用)
- [免责申明](#免责申明)
- [更新日志](#更新日志)
- [开发计划](#开发计划)
- [特别鸣谢](#特别鸣谢)
- [赞助开源](#赞助开源)
- [代理推荐](#代理推荐)

## 开发缘由

在渗透过程中，经常需要隐藏或更换IP地址以绕过安全设备。然而，市面上的隧道代理价格高昂，普遍在20-40元/天，这对于许多人来说难以接受。笔者注意到，短效IP的性价比很高，一个IP只需几分钱，平均每天0.2-3元。

综上所述，**ProxyCat** 应运而生！本工具旨在将持续时间仅有1分钟至60分钟不等的短效IP转变为固定IP供其他工具使用，形成代理池服务器，部署一次即可永久使用。

![项目原理图](./assets/项目原理图.png)

## 功能特点

- **两种协议监听**：支持 HTTP/SOCKS5 协议监听，兼容更多工具。
- **三种代理地址**：支持 HTTP/HTTPS/SOCKS5 代理服务器及身份鉴别。
- **灵活切换模式**：支持顺序、随机及自定义代理选择，优化流量分配。
- **动态获取代理**：通过 GetIP 函数即时获取可用代理，支持 API 接口调用。
- **代理保护机制**：在使用 GetIP 方式获取代理时，首次运行不会直接请求获取，将会在收到请求的时候才获取。
- **自动代理检测**：启动时自动检测代理有效性，剔除无效代理。
- **智能切换代理**：仅在请求运行时获取新代理，减少资源消耗。
- **失效代理切换**：代理失效后自动验证切换新代理，确保不中断服务。
- **身份认证支持**：支持用户名/密码认证和黑白名单管理，提高安全性。
- **实时状态显示**：展示代理状态和切换时间，实时掌握代理动态。
- **动态更新配置**：无需重启服务，动态检测配置并更新。
- **Web UI界面**：提供 Web 管理界面，操作管理更加便捷。
- **Docker部署**：Docker 一键部署，Web 统一管理。
- **中英文双语**：支持中文英文一键切换。
- **配置灵活**：通过 config.ini 文件自定义端口、模式和认证信息等。
- **版本检测**：自动检查软件更新，保证版本最新。

## 工具使用

[ProxyCat操作手册](../main/ProxyCat-Manual/Operation%20Manual.md)

## 报错排查

[ProxyCat排查手册](../main/ProxyCat-Manual/Investigation%20Manual.md)

## 免责申明

- 如果您下载、安装、使用、修改本工具及相关代码，即表明您信任本工具。
- 在使用本工具时造成对您自己或他人任何形式的损失和伤害，我们不承担任何责任。
- 如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。
- 请您务必审慎阅读、充分理解各条款内容，特别是免除或者限制责任的条款，并选择接受或不接受。
- 除非您已阅读并接受本协议所有条款，否则您无权下载、安装或使用本工具。
- 您的下载、安装、使用等行为即视为您已阅读并同意上述协议的约束。

## 更新日志

[更新日志记录](../main/ProxyCat-Manual/logs.md)

## 开发计划

- [ ] **增加请求切换IP配置**：支持设置随机范围内的请求次数来切换IP，提升对抗阈值类防御的能力。
- [ ] **babycat模块**：通过部署babycat子模块，可以在任意服务器或主机上快速搭建代理服务器，并通过Web端实现统一管理，简化操作流程。（针对红队进行开发强化）
- [ ] **爬虫代理池**：利用爬虫抓取免费代理地址，构建代理池。该代理池能够持续维护可用的高质量代理资源，支持负载均衡下的随机调用，同时允许用户指定IP归属地，满足不同场景需求。
- [ ] **机场协议支持**：接入机场协议后，可将每个节点作为代理地址使用，扩展代理服务器的功能和灵活性。
- [ ] **域名/IP黑白名单**：提供目标域名或IP的黑白名单配置功能，类似VPN规则模式，实现伪全局代理效果，确保特定流量按需转发。
- [ ] **版本自动升级**：内置版本自动升级模块，确保软件始终运行在最新版本，减少手动维护的工作量，同时提升安全性与兼容性。

如果您有好的创意，或在使用过程中遇到bug，请通过以下方式联系作者反馈！

微信公众号：**樱花庄的本间白猫**

## 特别鸣谢

本排名不分先后，感谢为本项目提供帮助的师傅们。

- [AabyssZG (曾哥)](https://github.com/AabyssZG)
- [ProbiusOfficial (探姬)](https://github.com/ProbiusOfficial)
- [gh0stkey (EvilChen)](https://github.com/gh0stkey)
- [huangzheng2016(HydrogenE7)](https://github.com/huangzheng2016)
- chars6
- qianzai（千载）
- ziwindlu
- yuzhegan
- 摘星怪

## 赞助开源

开源不易，如果您觉得工具不错，或许可以试着赞助一下作者的开发哦~

---
| 排名 |         ID          | 赞助金额（元） |
| :--: | :-----------------: | :------------: |
|  1   |      **陆沉**       |    1266.62     |
|  2   | **柯林斯.民间新秀** |      696       |
|  3   |      **明察涉网犯罪技术侦察实验室**      |      188       |
|  [赞助榜单](https://github.com/honmashironeko/Thanks-for-sponsorship)   |     您的每一份赞助都是作者源源不断的动力！      |      (´∀｀)♡       |

---
![赞助](./assets/赞助.png)

## 代理推荐

- [第一家便宜大碗代理购买，用邀请码注册得5000免费IP+10元优惠券](https://h.shanchendaili.com/invite_reg.html?invite=fM6fVG)
- [各大运营商流量卡](https://172.lot-ml.com/ProductEn/Index/0b7c9adef5e9648f)
- [国外匿名代理](https://www.ipmart.io?source=Shironeko)

![Star History Chart](https://api.star-history.com/svg?repos=honmashironeko/ProxyCat&type=Date)
