![ProxyCat](https://socialify.git.ci/honmashironeko/ProxyCat/image?description=1&descriptionEditable=%E4%B8%80%E6%AC%BE%E8%BD%BB%E9%87%8F%E7%BA%A7%E7%9A%84%E4%BC%98%E7%A7%80%E4%BB%A3%E7%90%86%E6%B1%A0%E4%B8%AD%E9%97%B4%E4%BB%B6%EF%BC%8C%E5%AE%9E%E7%8E%B0%E4%BB%A3%E7%90%86%E7%9A%84%E8%87%AA%E5%8A%A8%E8%BD%AE%E6%8D%A2&font=Bitter&forks=1&issues=1&language=1&logo=https%3A%2F%2Favatars.githubusercontent.com%2Fu%2F139044047%3Fv%3D4&name=1&owner=1&pattern=Circuit%20Board&pulls=1&stargazers=1&theme=Dark)

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

- **双协议监听**：支持 HTTP/SOCKS5 协议监听，兼容更多工具。
- **三种协议代理地址**：支持 HTTP/HTTPS/SOCKS5 代理服务器，满足不同需求。
- **灵活切换模式**：支持顺序、随机及自定义代理选择，优化流量分配。
- **动态获取代理**：通过 GetIP 函数即时获取可用代理，支持 API 接口调用。
- **代理保护机制**：在使用 GetIP 方式获取代理时，首次运行不会直接请求获取，将会在收到请求的时候才获取。
- **自动代理检测**：启动时自动检测代理有效性，剔除无效代理。
- **智能切换代理**：仅在请求运行时获取新代理，减少资源消耗。
- **失效代理切换**：代理失效后自动验证切换新代理，确保不中断服务。
- **身份认证支持**：支持用户名/密码认证和黑白名单管理，提高安全性。
- **实时状态显示**：展示代理状态和切换时间，实时掌握代理动态。
- **配置灵活**：通过 config.ini 文件自定义端口、模式和认证信息等。
- **版本检测**：自动检查软件更新，保证版本最新。

## 工具使用

[ProxyCat操作手册](#./ProxyCat-Manual/Operation Manual.md)

## 报错排查

[ProxyCat排查手册](./ProxyCat-Manual/Investigation Manual.md)

## 免责申明

- 如果您下载、安装、使用、修改本工具及相关代码，即表明您信任本工具。
- 在使用本工具时造成对您自己或他人任何形式的损失和伤害，我们不承担任何责任。
- 如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。
- 请您务必审慎阅读、充分理解各条款内容，特别是免除或者限制责任的条款，并选择接受或不接受。
- 除非您已阅读并接受本协议所有条款，否则您无权下载、安装或使用本工具。
- 您的下载、安装、使用等行为即视为您已阅读并同意上述协议的约束。

## 更新日志

[更新日志记录](./ProxyCat-Manual/logs.md)

## 开发计划

- [ ] 增加详细日志记录，记录所有连接 ProxyCat 的 IP 身份，支持多用户。
- [ ] 增加Web UI，提供更加强大易用的界面。
- [ ] 开发 babycat 模块，可将 babycat 在任意服务器或主机上运行，即可变成一台代理服务器。

如果您有好的创意，或在使用过程中遇到bug，请通过以下方式联系作者反馈！

微信公众号：**樱花庄的本间白猫**

## 特别鸣谢

本排名不分先后，感谢为本项目提供帮助的师傅们。

- [AabyssZG (曾哥)](https://github.com/AabyssZG)
- [ProbiusOfficial (探姬)](https://github.com/ProbiusOfficial)
- [gh0stkey (EvilChen)](https://github.com/gh0stkey)
- chars6
- qianzai（千载）
- ziwindlu

## 赞助开源

开源不易，如果您觉得工具不错，或许可以试着赞助一下作者的开发哦~

![赞助](./assets/赞助.png)

## 代理推荐

- [第一家便宜大碗代理购买，用邀请码注册得5000免费IP+10元优惠券](https://h.shanchendaili.com/invite_reg.html?invite=fM6fVG)
- [各大运营商流量卡](https://172.lot-ml.com/ProductEn/Index/0b7c9adef5e9648f)
- [国外匿名代理](https://www.ipmart.io?source=Shironeko)

![Star History Chart](https://api.star-history.com/svg?repos=honmashironeko/ProxyCat&type=Date)
