![ProxyCat](https://socialify.git.ci/honmashironeko/ProxyCat/image?description=1&descriptionEditable=A%20lightweight%20and%20excellent%20proxy%20pool%20middleware%20that%20implements%20automatic%20proxy%20rotation&font=Bitter&forks=1&issues=1&language=1&logo=https%3A%2F%2Favatars.githubusercontent.com%2Fu%2F139044047%3Fv%3D4&name=1&owner=1&pattern=Circuit%20Board&pulls=1&stargazers=1&theme=Dark)

<p align="center">
  <a href="/README.md">简体中文</a>
  ·
  <a href="/README-EN.md">English</a>
</p>

## 目录

- [项目背景](#项目背景)
- [核心特性](#核心特性)
- [外观展示](#外观展示)
- [快速部署](#快速部署)
- [文档导航](#文档导航)
- [免责声明](#免责声明)
- [开源协议](#开源协议)
- [开发计划](#开发计划)
- [特别感谢](#特别感谢)
- [赞助](#赞助)
- [代理推荐](#代理推荐)

## 项目背景

做渗透测试时，经常需要隐藏或更换 IP 来绕过安全设备。但市面上的隧道代理价格高昂，普遍在 3-6 元/天，
对很多人来说难以负担。而作者注意到，短效 IP 的性价比极高，每个 IP 只要几分钱，平均 0.03-0.4 元/天。

于是 **ProxyCat** 诞生了！本工具旨在将短效 IP（有效期 1-60 分钟）转换为固定 IP 供其他工具使用，
打造一个部署一次即可永久使用的代理池服务器。

![项目原理图](./assets/项目原理图.png)

## 核心特性

- **双协议监听**：同一个端口同时接受 HTTP 与 SOCKS5 入站请求；上游支持带认证的 HTTP / HTTPS / SOCKS5 代理。[详情](ProxyCat-Manual/Features.md#出口代理服务)
- **三种代理来源**：`local` 读本地列表、`api` 实时取接口、`pool` 直接用内置代理池，面板上切换即时生效。
- **多出口并发**：一直维持多个上游出口同时服务，请求按各出口的实时负载分摊，上游按出口 IP 限流时并发随出口数成倍放大。[上游出口与并发](ProxyCat-Manual/Features.md#上游出口与并发)
- **失败占比淘汰**：出口故障看滑动窗口里的失败占比，而不是连续失败次数 —— 把「一次网络抖动」和「这个出口就是坏的」区分开。
- **高峰期自动扩容**：负载顶上来了自动加出口，高峰过去一步收回；扩容与收回看的是两个不同的数，避免出口数来回震荡。
- **内置代理池**：插件化抓取、先验证再入库、三档验证强度、健康评分、离线归属地，自动重验证与自动清理。[内置代理池](ProxyCat-Manual/Features.md#内置代理池)
- **真实使用反馈**：运行期转发发现的坏出口会回流到池，连续失败达阈值即标记失效，重验证测通后自动恢复。
- **访问控制与出口认证**：客户端 IP 白名单 / 黑名单按优先级判定，绕过名单让指定目标直连；出口支持账号密码认证。
- **Web 管理面板**：代理配置、代理池、访问控制、运行日志四个页签，配置、名单、日志与服务启停一屏完成。[面板与运维](ProxyCat-Manual/Features.md#面板与运维)
- **容器化部署**：Docker 一键构建启动，容器以非 root 运行，健康检查按实际面板端口探活。

## 外观展示

面板是一个单页，左侧四个页签：代理配置、代理池、访问控制、运行日志。

| 代理配置 · 来源设置 | 代理池 · 代理管理 |
|---|---|
| ![代理配置 · 来源设置](./assets/screenshots/config-source.png) | ![代理池 · 代理管理](./assets/screenshots/pool-manage.png) |
| 在来源设置里选择代理来源（本地代理 / API代理 / 维护池代理），并填写当前来源需要的参数；图中为维护池代理的远程代理池地址（留空即用内置池）。 | 抓到的代理一览：协议、真实 IP、归属地、延迟、健康分与匿名度。 |

| 访问控制 | 运行日志 |
|---|---|
| ![访问控制](./assets/screenshots/access.png) | ![运行日志](./assets/screenshots/logs.png) |
| 出口认证账号、IP 黑白名单与代理绕过名单都在这里。 | 实时日志、历史文件回看，以及访问统计与逐条明细。 |

| 深色主题 · 出口轮换 | 英文界面 · 代理管理 |
|---|---|
| ![深色主题 · 出口轮换](./assets/screenshots/config-exits-dark.png) | ![英文界面 · 代理管理](./assets/screenshots/pool-manage-en.png) |
| 深色主题，布局与浅色完全相同。 | 英文界面，与中文界面共用同一份数据与服务端设置。 |

面板提供深色 / 浅色两档主题，未手动切换过时跟随系统的深色偏好；界面支持中文 / 英文切换，
语言是服务端设置，切换后整站文案与导出文件的表头一起变。

## 快速部署

### Docker 部署（推荐）

```bash
docker compose up -d --build
```

Compose 会构建镜像并启动容器，两个端口分别是：

| 端口 | 用途 |
|---|---|
| `1080` | 代理监听端口（HTTP 与 SOCKS5 共用） |
| `5001` | Web 面板端口 |

三个目录通过 bind mount 挂到宿主，数据和配置不会随容器销毁而丢失：`config/`、`logs/`、
`modules/proxypool/data/`。

### 源码运行

需要 **Python 3.10 及以上**：源码大量使用运行时求值的 `X | Y` 联合类型注解，3.9 及更早版本
会在导入阶段就报 `TypeError`。

```bash
pip install -r requirements.txt

# Windows 上命令名为 python
python3 app.py
```

`app.py` 会同时拉起 Web 面板与出口代理服务。仓库自带的 `config/config.ini` 出厂
`proxy_source_mode=pool`（程序内置默认是 `local`），因此按这份配置启动时，**内置代理池会随
服务自动启动**，开箱即有出口可用。

### 验证部署是否成功

两条命令就能确认服务真的在工作：

```bash
# 1. 面板在监听：期望 302（跳转到 /web）
curl -i http://127.0.0.1:5001/

# 2. 代理在转发：期望 200，且请求确实经过了上游代理
#    仓库自带配置的 [Users] 段有账号，请求须带认证，不带会得到 407
curl -x http://neko:123456@127.0.0.1:1080 https://www.baidu.com -I
```

### 首次部署必读

这四条都是**先出症状、后找原因**的典型，完整说明见[使用手册的「部署前必须知道的四件事」](ProxyCat-Manual/Operation%20Manual.md#部署前必须知道的四件事)：

1. **面板打不开，返回 401**：设置了 token 时**必须带上 `?token=` 才能打开**；仓库自带的 token 是公开的，对外使用前务必改掉 `config.ini` 的 `[Server] token` —— 改完约 1 秒内生效，旧 token 随即失效。
2. **容器起来了，却写不进配置或日志**：容器以非 root 运行，UID/GID 必须与宿主 `config/`、`logs/`、`modules/proxypool/data/` 三个目录的属主一致，不同就在 `.env` 里设置 `PUID` / `PGID`。
3. **重启后丢了最后一批数据**：停止时应用要排空写队列，`stop_grace_period` 已放宽到 60 秒，用 Docker 默认的 10 秒会在排空前被 `SIGKILL`，**请不要改小它**。
4. **改了 `web_port` 之后容器变成 unhealthy**：健康检查按 `config.ini` 里实际的 `web_port` 现读现探，改完必须重启进程并同步 `docker-compose.yml` 的端口映射。

### 网络行为提示

ProxyCat 除转发客户端流量外，自身还会主动发起一些对外请求，其中多条是**直连**的（以本机真实 IP 发出），例如版本检查、
代理池的本机公网 IP 查询、GeoNode 与 GitHub 抓取插件和离线归属地库更新。这些请求都可以关闭或改用自有地址（版本检查改用
`version_check_url` 指向自有地址即可避开内置的第三方镜像）；
逐条的触发时机、目的地与关闭方式见[功能特性](ProxyCat-Manual/Features.md#对外网络请求)。经代理转发的流量不在此列——那是客户端自己的流量。

## 文档导航

README 只保留基本介绍与快速部署，其余内容都在下列文档里：

| 文档 | 内容 |
|---|---|
| [功能特性](ProxyCat-Manual/Features.md) | 出口代理服务、内置代理池、面板与运维、上游出口与并发机制、对外网络请求、性能基准与项目结构 |
| [详细配置](ProxyCat-Manual/Configuration.md) | `[Server]` / `[Users]` / `[api_credentials]` / `[Pool]` 全部配置项：默认值、说明与生效方式 |
| [使用手册](ProxyCat-Manual/Operation%20Manual.md) | 安装部署、运行方式、面板逐页讲解、代理池使用、日志与访问记录、常见问题 Q&A |
| [报错排查手册](ProxyCat-Manual/Investigation%20Manual.md) | 常见报错的判断与处理 |
| [更新日志](ProxyCat-Manual/logs.md) | 各版本的改动记录 |
| [接口文档](API.md) | 面板 `/api/*` 与代理池 `/api/pool/*` 的参数、响应示例与错误码 |
| [代理池模块文档](modules/proxypool/README.md) | 抓取插件开发、验证策略、匿名度判定、归属地解析、自动清理等实现细节 |

**上表每一份文档都有英文版** —— 与中文版同名、加 `-EN` 后缀（如 `ProxyCat-Manual/Features-EN.md`、`API-EN.md`），英文入口见 [README-EN.md](README-EN.md)。

## 免责声明

- 您下载、安装、使用、修改本工具及相关代码，即表示您信任本工具。
- 使用本工具对自己或他人造成的任何形式的损失和伤害，我们不承担责任。
- 您使用本工具进行的任何非法行为，由您本人承担全部责任。
- 请仔细阅读并完全理解各项条款，尤其是免责条款。
- 如果您没有阅读并接受全部条款，您无权下载、安装或使用本工具。
- 您的下载、安装和使用行为即表示您接受本协议。

## 开源协议

本项目采用 **GNU General Public License v2.0（GPL-2.0）**，完整条款见 [LICENSE](LICENSE)。

- 这是**传染性许可**：分发本项目的修改版或衍生作品时，必须同样以 GPL-2.0 授权并提供源码。
- 本软件**不提供任何担保**，这也是上面免责声明的由来。

## 开发计划

- [x] 添加详细日志，记录所有连接 ProxyCat 的 IP 身份，支持多用户。
- [x] 添加 Web UI，提供更强大易用的界面。
- [x] 内置代理池：插件化抓取、验证、评分、归属地与自动清理。
- [ ] 开发 babycat 模块，可在任意服务器或主机上运行，将其变成代理服务器。
- [ ] 请求黑白名单：指定 URL、IP 或域名强制丢弃或绕过（绕过名单已支持，其余待补）。
- [ ] 打包到 PyPi，方便安装使用。

如果您有好的想法或在使用中遇到 BUG，欢迎通过以下方式联系作者：

微信公众号：**樱花庄的本间白猫**

## 特别感谢

排名不分先后，感谢所有为本项目提供帮助的贡献者：

- [AabyssZG (曾哥)](https://github.com/AabyssZG)
- [ProbiusOfficial (探姬)](https://github.com/ProbiusOfficial)
- [gh0stkey (EvilChen)](https://github.com/gh0stkey)
- [huangzheng2016(HydrogenE7)](https://github.com/huangzheng2016)
- chars6
- qianzai（千载）
- ziwindlu
- lalala-orz(啦啦啦)

## 赞助

开源不易，如果觉得本工具有帮助，欢迎赞助作者开发！

| 排名 | ID | 金额 (CNY) |
| :--: | :--: | :--------: |
| 1 | **陆沉** | 1266.62 |
| 2 | **柯林斯.民间新秀** | 696 |
| 3 | **北** | 170 |
| [赞助名单](https://github.com/honmashironeko/Thanks-for-sponsorship) | 每一份赞助都是作者的动力！ | (´∀｀)♡ |

![赞助](./assets/赞助.png)

## 代理推荐

- [第一家平价代理服务商 - 使用邀请码可获 5000 免费 IP + 10 元优惠券](https://h.shanchendaili.com/invite_reg.html?invite=fM6fVG)
- [各类运营商数据套餐](https://172.lot-ml.com/ProductEn/Index/0b7c9adef5e9648f)
- [点击这里购买](https://www.ipmart.io?source=Shironeko)

![Star History Chart](https://star-history.dera.page/svg?repos=honmashironeko/ProxyCat&type=Date)