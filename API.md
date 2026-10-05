# ProxyCat 接口文档

本文是 ProxyCat 对外 HTTP 接口的**唯一权威文档**，覆盖两套接口：

- **面板接口**（`/api/*`）—— 面板自身的接口，由 `app.py` 提供。
- **代理池接口**（`/api/pool/*`）—— 由 `modules/proxypool_api.py` 注册的 Flask 蓝图。

两套接口**共用同一个端口、同一套鉴权**，但**错误响应的约定不同**（面板多为
`HTTP 200 + status: "error"`，代理池用真实状态码 + `error_code`）。两套约定都在本文中
写明，调用前请先读 [一、通用约定](#一通用约定)。

> 历史版本把代理池接口的字段细节放在 `modules/proxypool/API.md`，该文件现已并入本文，
> 只剩一个指向本页的指针。

## 目录

- [分组导航](#分组导航)
- [一、通用约定](#一通用约定)
- [二、面板接口](#二面板接口)
- [三、代理池接口](#三代理池接口)
- [四、端到端调用示例](#四端到端调用示例)
- [五、注意事项](#五注意事项)
- [附录 A：错误码总表](#附录-a错误码总表)
- [附录 B：端点总索引](#附录-b端点总索引)
- [附录 C：字段字典](#附录-c字段字典)

## 分组导航

| 组 | 端点数 | 说明 |
|---|---|---|
| [1. 通用约定](#一通用约定) | — | 地址、鉴权、两套错误约定、参数解析规则、通用上限 |
| [2. 面板接口](#二面板接口) | 33 | 面板自身的 `/api/*`，含状态、配置、日志、访问记录 |
| [3. 代理池接口](#三代理池接口) | 38 | 代理池的 `/api/pool/*`，含抓取、验证、任务与数据库维护 |

按用途快速定位：

| 我想…… | 去这里 |
|---|---|
| 看服务当前在用什么代理 | [获取运行状态](#获取运行状态get-apistatus) |
| 改配置 | [保存配置](#保存配置post-apiconfig) |
| 看某个请求为什么失败 | [查询访问记录](#查询访问记录get-apilogsrecords) |
| 看某个域名走哪个上游成功率如何 | [查询域名统计](#查询域名统计get-apilogsdomains) |
| 拿一个可用代理给别的程序用 | [取一个代理](#取一个代理get-apipoolrandom) |
| 手动触发一次抓取 | [立即执行插件](#立即执行插件post-apipoolpluginsnamerun) |
| 看一个跑得久的任务到哪了 | [查询任务状态](#查询任务状态get-apipooltaskstask_id) |

---

# 一、通用约定

## 服务地址与端口

- 默认地址：`http://localhost:5001`，端口取自 `config/config.ini` 的 `[Server] web_port`。
- 面板与代理池**没有各自独立的进程或端口**，都运行在 ProxyCat 进程内，随进程一起启停。
- 代理监听端口（默认 `1080`）是另一个端口，只接受 HTTP 与 SOCKS5 代理请求，
  **不提供任何 HTTP 接口**。

## 鉴权

**除下文明确标注「免鉴权」的端点外，所有接口都需要带上 token：**

```
GET http://localhost:5001/api/status?token=<你的token>
```

token 在 `config/config.ini` 的 `[Server] token`。**校验只读查询串参数 `token`**，
不读请求头，也不读 Cookie。

**token 留空时一律放行**，即不启用鉴权。此时任何能连上面板端口的人都可以读写配置
（包括上游凭据）、查看访问记录、启停服务。仅在本机使用时可这样配置；要暴露到网络上
必须设置 token。

> **仓库自带的 `config/config.ini` 里 token 非空**，克隆下来直接用会得到 401。
> 见 [README 的快速部署](README.md#快速部署)。

**免鉴权的 API 端点只有 4 个**（`/` 与 `/static/<path>` 也不校验 token，见[附录 B](#附录-b端点总索引)）：

| 方法 | 路径 |
|---|---|
| GET | `/api/version` |
| GET | `/api/ads` |
| POST | `/api/ads/dismiss` |
| POST | `/api/ads/reopen` |

鉴权失败统一返回 **HTTP 401**：

```json
{
  "status": "error",
  "message": "无效的访问令牌"
}
```

## 两套错误约定

**这是本文最容易踩的地方：两套接口的错误表达方式不同，必须分别对待。**

| 情形 | 面板 `/api/*` | 代理池 `/api/pool/*` |
|---|---|---|
| 成功 | `200` + `status: "success"`；少数只读端点**直接返回数据、没有 `status` 字段** | `200` + 数据；错误时才带 `status` |
| 业务失败 | **`200`** + `status: "error"` + `message` | **真实状态码**（4xx/5xx）+ `status: "error"` + `message` + `error_code` |
| 参数错误 | `400`，仅 `POST /api/config` 会这样返回 | `400` + `error_code: "invalid_parameter"` |
| 未鉴权 | `401` + `status: "error"` | `401` + `status: "error"`（同一个钩子） |
| 池未运行 / 池太慢 | 不适用 | `503` `pool_unavailable` / `504` `pool_timeout` |

由此得出两条硬规则：

1. **永远同时判断 HTTP 状态码与 `status` 字段。** 面板侧只看状态码会漏掉业务失败，
   只看 `status` 又会漏掉鉴权与池侧错误。
2. **程序化分支只能依赖 `error_code`（池侧）或 HTTP 状态码 + 端点自有标志（面板侧），
   绝不能用 `message`。** `message` 的文案跟随当前界面语言（`[Server] language`），
   同一个错误在不同语言下返回不同文本。

## 参数解析规则（仅代理池接口）

代理池适配层按**处理函数的签名**解析参数，规则如下：

| 规则 | 说明 |
|---|---|
| 查询参数是**白名单** | 只有出现在处理函数签名里的查询参数才会被解析，**未知参数被静默忽略**。写错参数名不会报错，只会得到未筛选的全量结果 |
| 类型强制 | 依据类型注解，只识别 `bool` / `int` / `float`，其余按字符串原样传递 |
| 空串 | 非字符串类型的参数传空串（如 `?status=`）等同于**不传**该参数 |
| 请求体 | 必须是 JSON 对象；缺失必填字段返回 `400 invalid_parameter`，并在 `message` 里列出字段名 |
| 路径参数 | 如 `/api/pool/proxies/{id}/favorite` 中的 `{id}`，由路由本身解析 |

## 通用上限与截断

| 位置 | 上限 / 默认 | 说明 |
|---|---|---|
| `GET /api/logs` 的 `limit` | 钳制到 1-2000，默认 200 | 超出被静默钳制，不报错 |
| `GET /api/logs/file` 的 `lines` | 钳制到 1-5000，默认 500 | 同上 |
| `GET /api/logs/records` 的 `limit` | 钳制到 1-500，默认 100 | 同上；`since` 默认「1 小时前」 |
| 访问记录导出 | 单次最多 50000 条 | 被截断的标记只有 JSON 格式的元信息里有（`truncated`，条数达到上限即为 `true`），CSV 没有该标记 |
| 代理池 `page_size` / `limit` / 导出 | 统一受 50000 约束 | `limit` 存在时 `page` 被强制为 1，等效「取前 limit 条」 |
| `GET /api/version` | 只读缓存，**不发起请求** | 检查由进程启动时与每 24 小时的后台任务完成 |

## 阻塞与并发

面板由 **waitress 以 16 个线程**提供服务。每次调用代理池，**当前 Web 线程会一直被占用
到池返回结果**，最长可达 60 秒（HEAVY 档）。因此 16 个并发的大批量操作就会把面板
拖到无响应。调用重接口请控制并发，并给客户端留足够长的超时。

代理池的三档内部超时（会体现在错误码上）：

| 档 | 时限 | 用于 |
|---|---|---|
| QUERY | 10 秒 | 查询、统计、状态 |
| MUTATION | 20 秒 | 启停、单条修改 |
| HEAVY | 60 秒 | 导入、导出、数据库优化、手动执行插件、批量验证/删除 |

---

# 二、面板接口

## 页面与静态资源

### 打开面板（GET /web）

**鉴权：需要 token。**

`GET /web` 返回面板单页。token 校验与其他接口一致，所以**设置了 token 时，
直接访问 `http://127.0.0.1:5001/` 会在跳转后得到 401**。正确地址是：

```
http://127.0.0.1:5001/?token=<你的token>
```

`GET /` 本身不校验，只把 `?token=` 原样带上去跳转到 `/web`：

| 请求 | 响应 |
|---|---|
| `GET /?token=abc` | `302` → `/web?token=abc` |
| `GET /`（无 token） | `302` → `/web` |

`GET /static/<path>` 提供 `web/static/` 下的前端资源。带 `?v=<版本>` 查询参数的请求
返回 `Cache-Control: public, max-age=31536000, immutable`（页面里的每个静态引用都带该
参数，改版后参数变化、浏览器自然取新文件）；不带参数的请求返回 `Cache-Control: no-cache`，
每次回源校验。

## 运行状态

### 获取运行状态（GET /api/status）

无请求参数。返回出口代理服务的实时快照。

```json
{
  "current_proxy": "http://1.2.3.4:8080",
  "mode": "cycle",
  "port": 1080,
  "interval": 300,
  "time_left": 123.4,
  "switch_countdown_mode": "time",
  "total_proxies": 10,
  "active_proxies": [
    { "url": "http://1.2.3.4:8080", "inflight": 3, "active": 2, "capacity": 0, "failures": 0, "suspect": false, "failure_ratio": 0.0, "last_used": 12.5 }
  ],
  "proxy_source_mode": "local",
  "exit_count": 5,
  "elastic_active": true,
  "auth_required": false,
  "display_level": 1,
  "service_status": "running",
  "language": "cn",
  "request_interval": 0,
  "pool_running": true,
  "source_error": null
}
```

| 字段 | 说明 |
|---|---|
| `current_proxy` | **最近一次分配出去的**上游出口（已脱敏），不是「当前那个代理」—— 多出口下请求是按负载摊到整组出口上的；本地来源没有可用出口时是该语言的「无」文案，非本地来源此时为空串。整组状态见 `active_proxies` |
| `mode` | 运行模式。**同一个键在两种来源下是两件事**：本地来源问「挑谁」——`cycle`（按清单顺序，忽略负载）/ `loadbalance`（谁压力小先用谁）；API 与维护池问「什么时候换」——`continuous`（持续更换）/ `request`（触发更换）。按来源归一后的值，换来源后不属于新那组的值会退回该组默认值 |
| `port` | **实际绑定的**代理端口（取自监听套接字），服务未运行时回落到配置值 |
| `interval` | 时间轮换间隔（秒） |
| `time_left` | **最近到期的那个出口还剩多久**，单位随 `switch_countdown_mode` 变化；名册为空时为 `0`。改出口由请求驱动还是后台主动做，取决于 `mode`：`continuous`（持续更换）下后台每拍都在换，空闲时这个数照样走；`request`（触发更换）与本地来源下空闲时到期的出口会被移除，池子可能为空 |
| `switch_countdown_mode` | 倒计时口径：`time`（秒，按出口各自的寿命；`interval` 与 `request_interval` 都填时按这个报 —— 秒数能画进度条，剩余请求数由每个出口的 `requests_left` 单独给出）/ `request_count`（只填了 `request_interval`，报还剩多少次请求）/ `per_request`（两项都没填，只在缺人或失效时补货）。**不会再返回 `none`**：寿命对所有来源、四种运行模式都生效 |
| `total_proxies` | 当前在用的出口条数。目标是 `exit_count`（`[Server] exit_count`），某个出口被判失效、或还没补上时这个数会小于目标；高峰自动扩容期间会大于它（同时 `elastic_active` 为真） |
| `active_proxies` | 各上游出口的实时状态：`url`（已脱敏）、`active` **正在用这个出口的连接数**（请求在途 + 最近有中继数据的隧道，面板与 CLI 的「在用」取它）、`inflight` 还占着名额的连接数（含空闲隧道，恒 ≥ `active`）、`capacity` 单出口活跃连接额度（`0` 表示不限制，空闲隧道不计入）、`failures` 连续失败次数、`suspect` 近期失败是否居多（居多的会被优先让路，但仍然可用）、`failure_ratio` 近期失败占比、`expires_in` 剩余寿命秒数、`requests_left` 剩余可服务的请求数（两个都是 `null` 表示没有启用该口径）、`last_used` / `added_at` / `expires_at` / `requests_served`（`time.monotonic()` 与计数，仅供同进程内比较） |
| `proxy_source_mode` | 代理来源：`local` / `api` / `pool` |
| `exit_count` | 出口池的目标容量（`[Server] exit_count`），与 `total_proxies` 成对读。**换的时机由运行模式决定**：持续更换（`continuous`）模式下空闲时也保持这么多；触发更换（`request`）与本地来源由请求驱动，空闲时到期的出口会被移除、池子可能空掉，下一个请求到达时才重新取货填满 |
| `elastic_active` | 出口数是否高于目标：突发扩容/高峰自动扩容中，或扩容已停止但多出来的出口还没到寿命（它们用满自己的寿命才逐个撤下） |
| `auth_required` | 出口代理是否要求用户名密码认证 |
| `display_level` | 控制台详细程度（`[Server] display_level`） |
| `service_status` | `running` / `stopped` |
| `language` | 当前界面语言 |
| `request_interval` | 按请求数切换的阈值（分配次数，不是「服务成功」的次数）。它与 `interval` 同时生效，谁先到谁换 |
| `pool_running` | 代理池是否在运行 |
| `source_error` | 最近一次从来源取出口失败的原因与时间（`{"message": ..., "at": ...}`）；没有失败时为 `null` |

## 配置管理

### 读取配置（GET /api/config）

返回 `[Server]` 与 `[Pool]` 两段的全部键值。

```json
{
  "status": "success",
  "server": { "port": "1080", "web_port": "5001", "mode": "cycle" },
  "pool": { "validator.timeout_seconds": "10" }
}
```

- **`token` 键已被剔除**，不会出现在响应里 —— 面板不需要回显它，避免它出现在页面源码、
  浏览器缓存或前端日志中。
- `[Users]` 与 `[api_credentials]` 不在这里返回，各有独立端点。
- 布尔项已被归一化成 `"true"` / `"false"`：`config.ini` 里写 `yes` / `on` / `1` 在运行期
  都算真，而界面只认 `"true"`，不归一化会让复选框显示成未勾选 —— 用户随手保存一次就把
  开关关掉了。

### 保存配置（POST /api/config）

请求体中的两段都可省略，但至少要有一段非空：

```json
{
  "server": { "mode": "loadbalance", "interval": "600" },
  "pool": { "validator.timeout_seconds": "15" }
}
```

键名经白名单校验，未知键与非法取值会被拒绝，返回 **HTTP 400**。

> `token` 也是合法的 `server` 键：**面板不提供它的编辑入口，但本接口接受它**，
> 因此改 token 可以走 `POST /api/config`（立即生效），也可以直接改 `config.ini`
> 后重启进程。

```json
{
  "status": "success",
  "port_changed": false,
  "web_port_changed": false,
  "service_status": "running",
  "applied": { "proxy": true, "pool": true }
}
```

| 字段 | 说明 |
|---|---|
| `port_changed` | 代理监听端口是否变了。配置热重载本身不重新绑定端口；**面板会据此自动重启出口服务**（`POST /api/service` 的 `restart`）以换到新端口，用命令行入口时需重启进程 |
| `web_port_changed` | 面板端口是否变了。**必须重启整个进程**才生效，当前面板仍运行在旧端口 |
| `applied.proxy` | 新配置是否成功推送给出口代理服务 |
| `applied.pool` | 新配置是否成功推送给代理池 |

`applied` 里的某一项为 `false` 表示**配置已落盘、但推送失败**，应答本身仍是 `success`。
此时应以 `applied` 为准判断是否真的生效。

校验失败时（HTTP 400）除 `message` 外还带 `details`，指明是哪个键、以及按界面语言渲染
好的原因，面板据此把提示落到具体输入框上：

```json
{
  "status": "error",
  "message": "配置项 port 非法（当前值: 70000）：不能大于 65535",
  "details": { "key": "port", "reason": "不能大于 65535" }
}
```

`details` 在 `key` 与 `reason_key` 齐备时才会出现（`[Server]` 与 `[Pool]` 的校验异常
都带这两个属性），其余异常只有 `message`。`message` 始终保留，老客户端不受影响。

保存配置时，若当前代理来源为 `pool`、未配置外部池地址（`pool_remote_url`）且池未运行，
会顺带自动拉起池服务。

## 语言

### 切换界面语言（POST /api/language）

语言是**服务端设置**，不是浏览器设置：它写回 `config.ini` 的 `[Server] language`，
并切换整个进程的文案（含面板、控制台横幅、接口 `message`、导出文件的表头与状态列）。

```json
{ "language": "en" }
```

| 字段 | 类型 | 必填 | 取值 |
|---|---|---|---|
| `language` | string | 否 | `cn` / `en`，缺省按 `cn` 处理 |

```json
{ "status": "success", "language": "en" }
```

取值不在 `cn` / `en` 之内时**仍返回 HTTP 200**，靠 `status` 判断：

```json
{ "status": "error", "message": "不支持的语言" }
```

> 该端点走的是面板侧的「业务失败返回 200」约定，不要只看状态码。

## 本地代理与名单

### 读写本地代理列表（GET/POST /api/proxies）

**GET** 返回 `config/` 下代理列表文件的内容。

```json
{ "proxies": ["http://1.2.3.4:8080", "socks5://5.6.7.8:1080"] }
```

读失败时返回错误，**不是**空列表——空列表会让界面显示成「一个代理都没有」，
用户随手一保存就把代理文件清空了：

```json
{ "status": "error", "message": "加载代理文件失败: ..." }
```

**POST** 整份覆盖写入，并立即热载入出口服务（不重新检测可用性）：

```json
{ "proxies": ["http://1.2.3.4:8080"] }
```

`proxies` **必须是数组**（传字符串会被逐字符拆行、传对象只会写进键名，两种都会
把文件覆盖成垃圾），否则：

```json
{ "status": "error", "message": "代理列表必须是数组" }
```

文件被其他进程占用时（Windows 上常见）可能失败：

```json
{ "status": "error", "message": "..." }
```

### 检测代理可用性（GET /api/check_proxies）

| 参数 | 必填 | 默认 | 说明 |
|---|---|---|---|
| `test_url` | 否 | `https://www.baidu.com` | 存活检测的目标地址 |

对**源清单**逐个检测，并发数取自 `[Server] check_concurrency`：

- `local` 来源：`proxy_file` 里的全部条目 —— 故意不查活名册，因为出口因失败被停用后
  就从名册里消失了，而那恰恰是最需要复查的那些。
- `api` / `pool` 来源：没有可读的本地清单，检测当前在用的出口。

```json
{
  "status": "success",
  "valid_proxies": ["http://1.2.3.4:8080"],
  "checked": 3,
  "total": 1,
  "message": "代理检查完成，有效代理：1个"
}
```

| 字段 | 说明 |
|---|---|
| `valid_proxies` | 检测通过的地址 |
| `checked` | 本次实际检测了几个（源清单的条数） |
| `total` | 检测通过的数量 |

检测只报告结论，不改变活名册 —— 想把新验证过的出口投入使用，等下一次批次刷新即可。

检测耗时随代理数量增长，请求可能等待较久（内部超时 30 秒）。

### 读写 IP 白名单 / 黑名单（GET/POST /api/ip_lists）

**GET**：

```json
{ "whitelist": ["127.0.0.1"], "blacklist": ["1.2.3.4"] }
```

**POST**：

```json
{ "type": "whitelist", "list": ["127.0.0.1"] }
```

| 字段 | 说明 |
|---|---|
| `type` | `whitelist` 或 `blacklist`，其他取值返回错误 |
| `list` | 完整名单，整份覆盖写入 |

写盘后立即热载入出口服务，无需重启。两份名单校验的是**客户端来源 IP**（连到代理端口
的那一端），在每个新连接建立时先判定，未通过直接返回 403 并记录「未授权的IP尝试访问」，
连接不会被转发。同时命中两份名单时的判定优先级由 `[Server] ip_auth_priority` 决定
（`whitelist` 放行 / `blacklist` 拦截）。

### 读写绕过名单（GET/POST /api/bypass_whitelist）

**GET**：

```json
{ "list": ["192.168.0.0/16"] }
```

**POST**：

```json
{ "list": ["192.168.0.0/16"] }
```

名单内的**目标地址**不做任何上游转发，直接由本机连接（不参与出口调度）。它与上面
按客户端来源 IP 判定的黑白名单是两回事：把某个目标加进本名单，不会跳过对客户端
IP 的黑白名单校验。

## 服务控制

### 启停出口代理服务（POST /api/service）

```json
{ "action": "start" }
```

| action | 说明 |
|---|---|
| `start` | 服务未运行时启动；已在运行则直接返回成功 |
| `stop` | 停止服务 |
| `restart` | 先停后起 |

```json
{ "status": "success", "message": "服务启动成功", "service_status": "running" }
```

`start` / `stop` 的响应会带 `service_status`（取值 `running` / `stopped`）；`restart` 成功时不带该字段。

**这个接口是串行且带超时的**：启动要等旧线程退出（最多 10 秒）再等服务就绪（最多 5 秒），
停止最多等 10 秒。超时即返回 `status` 为 `error`，**不会静默改用其他端口**。因此调用方
应留出足够长的请求超时。

端口被占用时返回错误，且不会启动服务：

```json
{
  "status": "error",
  "message": "端口 1080 已被其他程序占用，请更换其他端口后重试",
  "service_status": "stopped"
}
```

### 手动切换上游代理（GET /api/switch_proxy）

丢开现有候补、立刻调一次来源：**池子不满就补满；启用了出口寿命（`interval` 或
`request_interval` 非 0）时，满员则换掉最近到期的那个出口**（只填了
`request_interval` 时各出口没有时间寿命，实际换掉的是名册里的第一个）。
不是「换到下一个 IP」（所有出口本来就同时在用），也不是整批替换。响应有四种形态：

**切换成功**

```json
{
  "status": "success",
  "current_proxy": "http://1.2.3.4:8080",
  "active_proxies": [
    { "url": "http://1.2.3.4:8080", "inflight": 0, "active": 0, "capacity": 0, "failures": 0, "suspect": false, "failure_ratio": 0.0, "last_used": 0.0 }
  ],
  "total_proxies": 1,
  "message": "出口批次已刷新"
}
```

| 字段 | 说明 |
|---|---|
| `current_proxy` | 当前出口（最近一次分配出去的出口，已脱敏）；它被换掉时回退到名册里的第一个 |
| `active_proxies` | 当前名册的快照，字段含义同 `/api/status` |
| `total_proxies` | 当前名册里的出口数量 |

「成功」按刷新后**名册是否非空**判定 —— 已经是满员且这次只轮换了一个出口，同样算成功。

**处于冷却期**（距上次切换过近，`[Server] switch_cooldown` 内不再切换）

```json
{
  "status": "error",
  "cooldown": true,
  "cooldown_remaining": 12,
  "message": "..."
}
```

**已有切换在进行中**

```json
{ "status": "error", "switching": true, "message": "..." }
```

**切换失败**

```json
{ "status": "error", "current_proxy": "...", "message": "..." }
```

调用方应据 `cooldown` / `switching` 字段区分「暂时不切」与「真的失败」，两者都是
`status: error`。

## 日志

日志按用途分为四个类别：`access`（代理访问）、`proxy`（代理生命周期）、`main`（主程序）、
`pool`（代理池）。其中 `access` / `proxy` / `main` 三个类别有对应的日志文件，`pool` 只进
内存环形缓冲与 `error.log`，其自身文件在 `modules/proxypool/logs/` 下，不通过本组接口浏览。

### 查询内存日志（GET /api/logs）

| 参数 | 必填 | 默认 | 说明 |
|---|---|---|---|
| `category` | 否 | `all` | `all` / `access` / `proxy` / `main` / `pool`，其他取值返回错误 |
| `start` | 否 | `0` | **从最新一条往前跳过的条数** |
| `limit` | 否 | `200` | 返回条数，被限制在 1-2000 |
| `level` | 否 | `ALL` | 按级别过滤 |
| `search` | 否 | 空 | 关键词过滤 |

```json
{
  "logs": [
    {
      "seq": 8821,
      "time": "2026-09-30 12:00:00",
      "level": "INFO",
      "category": "main",
      "message": "..."
    }
  ],
  "total": 1234,
  "status": "success"
}
```

- `seq` 是**跨类别唯一的全局递增序号**，多个类别合并返回时按它还原真实先后。
  条目按时间正序排列。
- `total` 是**过滤后的总数**，不是本次返回的条数。
- `start` 的语义与常规分页相反：它是从最新一条往回数的偏移量，配 `limit` 用于
  「翻页看更早的日志」。

### 日志统计（GET /api/logs/stats）

```json
{
  "status": "success",
  "stats": {
    "total": 170,
    "levels": { "INFO": 150, "WARNING": 20 },
    "categories": { "main": 100, "access": 50, "proxy": 20, "pool": 0 },
    "capacity": { "main": 20000, "access": 5000, "proxy": 20000, "pool": 20000 },
    "first_time": "2026-09-30 10:00:00",
    "last_time": "2026-09-30 12:00:00"
  }
}
```

`total` 是四个环加起来的条数，`capacity` 是各环容量（`access` 环更小）。
`first_time` / `last_time` 在缓冲为空时不出现。

### 列出日志文件（GET /api/logs/files）

```json
{
  "status": "success",
  "files": [
    { "name": "main.log", "category": "main", "size": 20480,
      "modified": "2026-10-02 15:30:00", "current": true, "rotated": false }
  ]
}
```

| 字段 | 说明 |
|---|---|
| `name` | 文件名（面板拿它调 `/api/logs/file`） |
| `category` | `main` / `proxy` / `access` / **`error`**。`error` 是 ERROR 及以上的汇总文件，**不能**当作 `GET /api/logs` 的 `category` 参数传 |
| `size` / `modified` | 字节数 / 最后修改时间 |
| `current` | 是不是当前在写的那个；`rotated` 是它的反面（轮转出来的历史份） |

只列出 `logs/` 目录下的白名单文件（含轮转份），不含代理池自己的 `proxy_pool.log`。

### 读取日志文件（GET /api/logs/file）

| 参数 | 必填 | 默认 | 说明 |
|---|---|---|---|
| `name` | 是 | 空 | 文件名，取白名单内的名字 |
| `lines` | 否 | `500` | 读取末尾行数，被限制在 1-5000 |

```json
{ "status": "success", "name": "main.log", "lines": ["..."], "truncated": true }
```

`truncated` 为 `true` 表示文件的行数**不少于**请求的行数（恰好相等时也为 `true`），
本次只返回了末尾部分。文件名不在白名单内返回错误（**按白名单校验而非路径拼接，
杜绝目录穿越**）。

### 导出日志（GET /api/logs/export）

| 参数 | 必填 | 说明 |
|---|---|---|
| `file` | 否 | 指定文件名时**下载该文件的附件**；省略则导出内存日志 |
| `category` | 否 | 省略 `file` 时生效，同 `GET /api/logs` |
| `level` / `search` | 否 | 同上 |

省略 `file` 时返回纯文本附件，文件名为 `proxycat_export.log`。

### 清空日志（POST /api/logs/clear）

```json
{ "category": "all" }
```

清空对应类别的内存环形缓冲，并截断对应的日志文件。`category` 为 `all` 时清空全部。

```json
{ "status": "success", "message": "日志已清除" }
```

**会删掉磁盘上的日志内容**，不可恢复。

## 访问记录

逐条记录每一次代理请求。与「日志」的区别是它面向查询与统计：按列存储、可过滤、可导出。

### 查询访问记录（GET /api/logs/records）

| 参数 | 必填 | 默认 | 说明 |
|---|---|---|---|
| `since` | 否 | 1 小时前 | 起始时间，接受 `YYYY-MM-DD`、`YYYY-MM-DD HH:MM`、`YYYY-MM-DD HH:MM:SS`，也接受 `T` 分隔 |
| `until` | 否 | 不限 | 结束时间，粒度到分钟或日期时自动补到该时刻的最后一秒 |
| `outcome` | 否 | 不限 | `success` / `failure` / `aborted`，其他取值返回错误 |
| `upstream` | 否 | 不限 | 按上游代理过滤 |
| `host` | 否 | 不限 | 按目标主机过滤 |
| `search` | 否 | 空 | 关键词过滤 |
| `limit` | 否 | `100` | 被限制在 1-500 |
| `offset` | 否 | `0` | 分页偏移 |
| `order` | 否 | `desc` | 时间排序方向 |

```json
{
  "status": "success",
  "enabled": true,
  "range": { "since": "2026-09-30 11:00:00", "until": "" },
  "outcome_counts": { "success": 100, "failure": 3, "aborted": 1 },
  "total": 104,
  "export_limit": 50000,
  "records": [
    {
      "id": 12345,
      "ts": "2026-09-30 12:00:00",
      "kind": "http",
      "method": "GET",
      "client": "127.0.0.1/-",
      "client_ip": "127.0.0.1",
      "client_user": "-",
      "host": "example.com",
      "port": 443,
      "target": "example.com:443",
      "upstream": "http://1.2.3.4:8080",
      "upstream_label": "http://1.2.3.4:8080",
      "real_ip": "203.0.113.7",
      "outcome": "success",
      "status_code": 200,
      "elapsed_ms": 123,
      "reason": ""
    }
  ]
}
```

- `id` 是自增主键；`client`（`client_ip/client_user`）与 `target`（`host:port`）是**派生
  字段**，只是把相邻两列拼成界面直接可用的形态，与 `client_ip` / `host` 同源。
- `upstream` 为特殊值时用 `upstream_label` 给出可读文案：直连（`direct`）与未知上游
  （`unknown`）各有一种取值。
- 失败（`outcome=failure`）时 `status_code` 一律为空：隧道先建好、之后才失败的行不会
  带着建连那一下的 200 出现在这里（历史库里存过这种行，读取时统一收敛）。
- `real_ip` 是**这个出口实际用的出口 IP**（目标站看到的那个），网关型出口的地址与它
  不是一回事。它是展示字段：代理池来源由池收录时验证得出，API 来源在
  `[Server] access_records_real_ip_probe` 打开时由后台探测得出，本地来源恒为空串。
  探不到或没开启时是 `""`，界面显示成 `--`；直连的请求也是 `""`。
  它**不参与**出口调度、寿命与故障判定，老库里的历史记录同样是 `""`。
- 响应里另有三个落库状态字段与 `records` 平级返回：`pending`（尚未落盘的缓冲条数）、
  `dropped`（因缓冲写满而丢弃的条数）、`oldest_ts`（库里最早一条记录的时间，空串表示没有）。
  `dropped` 非零说明落盘跟不上，记录有丢失。

### 导出访问记录（GET /api/logs/records/export）

过滤参数与查询接口相同，额外一个：

| 参数 | 必填 | 默认 | 说明 |
|---|---|---|---|
| `format` | 否 | `csv` | `csv` 或 `json`，其他取值返回错误 |

- **CSV**：带 UTF-8 BOM，Excel 直接打开不乱码；**表头按当前界面语言渲染**。
- **JSON**：UTF-8，含 `exported_at`、过滤条件、`count` 与 `truncated` 元信息。

两种格式都受 `export_limit`（50000）限制；被截断的标记只有 JSON 的元信息里有
（`truncated`，取到的条数达到 50000 即为 `true`），CSV 只有正文、没有该标记。响应为
附件下载，文件名形如 `access_records_20260930_120000.csv`。

### 列出过滤候选项（GET /api/logs/records/options）

返回当前记录里出现过的上游代理与目标主机取值，供前端渲染下拉框。

```json
{ "status": "success", "upstreams": [{ "value": "http://1.2.3.4:8080", "label": "..." }] }
```

### 清空访问记录（POST /api/logs/records/clear）

```json
{ "status": "success", "removed": 1234, "message": "已清除 1234 条访问记录" }
```

**不可恢复。**

## 域名统计

按「目标域名 × 上游代理」累计请求的成败次数。与访问记录的区别：这里是聚合计数，
访问记录是逐条明细；因此访问记录可以清空而这里的累计值仍在，反之亦然。

### 查询域名统计（GET /api/logs/domains）

| 参数 | 必填 | 默认 | 说明 |
|---|---|---|---|
| `upstream` | 否 | 空 | **指定时下钻到该上游的域名明细，省略时按上游汇总** |
| `sort` | 否 | `last_seen` | 排序字段 |
| `order` | 否 | `desc` | 排序方向 |
| `search` | 否 | 空 | 关键词过滤 |
| `limit` | 否 | `100` | 被限制在 1-1000 |
| `offset` | 否 | `0` | 分页偏移 |

**省略 `upstream`——按上游汇总：**

```json
{
  "status": "success",
  "enabled": true,
  "summary": { "pairs": 42, "hosts": 12, "upstreams": 5, "success": 3400, "failure": 56 },
  "mode": "proxies",
  "proxies": [
    {
      "upstream": "http://1.2.3.4:8080",
      "upstream_label": "http://1.2.3.4:8080",
      "host_count": 7,
      "success": 100,
      "failure": 2,
      "total": 102,
      "rate": 98,
      "first_seen": "2026-09-30 10:00:00",
      "last_seen": "2026-09-30 12:00:00",
      "last_error": ""
    }
  ],
  "total": 1
}
```

**指定 `upstream`——下钻到域名：**

```json
{
  "status": "success",
  "enabled": true,
  "summary": { "pairs": 42, "hosts": 12, "upstreams": 5, "success": 3400, "failure": 56 },
  "mode": "domains",
  "upstream": "http://1.2.3.4:8080",
  "upstream_label": "http://1.2.3.4:8080",
  "domains": [
    {
      "host": "example.com",
      "upstream": "http://1.2.3.4:8080",
      "success": 50,
      "failure": 1,
      "first_seen": "2026-09-30 10:00:00",
      "last_seen": "2026-09-30 12:00:00",
      "last_status": 200,
      "last_error": ""
    }
  ],
  "total": 1
}
```

- `summary` 的 `pairs` 是「域名 × 上游」的组合数，`rate` 是成功率百分比（取整）。
- **用返回的 `mode` 字段区分两种形态，不要靠猜。**
- `enabled` 为 `false` 表示域名统计功能未开启（`[Server] domain_stats_enabled`），
  此时没有数据可查。

### 清空域名统计（POST /api/logs/domains/clear）

```json
{ "status": "success", "removed": 42, "message": "已清除 42 个域名的访问统计" }
```

## 用户与 API 凭据

### 读写出口代理账号（GET/POST /api/users）

**GET**：

```json
{ "status": "success", "users": { "neko": "123456" } }
```

读失败时返回 `status: "error"` 与 `users: null`，**不是空对象**——空对象会让界面
显示成「一个用户都没有」，管理员加一个用户再保存就用空表覆盖原账号，等于把出口
认证关掉。**响应里是明文密码**。

**POST** 整份覆盖 `[Users]` 段：

```json
{ "users": { "neko": "123456" } }
```

**传空对象即可关闭出口认证**（账号表为空时 `auth_required` 为 `false`）。

```json
{ "status": "success", "message": "用户保存成功" }
```

### 管理上游 API 凭据（GET/POST /api/api_credentials）

存多套「取代理接口」的凭据，并指定当前生效的一套。用 `set_active` 切换生效项、
或删除的正是生效项时，会**同步改写 `[Server] api_proxy_url` / `proxy_username` /
`proxy_password`**，因此代理来源为 `api` 时会立即用上新凭据；`save` 不同步这三键 ——
它只更新凭据集合与生效项标记，要让新保存的值真正被代理来源使用，需要对它再调一次
`set_active`（或由删除生效项触发的自动切换）把三键写回 `[Server]`。

**GET**：

```json
{
  "status": "success",
  "sets": [{ "name": "闪臣", "url": "https://...", "username": "", "password": "" }],
  "active_credential": "闪臣"
}
```

**响应含明文凭据。**

**POST**：

```json
{ "action": "save", "name": "闪臣", "url": "https://...", "username": "", "password": "" }
```

| action | 需要字段 | 说明 |
|---|---|---|
| `save` | `name`、`url`、`username`、`password` | 按 `name` 存在则更新，否则新增；`name` 为空返回错误。若当前没有生效项，或生效项正是这一条，则把它设为生效项 |
| `delete` | `name` | 按 `name` 删除；若删掉的正是生效项，则把第一条剩余项设为生效项、**并把它的三个键同步写回 `[Server]`**（没有剩余则清空这三键）—— 不换的话运行中的服务会继续用已删除的接口 |
| `set_active` | `name` | 切换生效项，并把它的 `url`/`username`/`password` 写进 `[Server]`；`name` 不在凭据集合里时返回错误，不会写一个「未选用」的中间态 |

`save` 与 `delete` 返回更新后的 `sets` 与 `active_credential`；`set_active` 返回
`active_credential` 与生效项的 `credential`，**不返回 `sets`**。未知 `action` 与空 `name`
返回错误（`{ "status": "error", "message": "..." }`），`set_active` 的 `name` 不在凭据集合
里时也返回错误。`save` 传一个不存在的 `name` 是新增；`delete` 不校验名字是否存在，
删除一个不存在的凭据名照常返回 `success`（`sets` 原样返回）。

## 版本检查与广告

> **本节端点无鉴权**，配置了 token 也无需携带。

### 检查版本（GET /api/version）

返回**最近一次**版本检查的结果。**本端点只读缓存，不会发起任何外部请求** ——
请求它永远不会产生网络等待。

```json
{
  "status": "success",
  "is_latest": true,
  "current_version": "ProxyCat-V3.0.0",
  "latest_version": "ProxyCat-V3.0.0"
}
```

| 字段 | 说明 |
|---|---|
| `is_latest` | 远端版本是否不高于当前版本；**每次读取时按当前的 `CURRENT_VERSION` 重算** |
| `current_version` | 本进程的版本 |
| `latest_version` | 最近一次检查取到的远端版本 |

**检查的节奏由进程自己掌握，不由本端点触发：**

- **进程启动时查一次**，之后**每 24 小时一次**。
- **24 小时内重启不会重复检查**：上次检查的时间写在 `logs/version_check.json` 里，
  重启后读回来继续用。两个入口（`app.py` 与 `ProxyCat.py`）都是这个节奏。
- **无论成败都记录时间**，因此对外最多 24 小时发起一次请求；断网时不会再出现
  「每次打开面板都要等一次超时」的情况。
- 检查在后台线程里做，不阻塞启动，也不占用 Web 工作线程。

**既没有成功结果、也没有失败记录时**（启动后第一次检查还没跑完）返回：

```json
{
  "status": "error",
  "message": "尚未完成版本检查"
}
```

**检查失败时**（断网、远端页面结构变化）返回 `status` 为 `error`，`message` 说明原因；
但若此前成功过，则**继续返回上一次成功的结果** —— 面板不是监控工具，展示最后已知的
版本状态比展示错误更有用。失败本身记在日志里。

> 升级到新版本后，即使距上次检查不足 24 小时也会立即重查：状态文件里存着
> 「当时检查的当前版本」，与进程里的版本不一致即视为过期。

### 获取广告（GET /api/ads）

读取 `config/ads/` 目录下所有 `*.json`，返回 `enabled` 不为 `false` 的条目。
解析失败的文件静默跳过。

```json
{
  "status": "success",
  "ads": [
    {
      "id": "example",
      "title": "...",
      "body": "...",
      "image_url": "",
      "link_url": "",
      "link_text": "",
      "display_time": 15
    }
  ],
  "total": 1,
  "dismissed": false
}
```

`dismissed` 是**进程内的关闭状态，重启即丢失**。

### 关闭 / 重新开启广告（POST /api/ads/dismiss、POST /api/ads/reopen）

两个端点都无参数、无鉴权，响应体是 `{ "status": "success", "dismissed": <布尔值> }`，
关闭置 `true`、重新开启置 `false`：

```json
{ "status": "success", "dismissed": true }
```

---

# 三、代理池接口

全部挂在 `/api/pool` 前缀下，**鉴权与面板一致**（同一个 `before_request` 钩子）。

## 池侧约定

### 成功响应没有统一外壳

适配层把处理函数的返回值**直接序列化成响应体**，因此：

- `GET /api/pool/get` 返回一个 **JSON 数组**（不是 `{"status": ..., "data": [...]}`）。
- `GET /api/pool/count` 返回 `{"count": 12}`，**没有 `status` 字段**。
- `GET /api/pool/random?format=text` 与导出接口返回**纯文本或附件**，不是 JSON。
- 只有部分端点会在返回值里自带 `status` 与 `message`（如生命周期端点）；插件操作返回的是
  `success` 与 `message`，没有 `status` 字段。

**判断成功请看 HTTP 状态码与响应内容本身，不要假设一定有 `status` 字段。**

### 错误响应

```json
{
  "status": "error",
  "message": "错误描述",
  "error_code": "invalid_parameter"
}
```

| error_code | HTTP | 含义 |
|---|---|---|
| `invalid_parameter` | 400 | 请求参数非法（含缺失必填字段、取值越界） |
| `api_error` | 4xx / 5xx | 业务错误，如代理不存在、规格不匹配。HTTP 状态码随错误自带（如插件操作失败、备份恢复失败为 500，归属地解析服务未启用为 503），不要按 4xx 写死分支 |
| `pool_running` | 409 | 池运行中，不允许该操作（**仅备份恢复**会返回） |
| `pool_unavailable` | 503 | 代理池未运行或正在重启 |
| `pool_timeout` | 504 | 代理池响应超时 |
| `queue_full` | 503 | 写入队列已满，请求被拒（背压） |
| `internal_error` | 500 | 服务端内部错误 |

**两个例外要知道：**

- `POST /api/pool/start|stop|restart` 失败时返回 **500 且不带 `error_code`**，
  只有 `status` / `message` / `is_running`。
- `message` 跟随界面语言，**不可用于程序判断**。

### 池未运行时

池未启动时，除状态查询、生命周期端点、备份列表/恢复与 `/schema` 外，**其余端点一律返回
`503 pool_unavailable`**。调用方应先查 `GET /api/pool/status` 确认 `is_running`。

### 任务模型

所有耗时操作（批量验证、导入、抓取、归属地更新/重算）都**立即返回 `task_id`**，
真正的执行在后台，进度按 `task_id` 轮询。

- 任务状态是**进程内内存态**：进程重启即全部丢失。
- 已完成/失败的任务保留 **1 小时**（TTL），超过即被淘汰；状态表上限 200 条。
- 创建时返回的 `status`（`queued` / `running`）**只是创建瞬间的快照，不代表执行结果**；
  任务表里的条目从创建起就直接写 `running`，不存在 `queued` 状态的条目。
- 任务表里实际出现的状态：`running` / `completed` / `failed` / `cancelled`
  （`queued` 只在部分创建响应里出现，用它过滤任务永远筛不到条目）。

### 没有上报使用反馈的接口

「使用期反馈」是出口代理在真实转发过程中**在进程内部**回报给池的（见
[功能特性里的「代理池机制」](ProxyCat-Manual/Features.md#代理池机制)），**没有任何 HTTP 端点可以上报使用结果**，
不必去找。

## 池状态与生命周期

### 获取池状态（GET /api/pool/status）

```json
{
  "status": "success",
  "is_running": true,
  "last_error": null,
  "stats": {
    "total_proxies": 120,
    "valid_proxies": 86,
    "invalid_proxies": 34,
    "anonymity_fallback_proxies": 5,
    "protocol_distribution": { "http": 60, "socks5": 26 },
    "region_distribution": { "中国": 40, "美国": 12 }
  }
}
```

| 字段 | 说明 |
|---|---|
| `is_running` | 池是否在运行 |
| `last_error` | 最近一次错误文案，无错误时为 `null` |
| `stats` | 全局统计；**池未运行时为 `null`**。统计本身失败也不影响本端点返回成功，只是 `stats` 为 `null` |
| `anonymity_fallback_proxies` | 匿名度被判成兜底档的条数 |
| `region_distribution` | 只取数量最多的前 10 个地区 |

### 获取池配置字段结构（GET /api/pool/schema）

返回 `[Pool]` 段的字段分组、类型、说明与取值区间，**面板的「池设置」表单就是按它渲染的**。
文案跟随当前界面语言。

```json
{
  "status": "success",
  "groups": [
    {
      "title": "数据库",
      "sub": "数据存在哪、怎么备份",
      "id": "database",
      "fields": [
        { "key": "database.path", "doc": "代理池所有数据存放的文件（SQLite 格式）", "type": "text",
          "title": "数据库文件路径", "hint": "改动需重启池服务；相对路径从 proxypool 目录起算" },
        { "key": "database.pool_max_readers", "doc": "...", "type": "int", "low": 1, "high": 64,
          "title": "读连接数上限", "tier": "advanced" },
        { "key": "database.backup_interval_hours", "doc": "...", "type": "int", "low": 1,
          "title": "备份间隔", "unit": "小时", "tier": "advanced", "visible_when": "database.backup_enabled=true" }
      ]
    }
  ]
}
```

| 字段 | 说明 |
|---|---|
| `type` | 字段类型，取值 `bool` / `int` / `float` / `list` / `text`（字符串字段一律是 `text`，没有 `str`） |
| `doc` | 完整说明，与 `config.ini` 里的注释逐字一致 |
| `title` | 短标题，直接当表单的字段标签用 |
| `hint` | 控件下方的一行提示；是否出现取决于字段是否写了提示 |
| `unit` | 计量单位，由面板渲染在输入框右侧。**单位不写进 `title`**，语言包无对应值时该键不输出 |
| `tier` | 为 `"advanced"` 时归入「高级选项」折叠区 |
| `visible_when` | 声明式显隐规则 `键=值1\|值2;键2!=值`（分号是「与」、竖线是「或」）。带此规则的字段内联显示、不折叠。隐藏只影响显示，字段照常收集与保存 |
| `sub`（分组级） | 分组副标题，显示在卡片标题右侧 |

`low` / `high` 只在配置项有取值区间时出现。**本端点不返回当前值** —— 当前值走
`GET /api/config` 的 `pool` 字段。

### 启动池（POST /api/pool/start）

无参数。

```json
{ "status": "success", "message": "维护池启动成功", "is_running": true }
```

### 停止池（POST /api/pool/stop）

无参数。**会等写队列排空**，可能耗时数秒。

```json
{ "status": "success", "message": "维护池停止成功", "is_running": false }
```

### 重启池（POST /api/pool/restart）

无参数。先停后起，停止与启动各最多等 30 秒。

失败时（三个生命周期端点相同）：

```json
{ "status": "error", "message": "...", "is_running": false }
```

HTTP 状态码为 **500，且不带 `error_code`**。

## 代理查询与单条操作

### 查询代理列表（GET /api/pool/get）

**返回一个 JSON 数组**，元素为[代理对象](#附录-c字段字典)。

| 参数 | 类型 | 默认 | 取值与语义 |
|---|---|---|---|
| `protocol` | string | 不限 | `http` / `https` / `socks5`，其他取值返回 400 |
| `region` | string | 不限 | 归属地模糊匹配（中、英两列都匹配）；**以 `-` 开头表示排除**，如 `-美国` 表示排除归属地含「美国」的代理 |
| `min_delay` | int | 不限 | 最小延迟（毫秒），负数报错 |
| `max_delay` | int | 不限 | 最大延迟（毫秒），负数报错；与 `min_delay` 顺序颠倒报错 |
| `status` | string | 不限 | `valid` / `invalid`，其他取值返回 400 |
| `source` | string | 不限 | 来源插件名 |
| `sort_by` | string | `delay_ms` | 见下方白名单 |
| `sort_order` | string | `asc` | `asc` / `desc` |
| `limit` | int | 不限 | 只取前 N 条；设置后 `page` 被强制为 1。上限 50000 |
| `page` | int | `1` | 页码，必须 ≥ 1 |
| `page_size` | int | `50` | 每页条数，1 到 50000 |
| `format` | string | `json` | `json` 或 `text`；`text` 返回每行一个代理地址的纯文本 |
| `ip` | string | 不限 | 按 IP 模糊匹配 |
| `is_favorite` | bool | 不限 | 只看收藏 / 只看未收藏 |
| `anonymity_level` | string | 不限 | `transparent` / `anonymous` / `elite` / `unverified` |
| `min_health_score` | float | 不限 | 最低健康分，负数报错 |
| `supports_https` | bool | 不限 | 只看支持 / 不支持 HTTPS 的代理 |

`sort_by` 白名单：`delay_ms`、`protocol`、`region`、`validated_at`、`created_at`、
`health_score`、`anonymity_level`、`success_count`、`total_checks`、`avg_delay_ms`、
`failure_count`、`is_favorite`、`supports_https`、`success_rate`、`region_en`。

> **写错 `sort_by` 不会报错**：不在白名单内会**静默回落到 `delay_ms`**；`sort_order`
> 不是 `asc` / `desc` 时静默回落到 `asc`。排序结果不对时先检查参数名拼写。

> **未知查询参数被静默忽略**（见 [参数解析规则](#参数解析规则仅代理池接口)）。
> 参数名写错时不会报错，只会返回未筛选的结果。

### 取一个代理（GET /api/pool/random）

随机返回一个符合条件的代理，筛选参数与 `/get` 相同（**没有** `sort_by` / `sort_order` /
`limit` / `page` / `page_size`），另有：

| 参数 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `format` | string | `json` | `json` 返回完整[代理对象](#附录-c字段字典)；`text` 只返回 `协议://ip:端口` 一行 |

```json
{
  "id": 42,
  "proxy_url": "http://1.2.3.4:8080",
  "protocol": "http",
  "ip": "1.2.3.4",
  "port": 8080,
  "delay_ms": 320.5,
  "health_score": 87.3,
  "anonymity_level": "elite",
  "region": "中国 广东 深圳"
}
```

（上例为节选，完整字段见[附录 C](#附录-c字段字典)。）

纯文本形态的 `format=text` 响应体就是一行：

```
http://1.2.3.4:8080
```

**错误与边界：**

- 没有符合条件的代理 → **404 `api_error`**。
- `format` 不是 `json` / `text` → 400 `api_error`。

> **随机不是严格等概率**：实现是「先计数、随机挑一页（每页 100 条）、再随机挑一条」，
> 以页为粒度。池子很小时各条被取到的概率略有差异，但对取用没有实际影响。

> 这个端点的 `format=text` 正是 [`pool_remote_url`](ProxyCat-Manual/Configuration.md#来源设置) 期望的响应形态 ——
> 可以用另一个 ProxyCat 实例的 `/api/pool/random?format=text&token=...` 作为外部池地址。

### 统计代理数量（GET /api/pool/count）

筛选参数与 `/get` 相同（去掉排序与分页）。

```json
{ "count": 86 }
```

### 导出代理（GET /api/pool/export）

筛选参数与 `/get` 相同（去掉排序与分页），另有：

| 参数 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `format` | string | `txt` | `txt` / `json` / `csv`，其他取值返回 400 |

- **`txt`**：每行一个代理地址，附件名 `proxies_YYYYMMDD_HHMMSS.txt`。
- **`json`**：附件，字段为 `protocol`、`ip`、`port`、`username`、`password`、`url`、
  `region`、`region_en`、`delay_ms`、`is_valid`、`real_ip`、`source_plugin`、`validated_at`。
- **`csv`**：附件，带 UTF-8 BOM；**表头列数与顺序是对外契约**（协议、IP、端口、用户名、
  密码、代理地址、归属地、延迟、状态、真实 IP、来源、验证时间），表头与状态列文案跟随
  界面语言。英文归属地列**刻意不在导出里**。

**一次最多导出 50000 条。**

**错误与边界：** 没有符合条件的代理 → **404 `api_error`**。

### 导入代理（POST /api/pool/import）

请求体：

```json
{ "proxies": ["http://1.2.3.4:8080", "socks5://user:pass@5.6.7.8:1080"] }
```

导入与插件抓取走**同一条流水线**：先端口初筛、再做完整验证，**只有验证通过的才入库**，
来源固定记为 `manual_import`。本端点为 HEAVY 档。

响应有三种结果，**调用方必须同时看 `message` 与 `proxy_count`，不能只看 `success`**：

| 情形 | 响应 |
|---|---|
| 正常受理 | `{ "success": true, "message": "正在后台验证 N 个代理，通过后才入库", "proxy_count": N, "task_id": "..." }` |
| 全部解析失败 | `{ "success": false, "message": "...", "proxy_count": 0 }` |
| 全部已存在 | `{ "success": true, "message": "所有代理已存在，未导入新代理", "proxy_count": 0 }` |

- 空列表 → **400 `invalid_parameter`**。
- 「已存在」的判据是逐条按 `ip:port` 查库，不走去重缓存。
- 受理后进度按返回的 `task_id` 轮询。

### 切换收藏状态（POST /api/pool/proxies/{id}/favorite）

无请求体。

```json
{
  "success": true,
  "is_favorite": true,
  "message": "代理已收藏"
}
```

**这是「切换」而不是「设置」，重复调用会在两个状态之间来回翻转**，没有幂等参数。
代理不存在 → 404 `api_error`。收藏状态代表用户选择，抓取与验证写入不会覆盖它。

## 统计与主机信息

### 获取池统计（GET /api/pool/stats）

```json
{
  "total_proxies": 120,
  "valid_proxies": 86,
  "invalid_proxies": 34,
  "anonymity_fallback_proxies": 5,
  "protocol_distribution": { "http": 60, "socks5": 26 },
  "region_distribution": { "中国": 40, "美国": 12 }
}
```

**响应没有 `status` 字段**，直接就是统计对象（与 `/status` 里的 `stats` 同构）。

### 获取来源列表（GET /api/pool/sources）

```json
{ "sources": ["geonode_plugin", "github_proxy_plugin", "manual_import"] }
```

返回库里出现过的全部来源插件名，包含手动导入用的伪插件名 `manual_import`。

### 获取本机出口 IP（GET /api/pool/host-ip）

返回本机公网出口 IP，它是判定「透明代理」的对比基准。

```json
{
  "host_public_ip": "203.0.113.7",
  "host_public_ipv4": "203.0.113.7",
  "host_public_ipv6": "240e:37a:2563:cb00:9424:56ad:5734:d8",
  "source": "detected",
  "check_anonymity": true
}
```

| 字段 | 说明 |
|---|---|
| `host_public_ip` | 本机出口 IP 的单值形态，**优先 IPv4**，只有 IPv6 时给 IPv6；**拿不到时为 `null`，这是正常状态而非故障** |
| `host_public_ipv4` | 该族的出口 IP，拿不到时为 `null` |
| `host_public_ipv6` | 该族的出口 IP，拿不到时为 `null` |
| `source` | 该值的来源（`configured` 手动指定 / `detected` 自动查询），拿不到时为空串 |
| `check_anonymity` | 匿名度检测是否开启 |

双栈主机两族各有一个出口 IP，**两族都会参与匿名度比对**，所以这里分族给出。

基准值优先取 `[Pool] validator.host_public_ip`（可填逗号分隔的一到两个，IPv4 与 IPv6 各至多一个）；留空时由程序自行查询 —— 查询会**钉死地址族各问一次**，不是取第一个应答的端点，否则拿到的族别会随端点可用性漂移。每 30 分钟最多一次。

## 插件管理

### 列出插件（GET /api/pool/plugins）

```json
[
  {
    "name": "geonode_plugin",
    "enabled": true,
    "interval_minutes": 60,
    "last_run": "2026-09-30T11:00:00",
    "next_run": "2026-09-30T12:00:00",
    "last_error": null,
    "is_loaded": true,
    "test_url": "",
    "reval_enabled": true,
    "reval_interval_minutes": 0,
    "skip_validation": false
  }
]
```

| 字段 | 说明 |
|---|---|
| `name` | 插件名，**等于插件文件的文件名（不含扩展名）** |
| `enabled` | 是否参与自动抓取调度 |
| `interval_minutes` | 抓取周期（分钟） |
| `last_run` / `next_run` | ISO 8601 字符串或 `null` |
| `last_error` | 最近一次错误；**若是内置文案键则按当前语言渲染，若是插件自己抛的异常文本则原样给出** |
| `is_loaded` | 模块是否已成功加载。**响应只包含加载成功的插件，因此恒为 `true`**；加载失败的插件不会出现在列表里（错误只记在池的日志中） |
| `test_url` | 该插件专用的存活检测地址，空串表示继承全局 `[Server] test_url` |
| `reval_enabled` | 是否参与自动重验证 |
| `reval_interval_minutes` | 重验证周期，`0` 表示继承全局 |
| `skip_validation` | 是否跳过入库验证（**高危**，见下） |

**响应是 JSON 数组，没有 `status` 字段。**

### 启用 / 禁用插件（POST /api/pool/plugins/{name}/enable、POST /api/pool/plugins/{name}/disable）

无请求体。

```json
{ "success": true, "message": "插件 geonode_plugin 已启用" }
```

失败时返回 500 `api_error`。

### 设置抓取周期（PUT /api/pool/plugins/{name}/interval）

```json
{ "minutes": 30 }
```

`minutes` 必须 ≥ 1，否则 400 `invalid_parameter`。

```json
{ "success": true, "message": "插件 geonode_plugin 运行周期已设置为 30 分钟" }
```

### 设置插件检测地址（PUT /api/pool/plugins/{name}/test-url）

```json
{ "test_url": "https://example.com" }
```

**`test_url` 为空串或全空白表示继承全局** `[Server] test_url`：

```json
{ "success": true, "message": "插件 geonode_plugin 的测试地址已恢复为继承全局地址" }
```

### 设置插件验证策略（PUT /api/pool/plugins/{name}/validation）

```json
{ "reval_enabled": true, "reval_interval_minutes": 0, "skip_validation": false }
```

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `reval_enabled` | bool | `true` | 是否参与自动重验证 |
| `reval_interval_minutes` | int | `0` | 重验证周期（分钟）；**`0` 表示继承全局**。传字符串也能接受，非整数返回 400 |
| `skip_validation` | bool | `false` | 跳过入库验证 |

```json
{ "success": true, "message": "插件 geonode_plugin 的验证策略已更新" }
```

> **`skip_validation` 是危险开关**：打开后该插件抓到的代理**不经验证直接入库**，
> 池的质量评分与自动清理都会失去意义。它只对**已加载的真实插件**开放，对伪插件名
> `manual_import` 会返回 404 —— 否则一次性打开就会让此后所有手动导入都不再验证。

### 立即执行插件（POST /api/pool/plugins/{name}/run）

无请求体。**只创建后台任务便返回**，被抓取本身受 `[Pool] plugins.execution_timeout_seconds`
约束。

```json
{
  "task_id": "8f14e45f-ea6b-4c1e-9c1a-0f3b2d5e7a91",
  "status": "running",
  "message": "插件 geonode_plugin 抓取任务已创建"
}
```

`status` 只是创建瞬间的快照，进度与结果按 `task_id` 轮询。插件未加载 → 404 `api_error`。

### 热重载插件（POST /api/pool/plugins/{name}/reload）

无请求体。改完插件源码后无需重启进程。

**可预期的失败返回 200 + `success: false`，只有未预期异常才报 500：**

```json
{ "success": true, "message": "插件 geonode_plugin 热重载成功" }
```

```json
{ "success": false, "message": "插件 geonode_plugin 热重载失败（可能正在执行中或文件不存在）" }
```

插件文件不存在、正在执行、或加载返回空，都会走 `success: false`。

## 批量操作

**本节所有端点都立即返回 `task_id`**（除两个删除端点），进度按
[任务管理](#任务管理)轮询。

### 重新验证有效代理（POST /api/pool/validate/all-valid）

无参数。对当前所有 `is_valid = true` 的代理做一轮重验证。

```json
{ "task_id": "...", "status": "queued", "message": "验证任务已创建" }
```

### 重新验证失效代理（POST /api/pool/validate/all-invalid）

无参数。对当前所有 `is_valid = false` 的代理做一轮重验证。

> **这是把「被使用反馈标记失效」的代理立刻重验的入口**：被标记失效时 `total_checks`
> 会一并清零（日志记为「列入下一轮重验证候选」），而自动重验证每轮都会把
> `total_checks = 0` 的代理补充进候选（不受 `auto_revalidation.only_valid_proxies`
> 限制，但仍按各自的重验证间隔排期），所以这些代理不依赖本端点也会被重新验证。

```json
{ "task_id": "...", "status": "queued", "message": "验证任务已创建" }
```

### 全面检测并补归属地（POST /api/pool/update-geo/all）

无参数。对全部代理做完整评估（延迟、出口 IP、匿名度、协议支持），顺带补齐归属地。
比日常重验证重得多。

```json
{ "task_id": "...", "status": "queued", "message": "代理全面检测任务已创建" }
```

### 删除全部失效代理（DELETE /api/pool/delete/invalid）

无参数。**删完不可恢复。**

```json
{ "success": true, "message": "成功删除 34 个失效代理", "deleted_count": 34 }
```

没有失效代理时同样返回成功，`deleted_count` 为 0。本端点为 HEAVY 档。

### 批量验证指定代理（POST /api/pool/proxies/batch/validate）

```json
{ "proxy_ids": [1, 2, 3], "mode": "liveness" }
```

| 字段 | 类型 | 必填 | 默认 | 说明 |
|---|---|---|---|---|
| `proxy_ids` | int[] | 是 | — | 代理 id 列表；为空返回 400 |
| `mode` | string | 否 | `auto` | `auto` / `liveness` / `full`，其他取值返回 400 |

```json
{ "task_id": "...", "status": "running", "message": "正在验证 3 个代理" }
```

- **不存在的 id 会被静默忽略**，只有**一个都不存在**时才返回 404 `api_error`。
- 三种模式：`liveness` 只判通不通；`full` 做完整评估；`auto` 按代理已有信息自动选。

### 批量删除指定代理（DELETE /api/pool/proxies/batch/delete）

**注意：这是 DELETE 请求，但参数在请求体里。**

```json
{ "proxy_ids": [1, 2, 3] }
```

```json
{ "success": true, "message": "成功删除 3 个代理", "deleted_count": 3 }
```

`proxy_ids` 为空返回 400；不存在的 id 被静默忽略，`deleted_count` 取实际删除行数。

## 任务管理

### 列出任务（GET /api/pool/tasks）

| 参数 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `status` | string | 不限 | 按状态过滤：`running` / `completed` / `failed` / `cancelled`（任务表里没有 `queued`，传它筛不到条目） |

```json
{
  "tasks": [
    { "task_id": "8f14e45f-...", "status": "running", "progress": 40, "total": 120, "message": "..." }
  ],
  "total": 1
}
```

### 查询任务状态（GET /api/pool/tasks/{task_id}）

**响应就是任务条目本身，没有 `status` 外层字段**（条目内自带 `status` 表示任务状态）。

```json
{
  "status": "running",
  "message": "正在验证代理...",
  "stage": "validate",
  "progress": 40,
  "total": 120,
  "stage_done": 40,
  "stage_total": 120,
  "rate": 12.5,
  "eta_seconds": 6,
  "started_at": "2026-09-30T12:00:00",
  "valid_count": 22,
  "invalid_count": 10
}
```

字段随任务类型不同：只有导入/抓取类任务带 `stage` 与全套计数；批量验证与全面检测类
任务另有 `inconclusive_count`。**任务不存在或已被 TTL 淘汰 → 404 `api_error`。**

> 任务条目是**内存态**：进程重启后查不到任何历史任务。

### 取消任务（POST /api/pool/tasks/{task_id}/cancel）

无请求体。

```json
{ "success": true, "message": "任务已取消" }
```

**任务已经结束时返回 `success: false`，这不是错误**：

```json
{ "success": false, "message": "任务已经结束，无需取消" }
```

任务 id 不存在 → 404 `api_error`。

## 归属地维护

归属地解析用**离线库**（GeoLite2 与纯真库），不发外部查询请求。本节三个端点都是维护动作。

### 查询离线库状态（GET /api/pool/geo/status）

```json
{
  "available": true,
  "files": [ { "filename": "GeoLite2-City.mmdb", "exists": true,
               "size": 65383808, "modified_at": "2026-10-02 12:00:00" } ],
  "pending_recompute": 42
}
```

`modified_at` 在文件不存在时为 `null`。

| 字段 | 说明 |
|---|---|
| `available` | 离线库是否可用（**两个数据文件都在才算可用**） |
| `files` | 各数据文件的状态 |
| `pending_recompute` | 待重算归属地的记录数；查不到时按 0 返回，不报错 |

### 更新离线库（POST /api/pool/geo/update）

无参数。**会下载约 100 MB 的数据文件**，做成后台任务。

```json
{ "task_id": "...", "status": "queued", "message": "离线归属地库更新任务已创建" }
```

- 两个文件合计约 **105 MB**（GeoLite2 约 65 MB、纯真库约 40 MB）。
- **不校验磁盘空间**，空间不足会在下载中途失败。
- 一个文件失败不阻断另一个，失败项在任务结果的 `message` 里如实回报。

### 重算归属地（POST /api/pool/geo/recompute）

无参数。按离线库重算存量记录的归属地。

```json
{ "task_id": "...", "status": "queued", "message": "归属地重算任务已创建" }
```

**错误与边界：**

- **只重算 `country_code` 为空的记录**（即从未用离线库解析过的出口 IP）。已经解析过的
  记录不会被重算；更新数据文件后没有专门的立即刷新操作，但 `POST /api/pool/update-geo/all`
  的全面检测会把各出口 IP 重新交给解析器、可间接写回新归属地（受进程内查询缓存与耗时
  限制，并非即时生效）。
- 归属地解析服务未启用时直接返回 **503 `api_error`**，不创建任务。

## 数据库与备份

### 列出备份（GET /api/pool/backups）

```json
{
  "backups": [
    { "filename": "proxies_backup_20260930_030000.db", "size": 1048576, "created_at": "2026-09-30 03:00:00" }
  ]
}
```

备份由 `[Pool] database.backup_enabled` 控制的定时循环创建，本端点只列出已有备份。
**备份功能未启用时返回 404 `api_error`。** 本组备份列表与恢复是纯文件操作，
**池停止时同样可用**。

### 从备份恢复（POST /api/pool/backups/restore）

```json
{ "filename": "proxies_backup_20260930_030000.db" }
```

```json
{ "success": true, "message": "备份恢复成功，请重启代理池以加载恢复后的数据" }
```

**语义约定（三条都很重要）：**

1. **池运行中返回 409 `pool_running`** —— 覆盖正在打开的数据库文件会造成损坏，
   必须先停池。这是**唯一**会返回 `pool_running` 的端点。
2. 恢复**只覆盖库文件，不校验备份与当前库的版本兼容性**。
3. 恢复成功后**必须重启池**才会加载新数据。端点本身不重启池；面板的
   「数据库维护」页会在恢复完成后自动重启（恢复前先停池、恢复后按原状态启回），
   直接调接口的客户端要自己调 `POST /api/pool/start`。

`filename` 缺失 → 400 `invalid_parameter`。

### 数据库统计（GET /api/pool/database/stats）

```json
{ "stats": { "total_proxies": 120, "valid_proxies": 96, "invalid_proxies": 24,
             "db_size_mb": 1.05 } }
```

需要池在运行。维护功能未启用时返回 404 `api_error`。

### 优化数据库（POST /api/pool/database/optimize）

无参数。执行 `ANALYZE` + `REINDEX` + `VACUUM`，**HEAVY 档，且 VACUUM 会长时间独占
数据库锁**，期间其他数据库操作会被阻塞。

```json
{ "success": true, "message": "数据库优化完成" }
```

## 代理池错误码

见[池侧约定 → 错误响应](#错误响应)。汇总表见
[附录 A](#附录-a错误码总表)。

---

# 四、端到端调用示例

## Python

```python
import requests

HOST = "http://localhost:5001"
TOKEN = "你的token"
PARAMS = {"token": TOKEN}

# 面板：看运行状态
status = requests.get(f"{HOST}/api/status", params=PARAMS).json()
print(status["current_proxy"], status["proxy_source_mode"])

# 面板：手动切换一次上游代理
switched = requests.get(f"{HOST}/api/switch_proxy", params=PARAMS).json()
if switched["status"] != "success":
    # 冷却中和真的失败都是 error，靠字段区分
    print("冷却中" if switched.get("cooldown") else switched.get("message"))

# 面板：查询最近一小时的失败请求
records = requests.get(
    f"{HOST}/api/logs/records",
    params={**PARAMS, "outcome": "failure", "limit": 50},
).json()
for row in records["records"]:
    print(row["ts"], row["host"], row["upstream_label"], row["reason"])

# 代理池：取一个可用代理（纯文本）
proxy = requests.get(
    f"{HOST}/api/pool/random",
    params={**PARAMS, "status": "valid", "format": "text"},
).text.strip()
print(proxy)   # 例如 http://1.2.3.4:8080

# 代理池：创建批量验证任务并轮询
task = requests.post(
    f"{HOST}/api/pool/proxies/batch/validate",
    params=PARAMS,
    json={"proxy_ids": [1, 2, 3], "mode": "liveness"},
).json()
progress = requests.get(
    f"{HOST}/api/pool/tasks/{task['task_id']}", params=PARAMS
).json()
print(progress["status"], progress.get("progress"), progress.get("total"))
```

## cURL

```bash
# 面板：运行状态
curl "http://localhost:5001/api/status?token=YOUR_TOKEN"

# 面板：保存配置（改轮换模式）
curl -X POST "http://localhost:5001/api/config?token=YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"server": {"mode": "loadbalance"}}'

# 面板：重启出口代理服务
curl -X POST "http://localhost:5001/api/service?token=YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action": "restart"}'

# 面板：切换界面语言
curl -X POST "http://localhost:5001/api/language?token=YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"language": "en"}'

# 面板：导出最近一小时的访问记录为 CSV
curl -OJ "http://localhost:5001/api/logs/records/export?token=YOUR_TOKEN&format=csv"

# 代理池：筛选查询
curl "http://localhost:5001/api/pool/get?protocol=http&status=valid&limit=10&token=YOUR_TOKEN"

# 代理池：取一个可用代理（纯文本）
curl "http://localhost:5001/api/pool/random?status=valid&format=text&token=YOUR_TOKEN"

# 代理池：手动运行插件
curl -X POST "http://localhost:5001/api/pool/plugins/geonode_plugin/run?token=YOUR_TOKEN"

# 代理池：批量导入
curl -X POST "http://localhost:5001/api/pool/import?token=YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"proxies": ["http://1.2.3.4:8080"]}'
```

---

# 五、注意事项

1. **鉴权只在查询串里比对单一 token**，无 CSRF 防护，也不区分调用方权限：能访问面板即可
   修改配置（含下游凭据）。不要把面板直接暴露到公网。
2. **两套错误约定并存**：面板侧多数业务失败是 `200 + status: "error"`，代理池侧是真实
   4xx/5xx + `error_code`。调用方两个都要判。
3. **`message` 随界面语言变化**，只可用于展示，不可用于程序判断。
4. **运行状态在进程内存中**（当前代理、出口名册、任务表、广告关闭状态），进程重启即重置；
   访问记录与域名统计落在 SQLite，重启后仍在。
5. **`web_port` 改动需重启整个进程；`port` 改动需重启出口服务**（走 `POST /api/config`
   保存时面板会自动重启出口服务；手工编辑与命令行入口需自行重启），其余配置项保存后
   即时生效，但个别项例外：如访问记录缓冲 `access_records_buffer_size` 要等代理服务下次
   启动时才按新容量重建缓冲。手工编辑 `config.ini` 的 `[Server]` 改动也会被自动热重载
   （两个入口都在轮询配置文件），但端口换绑不会自动发生；`[Pool]` 段由池自行热加载。
6. **多数**批量操作返回 `task_id`（两个删除端点直接返回 `success` / `deleted_count`），
   用 `GET /api/pool/tasks/{task_id}` 查进度；任务动辄跑几十分钟，可随时用
   `POST /api/pool/tasks/{task_id}/cancel` 中止。注意离线归属地库更新任务的下载跑在
   不可取消的线程里，取消只会写出状态、下载仍会跑完。任务表是内存态且有 1 小时 TTL，
   进程重启后不可查。
7. **代理池的查询参数是签名白名单**：参数名写错会被静默忽略，返回未筛选的结果而不报错。
8. 修改 `/api/pool/*` 的端点或字段时，**必须同步更新本文档** —— 适配层是手写的 Flask 蓝图，
   不像 FastAPI 那样能自动生成 OpenAPI 描述。

---

# 附录 A：错误码总表

## 面板接口错误约定

| 情形 | HTTP | 响应体 |
|---|---|---|
| 成功 | 200 | `{"status": "success", ...}` |
| 成功（部分只读端点） | 200 | 直接返回数据，**无 `status` 字段** |
| 鉴权失败 | 401 | `{"status": "error", "message": "..."}` |
| 配置校验未通过（仅 `POST /api/config`） | 400 | `{"status": "error", "message": "...", "details": {"key": "...", "reason": "..."}}` |
| 其余业务失败 | **200** | `{"status": "error", "message": "..."}` |

## 代理池接口错误约定

| error_code | HTTP | 含义 |
|---|---|---|
| `invalid_parameter` | 400 | 请求参数非法 |
| `api_error` | 4xx / 5xx | 业务错误（代理不存在、无匹配结果、规格不符、插件操作失败、恢复失败等）；状态码随 `ApiError` 自带 |
| `pool_running` | 409 | 池运行中，不允许该操作（仅 `POST /api/pool/backups/restore`） |
| `pool_unavailable` | 503 | 代理池未运行或正在重启 |
| `pool_timeout` | 504 | 代理池响应超时 |
| `queue_full` | 503 | 写入队列已满 |
| `internal_error` | 500 | 服务端内部错误 |
| *（无）* | 500 | 池启停失败：`POST /api/pool/start\|stop\|restart` 失败时**不带 `error_code`** |

---

# 附录 B：端点总索引

## 页面路由（非 `api`）

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| GET | `/` | 否 | 带 token 跳转到 `/web` |
| GET | `/web` | 是 | 面板单页 |
| GET | `/static/<path>` | 否 | 前端静态资源 |

## 面板接口（33）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/status` | 运行状态 |
| GET | `/api/config` | 读取 `[Server]` / `[Pool]` 配置 |
| POST | `/api/config` | 保存配置 |
| POST | `/api/language` | 切换界面语言 |
| GET | `/api/proxies` | 读本地代理列表 |
| POST | `/api/proxies` | 写本地代理列表 |
| GET | `/api/check_proxies` | 检测源清单里的代理可用性（local 来源即 `ip.txt` 全部条目） |
| GET | `/api/ip_lists` | 读 IP 黑白名单 |
| POST | `/api/ip_lists` | 写 IP 黑白名单 |
| GET | `/api/bypass_whitelist` | 读绕过名单 |
| POST | `/api/bypass_whitelist` | 写绕过名单 |
| POST | `/api/service` | 启停 / 重启出口代理服务 |
| GET | `/api/switch_proxy` | 刷新出口池：不满则补满，满员则换掉最近到期的那个出口 |
| GET | `/api/logs` | 查询内存日志 |
| GET | `/api/logs/stats` | 日志统计 |
| GET | `/api/logs/files` | 列出日志文件 |
| GET | `/api/logs/file` | 读取日志文件 |
| GET | `/api/logs/export` | 导出日志 |
| POST | `/api/logs/clear` | 清空日志 |
| GET | `/api/logs/records` | 查询访问记录 |
| GET | `/api/logs/records/export` | 导出访问记录 |
| GET | `/api/logs/records/options` | 访问记录过滤候选项 |
| POST | `/api/logs/records/clear` | 清空访问记录 |
| GET | `/api/logs/domains` | 查询域名统计 |
| POST | `/api/logs/domains/clear` | 清空域名统计 |
| GET | `/api/users` | 读出口代理账号 |
| POST | `/api/users` | 写出口代理账号 |
| GET | `/api/api_credentials` | 读上游 API 凭据 |
| POST | `/api/api_credentials` | 管理上游 API 凭据 |
| GET | `/api/version` | 版本检查结果（只读缓存，**免鉴权**） |
| GET | `/api/ads` | 获取广告（**免鉴权**） |
| POST | `/api/ads/dismiss` | 关闭广告（**免鉴权**） |
| POST | `/api/ads/reopen` | 重新开启广告（**免鉴权**） |

## 代理池接口（38）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/pool/status` | 池状态与全局统计 |
| GET | `/api/pool/schema` | `[Pool]` 字段结构（面板表单同源） |
| POST | `/api/pool/start` | 启动池 |
| POST | `/api/pool/stop` | 停止池（等写队列排空） |
| POST | `/api/pool/restart` | 重启池 |
| GET | `/api/pool/get` | 筛选代理列表（`json` / `text`） |
| GET | `/api/pool/random` | 随机取一个代理（`json` / `text`） |
| GET | `/api/pool/count` | 统计符合条件的代理数 |
| GET | `/api/pool/export` | 导出代理（`txt` / `json` / `csv`） |
| POST | `/api/pool/import` | 批量导入（先验证再入库） |
| POST | `/api/pool/proxies/{id}/favorite` | 切换收藏状态 |
| GET | `/api/pool/stats` | 池统计 |
| GET | `/api/pool/sources` | 来源插件名列表 |
| GET | `/api/pool/host-ip` | 本机公网出口 IP |
| GET | `/api/pool/plugins` | 插件列表与状态 |
| POST | `/api/pool/plugins/{name}/enable` | 启用插件 |
| POST | `/api/pool/plugins/{name}/disable` | 禁用插件 |
| PUT | `/api/pool/plugins/{name}/interval` | 设置抓取周期 |
| PUT | `/api/pool/plugins/{name}/test-url` | 设置插件专用检测地址 |
| PUT | `/api/pool/plugins/{name}/validation` | 设置插件验证策略 |
| POST | `/api/pool/plugins/{name}/run` | 立即执行插件 |
| POST | `/api/pool/plugins/{name}/reload` | 热重载插件 |
| POST | `/api/pool/validate/all-valid` | 重新验证所有有效代理 |
| POST | `/api/pool/validate/all-invalid` | 重新验证所有失效代理 |
| POST | `/api/pool/update-geo/all` | 全面检测并补归属地 |
| DELETE | `/api/pool/delete/invalid` | 删除全部失效代理 |
| POST | `/api/pool/proxies/batch/validate` | 批量验证指定代理 |
| DELETE | `/api/pool/proxies/batch/delete` | 批量删除指定代理（参数在请求体） |
| GET | `/api/pool/tasks` | 列出任务 |
| GET | `/api/pool/tasks/{task_id}` | 查询任务状态 |
| POST | `/api/pool/tasks/{task_id}/cancel` | 取消任务 |
| GET | `/api/pool/geo/status` | 离线归属地库状态 |
| POST | `/api/pool/geo/update` | 更新离线归属地库（约 100 MB） |
| POST | `/api/pool/geo/recompute` | 重算存量记录的归属地 |
| GET | `/api/pool/backups` | 列出备份 |
| POST | `/api/pool/backups/restore` | 从备份恢复（需先停池） |
| GET | `/api/pool/database/stats` | 数据库统计 |
| POST | `/api/pool/database/optimize` | 优化数据库（ANALYZE / REINDEX / VACUUM） |

---

# 附录 C：字段字典

## 代理对象

`GET /api/pool/get`、`GET /api/pool/random`（`format=json`）返回的对象。

| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | int | 主键 |
| `proxy_url` | string | 完整代理地址；用户名与密码**都存在**时形如 `协议://用户:密码@ip:端口` |
| `protocol` | string | `http` / `https` / `socks5` |
| `ip` | string | 入口 IP |
| `port` | int | 端口 |
| `username` / `password` | string \| null | 代理认证凭据 |
| `real_ip` | string \| null | 出口 IP（经代理访问时对端看到的 IP） |
| `exit_ip_differs` | bool | 入口 IP 与出口 IP 是否不同。**查询与随机响应都提供**（两者共用同一序列化），导出路径刻意不带 |
| `region` | string | 中文归属地全名，如「中国 广东 深圳」；查不到为「未知」 |
| `country` / `province` / `city` | string | 中文归属地分级 |
| `region_en` / `country_en` / `province_en` / `city_en` | string \| null | 英文归属地分级 |
| `delay_ms` | float \| null | 最近一次测得的延迟（毫秒） |
| `validated_at` | string \| null | 最近一次验证时间（ISO 8601） |
| `source_plugin` | string | 来源插件名；手动导入为 `manual_import` |
| `is_favorite` | bool | 是否收藏（用户选择，抓取与验证不会覆盖） |
| `is_valid` | bool | 当前是否可用；列表用它给失效行打「失效」徽标。导出走自己的状态列 |
| `health_score` | float | 健康分，**0-100**，保留 1 位小数 |
| `anonymity_level` | string | `transparent` / `anonymous` / `elite` / `unverified` |
| `anonymity_fallback` | bool | 匿名度是否被判成兜底档 |
| `supports_https` / `supports_http` | bool | 是否支持对应协议 |
| `quality_assessed_at` | string \| null | 最近一次质量评估时间（ISO 8601） |
| `success_rate` | float | 验证成功率，0-1，保留 3 位小数 |
| `avg_delay_ms` | float \| null | 历史平均延迟（毫秒） |
| `total_checks` | int | 累计验证次数；缺值以 0 兜底 |
| `probe_success_rate` | float | 探测成功率，0-1，保留 3 位小数 |
| `probe_total_count` | int | 累计探测次数；缺值以 0 兜底 |

> **归属地空值的语义**：中英两套按列给出，`null` 表示**还没查过**（不是「未知」）。
> 英文列缺失时前端回退到中文列；两列相同表示该级没有对应译名。不要往这些列里写
> 「未知」文案 —— 「未知」是中文列查询过但没查到的取值。

## 任务对象

`GET /api/pool/tasks/{task_id}` 的响应，也是 `GET /api/pool/tasks` 列表里的元素。

| 字段 | 类型 | 说明 |
|---|---|---|
| `task_id` | string | 任务 id；**只在 `GET /api/pool/tasks` 的列表元素里出现**（列表逐条注入），单查接口的响应里没有 |
| `status` | string | `running` / `completed` / `failed` / `cancelled`（`queued` 只出现在部分创建响应里，任务表里没有） |
| `message` | string | 当前阶段的可读描述，跟随界面语言 |
| `progress` / `total` | int | 已完成 / 总数 |
| `started_at` / `completed_at` | string | 起止时间（ISO 8601）；未结束则无 `completed_at` |
| `stage` | string | `prescreen` / `validate` / `ingest` / `done`（完成时写 `done`），**仅导入与抓取类任务有** |
| `stage_done` / `stage_total` | int | 当前阶段的进度，同上 |
| `in_flight` | int | 当前阶段正在并发处理中的条数，同上 |
| `rate` | float | 处理速率（条/秒） |
| `eta_seconds` | int \| null | 预计剩余秒数 |
| `valid_count` / `invalid_count` / `inconclusive_count` | int | 验证结果分类计数 |
| `prescreened_out` | int | 端口初筛即淘汰的条数 |
| `incomplete_count` / `failed_count` | int | 未完成 / 失败条数 |
| `results` | object | 数据文件名到结果文案（`已更新` / `失败: ...`）的映射，**仅离线归属地库更新任务的完成态有** |

**字段集合随任务类型与端点不同**，上表是各处的并集；只依赖 `status`、`progress`、
`total`、`message` 这四个字段最稳妥。

## 备份对象

`GET /api/pool/backups` 列表里的元素。

| 字段 | 类型 | 说明 |
|---|---|---|
| `filename` | string | 备份文件名，作为 `POST /api/pool/backups/restore` 的参数 |
| `size` | int | 文件大小（字节） |
| `created_at` | string | 创建时间，格式固定为 `YYYY-MM-DD HH:MM:SS` |

