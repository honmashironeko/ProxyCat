![ProxyCat](https://socialify.git.ci/honmashironeko/ProxyCat/image?description=1&descriptionEditable=A%20lightweight%20and%20excellent%20proxy%20pool%20middleware%20that%20implements%20automatic%20proxy%20rotation&font=Bitter&forks=1&issues=1&language=1&logo=https%3A%2F%2Favatars.githubusercontent.com%2Fu%2F139044047%3Fv%3D4&name=1&owner=1&pattern=Circuit%20Board&pulls=1&stargazers=1&theme=Dark)

<p align="center">
  <a href="/README.md">简体中文</a>
  ·
  <a href="/README-EN.md">English</a>
</p>

## Table of Contents

- [Project Background](#project-background)
- [Key Features](#key-features)
- [Screenshots](#screenshots)
- [Quick Deployment](#quick-deployment)
- [Documentation](#documentation)
- [Disclaimer](#disclaimer)
- [License](#license)
- [Development Plan](#development-plan)
- [Special Thanks](#special-thanks)
- [Sponsor](#sponsor)
- [Proxy Recommendations](#proxy-recommendations)

## Project Background

During penetration testing you often need to hide or change your IP address to get past security devices. But tunnel proxies on the market are expensive — typically ¥3-6 per day — which puts them out of reach for many. The author noticed instead that short-lived IPs offer outstanding value: a few cents each, averaging ¥0.03-0.4 per day.

And so **ProxyCat** was born! The tool turns short-lived IPs (valid for 1-60 minutes) into fixed IPs that other tools can use, giving you a proxy pool server that is deployed once and then works indefinitely.

![Project Principle](./assets/项目原理图.png)

## Key Features

- **Dual-protocol listening**: a single port accepts both HTTP and SOCKS5 inbound requests; upstreams may be authenticated HTTP / HTTPS / SOCKS5 proxies. [Details](ProxyCat-Manual/Features-EN.md#outbound-proxy-service)
- **Three proxy sources**: `local` reads a local list, `api` fetches from an endpoint live, `pool` uses the built-in proxy pool directly — switching between them on the panel takes effect immediately.
- **Many exits serving at once**: several upstream exits are kept in service simultaneously, and requests are spread by each exit's live load — so when an upstream rate-limits per exit IP, concurrency scales with the number of exits. [Upstream Exits and Concurrency](ProxyCat-Manual/Features-EN.md#upstream-exits-and-concurrency)
- **Retirement by failure share**: an exit's health is judged by the failure share in its sliding window, not by a count of consecutive failures — which is what tells "one network hiccup" apart from "this exit is simply broken".
- **Automatic expansion at peak**: exits are added automatically when load climbs, and released in one step once the peak passes; growth and release look at two different numbers, so the exit count never oscillates.
- **Built-in proxy pool**: plugin-based collection, verify-before-storing, three validation intensities, health scoring, offline geolocation, automatic revalidation and cleanup. [Built-in Proxy Pool](ProxyCat-Manual/Features-EN.md#built-in-proxy-pool)
- **Real usage feedback**: bad exits found while forwarding flow back into the pool; once consecutive failures reach the threshold the entry is marked invalid, and a passing revalidation restores it automatically.
- **Access control and outbound authentication**: client IP whitelist / blacklist judged by priority, a bypass list that connects matching targets directly, and username / password authentication on the outbound side.
- **Web management panel**: four tabs — Proxy Config, Proxy Pool, Access Control and Logs — putting configuration, lists, logs and service start/stop on one screen. [Panel and Operations](ProxyCat-Manual/Features-EN.md#panel-and-operations)
- **Containerized deployment**: one-command Docker build and start; the container runs as non-root, and the health check probes the actual panel port.

## Screenshots

The panel is a single page with four tabs down the left side: Proxy Config, Proxy Pool, Access Control and Logs.

| Proxy Config · Source | Proxy Pool · Proxy Management |
|---|---|
| ![Proxy Config · Source](./assets/screenshots/config-source-en.png) | ![Proxy Pool · Proxy Management](./assets/screenshots/pool-manage-en.png) |
| Pick the proxy source (Local / API / Pool) and fill in whatever the current source needs — here, the remote pool URL for the built-in pool (leave it empty to use the in-process pool). | Every collected proxy at a glance: protocol, real IP, region, delay, health score and anonymity. |

| Access Control | Logs |
|---|---|
| ![Access Control](./assets/screenshots/access-en.png) | ![Logs](./assets/screenshots/logs-en.png) |
| Outbound authentication accounts, the IP whitelist / blacklist and the proxy bypass list all live here. | Live logs and past log files, plus access statistics and per-request detail. |

| Dark Theme · Exit Rotation | Dark Theme · Proxy Management |
|---|---|
| ![Dark Theme · Exit Rotation](./assets/screenshots/config-exits-dark.png) | ![Dark Theme · Proxy Management](./assets/screenshots/pool-manage-dark.png) |
| The dark theme: the layout is identical to the light one. | The same Proxy Management view in dark mode, sharing data and server-side settings with the light one. |

The panel offers two themes, dark and light; until you switch manually it follows the system's dark preference. The interface also switches between Chinese and English — the language is a server-side setting, so one flip updates the whole site's copy and the headers of exported files together.

## Quick Deployment

### Docker (Recommended)

```bash
docker compose up -d --build
```

Compose builds the image and starts the container. Two ports are exposed:

| Port | Purpose |
|---|---|
| `1080` | Proxy listening port (shared by HTTP and SOCKS5) |
| `5001` | Web panel port |

Three directories are bind-mounted to the host so your data and configuration survive container recreation: `config/`, `logs/` and `modules/proxypool/data/`.

### Running from Source

**Python 3.10 or later is required**: the source makes heavy use of runtime-evaluated `X | Y` union type annotations, and 3.9 or earlier raises a `TypeError` at import time.

```bash
pip install -r requirements.txt

# On Windows the command is `python`
python3 app.py
```

`app.py` brings up the web panel and the outbound proxy service together. The `config/config.ini` shipped in this repo sets `proxy_source_mode=pool` (the program's built-in default is `local`), so starting from this configuration **starts the built-in proxy pool automatically along with the service** — exits are available right out of the box.

### Verifying the Deployment

Two commands confirm the service is really working:

```bash
# 1. The panel is listening: expect 302 (redirect to /web)
curl -i http://127.0.0.1:5001/

# 2. The proxy is forwarding: expect 200, with the request actually going through an upstream.
#    The [Users] section of the shipped config has accounts, so requests must be authenticated;
#    without credentials you get a 407.
curl -x http://neko:123456@127.0.0.1:1080 https://www.baidu.com -I
```

### Must-Read for Your First Deployment

These four are all classic "symptom first, cause later" cases; the full explanations are in the operation manual's [Four Things To Know Before Deploying](ProxyCat-Manual/Operation%20Manual-EN.md#four-things-to-know-before-deploying):

1. **The panel won't open, and returns 401**: with a token set you **must pass `?token=` to open it**; the token shipped in this repo is public, so change `[Server] token` in `config.ini` before exposing the panel — the change takes effect within about a second, and the old token stops working immediately.
2. **The container is up but can't write configuration or logs**: the container runs as a non-root user, so its UID/GID must match the owner of `config/`, `logs/` and `modules/proxypool/data/` on the host; if they differ, set `PUID` / `PGID` in `.env`.
3. **A restart loses the last batch of data**: on shutdown the application drains its write queue, and `stop_grace_period` has been raised to 60 seconds — Docker's 10-second default `SIGKILL`s it before the drain finishes, **so please don't lower it**.
4. **The container turns unhealthy after changing `web_port`**: the health check reads the actual `web_port` from `config.ini` at probe time, so after changing it you must restart the process and update the port mapping in `docker-compose.yml`.

### Network Behaviour

Besides forwarding client traffic, ProxyCat itself also makes outbound requests, many of them **direct** (sent from this machine's real IP) — for example the version check, the pool's host public-IP lookup, the GeoNode and GitHub scraping plugins and the offline geolocation-database update. These requests can all be turned off or pointed at addresses of your own (the version check has no dedicated switch and must be blocked at the network layer); for each one's trigger, destination and how to stop it, see [Features](ProxyCat-Manual/Features-EN.md#outbound-network-requests). Traffic forwarded through a proxy is not on this list — that is the client's own traffic.

## Documentation

The README keeps only the basic introduction and quick deployment; everything else lives in the documents below:

| Document | Contents |
|---|---|
| [Features](ProxyCat-Manual/Features-EN.md) | Outbound proxy service, built-in proxy pool, panel and operations, upstream exits and concurrency, outbound network requests, performance benchmarks and project structure |
| [Configuration](ProxyCat-Manual/Configuration-EN.md) | Every option in `[Server]` / `[Users]` / `[api_credentials]` / `[Pool]`: defaults, descriptions and how changes take effect |
| [Operation Manual](ProxyCat-Manual/Operation%20Manual-EN.md) | Installation and deployment, entry points, a page-by-page tour of the panel, using the proxy pool, logs and access records, troubleshooting Q&A |
| [Investigation Manual](ProxyCat-Manual/Investigation%20Manual-EN.md) | How to diagnose and handle common errors |
| [Changelog](ProxyCat-Manual/logs-EN.md) | What changed in every release |
| [API Reference](API-EN.md) | Parameters, response examples and error codes for the panel's `/api/*` and the pool's `/api/pool/*` |
| [Proxy Pool Module Docs](modules/proxypool/README-EN.md) | Implementation details: scrape plugin development, validation strategy, anonymity detection, geolocation resolution, automatic cleanup |

The Chinese documents are the same files without the `-EN` suffix (e.g. `ProxyCat-Manual/Features.md`); the Chinese entry point is [README.md](README.md).

## Disclaimer

- By downloading, installing, using, or modifying this tool and related code, you indicate your trust in this tool.
- We are not responsible for any form of loss or damage caused to yourself or others while using this tool.
- You are solely responsible for any illegal activities conducted while using this tool.
- Please carefully read and fully understand all terms, especially liability exemption clauses.
- You have no right to download, install, or use this tool unless you have read and accepted all terms.
- Your download, installation, and usage actions indicate your acceptance of this agreement.

## License

This project is licensed under the **GNU General Public License v2.0 (GPL-2.0)**; the full text is in
[LICENSE](LICENSE).

- It is a **copyleft license**: if you distribute a modified version or a derivative work, it must also
  be licensed under GPL-2.0 with source available.
- The software comes with **no warranty** — which is also why the disclaimer above reads the way it does.

## Development Plan

- [x] Add detailed logging to record all IP identities connecting to ProxyCat, supporting multiple users.
- [x] Add Web UI for a more powerful and user-friendly interface.
- [x] Built-in proxy pool: plugin-based collection, validation, scoring, geolocation and automatic cleanup.
- [ ] Develop babycat module that can run on any server or host to turn it into a proxy server.
- [ ] Add request blacklist/whitelist to specify URLs, IPs, or domains to be forcibly dropped or bypassed (the bypass list is already supported; the rest is pending).
- [ ] Package to PyPi for easier installation and use.

If you have good ideas or run into bugs during use, please contact the author through:

WeChat Official Account: **樱花庄的本间白猫** (Honma Shironeko of Sakurasou)

## Special Thanks

In no particular order, thanks to all contributors who helped with this project:

- [AabyssZG (曾哥)](https://github.com/AabyssZG)
- [ProbiusOfficial (探姬)](https://github.com/ProbiusOfficial)
- [gh0stkey (EvilChen)](https://github.com/gh0stkey)
- [huangzheng2016(HydrogenE7)](https://github.com/huangzheng2016)
- chars6
- qianzai（千载）
- ziwindlu
- lalala-orz(啦啦啦)

## Sponsor

Open source development isn't easy. If you find this tool helpful, consider sponsoring the author's development!

| Rank | ID | Amount (CNY) |
| :--: | :--: | :----------: |
| 1 | **陆沉** | 1266.62 |
| 2 | **柯林斯.民间新秀** | 696 |
| 3 | **北** | 170 |
| [Sponsor List](https://github.com/honmashironeko/Thanks-for-sponsorship) | Every sponsorship is a motivation for the author! | (´∀｀)♡ |

![Sponsor](./assets/赞助.png)

## Proxy Recommendations

- [First affordable proxy service - Get 5000 free IPs + ¥10 coupon with invite code](https://h.shanchendaili.com/invite_reg.html?invite=fM6fVG)
- [Various carrier data plans](https://172.lot-ml.com/ProductEn/Index/0b7c9adef5e9648f)
- [Click here to purchase](https://www.ipmart.io?source=Shironeko)

![Star History Chart](https://star-history.dera.page/svg?repos=honmashironeko/ProxyCat&type=Date)