# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

ProxyCat is a local proxy-pool middleware. Client tools point at ProxyCat’s fixed local HTTP/SOCKS5 port; ProxyCat forwards traffic through a rotating set of short-lived upstream proxies (file list or API-fetched). It is not a system-wide VPN — only traffic sent to its listen port is proxied.

Current version string: `ProxyCat-V2.0.4` (hardcoded in `modules/modules.py` and `app.py`).

Python target: **3.8–3.11** (docs recommend **3.11**). No test suite, linter config, or CI is present in this repo.

## Common commands

```bash
# Install deps (from repo root)
pip install -r requirements.txt
# optional mirror:
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple/

# CLI-only proxy server (no Web UI)
python ProxyCat.py
python ProxyCat.py -c config/config.ini

# Recommended: Web UI + proxy (Flask on web_port, proxy on port)
python app.py

# Docker (exposes 1080 proxy + 5000 web; mounts ./config)
docker-compose up -d --build
docker-compose down
docker-compose up -d
docker logs proxycat
```

There are no unit/integration tests to run. Manual checks: start `app.py`, hit `http://127.0.0.1:5000/web?token=<token>`, send HTTP/SOCKS5 traffic through `port` (default 1080).

## Architecture

### Entry points

| Entry | Role |
|-------|------|
| `app.py` | Primary runtime (also Docker `CMD`). Starts Flask web panel and runs `AsyncProxyServer` in a daemon thread via `ProxyCat.run_server`. |
| `ProxyCat.py` | CLI runtime: loads config, optional startup proxy check, status/progress thread, then `asyncio.run(run_server(server))`. Exports `run_server` used by `app.py`. Contains a largely unused legacy `ProxyCat` class; real proxying is `AsyncProxyServer`. |

### Core components

```
Client tools  -->  :port (HTTP + SOCKS5 multiplex)  -->  AsyncProxyServer
                                                              |
                                                    current_proxy (upstream)
                                                              |
                                         config/ip.txt  OR  config/getip.py (API)
```

- **`modules/proxyserver.py`** — `AsyncProxyServer` (main engine, ~1.5k lines). Single listen socket on `0.0.0.0:port`. First byte discriminates SOCKS5 (`0x05`) vs HTTP. Handles CONNECT tunneling, plain HTTP proxying, client Basic auth (`[Users]`), IP white/black lists, upstream proxy selection, failure detection, cooldowns, and connection/client pools.
- **`modules/modules.py`** — shared helpers: bilingual `MESSAGES` / `get_message`, `load_config` / `DEFAULT_CONFIG`, proxy validity checks (`check_http_proxy` / `check_socks_proxy` / `check_proxies`), banner, version check against `https://y.shironekosan.cn/1.html`.
- **`config/getip.py`** — `newip()`: when `use_getip=true`, fetches one `IP:PORT` from `getip_url`, optionally auto-whitelists with a vendor API, returns `socks5://[user:pass@]host:port`. Customize this file if the provider response format differs.
- **`config/config.ini`** — all runtime knobs under `[Server]`; multi-user client credentials under `[Users]`.
- **`config/ip.txt`** — upstream proxy list when not using GetIP (`scheme://[user:pass@]host:port`, `#` comments allowed).
- **`config/whitelist.txt` / `blacklist.txt`** — client source IP allow/deny.
- **`web/templates/index.html` + `web/static/`** — single-page Web admin (Bootstrap/jQuery). No separate frontend build step.
- **`logs/proxycat.log`** — file log when running via `app.py` (also in-memory ring buffer for `/api/logs`).

### Config hot-reload

- CLI path (`ProxyCat.update_status`): polls mtime of `config/config.ini` and the proxy file; reloads without process restart (port changes still need a service restart to rebind).
- Web path: POST APIs write files and call `server._init_config_values` / `_handle_mode_change` / list reloads in-process.

Docker image removes baked-in `config/config.ini` at build time; runtime config must come from the mounted `./config` volume.

### Proxy rotation model

Modes (`mode` in config):

- **`cycle`** — walk the list on a timer (`interval` seconds). Timer only advances meaningfully with traffic; switch happens when a request needs a proxy and the interval has elapsed (resource-saving design).
- **`loadbalance`** — pick next proxy per request path; no countdown (`time_until_next_switch` is `inf`).
- **`interval = 0`** — effectively change IP on each request (cycle path).

Switch triggers (as of changelog): interval expiry, upstream failure auto-switch, Web manual switch (`/api/switch_proxy`), GetIP mode first request (lazy fetch — startup does not burn API quota).

Concurrency guards: `switching_proxy` flag, `switch_cooldown` (~5s), `proxy_failure_cooldown` (~3s), `proxy_failure_lock`.

Upstream formats: `http://`, `https://`, `socks5://`, with optional `user:pass@`.

### Auth layers

1. **Client → ProxyCat**: optional Basic auth from `[Users]`; empty section = open proxy. Also IP white/black lists with `ip_auth_priority` (`whitelist` or `blacklist`).
2. **ProxyCat → upstream**: credentials embedded in proxy URL or `proxy_username` / `proxy_password` (GetIP path).
3. **Web panel**: query `token` matching `Server.token` (empty token disables check). URL form: `/web?token=...`.

### Web API surface (`app.py`)

Notable routes (many gated by `@require_token`): `/api/status`, `/api/config`, `/api/proxies`, `/api/check_proxies`, `/api/ip_lists`, `/api/logs`, `/api/logs/clear`, `/api/switch_proxy`, `/api/service` (start/stop/restart), `/api/language`, `/api/version`, `/api/users`.

Service control starts/stops the asyncio proxy loop on a background thread; Flask stays up.

### i18n

All user-facing strings go through `get_message(key, lang, *args)` with `language` = `cn` | `en` from config. When adding messages, add both keys under `MESSAGES` in `modules/modules.py` (and any Web UI copy that mirrors them in `index.html`).

## Important behavioral constraints

- GetIP API must return a single `IP:PORT` line; non-conforming providers need edits in `config/getip.py`.
- Default listen: proxy **1080**, web **5000**.
- `check_proxies` can be disabled to avoid aggressive switching when validity probes are noisy or blocked.
- Failure handling should distinguish **upstream proxy death** from **destination site errors** (historical bug source — see `ProxyCat-Manual/logs.md`).
- Run processes from the **repo root** so relative paths (`config/…`, `web/…`, `logs/…`) resolve correctly.

## Docs in-repo

- `README.md` / `README-EN.md` — product overview
- `ProxyCat-Manual/Operation Manual.md` — install, config field reference, Docker, Web panel
- `ProxyCat-Manual/Investigation Manual.md` — troubleshooting
- `ProxyCat-Manual/logs.md` — changelog / known fix history
