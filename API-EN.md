# ProxyCat API Reference

This document is the **sole authoritative reference** for ProxyCat's public HTTP APIs, covering two API sets:

- **Panel API** (`/api/*`) — the panel's own API, served by `app.py`.
- **Pool API** (`/api/pool/*`) — a Flask blueprint registered by `modules/proxypool_api.py`.

The two APIs **share one port and one authentication scheme**, but their **error response conventions
differ** (the panel mostly returns `HTTP 200 + status: "error"`, while the pool uses a real status code
plus `error_code`). Both conventions are spelled out in this document; read
[1. General Conventions](#1-general-conventions) before making any call.

> Older versions kept the Pool API's field details in `modules/proxypool/API.md`; that file has since
> been merged into this document and now holds nothing but a pointer to this page.

## Table of Contents

- [Group Navigation](#group-navigation)
- [1. General Conventions](#1-general-conventions)
- [2. Panel API](#2-panel-api)
- [3. Pool API](#3-pool-api)
- [4. End-to-End Examples](#4-end-to-end-examples)
- [5. Notes](#5-notes)
- [Appendix A: Error Code Reference](#appendix-a-error-code-reference)
- [Appendix B: Endpoint Index](#appendix-b-endpoint-index)
- [Appendix C: Field Dictionary](#appendix-c-field-dictionary)

## Group Navigation

| Group | Endpoints | Description |
|---|---|---|
| [1. General Conventions](#1-general-conventions) | — | Addresses, authentication, the two error conventions, parameter parsing rules, general limits |
| [2. Panel API](#2-panel-api) | 33 | The panel's own `/api/*`: status, configuration, logs, access records |
| [3. Pool API](#3-pool-api) | 38 | The pool's `/api/pool/*`: fetching, validation, tasks and database maintenance |

Quick lookup by task:

| I want to… | Go here |
|---|---|
| See which proxies the service is currently using | [Get Runtime Status](#get-runtime-status-get-apistatus) |
| Change the configuration | [Save Configuration](#save-configuration-post-apiconfig) |
| Find out why a request failed | [Query Access Records](#query-access-records-get-apilogsrecords) |
| See which upstream a domain goes through and how its success rate looks | [Query Domain Statistics](#query-domain-statistics-get-apilogsdomains) |
| Grab a working proxy for another program | [Get One Proxy](#get-one-proxy-get-apipoolrandom) |
| Trigger a fetch by hand | [Run a Plugin Immediately](#run-a-plugin-immediately-post-apipoolpluginsnamerun) |
| Check how a long-running task is doing | [Query Task Status](#query-task-status-get-apipooltaskstask_id) |

---

# 1. General Conventions

## Service Address and Ports

- Default address: `http://localhost:5001`; the port comes from `[Server] web_port` in `config/config.ini`.
- The panel and the pool have **no separate processes or ports**; both run inside the ProxyCat process
  and start and stop with it.
- The proxy listening port (default `1080`) is a separate port: it only accepts HTTP and SOCKS5 proxy
  requests and **serves no HTTP API at all**.

## Authentication

**Except for the endpoints explicitly marked "no authentication" below, every API call must carry the token:**

```
GET http://localhost:5001/api/status?token=<your-token>
```

The token lives in `[Server] token` in `config/config.ini`. **Validation reads only the query-string
parameter `token`**; it does not read request headers or cookies.

**An empty token lets everything through**, i.e. authentication is off. Anyone who can reach the panel
port can then read and write the configuration (including upstream credentials), view access records,
and start or stop the service. Configure it this way only for local use; a token is mandatory if you
expose the port to a network.

> **The `config/config.ini` shipped in the repository has a non-empty token**, so using a fresh clone
> as-is gets you a 401. See [Quick Deployment in the README](README-EN.md#quick-deployment).

**Only 4 API endpoints skip authentication** (`/` and `/static/<path>` also skip the token check, see
[Appendix B](#appendix-b-endpoint-index)):

| Method | Path |
|---|---|
| GET | `/api/version` |
| GET | `/api/ads` |
| POST | `/api/ads/dismiss` |
| POST | `/api/ads/reopen` |

A failed authentication always returns **HTTP 401**:

```json
{
  "status": "error",
  "message": "Invalid access token"
}
```

## Two Sets of Error Conventions

**This is the spot in this document most likely to trip you up: the two APIs express errors differently
and must be treated separately.**

| Situation | Panel `/api/*` | Pool `/api/pool/*` |
|---|---|---|
| Success | `200` + `status: "success"`; a few read-only endpoints **return data directly, with no `status` field** | `200` + data; `status` appears only on errors |
| Business failure | **`200`** + `status: "error"` + `message` | **A real status code** (4xx/5xx) + `status: "error"` + `message` + `error_code` |
| Parameter error | `400`, returned only by `POST /api/config` | `400` + `error_code: "invalid_parameter"` |
| Not authenticated | `401` + `status: "error"` | `401` + `status: "error"` (the same hook) |
| Pool not running / pool too slow | Not applicable | `503` `pool_unavailable` / `504` `pool_timeout` |

Two hard rules follow:

1. **Always check the HTTP status code and the `status` field together.** On the panel side, looking at
   the status code alone misses business failures, and looking at `status` alone misses authentication
   and pool-side errors.
2. **Programmatic branching may rely only on `error_code` (pool side) or the HTTP status code plus
   endpoint-specific flags (panel side) — never on `message`.** The `message` text follows the current
   UI language (`[Server] language`), so the same error returns different text under different languages.

## Parameter Parsing Rules (Pool API Only)

The pool's adapter layer parses parameters from the **handler function's signature**, under these rules:

| Rule | Description |
|---|---|
| Query parameters are a **whitelist** | Only query parameters that appear in the handler signature are parsed; **unknown parameters are silently ignored**. A misspelled parameter name raises no error — you just get the unfiltered, full result |
| Type coercion | Driven by type annotations; only `bool` / `int` / `float` are recognized, everything else passes through as a string |
| Empty string | An empty string for a non-string parameter (e.g. `?status=`) is the same as **omitting** that parameter |
| Request body | Must be a JSON object; a missing required field returns `400 invalid_parameter`, with the field names listed in `message` |
| Path parameters | Such as `{id}` in `/api/pool/proxies/{id}/favorite`; parsed by the route itself |

## General Limits and Truncation

| Location | Limit / Default | Description |
|---|---|---|
| `limit` of `GET /api/logs` | Clamped to 1-2000, default 200 | Out-of-range values are silently clamped, with no error |
| `lines` of `GET /api/logs/file` | Clamped to 1-5000, default 500 | Same as above |
| `limit` of `GET /api/logs/records` | Clamped to 1-500, default 100 | Same as above; `since` defaults to "1 hour ago" |
| Access record export | At most 50000 records per call | The truncation flag exists only in the JSON metadata (`truncated`, `true` once the count reaches the limit); the CSV carries no such flag |
| Pool `page_size` / `limit` / export | All bound by the 50000 cap | When `limit` is present, `page` is forced to 1, equivalent to "take the first `limit` rows" |
| `GET /api/version` | Reads a cache, **makes no request** | The check is done at process start and by a background task every 24 hours |

## Blocking and Concurrency

The panel is served by **waitress with 16 threads**. On every pool call, **the current web thread stays
occupied until the pool returns a result**, up to 60 seconds (the HEAVY tier). So 16 concurrent large
batch operations will drag the panel into unresponsiveness. When calling heavy endpoints, keep
concurrency in check and give your client a long enough timeout.

The pool's three internal timeout tiers (they surface in error codes):

| Tier | Time limit | Used for |
|---|---|---|
| QUERY | 10 seconds | Queries, statistics, status |
| MUTATION | 20 seconds | Start/stop, single-record edits |
| HEAVY | 60 seconds | Import, export, database optimization, manual plugin runs, batch validation / deletion |

---

# 2. Panel API

## Pages and Static Assets

### Open the Panel (GET /web)

**Authentication: a token is required.**

`GET /web` returns the panel's single page. The token check is the same as for the other APIs, so
**with a token set, visiting `http://127.0.0.1:5001/` directly ends in a 401 after the redirect**. The
correct address is:

```
http://127.0.0.1:5001/?token=<your-token>
```

`GET /` itself performs no check; it simply carries `?token=` through unchanged when redirecting to `/web`:

| Request | Response |
|---|---|
| `GET /?token=abc` | `302` → `/web?token=abc` |
| `GET /` (no token) | `302` → `/web` |

`GET /static/<path>` serves the front-end assets under `web/static/`. Requests carrying the `?v=<version>`
query parameter return `Cache-Control: public, max-age=31536000, immutable` (every static reference in
the page carries it, so after a release the parameter changes and browsers naturally fetch the new files);
requests without it return `Cache-Control: no-cache`, revalidating against the origin on every load.

## Runtime Status

### Get Runtime Status (GET /api/status)

Takes no request parameters. Returns a live snapshot of the outbound proxy service.

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

| Field | Description |
|---|---|
| `current_proxy` | The upstream exit **assigned most recently** (masked) — not "the current proxy": with several exits, requests are spread across the whole group by load; when a local source has no usable exit this is the localized "none" text, and for non-local sources it is an empty string in that case. See `active_proxies` for the state of the whole group |
| `mode` | The run mode. **The same key means two different things depending on the source**: the local source asks "who to pick" — `cycle` (down the list in order, ignoring load) / `loadbalance` (whichever is under the least pressure goes first); the API and pool sources ask "when to rotate" — `continuous` (continuous rotation) / `request` (on-request rotation). The value is normalized per source; after a source switch, a value that does not belong to the new group falls back to that group's default |
| `port` | The **actually bound** proxy port (taken from the listening socket); falls back to the configured value when the service is not running |
| `interval` | The time-based rotation interval (seconds) |
| `time_left` | **How much longer the soonest-expiring exit has left**; the unit follows `switch_countdown_mode`; `0` when the roster is empty. Whether exits are replaced by requests or proactively by the background depends on `mode`: under `continuous` (continuous rotation) the background replaces on every tick, so the number keeps counting down while idle; under `request` (on-request rotation) and the local source, exits that expire while idle are removed and the pool may be empty |
| `switch_countdown_mode` | The countdown measure: `time` (seconds, by each exit's own lifetime; reported when both `interval` and `request_interval` are set — seconds can draw a progress bar, and the remaining request count is given per exit by `requests_left`) / `request_count` (only `request_interval` is set; reports how many requests remain) / `per_request` (neither is set; restocks only when exits are missing or invalid). **`none` is never returned anymore**: lifetime applies to every source and all four rotation modes |
| `total_proxies` | The number of exits currently in use. The target is `exit_count` (`[Server] exit_count`); the number falls below the target when an exit is judged invalid or has not been replaced yet, and rises above it during peak auto-expansion (when `elastic_active` is also true) |
| `active_proxies` | Live state of each upstream exit: `url` (masked), `active` — **the number of connections currently using this exit** (requests in flight plus tunnels that recently relayed data; this is the "in use" figure shown by the panel and the CLI), `inflight` — connections still holding a slot (idle tunnels included, always ≥ `active`), `capacity` — the per-exit active connection allowance (`0` means unlimited; idle tunnels don't count), `failures` — consecutive failures, `suspect` — whether recent failures dominate (such exits give way first but remain usable), `failure_ratio` — the recent failure share, `expires_in` — remaining lifetime in seconds, `requests_left` — requests left to serve (both are `null` when that measure is not enabled), `last_used` / `added_at` / `expires_at` / `requests_served` (`time.monotonic()` values and counters, for comparison within the same process only) |
| `proxy_source_mode` | Proxy source: `local` / `api` / `pool` |
| `exit_count` | The exit pool's target capacity (`[Server] exit_count`); read it together with `total_proxies`. **When rotation happens depends on the mode**: under continuous rotation the pool holds this many even while idle; under request-driven rotation and the local source, exits that expire while idle are removed rather than replaced and the pool may drain, until the next request fetches a fresh set to fill it |
| `elastic_active` | Whether the exit count is above the target: a burst or peak auto-expansion is in progress, or the expansion has stopped but the surplus exits have not yet reached the end of their lifetime (each is retired one by one only after serving out its full lifetime) |
| `auth_required` | Whether the outbound proxy requires username / password authentication |
| `display_level` | Console verbosity (`[Server] display_level`) |
| `service_status` | `running` / `stopped` |
| `language` | The current UI language |
| `request_interval` | The threshold for switching by request count (an assignment count, not the number of requests served successfully). It takes effect together with `interval`; whichever threshold is reached first triggers the rotation |
| `pool_running` | Whether the proxy pool is running |
| `source_error` | The reason and time of the most recent failure to fetch exits from the source (`{"message": ..., "at": ...}`); `null` when nothing has failed |

## Configuration Management

### Read Configuration (GET /api/config)

Returns every key and value of the `[Server]` and `[Pool]` sections.

```json
{
  "status": "success",
  "server": { "port": "1080", "web_port": "5001", "mode": "cycle" },
  "pool": { "validator.timeout_seconds": "10" }
}
```

- **The `token` key is stripped out** and never appears in the response — the panel has no need to
  echo it back, keeping it out of the page source, browser cache and frontend logs.
- `[Users]` and `[api_credentials]` are not returned here; each has its own endpoint.
- Boolean values are normalized to `"true"` / `"false"`: `yes` / `on` / `1` in `config.ini` all
  count as true at runtime, but the UI recognizes only `"true"`, and without normalization the
  checkbox would show as unchecked — a single casual save by the user would switch the option off.

### Save Configuration (POST /api/config)

Either section in the request body may be omitted, but at least one must be non-empty:

```json
{
  "server": { "mode": "loadbalance", "interval": "600" },
  "pool": { "validator.timeout_seconds": "15" }
}
```

Key names are validated against a whitelist; unknown keys and invalid values are rejected with **HTTP 400**.

> `token` is also a valid `server` key: **the panel provides no editor for it, but this API accepts
> it** — so to change the token you can either call `POST /api/config` (effective immediately) or
> edit `config.ini` directly and restart the process.

```json
{
  "status": "success",
  "port_changed": false,
  "web_port_changed": false,
  "service_status": "running",
  "applied": { "proxy": true, "pool": true }
}
```

| Field | Description |
|---|---|
| `port_changed` | Whether the proxy listening port changed. Hot-reloading the configuration does not rebind ports by itself; **the panel restarts the outbound proxy service based on this flag** (`restart` of `POST /api/service`) to move to the new port. When using the command-line entry point, the process must be restarted instead |
| `web_port_changed` | Whether the panel port changed. **The entire process must be restarted** for it to take effect; the current panel still runs on the old port |
| `applied.proxy` | Whether the new configuration was pushed to the outbound proxy service |
| `applied.pool` | Whether the new configuration was pushed to the proxy pool |

An entry of `false` under `applied` means **the configuration was written to disk but the push
failed**; the response itself is still `success`. In that case, go by `applied` to judge whether
the change really took effect.

On a validation failure (HTTP 400), besides `message` the response carries `details`, naming the
offending key and the reason rendered in the current UI language; the panel uses it to attach the
hint to the specific input box:

```json
{
  "status": "error",
  "message": "Invalid option port (current value: 70000): must not be greater than 65535",
  "details": { "key": "port", "reason": "must not be greater than 65535" }
}
```

`details` is present only when both `key` and `reason_key` are set (validation exceptions for
`[Server]` and `[Pool]` all carry these two attributes); other exceptions have only `message`.
`message` is always retained, so older clients are unaffected.

When saving the configuration, if the current proxy source is `pool`, no external pool address
(`pool_remote_url`) is configured and the pool is not running, the pool service is started
automatically along the way.

## Language

### Switch UI Language (POST /api/language)

The language is a **server-side setting**, not a browser setting: it is written back to
`[Server] language` in `config.ini` and switches the wording of the whole process (including the
panel, the console banner, API `message` fields, and the headers and status columns of exported
files).

```json
{ "language": "en" }
```

| Field | Type | Required | Values |
|---|---|---|---|
| `language` | string | No | `cn` / `en`; defaults to `cn` |

```json
{ "status": "success", "language": "en" }
```

A value outside `cn` / `en` **still returns HTTP 200**; judge by `status`:

```json
{ "status": "error", "message": "Unsupported language" }
```

> This endpoint follows the panel-side convention that business failures return 200 — do not go by
> the status code alone.

## Local Proxies and Lists

### Read / Write the Local Proxy List (GET/POST /api/proxies)

**GET** returns the contents of the proxy list file under `config/`.

```json
{ "proxies": ["http://1.2.3.4:8080", "socks5://5.6.7.8:1080"] }
```

A read failure returns an error, **not** an empty list — an empty list would make the UI show "no
proxies at all", and a single casual save by the user would wipe the proxy file:

```json
{ "status": "error", "message": "Failed to load proxy file: ..." }
```

**POST** overwrites the whole file and hot-loads the outbound service immediately (without
re-checking availability):

```json
{ "proxies": ["http://1.2.3.4:8080"] }
```

`proxies` **must be an array** (a string is torn into lines character by character, and an object
writes only its key names — either way the file is overwritten with garbage), otherwise:

```json
{ "status": "error", "message": "The proxy list must be an array" }
```

The write may also fail when the file is held by another process (common on Windows):

```json
{ "status": "error", "message": "..." }
```

### Check Proxy Availability (GET /api/check_proxies)

| Parameter | Required | Default | Description |
|---|---|---|---|
| `test_url` | No | `https://www.baidu.com` | Target URL for the liveness check |

Checks the **source list** entry by entry, with the concurrency taken from `[Server] check_concurrency`:

- `local` source: every entry in `proxy_file` — the active roster is deliberately not checked,
  because an exit that has been disabled by failures disappears from the roster, and those are
  exactly the ones that most need a re-check.
- `api` / `pool` sources: there is no readable local list, so the exits currently in use are checked.

```json
{
  "status": "success",
  "valid_proxies": ["http://1.2.3.4:8080"],
  "checked": 3,
  "total": 1,
  "message": "Proxy check completed, valid proxies: 1"
}
```

| Field | Description |
|---|---|
| `valid_proxies` | Addresses that passed the check |
| `checked` | How many were actually checked this time (the number of source-list entries) |
| `total` | The number that passed the check |

The check only reports its findings and does not change the active roster — to put newly validated
exits into service, simply wait for the next batch refresh.

The check takes longer as the proxy count grows, so the request may wait a while (internal timeout
30 seconds).

### Read / Write the IP Whitelist / Blacklist (GET/POST /api/ip_lists)

**GET**:

```json
{ "whitelist": ["127.0.0.1"], "blacklist": ["1.2.3.4"] }
```

**POST**:

```json
{ "type": "whitelist", "list": ["127.0.0.1"] }
```

| Field | Description |
|---|---|
| `type` | `whitelist` or `blacklist`; any other value returns an error |
| `list` | The complete list; written as a full overwrite |

After the file is written, the outbound service is hot-loaded immediately — no restart needed.
Both lists validate the **client source IP** (the endpoint connecting to the proxy port): the
decision is made first as each new connection is established, and a client that fails it gets a
403 directly plus a logged "Unauthorized IP attempt" — the connection is not forwarded. When a
client matches both lists, the priority is set by `[Server] ip_auth_priority` (`whitelist` allows
/ `blacklist` blocks).

### Read / Write the Bypass List (GET/POST /api/bypass_whitelist)

**GET**:

```json
{ "list": ["192.168.0.0/16"] }
```

**POST**:

```json
{ "list": ["192.168.0.0/16"] }
```

**Target addresses** on the list are not forwarded through any upstream; they are connected to
directly from this host (taking no part in exit scheduling). This is a different matter from the
client-source-IP whitelist / blacklist above: adding a target to this list does not skip the
client-IP whitelist / blacklist check.

## Service Control

### Start / Stop the Outbound Proxy Service (POST /api/service)

```json
{ "action": "start" }
```

| action | Description |
|---|---|
| `start` | Starts the service if it is not running; returns success directly if it is already running |
| `stop` | Stops the service |
| `restart` | Stops first, then starts |

```json
{ "status": "success", "message": "Service started successfully", "service_status": "running" }
```

`start` / `stop` responses carry `service_status` (values `running` / `stopped`); a successful
`restart` does not carry that field.

**This endpoint is serialized and has timeouts**: a start waits for the old thread to exit (up to
10 seconds) and then for the service to be ready (up to 5 seconds); a stop waits up to 10 seconds.
On timeout it returns `status` as `error` and **will not silently fall back to another port**.
Callers should therefore allow a sufficiently long request timeout.

When the port is in use, it returns an error and does not start the service:

```json
{
  "status": "error",
  "message": "Port 1080 is already in use by another program, please choose a different port and retry",
  "service_status": "stopped"
}
```

### Manually Switch the Upstream Proxy (GET /api/switch_proxy)

Discards the existing standby entries and calls the source once immediately: **if the pool is not
full it is topped up; when exit lifetime is enabled (`interval` or `request_interval` non-zero), a
full pool has its soonest-expiring exit replaced** (when only `request_interval` is filled in,
exits have no time-based lifetime, so what actually gets replaced is the first entry in the
roster). This is not "switching to the next IP" (all exits are already in use at the same time),
nor a wholesale replacement. The response has four forms:

**Switch succeeded**

```json
{
  "status": "success",
  "current_proxy": "http://1.2.3.4:8080",
  "active_proxies": [
    { "url": "http://1.2.3.4:8080", "inflight": 0, "active": 0, "capacity": 0, "failures": 0, "suspect": false, "failure_ratio": 0.0, "last_used": 0.0 }
  ],
  "total_proxies": 1,
  "message": "Upstream exit batch refreshed"
}
```

| Field | Description |
|---|---|
| `current_proxy` | The current exit (the most recently handed-out exit, masked); when it is replaced, falls back to the first entry in the roster |
| `active_proxies` | A snapshot of the current roster; field meanings are the same as `/api/status` |
| `total_proxies` | Number of exits in the current roster |

"Success" is judged by whether the **roster is non-empty** after the refresh — if it was already
full and only one exit was rotated this time, that still counts as success.

**In the cooldown period** (too soon after the last switch; no switching within `[Server] switch_cooldown`)

```json
{
  "status": "error",
  "cooldown": true,
  "cooldown_remaining": 12,
  "message": "..."
}
```

**A switch is already in progress**

```json
{ "status": "error", "switching": true, "message": "..." }
```

**Switch failed**

```json
{ "status": "error", "current_proxy": "...", "message": "..." }
```

Callers should use the `cooldown` / `switching` fields to tell "not switching right now" apart from
"genuinely failed"; both are `status: error`.

## Logs

By purpose, logs fall into four categories: `access` (proxy access), `proxy` (proxy lifecycle),
`main` (main program) and `pool` (proxy pool). Of these, `access` / `proxy` / `main` have
corresponding log files, while `pool` only goes into the in-memory ring buffer and `error.log`; its
own files live under `modules/proxypool/logs/` and are not browsed through this group of endpoints.

### Query In-Memory Logs (GET /api/logs)

| Parameter | Required | Default | Description |
|---|---|---|---|
| `category` | No | `all` | `all` / `access` / `proxy` / `main` / `pool`; any other value returns an error |
| `start` | No | `0` | **Number of entries to skip backwards from the newest one** |
| `limit` | No | `200` | Number of entries to return, clamped to 1-2000 |
| `level` | No | `ALL` | Filter by level |
| `search` | No | empty | Keyword filter |

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

- `seq` is a **globally incrementing sequence number, unique across categories**; when several
  categories are merged into a single response, it restores their true order. Entries are listed in
  ascending chronological order.
- `total` is the **total after filtering**, not the number of entries returned this time.
- The semantics of `start` are the opposite of ordinary pagination: it is an offset counted back
  from the newest entry, and together with `limit` it is used to "page back through older logs".

### Log Statistics (GET /api/logs/stats)

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

`total` is the combined count of the four rings, and `capacity` is each ring's capacity (the
`access` ring is smaller). `first_time` / `last_time` are absent when the buffers are empty.

### List Log Files (GET /api/logs/files)

```json
{
  "status": "success",
  "files": [
    { "name": "main.log", "category": "main", "size": 20480,
      "modified": "2026-10-02 15:30:00", "current": true, "rotated": false }
  ]
}
```

| Field | Description |
|---|---|
| `name` | File name (the panel uses it to call `/api/logs/file`) |
| `category` | `main` / `proxy` / `access` / **`error`**. `error` is the aggregated file for ERROR and above, and **must not** be passed as the `category` parameter of `GET /api/logs` |
| `size` / `modified` | Size in bytes / last modified time |
| `current` | Whether this is the one currently being written; `rotated` is its opposite (a rotated historical copy) |

Only whitelisted files under the `logs/` directory are listed (rotated copies included); the proxy
pool's own `proxy_pool.log` is not included.

### Read a Log File (GET /api/logs/file)

| Parameter | Required | Default | Description |
|---|---|---|---|
| `name` | Yes | empty | File name; must be a name from the whitelist |
| `lines` | No | `500` | Number of trailing lines to read, clamped to 1-5000 |

```json
{ "status": "success", "name": "main.log", "lines": ["..."], "truncated": true }
```

`truncated` of `true` means the file's line count is **no fewer than** the requested count (it is
also `true` when they are exactly equal), and only the trailing part was returned. A file name that
is not on the whitelist returns an error (**validated against the whitelist rather than by path
concatenation, ruling out directory traversal**).

### Export Logs (GET /api/logs/export)

| Parameter | Required | Description |
|---|---|---|
| `file` | No | When a file name is specified, **downloads that file as an attachment**; when omitted, exports the in-memory logs |
| `category` | No | Takes effect when `file` is omitted; same as `GET /api/logs` |
| `level` / `search` | No | As above |

When `file` is omitted, a plain-text attachment named `proxycat_export.log` is returned.

### Clear Logs (POST /api/logs/clear)

```json
{ "category": "all" }
```

Clears the in-memory ring buffer of the given category and truncates the corresponding log file.
When `category` is `all`, everything is cleared.

```json
{ "status": "success", "message": "Logs cleared" }
```

**This deletes log content on disk** and cannot be undone.

## Access Records

Records every proxy request individually. What sets it apart from Logs is that it is built for querying and statistics: stored in columns, filterable and exportable.

### Query Access Records (GET /api/logs/records)

| Parameter | Required | Default | Description |
|---|---|---|---|
| `since` | No | 1 hour ago | Start time; accepts `YYYY-MM-DD`, `YYYY-MM-DD HH:MM`, `YYYY-MM-DD HH:MM:SS`, and the `T` separator as well |
| `until` | No | No limit | End time; when given at minute or date granularity it is padded to the last second of that moment |
| `outcome` | No | Any | `success` / `failure` / `aborted`; any other value returns an error |
| `upstream` | No | Any | Filter by upstream proxy |
| `host` | No | Any | Filter by target host |
| `search` | No | Empty | Keyword filter |
| `limit` | No | `100` | Clamped to 1-500 |
| `offset` | No | `0` | Pagination offset |
| `order` | No | `desc` | Time sort direction |

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

- `id` is the auto-increment primary key; `client` (`client_ip/client_user`) and `target` (`host:port`) are **derived fields** — they merely join the two adjacent columns into a form the UI can use directly, and come from the same source as `client_ip` / `host`.
- When `upstream` holds a special value, `upstream_label` supplies a readable label: direct (`direct`) and unknown upstream (`unknown`) each have their own value.
- On failure (`outcome=failure`) `status_code` is always empty: rows that failed only after the tunnel was established do not appear here carrying the 200 from connection setup (such rows were once stored in the database; reads normalize them uniformly).
- `real_ip` is **the egress IP this exit actually uses** (the one the target site sees); for a gateway-type exit its address is a different thing. It is a display field: for the pool source it comes from the verification performed when the pool accepts the proxy, for the api source it is produced by a background probe when `[Server] access_records_real_ip_probe` is on, and for the local source it is always an empty string. When probing fails or the setting is off it is `""` and the UI renders `--`; direct requests are also `""`. It **does not participate** in exit scheduling, lifetime or failure decisions, and historical records in an older database are likewise `""`.
- The response returns three persistence-status fields alongside `records`: `pending` (buffered rows not yet flushed), `dropped` (rows discarded because the buffer filled up), `oldest_ts` (timestamp of the oldest row in the database; an empty string means none). A non-zero `dropped` means flushing cannot keep up and records are being lost.

### Export Access Records (GET /api/logs/records/export)

The filter parameters are the same as for the query endpoint, plus one more:

| Parameter | Required | Default | Description |
|---|---|---|---|
| `format` | No | `csv` | `csv` or `json`; any other value returns an error |

- **CSV**: carries a UTF-8 BOM so Excel opens it without mojibake; **the header row is rendered in the current UI language**.
- **JSON**: UTF-8, with `exported_at`, the filter conditions, `count` and `truncated` metadata.

Both formats are capped by `export_limit` (50000); the truncation flag exists only in JSON's metadata (`truncated`, `true` once the number of rows fetched reaches 50000) — CSV has just the body and no such flag. The response is an attachment download, with a filename like `access_records_20260930_120000.csv`.

### List Filter Options (GET /api/logs/records/options)

Returns the upstream proxy and target host values that appear in the current records, for the frontend to render dropdowns.

```json
{ "status": "success", "upstreams": [{ "value": "http://1.2.3.4:8080", "label": "..." }] }
```

### Clear Access Records (POST /api/logs/records/clear)

```json
{ "status": "success", "removed": 1234, "message": "Cleared 1234 access records" }
```

**Irreversible.**

## Domain Statistics

Accumulates success and failure counts per "target domain × upstream proxy". The difference from Access Records: this is an aggregate count while access records are per-request detail; clearing access records therefore leaves these totals intact, and vice versa.

### Query Domain Statistics (GET /api/logs/domains)

| Parameter | Required | Default | Description |
|---|---|---|---|
| `upstream` | No | Empty | **When given, drills down to the domain detail for that upstream; when omitted, aggregates by upstream** |
| `sort` | No | `last_seen` | Sort field |
| `order` | No | `desc` | Sort direction |
| `search` | No | Empty | Keyword filter |
| `limit` | No | `100` | Clamped to 1-1000 |
| `offset` | No | `0` | Pagination offset |

**`upstream` omitted — aggregate by upstream:**

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

**`upstream` given — drill down to domains:**

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

- In `summary`, `pairs` is the number of "domain × upstream" combinations; `rate` is the success rate as a rounded percentage.
- **Use the returned `mode` field to tell the two shapes apart — don't guess.**
- `enabled` being `false` means the domain statistics feature is off (`[Server] domain_stats_enabled`), in which case there is no data to query.

### Clear Domain Statistics (POST /api/logs/domains/clear)

```json
{ "status": "success", "removed": 42, "message": "Cleared access statistics for 42 domains" }
```

## Users and API Credentials

### Read / Write Outbound Proxy Accounts (GET/POST /api/users)

**GET**:

```json
{ "status": "success", "users": { "neko": "123456" } }
```

A failed read returns `status: "error"` with `users: null`, **not an empty object** — an empty object makes the UI show "no users at all", and the next time an administrator adds a user and saves, that empty table overwrites the original accounts, which amounts to turning outbound authentication off. **The response contains plaintext passwords.**

**POST** replaces the whole `[Users]` section:

```json
{ "users": { "neko": "123456" } }
```

**An empty object turns outbound authentication off** (when the account table is empty, `auth_required` is `false`).

```json
{ "status": "success", "message": "Users saved successfully" }
```

### Manage Upstream API Credentials (GET/POST /api/api_credentials)

Stores multiple credential sets for the upstream proxy-fetch endpoint and designates the one currently in effect. When you switch the active set with `set_active`, or when the set you delete is the active one, the **`[Server] api_proxy_url` / `proxy_username` / `proxy_password` keys are rewritten in step**, so with the proxy source set to `api` the new credentials take effect immediately; `save` does not sync those three keys — it only updates the credential collection and the active-set marker. For newly saved values to actually be used by proxy sourcing, call `set_active` on them once more (or let the automatic switch triggered by deleting the active set) write the three keys back into `[Server]`.

**GET**:

```json
{
  "status": "success",
  "sets": [{ "name": "闪臣", "url": "https://...", "username": "", "password": "" }],
  "active_credential": "闪臣"
}
```

**The response contains plaintext credentials.**

**POST**:

```json
{ "action": "save", "name": "闪臣", "url": "https://...", "username": "", "password": "" }
```

| action | Required fields | Description |
|---|---|---|
| `save` | `name`, `url`, `username`, `password` | Updates the entry by `name` if it exists, otherwise adds one; an empty `name` returns an error. If there is no active set yet, or the active set is this very entry, it is made the active set |
| `delete` | `name` | Deletes by `name`; if the entry deleted is the active set, the first remaining entry is made active **and its three keys are written back to `[Server]` in step** (with no entries left, the three keys are cleared) — without the switch, the running service would keep using the deleted endpoint |
| `set_active` | `name` | Switches the active set and writes its `url`/`username`/`password` into `[Server]`; if `name` is not in the credential collection it returns an error and never writes a "nothing selected" intermediate state |

`save` and `delete` return the updated `sets` and `active_credential`; `set_active` returns `active_credential` and the active entry's `credential` but **does not return `sets`**. An unknown `action` and an empty `name` return an error (`{ "status": "error", "message": "..." }`), as does `set_active` when its `name` is not in the credential collection. Passing a `name` that does not exist to `save` adds a new entry; `delete` does not check whether the name exists — deleting a credential name that does not exist returns `success` all the same (`sets` returned unchanged).

## Version Check and Ads

> **The endpoints in this section require no authentication**; even when a token is configured,
> you do not need to send it.

### Check Version (GET /api/version)

Returns the result of the **most recent** version check. **This endpoint only reads a cache and
never makes an external request** — calling it never incurs a network wait.

```json
{
  "status": "success",
  "is_latest": true,
  "current_version": "ProxyCat-V3.0.0",
  "latest_version": "ProxyCat-V3.0.0"
}
```

| Field | Description |
|---|---|
| `is_latest` | Whether the remote version is no newer than the current version; **recomputed against the current `CURRENT_VERSION` on every read** |
| `current_version` | The version of this process |
| `latest_version` | The remote version fetched by the most recent check |

**The check cadence is up to the process itself, not triggered by this endpoint:**

- **Once at process startup**, then **once every 24 hours**.
- **A restart within 24 hours does not re-check**: the time of the last check is written to
  `logs/version_check.json` and read back after a restart to be reused. Both entry points
  (`app.py` and `ProxyCat.py`) follow this cadence.
- **The time is recorded whether the check succeeds or fails**, so at most one external request
  is made every 24 hours; when the network is down, the "every panel open waits out one timeout"
  situation no longer happens.
- The check runs on a background thread: it does not block startup, and it does not occupy a web
  worker thread.

**When there is neither a successful result nor a failure record** (the first check after startup
has not finished yet), it returns:

```json
{
  "status": "error",
  "message": "Version check has not completed yet"
}
```

**When the check fails** (no network, remote page structure changed) it returns `status` `error`
with a `message` explaining the cause; but if a check has succeeded before, it **keeps returning
the last successful result** — the panel is not a monitoring tool, and showing the last known
version state is more useful than showing an error. The failure itself is written to the logs.

> After upgrading to a new version, a re-check happens immediately even if less than 24 hours
> have passed since the last one: the state file stores "the current version at the time of the
> check", and a mismatch with the version in the process counts as stale.

### Get Ads (GET /api/ads)

Reads every `*.json` in the `config/ads/` directory and returns the entries whose `enabled` is
not `false`. Files that fail to parse are skipped silently.

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

`dismissed` is the **in-process dismissed state; it is lost on restart**.

### Dismiss / Reopen Ads (POST /api/ads/dismiss, POST /api/ads/reopen)

Both endpoints take no parameters and require no authentication; the response body is
`{ "status": "success", "dismissed": <boolean> }`, where dismiss sets `true` and reopen sets
`false`:

```json
{ "status": "success", "dismissed": true }
```

---

# 3. Pool API

They all live under the `/api/pool` prefix, and **authentication is the same as the panel's**
(the same `before_request` hook).

## Pool API Conventions

### Success Responses Have No Uniform Envelope

The adapter layer serializes the handler's return value **straight into the response body**, so:

- `GET /api/pool/get` returns a **JSON array** (not `{"status": ..., "data": [...]}`).
- `GET /api/pool/count` returns `{"count": 12}`, **with no `status` field**.
- `GET /api/pool/random?format=text` and the export endpoints return **plain text or an
  attachment**, not JSON.
- Only some endpoints carry their own `status` and `message` in the return value (such as the
  lifecycle endpoints); plugin operations return `success` and `message`, with no `status` field.

**To tell success apart, read the HTTP status code and the response content itself; do not assume
a `status` field is always present.**

### Error Responses

```json
{
  "status": "error",
  "message": "Error description",
  "error_code": "invalid_parameter"
}
```

| error_code | HTTP | Meaning |
|---|---|---|
| `invalid_parameter` | 400 | Invalid request parameters (including missing required fields and out-of-range values) |
| `api_error` | 4xx / 5xx | A business error, such as a proxy not existing or a spec mismatch. The HTTP status code comes with the error itself (e.g. plugin operation failure and backup restore failure are 500, geolocation resolution service not enabled is 503) — do not hard-code 4xx branches |
| `pool_running` | 409 | The pool is running and this operation is not allowed (**only backup restore** returns this) |
| `pool_unavailable` | 503 | The pool is not running, or is restarting |
| `pool_timeout` | 504 | The pool response timed out |
| `queue_full` | 503 | The write queue is full and the request was rejected (backpressure) |
| `internal_error` | 500 | Internal server error |

**Two exceptions to be aware of:**

- When `POST /api/pool/start|stop|restart` fails, it returns **500 with no `error_code`**, only
  `status` / `message` / `is_running`.
- `message` follows the UI language and **must not be used for programmatic decisions**.

### When the Pool Is Not Running

While the pool has not started, apart from the status query, the lifecycle endpoints, backup
listing/restore and `/schema`, **every other endpoint returns `503 pool_unavailable`**. Callers
should first query `GET /api/pool/status` to confirm `is_running`.

### Task Model

Every long-running operation (batch validation, import, fetching, geolocation update/recompute)
**returns a `task_id` immediately**; the actual execution is in the background, and progress is
polled by `task_id`.

- Task state is **in-process memory state**: all of it is lost when the process restarts.
- Completed/failed tasks are retained for **1 hour** (TTL) and are evicted after that; the status
  table holds at most 200 entries.
- The `status` returned at creation (`queued` / `running`) **is only a snapshot of the creation
  moment and does not represent the execution result**; entries in the task table are written
  straight as `running` from creation, and no entry is ever in the `queued` state.
- The states that actually appear in the task table: `running` / `completed` / `failed` /
  `cancelled` (`queued` appears only in some creation responses — filtering tasks by it will
  never match an entry).

### No Endpoint for Reporting Usage Feedback

"Usage feedback" is what the outbound proxy reports back to the pool **inside the process**
during real forwarding (see the
[Proxy Pool Mechanics](ProxyCat-Manual/Features-EN.md#proxy-pool-mechanics) section in
Features); **there is no HTTP endpoint for reporting a usage outcome**, so do not go looking
for one.

## Pool Status and Lifecycle

### Get Pool Status (GET /api/pool/status)

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

| Field | Description |
|---|---|
| `is_running` | Whether the pool is running |
| `last_error` | Text of the most recent error; `null` when there is none |
| `stats` | Global statistics; **`null` while the pool is not running**. A failure of the statistics themselves does not stop this endpoint from returning success — `stats` is simply `null` |
| `anonymity_fallback_proxies` | Number of proxies whose anonymity was judged as the fallback tier |
| `region_distribution` | Only the 10 regions with the most proxies |

### Get Pool Config Field Schema (GET /api/pool/schema)

Returns the field groups, types, descriptions and value ranges of the `[Pool]` section; **the panel's "Pool Settings" form is rendered from it**.
The wording follows the current UI language.

```json
{
  "status": "success",
  "groups": [
    {
      "title": "Database",
      "sub": "Where data lives and how it is backed up",
      "id": "database",
      "fields": [
        { "key": "database.path", "doc": "File holding all pool data (SQLite)", "type": "text",
          "title": "Database file path", "hint": "Relative paths start from the proxypool directory; changes need a pool restart" },
        { "key": "database.pool_max_readers", "doc": "...", "type": "int", "low": 1, "high": 64,
          "title": "Max read connections", "tier": "advanced" },
        { "key": "database.backup_interval_hours", "doc": "...", "type": "int", "low": 1,
          "title": "Backup interval", "unit": "h", "tier": "advanced", "visible_when": "database.backup_enabled=true" }
      ]
    }
  ]
}
```

| Field | Description |
|---|---|
| `type` | Field type, one of `bool` / `int` / `float` / `list` / `text` (string fields are always `text`; there is no `str`) |
| `doc` | Full description, word for word the comment in `config.ini` |
| `title` | Short title, used directly as the form field label |
| `hint` | One-line hint under the control; whether it appears depends on whether the field has one |
| `unit` | Unit of measure, rendered by the panel to the right of the input box. **The unit is not folded into `title`**, and the key is omitted when the language pack has no value for it |
| `tier` | When `"advanced"`, the field goes into the "Advanced" collapsible section |
| `visible_when` | Declarative show/hide rule `key=value1\|value2;key2!=value` (a semicolon means "and", a pipe means "or"). A field carrying this rule is shown inline and never collapsed. Hiding only affects display; the field is still collected and saved as usual |
| `sub` (group level) | Group subtitle, shown to the right of the card title |

`low` / `high` appear only for options that have a value range. **This endpoint does not return current values** — for those, use
the `pool` field of `GET /api/config`.

### Start the Pool (POST /api/pool/start)

No parameters.

```json
{ "status": "success", "message": "Pool started successfully", "is_running": true }
```

### Stop the Pool (POST /api/pool/stop)

No parameters. **Waits for the write queue to drain**, so it can take several seconds.

```json
{ "status": "success", "message": "Pool stopped successfully", "is_running": false }
```

### Restart the Pool (POST /api/pool/restart)

No parameters. Stops and then starts; the stop and the start each wait up to 30 seconds.

On failure (the same for all three lifecycle endpoints):

```json
{ "status": "error", "message": "...", "is_running": false }
```

The HTTP status code is **500, and no `error_code` is included**.

## Proxy Queries and Single-Proxy Operations

### Query the Proxy List (GET /api/pool/get)

**Returns a JSON array** whose elements are [proxy objects](#appendix-c-field-dictionary).

| Parameter | Type | Default | Values and meaning |
|---|---|---|---|
| `protocol` | string | any | `http` / `https` / `socks5`; anything else returns 400 |
| `region` | string | any | Fuzzy region match (matches both the Chinese and the English column); **a leading `-` means exclude**, e.g. `-United States` excludes proxies whose region contains the United States |
| `min_delay` | int | any | Minimum delay (milliseconds); a negative value is an error |
| `max_delay` | int | any | Maximum delay (milliseconds); a negative value is an error, and so is reversing the order against `min_delay` |
| `status` | string | any | `valid` / `invalid`; anything else returns 400 |
| `source` | string | any | Source plugin name |
| `sort_by` | string | `delay_ms` | See the whitelist below |
| `sort_order` | string | `asc` | `asc` / `desc` |
| `limit` | int | any | Return only the first N rows; when set, `page` is forced to 1. Cap: 50000 |
| `page` | int | `1` | Page number, must be ≥ 1 |
| `page_size` | int | `50` | Rows per page, 1 to 50000 |
| `format` | string | `json` | `json` or `text`; `text` returns plain text with one proxy address per line |
| `ip` | string | any | Fuzzy match on IP |
| `is_favorite` | bool | any | Favorited only / unfavorited only |
| `anonymity_level` | string | any | `transparent` / `anonymous` / `elite` / `unverified` |
| `min_health_score` | float | any | Minimum health score; a negative value is an error |
| `supports_https` | bool | any | Only proxies that do / do not support HTTPS |

`sort_by` whitelist: `delay_ms`, `protocol`, `region`, `validated_at`, `created_at`,
`health_score`, `anonymity_level`, `success_count`, `total_checks`, `avg_delay_ms`,
`failure_count`, `is_favorite`, `supports_https`, `success_rate`, `region_en`.

> **A misspelled `sort_by` raises no error**: a value outside the whitelist **falls back to
> `delay_ms` silently**, and a `sort_order` other than `asc` / `desc` falls back to `asc`
> silently. When the sort order looks wrong, check the spelling of the parameter names first.

> **Unknown query parameters are silently ignored** (see [Parameter Parsing Rules](#parameter-parsing-rules-pool-api-only)).
> A misspelled parameter name raises no error; you simply get unfiltered results.

### Get One Proxy (GET /api/pool/random)

Returns one random proxy that matches the filters. The filter parameters are the same as for
`/get` (**there is no** `sort_by` / `sort_order` / `limit` / `page` / `page_size`), plus:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `format` | string | `json` | `json` returns the full [proxy object](#appendix-c-field-dictionary); `text` returns only one line, `protocol://ip:port` |

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

(The example above is abridged; for the full field list see [Appendix C](#appendix-c-field-dictionary).)

In its plain-text form, a `format=text` response body is exactly one line:

```
http://1.2.3.4:8080
```

**Errors and edge cases:**

- No proxy matches the filters → **404 `api_error`**.
- `format` is neither `json` nor `text` → 400 `api_error`.

> **The pick is not strictly uniform**: the implementation counts the rows, picks a page at
> random (100 rows per page), then picks one row on that page — the granularity is the page.
> With a small pool the odds differ slightly from row to row, but that has no practical effect
> on use.

> This endpoint's `format=text` is exactly the response shape [`pool_remote_url`](ProxyCat-Manual/Configuration-EN.md#source) expects —
> another ProxyCat instance's `/api/pool/random?format=text&token=...` can serve as an external pool address.

### Count Proxies (GET /api/pool/count)

The filter parameters are the same as for `/get` (minus sorting and pagination).

```json
{ "count": 86 }
```

### Export Proxies (GET /api/pool/export)

The filter parameters are the same as for `/get` (minus sorting and pagination), plus:

| Parameter | Type | Default | Description |
|---|---|---|---|
| `format` | string | `txt` | `txt` / `json` / `csv`; anything else returns 400 |

- **`txt`**: one proxy address per line, as an attachment named `proxies_YYYYMMDD_HHMMSS.txt`.
- **`json`**: an attachment with the fields `protocol`, `ip`, `port`, `username`, `password`, `url`,
  `region`, `region_en`, `delay_ms`, `is_valid`, `real_ip`, `source_plugin`, `validated_at`.
- **`csv`**: an attachment with a UTF-8 BOM; **the number and order of header columns are a public
  contract** (Protocol, IP, Port, Username, Password, Proxy URL, Region, Delay (ms), Status, Exit IP,
  Source, Validated at), and the wording of the header and status columns follows the UI language.
  The English region column is **deliberately left out of the export**.

**A single export is capped at 50000 rows.**

**Errors and edge cases:** no proxy matches the filters → **404 `api_error`**.

### Import Proxies (POST /api/pool/import)

Request body:

```json
{ "proxies": ["http://1.2.3.4:8080", "socks5://user:pass@5.6.7.8:1080"] }
```

Import goes through **the same pipeline** as plugin fetching: a quick port screen first, then a full
validation, and **only proxies that pass validation are saved**, with their source always recorded as
`manual_import`. This endpoint is in the HEAVY tier.

The response has three possible outcomes; **callers must read `message` and `proxy_count` together,
not `success` alone**:

| Case | Response |
|---|---|
| Accepted | `{ "success": true, "message": "Validating N proxies in the background; only working ones are saved", "proxy_count": N, "task_id": "..." }` |
| All failed to parse | `{ "success": false, "message": "...", "proxy_count": 0 }` |
| All already exist | `{ "success": true, "message": "All proxies already exist, none imported", "proxy_count": 0 }` |

- An empty list → **400 `invalid_parameter`**.
- "Already exists" is decided by looking each entry up in the database by `ip:port`; the deduplication cache is not consulted.
- Once accepted, poll progress with the returned `task_id`.

### Toggle Favorite Status (POST /api/pool/proxies/{id}/favorite)

No request body.

```json
{
  "success": true,
  "is_favorite": true,
  "message": "Proxy added to favorites"
}
```

**This is a toggle, not a setter — calling it again flips back and forth between the two states**,
and there is no idempotent parameter. If the proxy does not exist → 404 `api_error`. Favorite status
represents a user choice; writes from fetching and validation never overwrite it.

## Statistics and Host Information

### Get Pool Statistics (GET /api/pool/stats)

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

**The response has no `status` field**; it is the statistics object itself (structurally identical to `stats` inside `/status`).

### List Sources (GET /api/pool/sources)

```json
{ "sources": ["geonode_plugin", "github_proxy_plugin", "manual_import"] }
```

Returns every source plugin name that has appeared in the database, including the pseudo-plugin name `manual_import` used for manual imports.

### Get This Host's Public Egress IP (GET /api/pool/host-ip)

Returns this host's public egress IP, the baseline for deciding whether a proxy is transparent.

```json
{
  "host_public_ip": "203.0.113.7",
  "host_public_ipv4": "203.0.113.7",
  "host_public_ipv6": "240e:37a:2563:cb00:9424:56ad:5734:d8",
  "source": "detected",
  "check_anonymity": true
}
```

| Field | Description |
|---|---|
| `host_public_ip` | The single-value form of this host's egress IP, **IPv4 preferred**; IPv6 is given only when there is no IPv4. **`null` when it cannot be determined, which is a normal state rather than a fault** |
| `host_public_ipv4` | The egress IP of that family; `null` when it cannot be determined |
| `host_public_ipv6` | The egress IP of that family; `null` when it cannot be determined |
| `source` | Where the value comes from (`configured` set manually / `detected` looked up automatically); an empty string when it cannot be determined |
| `check_anonymity` | Whether anonymity detection is enabled |

A dual-stack host has one egress IP per family, and **both families take part in the anonymity comparison**, which is why they are reported per family here.

The baseline is taken first from `[Pool] validator.host_public_ip` (one or two comma-separated values, at most one IPv4 and one IPv6); when it is left empty the program performs the lookup itself — the lookup **pins the address family and queries each family once**, rather than taking the first endpoint that answers, which would otherwise let the family obtained drift with endpoint availability. At most once every 30 minutes.

## Plugin Management

### List Plugins (GET /api/pool/plugins)

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

| Field | Description |
|---|---|
| `name` | The plugin name, **equal to the plugin file's file name without its extension** |
| `enabled` | Whether the plugin takes part in automatic fetch scheduling |
| `interval_minutes` | Fetch interval in minutes |
| `last_run` / `next_run` | An ISO 8601 string or `null` |
| `last_error` | The most recent error; **a built-in message key is rendered in the current language, while an exception text raised by the plugin itself is passed through as-is** |
| `is_loaded` | Whether the module loaded successfully. **The response only includes plugins that loaded successfully, so this is always `true`**; a plugin that failed to load does not appear in the list (the error is only recorded in the pool's log) |
| `test_url` | The liveness test URL used only by this plugin; an empty string means it inherits the global `[Server] test_url` |
| `reval_enabled` | Whether the plugin takes part in automatic revalidation |
| `reval_interval_minutes` | Revalidation interval; `0` means inherit the global value |
| `skip_validation` | Whether to skip validation before storing (**high risk**, see below) |

**The response is a JSON array with no `status` field.**

### Enable / Disable a Plugin (POST /api/pool/plugins/{name}/enable, POST /api/pool/plugins/{name}/disable)

No request body.

```json
{ "success": true, "message": "Plugin geonode_plugin enabled" }
```

On failure it returns 500 `api_error`.

### Set the Fetch Interval (PUT /api/pool/plugins/{name}/interval)

```json
{ "minutes": 30 }
```

`minutes` must be ≥ 1, otherwise 400 `invalid_parameter`.

```json
{ "success": true, "message": "Plugin geonode_plugin interval set to 30 minutes" }
```

### Set the Plugin Test URL (PUT /api/pool/plugins/{name}/test-url)

```json
{ "test_url": "https://example.com" }
```

**An empty or all-whitespace `test_url` means inheriting the global** `[Server] test_url`:

```json
{ "success": true, "message": "Test URL of plugin geonode_plugin restored to inherit the global URL" }
```

### Set the Plugin Validation Policy (PUT /api/pool/plugins/{name}/validation)

```json
{ "reval_enabled": true, "reval_interval_minutes": 0, "skip_validation": false }
```

| Field | Type | Default | Description |
|---|---|---|---|
| `reval_enabled` | bool | `true` | Whether the plugin takes part in automatic revalidation |
| `reval_interval_minutes` | int | `0` | Revalidation interval in minutes; **`0` means inherit the global value**. A string value is also accepted; a non-integer returns 400 |
| `skip_validation` | bool | `false` | Skip validation before storing |

```json
{ "success": true, "message": "Validation policy of plugin geonode_plugin updated" }
```

> **`skip_validation` is a dangerous switch**: once it is on, proxies fetched by that plugin are **written to the database without
> validation**, and the pool's quality scoring and automatic cleanup both lose their meaning. It is only available for **real, loaded
> plugins**; for the pseudo-plugin name `manual_import` it returns 404 — otherwise turning it on once would make every manual import afterward skip validation.

### Run a Plugin Immediately (POST /api/pool/plugins/{name}/run)

No request body. **The call returns as soon as a background task is created**; the fetch itself is bounded by `[Pool] plugins.execution_timeout_seconds`.

```json
{
  "task_id": "8f14e45f-ea6b-4c1e-9c1a-0f3b2d5e7a91",
  "status": "running",
  "message": "Fetch task created for plugin geonode_plugin"
}
```

`status` is only a snapshot from the moment of creation; poll `task_id` for progress and results. Plugin not loaded → 404 `api_error`.

### Hot-Reload a Plugin (POST /api/pool/plugins/{name}/reload)

No request body. After editing a plugin's source code you do not need to restart the process.

**An expected failure returns 200 with `success: false`; only an unexpected exception produces a 500:**

```json
{ "success": true, "message": "Plugin geonode_plugin reloaded successfully" }
```

```json
{ "success": false, "message": "Failed to reload plugin geonode_plugin (it may be running or the file does not exist)" }
```

A missing plugin file, a plugin that is currently running, or a load that returns empty all take the `success: false` path.

## Batch Operations

**Every endpoint in this section returns `task_id` immediately** (except the two delete
endpoints); poll progress under [Task Management](#task-management).

### Revalidate Valid Proxies (POST /api/pool/validate/all-valid)

No parameters. Runs one round of revalidation over all proxies currently with `is_valid = true`.

```json
{ "task_id": "...", "status": "queued", "message": "Validation task created" }
```

### Revalidate Invalid Proxies (POST /api/pool/validate/all-invalid)

No parameters. Runs one round of revalidation over all proxies currently with `is_valid = false`.

> **This is the entry point for immediately revalidating proxies that usage feedback marked
> invalid**: when a proxy is marked invalid, `total_checks` is reset to zero along with it (the
> log records it as "added to the next revalidation candidate round"), and every round of auto
> revalidation adds proxies with `total_checks = 0` back into the candidates (not subject to
> `auto_revalidation.only_valid_proxies`, though still scheduled by each proxy's own
> revalidation interval), so these proxies are revalidated even without this endpoint.

```json
{ "task_id": "...", "status": "queued", "message": "Validation task created" }
```

### Full Check and Region Backfill (POST /api/pool/update-geo/all)

No parameters. Runs a complete assessment of every proxy (latency, egress IP, anonymity,
protocol support) and backfills regions along the way. Much heavier than routine revalidation.

```json
{ "task_id": "...", "status": "queued", "message": "Full proxy check task created" }
```

### Delete All Invalid Proxies (DELETE /api/pool/delete/invalid)

No parameters. **Deletion is irreversible.**

```json
{ "success": true, "message": "Deleted 34 invalid proxies", "deleted_count": 34 }
```

With no invalid proxies it returns success all the same, with `deleted_count` 0. This endpoint
is in the HEAVY tier.

### Batch Validate Specified Proxies (POST /api/pool/proxies/batch/validate)

```json
{ "proxy_ids": [1, 2, 3], "mode": "liveness" }
```

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `proxy_ids` | int[] | Yes | — | List of proxy ids; an empty list returns 400 |
| `mode` | string | No | `auto` | `auto` / `liveness` / `full`; any other value returns 400 |

```json
{ "task_id": "...", "status": "running", "message": "Validating 3 proxies" }
```

- **Non-existent ids are silently ignored**; a 404 `api_error` is returned only when **none of
  them exist**.
- Three modes: `liveness` only checks reachability; `full` runs a complete assessment; `auto`
  picks one automatically from the information already held for each proxy.

### Batch Delete Specified Proxies (DELETE /api/pool/proxies/batch/delete)

**Note: this is a DELETE request, but the parameters go in the request body.**

```json
{ "proxy_ids": [1, 2, 3] }
```

```json
{ "success": true, "message": "Deleted 3 proxies", "deleted_count": 3 }
```

An empty `proxy_ids` returns 400; non-existent ids are silently ignored, and `deleted_count`
reports the rows actually deleted.

## Task Management

### List Tasks (GET /api/pool/tasks)

| Parameter | Type | Default | Description |
|---|---|---|---|
| `status` | string | Unrestricted | Filter by status: `running` / `completed` / `failed` / `cancelled` (the task table has no `queued`, so passing it matches nothing) |

```json
{
  "tasks": [
    { "task_id": "8f14e45f-...", "status": "running", "progress": 40, "total": 120, "message": "..." }
  ],
  "total": 1
}
```

### Query Task Status (GET /api/pool/tasks/{task_id})

**The response is the task entry itself, with no outer `status` field** (the entry carries its
own `status` for the task state).

```json
{
  "status": "running",
  "message": "Validating proxies...",
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

Fields vary by task type: only import / fetch tasks carry `stage` and the full set of counters;
batch validation and full check tasks additionally have `inconclusive_count`. **A task that does
not exist or has been evicted by its TTL → 404 `api_error`.**

> Task entries are **in-memory state**: after a process restart, no historical task can be
> queried.

### Cancel a Task (POST /api/pool/tasks/{task_id}/cancel)

No request body.

```json
{ "success": true, "message": "Task cancelled" }
```

**When the task has already finished it returns `success: false`, and this is not an error**:

```json
{ "success": false, "message": "The task has already finished, nothing to cancel" }
```

A non-existent task id → 404 `api_error`.

## Geolocation Maintenance

Geolocation resolution uses an **offline database** (GeoLite2 and the Chunzhen library) and
issues no external lookup requests. All three endpoints in this section are maintenance actions.

### Query Offline Geolocation Database Status (GET /api/pool/geo/status)

```json
{
  "available": true,
  "files": [ { "filename": "GeoLite2-City.mmdb", "exists": true,
               "size": 65383808, "modified_at": "2026-10-02 12:00:00" } ],
  "pending_recompute": 42
}
```

`modified_at` is `null` when the file does not exist.

| Field | Description |
|---|---|
| `available` | Whether the offline database is usable (**usable only when both data files are present**) |
| `files` | Status of each data file |
| `pending_recompute` | Number of records whose region is pending recomputation; when it cannot be determined, it returns 0 rather than an error |

### Update the Offline Geolocation Database (POST /api/pool/geo/update)

No parameters. **Downloads roughly 100 MB of data files**, run as a background task.

```json
{ "task_id": "...", "status": "queued", "message": "Geo database update task created" }
```

- The two files total around **105 MB** (GeoLite2 about 65 MB, the Chunzhen library about
  40 MB).
- **Disk space is not checked**; if space runs short, the download fails partway through.
- A failure on one file does not block the other; failures are reported faithfully in the task
  result's `message`.

### Recompute Regions (POST /api/pool/geo/recompute)

No parameters. Recomputes the regions of existing records from the offline database.

```json
{ "task_id": "...", "status": "queued", "message": "Geo recompute task created" }
```

**Errors and edge cases:**

- **Only records whose `country_code` is empty are recomputed** (that is, egress IPs never
  resolved through the offline database). Records already resolved are not recomputed; there is
  no dedicated immediate-refresh operation after updating the data files, but the full check
  from `POST /api/pool/update-geo/all` hands each egress IP back to the resolver and can write
  the new region back indirectly (not effective immediately, being subject to the in-process
  query cache and the time it takes).
- When the geolocation resolution service is not enabled it returns **503 `api_error`**
  directly and creates no task.

## Database and Backups

### List Backups (GET /api/pool/backups)

```json
{
  "backups": [
    { "filename": "proxies_backup_20260930_030000.db", "size": 1048576, "created_at": "2026-09-30 03:00:00" }
  ]
}
```

Backups are created by a scheduled loop controlled by `[Pool] database.backup_enabled`; this endpoint only lists existing backups.
**When the backup feature is not enabled, it returns 404 `api_error`.** The backup listing and restore endpoints in this group are pure file operations and
**also work while the pool is stopped**.

### Restore from a Backup (POST /api/pool/backups/restore)

```json
{ "filename": "proxies_backup_20260930_030000.db" }
```

```json
{ "success": true, "message": "Backup restored successfully; please restart the proxy pool to load the restored data" }
```

**Semantic contract (all three points matter):**

1. **Returns 409 `pool_running` while the pool is running** — overwriting an open database file would corrupt it,
   so the pool must be stopped first. This is the **only** endpoint that returns `pool_running`.
2. Restore **only overwrites the database file; it does not check the backup for version compatibility with the current database**.
3. After a successful restore, **the pool must be restarted** before the new data is loaded. The endpoint itself does not restart the pool; the panel's
   "Database Maintenance" page restarts it automatically once the restore completes (it stops the pool first, then starts it back in its previous state),
   while clients calling the API directly must call `POST /api/pool/start` themselves.

Missing `filename` → 400 `invalid_parameter`.

### Database Statistics (GET /api/pool/database/stats)

```json
{ "stats": { "total_proxies": 120, "valid_proxies": 96, "invalid_proxies": 24,
             "db_size_mb": 1.05 } }
```

Requires the pool to be running. Returns 404 `api_error` when the maintenance feature is not enabled.

### Optimize the Database (POST /api/pool/database/optimize)

No parameters. Runs `ANALYZE` + `REINDEX` + `VACUUM`; **it is a HEAVY-tier operation and VACUUM holds an exclusive
database lock for a long time**, so other database operations are blocked while it runs.

```json
{ "success": true, "message": "Database optimization complete" }
```

## Pool Error Codes

See [Pool API Conventions → Error Responses](#error-responses). For the summary table, see
[Appendix A](#appendix-a-error-code-reference).

---

# 4. End-to-End Examples

## Python

```python
import requests

HOST = "http://localhost:5001"
TOKEN = "YOUR_TOKEN"
PARAMS = {"token": TOKEN}

# Panel: view runtime status
status = requests.get(f"{HOST}/api/status", params=PARAMS).json()
print(status["current_proxy"], status["proxy_source_mode"])

# Panel: manually switch the upstream proxy once
switched = requests.get(f"{HOST}/api/switch_proxy", params=PARAMS).json()
if switched["status"] != "success":
    # A cooldown and a genuine failure both come back as error; tell them apart by the field
    print("In cooldown" if switched.get("cooldown") else switched.get("message"))

# Panel: query failed requests from the past hour
records = requests.get(
    f"{HOST}/api/logs/records",
    params={**PARAMS, "outcome": "failure", "limit": 50},
).json()
for row in records["records"]:
    print(row["ts"], row["host"], row["upstream_label"], row["reason"])

# Pool: get an available proxy (plain text)
proxy = requests.get(
    f"{HOST}/api/pool/random",
    params={**PARAMS, "status": "valid", "format": "text"},
).text.strip()
print(proxy)   # for example http://1.2.3.4:8080

# Pool: create a batch validation task and poll it
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
# Panel: runtime status
curl "http://localhost:5001/api/status?token=YOUR_TOKEN"

# Panel: save configuration (change the rotation mode)
curl -X POST "http://localhost:5001/api/config?token=YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"server": {"mode": "loadbalance"}}'

# Panel: restart the outbound proxy service
curl -X POST "http://localhost:5001/api/service?token=YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action": "restart"}'

# Panel: switch the UI language
curl -X POST "http://localhost:5001/api/language?token=YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"language": "en"}'

# Panel: export the past hour of access records as CSV
curl -OJ "http://localhost:5001/api/logs/records/export?token=YOUR_TOKEN&format=csv"

# Pool: filtered query
curl "http://localhost:5001/api/pool/get?protocol=http&status=valid&limit=10&token=YOUR_TOKEN"

# Pool: get an available proxy (plain text)
curl "http://localhost:5001/api/pool/random?status=valid&format=text&token=YOUR_TOKEN"

# Pool: run a plugin manually
curl -X POST "http://localhost:5001/api/pool/plugins/geonode_plugin/run?token=YOUR_TOKEN"

# Pool: batch import
curl -X POST "http://localhost:5001/api/pool/import?token=YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"proxies": ["http://1.2.3.4:8080"]}'
```

---

# 5. Notes

1. **Authentication only compares a single token in the query string**; there is no CSRF protection and caller permissions are not distinguished: anyone who can reach the panel can
   change the configuration (including downstream credentials). Do not expose the panel directly to the public internet.
2. **Two sets of error conventions coexist**: on the panel side most business failures are `200 + status: "error"`, while on the pool side they are real
   4xx/5xx + `error_code`. Callers must check both.
3. **`message` varies with the UI language**; use it for display only, never for program logic.
4. **Runtime state lives in process memory** (current proxy, exit roster, task table, ads dismissal state) and resets when the process restarts;
   access records and domain statistics live in SQLite and survive a restart.
5. **Changing `web_port` requires restarting the whole process; changing `port` requires restarting the outbound service** (when you save through `POST /api/config`
   the panel restarts the outbound service automatically; manual edits and the command-line entry point require you to restart it yourself). Every other configuration item takes effect
   immediately once saved, with a few exceptions: the access-record buffer `access_records_buffer_size`, for example, is rebuilt at the new capacity only the next time the proxy service
   starts. Changes to `[Server]` made by hand-editing `config.ini` are also hot-reloaded automatically
   (both entry points poll the configuration file), but port rebinding does not happen automatically; the `[Pool]` section is hot-reloaded by the pool itself.
6. **Most** batch operations return a `task_id` (the two delete endpoints return `success` / `deleted_count` directly);
   poll progress with `GET /api/pool/tasks/{task_id}`. Tasks routinely run for tens of minutes and can be aborted at any time with
   `POST /api/pool/tasks/{task_id}/cancel`. Note that the download in the offline geolocation database update task runs on
   a thread that cannot be cancelled — cancelling only writes out the status, and the download still runs to completion. The task table is in-memory with a 1-hour TTL and
   cannot be queried after the process restarts.
7. **The Pool API's query parameters are a signature-based whitelist**: a misspelled parameter name is silently ignored, and the endpoint returns unfiltered results instead of an error.
8. When you change an endpoint or field under `/api/pool/*`, **this document must be updated in step** — the adaptation layer is a hand-written Flask blueprint
   and cannot generate an OpenAPI description automatically the way FastAPI does.

---

# Appendix A: Error Code Reference

## Panel API Error Conventions

| Case | HTTP | Response Body |
|---|---|---|
| Success | 200 | `{"status": "success", ...}` |
| Success (some read-only endpoints) | 200 | Returns the data directly, **with no `status` field** |
| Authentication failure | 401 | `{"status": "error", "message": "..."}` |
| Configuration validation failed (`POST /api/config` only) | 400 | `{"status": "error", "message": "...", "details": {"key": "...", "reason": "..."}}` |
| Other business failures | **200** | `{"status": "error", "message": "..."}` |

## Pool API Error Conventions

| error_code | HTTP | Meaning |
|---|---|---|
| `invalid_parameter` | 400 | Invalid request parameters |
| `api_error` | 4xx / 5xx | Business error (proxy not found, no matching results, spec mismatch, plugin operation failure, restore failure, etc.); the status code comes from the `ApiError` itself |
| `pool_running` | 409 | The pool is running, so this operation is not allowed (`POST /api/pool/backups/restore` only) |
| `pool_unavailable` | 503 | The pool is not running or is restarting |
| `pool_timeout` | 504 | The pool timed out while responding |
| `queue_full` | 503 | The write queue is full |
| `internal_error` | 500 | Internal server error |
| *(none)* | 500 | Pool start/stop failure: **no `error_code`** when `POST /api/pool/start\|stop\|restart` fails |

---

# Appendix B: Endpoint Index

## Page Routes (Non-`api`)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/` | No | Redirects to `/web` with the token |
| GET | `/web` | Yes | Panel single page |
| GET | `/static/<path>` | No | Frontend static assets |

## Panel API (33)

| Method | Path | Description |
|---|---|---|
| GET | `/api/status` | Runtime status |
| GET | `/api/config` | Read `[Server]` / `[Pool]` configuration |
| POST | `/api/config` | Save configuration |
| POST | `/api/language` | Switch the UI language |
| GET | `/api/proxies` | Read the local proxy list |
| POST | `/api/proxies` | Write the local proxy list |
| GET | `/api/check_proxies` | Check availability of the proxies in the source list (for the local source, all entries in `ip.txt`) |
| GET | `/api/ip_lists` | Read the IP whitelist / blacklist |
| POST | `/api/ip_lists` | Write the IP whitelist / blacklist |
| GET | `/api/bypass_whitelist` | Read the bypass list |
| POST | `/api/bypass_whitelist` | Write the bypass list |
| POST | `/api/service` | Start / stop / restart the outbound proxy service |
| GET | `/api/switch_proxy` | Refresh the exit pool: top it up when under capacity, replace the exit closest to expiry when full |
| GET | `/api/logs` | Query in-memory logs |
| GET | `/api/logs/stats` | Log statistics |
| GET | `/api/logs/files` | List log files |
| GET | `/api/logs/file` | Read a log file |
| GET | `/api/logs/export` | Export logs |
| POST | `/api/logs/clear` | Clear logs |
| GET | `/api/logs/records` | Query access records |
| GET | `/api/logs/records/export` | Export access records |
| GET | `/api/logs/records/options` | Filter options for access records |
| POST | `/api/logs/records/clear` | Clear access records |
| GET | `/api/logs/domains` | Query domain statistics |
| POST | `/api/logs/domains/clear` | Clear domain statistics |
| GET | `/api/users` | Read outbound proxy accounts |
| POST | `/api/users` | Write outbound proxy accounts |
| GET | `/api/api_credentials` | Read upstream API credentials |
| POST | `/api/api_credentials` | Manage upstream API credentials |
| GET | `/api/version` | Version check result (read-only cache, **no authentication**) |
| GET | `/api/ads` | Get ads (**no authentication**) |
| POST | `/api/ads/dismiss` | Dismiss ads (**no authentication**) |
| POST | `/api/ads/reopen` | Reopen ads (**no authentication**) |

## Pool API (38)

| Method | Path | Description |
|---|---|---|
| GET | `/api/pool/status` | Pool status and global statistics |
| GET | `/api/pool/schema` | `[Pool]` field schema (same source as the panel form) |
| POST | `/api/pool/start` | Start the pool |
| POST | `/api/pool/stop` | Stop the pool (waits for the write queue to drain) |
| POST | `/api/pool/restart` | Restart the pool |
| GET | `/api/pool/get` | Filtered proxy list (`json` / `text`) |
| GET | `/api/pool/random` | Get a random proxy (`json` / `text`) |
| GET | `/api/pool/count` | Count proxies matching the filters |
| GET | `/api/pool/export` | Export proxies (`txt` / `json` / `csv`) |
| POST | `/api/pool/import` | Batch import (validate before ingesting) |
| POST | `/api/pool/proxies/{id}/favorite` | Toggle favorite status |
| GET | `/api/pool/stats` | Pool statistics |
| GET | `/api/pool/sources` | List of source plugin names |
| GET | `/api/pool/host-ip` | This host's public egress IP |
| GET | `/api/pool/plugins` | Plugin list and status |
| POST | `/api/pool/plugins/{name}/enable` | Enable a plugin |
| POST | `/api/pool/plugins/{name}/disable` | Disable a plugin |
| PUT | `/api/pool/plugins/{name}/interval` | Set the fetch interval |
| PUT | `/api/pool/plugins/{name}/test-url` | Set the plugin's dedicated test URL |
| PUT | `/api/pool/plugins/{name}/validation` | Set the plugin validation policy |
| POST | `/api/pool/plugins/{name}/run` | Run a plugin immediately |
| POST | `/api/pool/plugins/{name}/reload` | Hot-reload a plugin |
| POST | `/api/pool/validate/all-valid` | Revalidate all valid proxies |
| POST | `/api/pool/validate/all-invalid` | Revalidate all invalid proxies |
| POST | `/api/pool/update-geo/all` | Full check and region backfill |
| DELETE | `/api/pool/delete/invalid` | Delete all invalid proxies |
| POST | `/api/pool/proxies/batch/validate` | Batch validate specified proxies |
| DELETE | `/api/pool/proxies/batch/delete` | Batch delete specified proxies (parameters in the request body) |
| GET | `/api/pool/tasks` | List tasks |
| GET | `/api/pool/tasks/{task_id}` | Query task status |
| POST | `/api/pool/tasks/{task_id}/cancel` | Cancel a task |
| GET | `/api/pool/geo/status` | Offline geolocation database status |
| POST | `/api/pool/geo/update` | Update the offline geolocation database (about 100 MB) |
| POST | `/api/pool/geo/recompute` | Recompute regions for existing records |
| GET | `/api/pool/backups` | List backups |
| POST | `/api/pool/backups/restore` | Restore from a backup (the pool must be stopped first) |
| GET | `/api/pool/database/stats` | Database statistics |
| POST | `/api/pool/database/optimize` | Optimize the database (ANALYZE / REINDEX / VACUUM) |

---

# Appendix C: Field Dictionary

## Proxy Object

The object returned by `GET /api/pool/get` and `GET /api/pool/random` (`format=json`).

| Field | Type | Description |
|---|---|---|
| `id` | int | Primary key |
| `proxy_url` | string | Full proxy address; when the username and password **are both present**, it takes the form `protocol://user:password@ip:port` |
| `protocol` | string | `http` / `https` / `socks5` |
| `ip` | string | Entry IP |
| `port` | int | Port |
| `username` / `password` | string \| null | Proxy authentication credentials |
| `real_ip` | string \| null | Egress IP (the IP the peer sees when requests go through the proxy) |
| `exit_ip_differs` | bool | Whether the entry IP differs from the egress IP. **Supplied in both the query and random responses** (the two share one serialization); the export paths deliberately leave it out |
| `region` | string | Full Chinese region name, e.g. 「中国 广东 深圳」; 「未知」 ("unknown") when the lookup finds nothing |
| `country` / `province` / `city` | string | Chinese region levels |
| `region_en` / `country_en` / `province_en` / `city_en` | string \| null | English region levels |
| `delay_ms` | float \| null | Most recently measured delay (milliseconds) |
| `validated_at` | string \| null | Most recent validation time (ISO 8601) |
| `source_plugin` | string | Source plugin name; `manual_import` for manual imports |
| `is_favorite` | bool | Whether the proxy is favorited (a user choice that fetching and validation do not overwrite) |
| `is_valid` | bool | Whether the proxy is currently usable; the list uses it to badge invalid rows as 「失效」 ("invalid"). Exports use their own status column |
| `health_score` | float | Health score, **0-100**, 1 decimal place |
| `anonymity_level` | string | `transparent` / `anonymous` / `elite` / `unverified` |
| `anonymity_fallback` | bool | Whether the anonymity level was judged to be the anonymity fallback |
| `supports_https` / `supports_http` | bool | Whether the corresponding protocol is supported |
| `quality_assessed_at` | string \| null | Most recent quality assessment time (ISO 8601) |
| `success_rate` | float | Validation success rate, 0-1, 3 decimal places |
| `avg_delay_ms` | float \| null | Historical average delay (milliseconds) |
| `total_checks` | int | Cumulative validation count; missing values fall back to 0 |
| `probe_success_rate` | float | Probe success rate, 0-1, 3 decimal places |
| `probe_total_count` | int | Cumulative probe count; missing values fall back to 0 |

> **Semantics of empty region values**: the Chinese and English sets are given as separate columns, and `null` means **not looked up yet** (not 「未知」).
> When an English column is missing, the front end falls back to the Chinese column; identical values in the two columns mean that level has no corresponding translation. Do not write
> 「未知」 into these columns — 「未知」 is the value the Chinese columns take when they have been queried but nothing was found.

## Task Object

The response of `GET /api/pool/tasks/{task_id}`, and also an element of the `GET /api/pool/tasks` list.

| Field | Type | Description |
|---|---|---|
| `task_id` | string | Task id; **it appears only on the elements of the `GET /api/pool/tasks` list** (injected per item by the list) and is absent from the single-task response |
| `status` | string | `running` / `completed` / `failed` / `cancelled` (`queued` appears only in some creation responses, never in the task table) |
| `message` | string | Human-readable description of the current stage, following the UI language |
| `progress` / `total` | int | Completed / total |
| `started_at` / `completed_at` | string | Start and end times (ISO 8601); `completed_at` is absent until the task finishes |
| `stage` | string | `prescreen` / `validate` / `ingest` / `done` (`done` is written on completion), **present only on import and fetch tasks** |
| `stage_done` / `stage_total` | int | Progress within the current stage; same availability as above |
| `in_flight` | int | Number of items being processed concurrently in the current stage; same availability as above |
| `rate` | float | Processing rate (items/second) |
| `eta_seconds` | int \| null | Estimated seconds remaining |
| `valid_count` / `invalid_count` / `inconclusive_count` | int | Counts by validation result category |
| `prescreened_out` | int | Number of items eliminated by the port prescreen |
| `incomplete_count` / `failed_count` | int | Incomplete / failed counts |
| `results` | object | Map from data file name to result text (`已更新` / `失败: ...`, in the Chinese UI), **present only in the completed state of an offline geolocation database update task** |

**The set of fields varies with task type and endpoint**; the table above is the union across
all of them; relying only on the four fields `status`, `progress`,
`total`, and `message` is the safest.

## Backup Object

An element of the `GET /api/pool/backups` list.

| Field | Type | Description |
|---|---|---|
| `filename` | string | Backup file name, used as the parameter of `POST /api/pool/backups/restore` |
| `size` | int | File size (bytes) |
| `created_at` | string | Creation time, always formatted as `YYYY-MM-DD HH:MM:SS` |
