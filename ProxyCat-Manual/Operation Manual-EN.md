# ProxyCat Operation Manual

> Documentation: [Back to README](../README-EN.md) · [Features](Features-EN.md) · [Configuration](Configuration-EN.md) · [Investigation Manual](Investigation%20Manual-EN.md) · [Changelog](logs-EN.md) · [API Documentation](../API-EN.md)

## Important Notes

- Python **3.10 or later** is required (3.8 / 3.9 fail with an error at import time); the Docker image is based on Python 3.11.
- The packaged builds under Releases are the more stable ones, though not necessarily the newest.
- The API endpoint's response is parsed line by line: you may return several proxy addresses at once, a line without a protocol is completed as `http`, and lines with an invalid format are skipped. To attach one username / password to every fetched address, set `proxy_username` / `proxy_password` (both must be non-empty to take effect).
- The `config/config.ini` shipped with the repository has been tuned by the author, so a few values differ from the program's built-in defaults. This manual does not repeat per-key documentation: what each key means, its default, how it takes effect and the authoritative reference are all in [Configuration](Configuration-EN.md).

## Installation and Deployment

### From Source

**Windows and Mac**: visit the source repository on GitHub in your browser and download it: [ProxyCat](https://github.com/honmashironeko/ProxyCat)

**Linux**: clone the project locally with Git:

```bash
git clone https://github.com/honmashironeko/ProxyCat.git
```

![Cloning the project with Git](./Operation%20Manual.assets/Linux%20Download.png)

Install the Python dependencies (**Python 3.10 or later is required**: the source leans heavily on runtime-evaluated `X | Y` union type annotations, so 3.9 and earlier raise a `TypeError` at import time):

```bash
pip install -r requirements.txt
# Or use a mirror:
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple/
```

Open the `config` folder and find `config.ini`, then choose the proxy-serving method that matches the resources you have:

(1) If your proxy server addresses are fixed connections that never need rotating, serve them from the local `ip.txt`, one `protocol://[user:password@]host:port` per line. The http / https / socks5 protocols and username / password authentication are all supported. The format looks like this:

```text
socks5://neko:123456@127.0.0.1:7890
https://neko:123456@127.0.0.1:7890
http://neko:123456@127.0.0.1:7890
socks5://127.0.0.1:7890
https://127.0.0.1:7890
http://127.0.0.1:7890
...
```

(2) If you fetch proxy addresses through an API, set `proxy_source_mode` to `api` in `config.ini` and fill in `api_proxy_url` (once set, `ip.txt` is no longer read). The response is parsed line by line; to attach one username / password to every fetched address, fill in `proxy_username` and `proxy_password` (both must be non-empty to take effect).

Once that is configured you can run the tool; for the difference between the two entry points and how to choose, see [Entry Points](#entry-points).

### Docker Deployment

On Windows you can download Docker's official tool: [Docker Desktop](https://docs.dockerd.com.cn)

![Docker Desktop download guide](./Operation%20Manual.assets/Docker%20Desktop%20Download.png)

On Linux you can install Docker with one command from the script provided by the Tsinghua mirror: [Tsinghua install script](https://mirrors.tuna.tsinghua.edu.cn/help/docker-ce/)

![Docker installation guide](./Operation%20Manual.assets/Docker%20Download.png)

Once installed, first check that `docker` and `docker compose` work.

On Windows and Linux, go into the ProxyCat folder (**first complete the basic `config.ini` changes described under From Source**) and run:

```bash
# From inside the ProxyCat folder, build the image and start the container
docker compose up -d --build
```

Compose builds the image and starts the container. The two ports are:

| Port | Purpose |
|---|---|
| `1080` | Proxy listening port (shared by HTTP and SOCKS5) |
| `5001` | Web panel port |

Three directories are bind-mounted to the host so that data and configuration survive container recreation: `config/`, `logs/` and `modules/proxypool/data/`. The image itself ships no `config.ini` (it is deleted at build time), so the first start creates it inside the mounted directory.

### Four Things To Know Before Deploying

These four all show up as a symptom first and a cause second, so read them upfront:

**1. The panel won't open — it returns 401**

The panel page itself is token-guarded, so with a token set you **must pass `?token=` to open it**. The `config/config.ini` shipped in this repo has a non-empty token, so visiting `http://127.0.0.1:5001/` directly ends in a 401 after the redirect. The correct URL is:

```text
http://127.0.0.1:5001/?token=honmashironeko
```

**That token is public in this repository — change it before exposing the panel**: the panel offers no field for it, so edit `[Server] token` in `config.ini` directly; the change hot-reloads within about a second and **the old token stops working right away**, so remember to reopen the panel with the new one.

**2. The container is up, but it can't write configuration or logs**

The container runs as a non-root user whose UID/GID must match the owner of `config/`, `logs/` and `modules/proxypool/data/` on the host, otherwise it cannot write to them. The reason is that the `chown` inside the image does not apply to a host bind mount, and the image itself ships no `config.ini` (it is deleted at build time), so the first start has to create it inside the mounted directory. If your host UID/GID is not 1000, set them in a `.env` file next to the compose file:

```text
PUID=your_uid
PGID=your_gid
```

**3. A restart loses the last batch of data**

On shutdown the application drains its write queue, so `stop_grace_period` has been widened to 60 seconds. Docker's 10-second default results in a `SIGKILL`, losing the last batch of validation results and access records. **Please do not lower it.**

**4. The container turns unhealthy after changing `web_port`**

The health check reads the **actual** `web_port` from `config.ini` at probe time rather than assuming 5001. So after changing the port you must restart the process and update the port mapping in `docker-compose.yml` to match.

### Common Docker Commands

```bash
# Stop and start the service
docker compose down
docker compose up -d

# View the logs
docker compose logs -f proxycat

# Rebuild and start after changing the Dockerfile or dependencies
docker compose up -d --build

# Docker ports default to 1080 and 5001: 1080 is the listening port, 5001 the web panel.
# For other ports, change the port mapping accordingly and allow them through.
```

**Which changes need a container restart**: only entries bound when the service starts, such as `port` / `web_port` — changing `web_port` requires restarting the whole application and updating the port mapping in `docker-compose.yml` to match, while `port` leaves the process alone: restarting the proxy service once from the panel binds the new port. Every other setting, whether saved from the panel or hand-edited in `config.ini`, hot-reloads and needs **no** container restart (for the full hot-reload boundaries see [Entry Points](#entry-points)).

## Entry Points

There are two entry points; pick whichever fits:

| Entry Point | What it starts | When to use |
|---|---|---|
| `python app.py` | Web panel + outbound proxy service (+ proxy pool, auto-started depending on the source) | Daily use; recommended |
| `python ProxyCat.py` | Outbound proxy service (+ proxy pool, auto-started depending on the source), CLI only, no panel | Servers that don't need the panel |

The CLI entry point accepts `-c` to point at a configuration file, defaulting to `config/config.ini`:

```bash
python ProxyCat.py -c config/config.ini
# On Windows the command is python, so write it as python ProxyCat.py
```

Both entry points read the same `config.ini`. On the CLI entry, `display_level` (**0-2**) controls console verbosity: `1` is a countdown progress bar, and `2` adds elapsed time and error details. **Inside a container the progress bar is replaced by periodic log lines** — a missing progress bar is not a fault.

> **Hot-reload boundaries** (easy to get wrong):
>
> - **Configuration saved from the panel applies immediately**, on both entry points.
> - **When you hand-edit `config.ini`**, both entry points reload the `[Server]` section: `app.py` runs a background thread that polls the file every second, and `ProxyCat.py` likewise picks the change up in its status polling and reloads it — about a second in countdown mode, and up to about five seconds under `loadbalance` or when rotation is not time-based (`interval` is `0`).
> - The `[Pool]` section is hot-reloaded as well, taking effect within about 3 seconds on both entry points.
> - `port` and `web_port` are bound only when the service starts: changing `web_port` requires restarting the whole application (the panel only warns you when you save it); `port` leaves the process alone — restarting the proxy service once from the panel binds the new port.

## The Panel

The panel is **a single page** at `http://127.0.0.1:5001/web` (remember the `?token=`), with four tabs down the left:

| Tab | What you do here | What backs it |
|---|---|---|
| **Proxy Config** | Switch the proxy source (Local / API / Pool), change the rotation mode and interval, edit the local proxy list, save API credentials, tune the logging and statistics switches; tuning items such as concurrency sit in the **Performance** and **Advanced** groups | The `[Server]` section |
| **Proxy Pool** | See the three sub-views below | The `[Pool]` section + `/api/pool/*` |
| **Access Control** | User management (outbound auth accounts), IP whitelist / blacklist and their priority, the proxy bypass list | The `[Users]` section and the list files under `config/` |
| **Logs** | Live logs by category, historical log files, access statistics and per-request detail | The logs and the two statistics databases under `logs/` |

The Proxy Pool tab has three sub-views:

| Sub-view | What you do here |
|---|---|
| **Proxy Management** | Inspect collected proxies (protocol / real IP / region / delay / health score / anonymity), filter, batch validate and delete, import/export, trigger a plugin run manually |
| **Pool Settings** | Tune the pool's own runtime parameters (validation concurrency and timeouts, fetch intervals, auto re-validation, auto cleanup, usage feedback, write queue) |
| **Database Maintenance** | Database stats and optimization, backup list and restore, offline geolocation database update and recompute |

Each tab is covered in turn below.

### Proxy Config

![Proxy Config tab: Source group with the Pool source selected](../assets/screenshots/config-source-en.png)

The screenshot shows the Proxy Config tab: the header carries the service controls (Start / Stop / Restart), the two listening addresses and the proxy status; below it you can switch between the three sources — Local / API / Pool — with the configuration groups as navigation on the left and the current group's form on the right. The screenshot has the **Pool** source selected and the **Source** group open — that group shows only the fields the current source actually uses.

The settings are divided into seven groups by purpose:

- **Source**: shows only the fields the current source uses;
- **Listening ports**: only worth changing when a port is taken;
- **Exit rotation**: how long an exit serves, and how many serve at once;
- **Availability checks**: what may enter the pool;
- **Performance**: how many requests this host can carry at once;
- **Logging and records**: what is recorded, and for how long;
- **Advanced**: tuning items that require understanding the internals are collected here.

The **Remote pool URL** (`pool_remote_url`) under Source is a **fetch endpoint, not a management API**: it sends a single GET to the address you provide and parses every line of the response body as a proxy address (say `http://1.2.3.4:8080`), performing no management operations; a 404 means no proxy is available right now. Left empty, the in-process built-in pool is used; if you switch the source to Pool while the pool is not running, it is brought up automatically (see [Using the Proxy Pool](#using-the-proxy-pool)).

The `mode` field in the Exit rotation group **asks two different questions depending on the source**. A local source asks *which exit to pick*: `cycle` works down the list in order (ignoring load — the next entry is used only once the previous one is full), while `loadbalance` picks whichever exit is under the least pressure. API and pool sources ask *when to rotate*: `request` (On request) is listed first and only fetches and rotates exits when a new task arrives — with no tasks at all, expired exits are removed outright and the pool empties, then the next request fetches a fresh set to fill it; `continuous` (Continuous) is decoupled from traffic, replacing expired exits in the background on lifetime and topping the pool up. When you switch sources, a value that does not belong to the new source's group is normalised to that group's first entry — **the api / pool group normalises to `request`**. For the trade-off between the two rotation rhythms, see the [FAQ](#faq).

The local proxy list is edited right here in this tab; saving it reloads the roster. The **Check** button below the list tests the **source list** (for the `local` source, every entry in `ip.txt`), so broken exits that have already been retired can still be re-checked.

![Proxy Config tab: Performance group](../assets/screenshots/config-perf-en.png)

The **Performance** group governs how many requests this host can carry at once: the global concurrency cap is the limit across all exits combined, and anything above it queues on a semaphore; a per-exit concurrency cap of `0` means unlimited, leaving concurrency bounded only by the global cap; set it to a non-zero value and total upstream concurrency becomes roughly exits × this value (still capped by the global limit). The note shown in the screenshot — "Expansion only matters when 'Concurrency per exit' is not 0: with 0 nothing expands, but an existing expansion is still released" — is exactly the switch condition for auto-expansion: with `0` nothing expands, though an existing expansion is released as usual. For why growth and release look at two different numbers, and why relaxing the per-exit limit is a last resort, see [Upstream Exits and Concurrency](Features-EN.md#upstream-exits-and-concurrency).

For what each option means, its default and how it takes effect (immediately / needs a restart), [Configuration](Configuration-EN.md) is the authority; the panel forms validate input and apply on save, so they are the recommended place for day-to-day changes.

### Proxy Pool

#### Proxy Management

![Proxy Pool sub-view: Proxy Management](../assets/screenshots/pool-manage-en.png)

Top to bottom, the screenshot shows: the stat cards (Total / Valid / Invalid / Availability), the plugin table (each plugin's status, interval, last and next run, re-validation policy, plus the Fetch, Test URL and Reload buttons), and the filterable proxy list (Protocol / Address / Real IP / Region / Delay / Health / Anonymity, with Import / Export / Copy API link in the top-right corner).

Here you can: filter by protocol / validity / anonymity / source (plus advanced filters), batch-validate and delete selected proxies, import and export proxies, and trigger a plugin run manually. The list also flags whether an anonymity level was measured or inferred — proxies with no echo evidence can only be given an inferred value.

#### Pool Settings

![Proxy Pool sub-view: Pool Settings](../assets/screenshots/pool-settings-en.png)

Pool Settings is divided into eight groups by purpose: Database / Proxy validation / Fetch plugins / Automatic re-validation / Automatic cleanup / Use-time feedback / Write queue / Logging, with each group's tuning items folded under Advanced. The screenshot has the **Database** group selected, which controls the automatic-backup switch, interval (hours) and retention (days) — with automatic backup off no new backups are made, and the retention period decides how far back you can restore. For each field's description, the `[Pool]` section of [Configuration](Configuration-EN.md) is the authority.

#### Database Maintenance

![Proxy Pool sub-view: Database Maintenance](../assets/screenshots/pool-db-en.png)

Top to bottom, the screenshot shows: database statistics (Proxies / Valid / Invalid / DB size) with the **Optimize Database** button; the backup history (time, size, the newest tagged Latest), each restorable in one click; and the geo databases at the bottom — the offline databases' availability, data files and modification time, plus the **Update Geo Databases** and **Recompute Geo** actions.

- **Optimize Database** rebuilds the database indexes and compacts the file; writes briefly wait while it runs.
- **Restore** **overwrites the current database with that backup**: the pool stops first and restarts automatically once the restore finishes.
- When the offline geo databases are available, city-level lookups in China use the Chunzhen library (`qqwry.ipdb`) and everything else uses GeoLite2 (`GeoLite2-City.mmdb`); **Update Geo Databases** needs a network download (about 104 MB, taking several minutes), while **Recompute Geo** re-resolves existing records and is enabled only when there are records pending recompute.

### Access Control

![Access Control tab](../assets/screenshots/access-en.png)

The screenshot has three parts: **Users** at the top left lists the outbound authentication accounts (the two shipped in the repo, `k` and `neko`; passwords can be changed and accounts added or removed); to the right is **IP Access** with the **Whitelist** and **Blacklist**, the dropdown below choosing which one wins when a client matches both, and **Save** writing the lists to disk; below is the **Proxy Bypass Whitelist** — matching target addresses connect directly instead of going through an upstream proxy, and wildcards are supported.

- User management edits the `[Users]` section (one `account = password` per line): **when the account table is empty the proxy requires no authentication**. The program's built-in default has no `[Users]` section and requires no authentication; the `config.ini` shipped in the repo comes with factory accounts `k = 123` and `neko = 123456`, so requests without credentials get a 407. Change accounts through the panel's user management; hand-editing the `[Users]` section of `config.ini` is also read in through the configuration hot reload (effective within about a second).
- The whitelist / blacklist files are always read from the `config/` directory; when a client matches both lists, `ip_auth_priority` (`whitelist` allows / `blacklist` blocks) decides.
- For the three lists' file names and matching rules, see [Configuration](Configuration-EN.md).

### Logs

![Logs tab](../assets/screenshots/logs-en.png)

Along the top of the screenshot are two rows of filters: category (All / Main / Proxy / Access / Pool) and level (All / Important / Info / Warning / Error / Critical); on the right you can switch between the live log and browsable historical log files, and use **Auto refresh**, **Follow**, **Export** and **Clear**. Every line in the log list carries a time, level and category.

- The **Access** category holds access statistics grouped by proxy and the per-request detail; see [Logs and Access Records](#logs-and-access-records).
- **The log level and the access log are linked**: successful access lines are INFO, so at WARNING and above the access log keeps only failures and errors; the panel warns you in place when that happens.
- Reviewing historical files, exporting and clearing all act on the log files under `logs/`.

The language toggle sits at the bottom of the sidebar and **changes a server-side setting**: the panel text, API error text and exported file headers all switch with it (the console banner printed by the command-line entry only appears once at startup and is not reprinted).

## Using the Proxy Pool

### When It Starts

The built-in proxy pool **only starts when it is actually going to be used as the proxy source**, determined by `proxy_source_mode` in `[Server]`:

| `proxy_source_mode` | Does the pool start with the service? |
|---|---|
| `pool` (the built-in pool) | Yes |
| `local` (local file) | No |
| `api` (API fetch) | No |

Setting `pool_remote_url` (using an external proxy pool) keeps it off too — that case never touches the in-process pool. Note that the URL is the external pool's **fetch endpoint**, not a management API; details are under [Proxy Config](#proxy-config).

With a local file or an API source, a running pool would only waste resources fetching and validating proxies from the network, so it stays off by default. If you switch the source to Pool in the panel while the pool is not running, it is **brought up automatically**; switching away does not stop it, so a pool that is currently serving proxies is not shut down by mistake — stop it manually from the Proxy Pool tab when you want it stopped.

### Collection Plugins

Drop a fetch plugin into `modules/proxypool/plugins/` and it takes effect after the pool service restarts (the directory is scanned once, at pool service startup); for a plugin already in the list, changed code can be hot-reloaded with **Reload** in the panel under Proxy Pool → Proxy Management, where you can also set a plugin's fetch interval and test address individually. Two conventions bite people most often:

- **A failed fetch must raise an exception.** Returning an empty list counts as "the fetch succeeded, it just found nothing this round" — the error is swallowed, the schedule advances normally, and the symptom is simply that you never collect anything.
- **A plugin's file name (without the extension) is its identity** — configuration, scheduling and provenance records all use that name.

The plugin list also lets you configure a re-validation policy per plugin, including "skip ingest validation and store fetched proxies directly" — suited to proxy sources billed per request whose validity the provider guarantees; such records have no exit IP, anonymity or health score, so it is best to turn re-validation off for them at the same time, otherwise they will still be checked periodically and incur charges. For the full plugin authoring contract see the [proxy pool module documentation](../modules/proxypool/README.md).

### Batch Validation

- On the Proxy Management page you can check the selected proxies for liveness (**Check liveness**); the toolbar also carries three batch actions: **Validate valid**, **Validate invalid** and **Full check**.
- Validation intensity comes in three levels: `liveness` only tests reachability, `identity` additionally fills in identity information, and `full` runs the complete evaluation. Batch validation on the panel can be run as `liveness` / `full` by hand; passing `auto` still follows the strategy (`identity` is not a valid choice for the batch API).
- **Proxies marked invalid by usage feedback are queued as candidates for the next automatic re-validation round**, and a successful re-validation flips them back to valid automatically; if you don't want to wait, **Validate invalid** in Proxy Management re-tests them right away.
- The **Check** button tests the **source list** (for the `local` source, every entry in `ip.txt`); that is a different matter from batch validation inside the pool.

### Import and Export

- **Import**: paste the proxy addresses to import; every imported proxy is **validated one by one first, and only confirmed-working ones are stored**; geolocation is looked up asynchronously after storing.
- **Export**: the export range follows the current filter, and the panel tells you how many records will be exported before it starts.
- **Copy API link**: builds the pool's fetch endpoint URL from the current filter and copies it to the clipboard, so external programs or another ProxyCat instance can fetch proxies on demand.

### Database Backup and Restore

- The Database group in Pool Settings controls automatic backups: the switch, the backup interval (hours) and the retention (days).
- Under Proxy Pool → Database Maintenance you can see the backup history (time, size), and each one can be **restored**: **it overwrites the current database with that backup; the pool stops first and restarts automatically once the restore finishes**.
- To compact the database right away, click **Optimize Database**: it rebuilds the indexes and compacts the file, and writes briefly wait while it runs.

## Logs and Access Records

### The Four Log Files

Logs are routed by purpose into four files under `logs/`, never mixed together, each rotating by size:

| File | Contents |
|---|---|
| `logs/main.log` | Main program: startup, configuration, panel address, shutdown |
| `logs/access.log` | Proxy requests: time, client, upstream proxy, target host, success or failure, duration |
| `logs/proxy.log` | Proxy lifecycle: loading, rotation, validation, retries |
| `logs/error.log` | Everything at ERROR and above from all the categories above — look here first when troubleshooting |

The pool keeps its own log at `modules/proxypool/logs/proxy_pool.log`.

Switches for the log level, per-file size cap and rotation keep-count are in [Configuration](Configuration-EN.md).

### Reading the Access Log

Each access log line looks like this:

```text
2026-09-14 20:03:31 - INFO - [OK] client 127.0.0.1/neko upstream socks5://1.2.3.4:1088 target www.example.com:443 CONNECT 235ms status 200
2026-09-14 20:03:19 - WARNING - [FAIL] client 127.0.0.1/neko upstream socks5://5.6.7.8:3128 target www.baidu.com:443 CONNECT 36080ms status 504 reason Connection Timeout
```

The password inside an upstream proxy address is always written as `***`; plaintext credentials are never logged.

A line reports one of three outcomes, and they mean different things:

| Outcome | Meaning |
|---|---|
| `[OK]` | the request really went through (for an HTTPS tunnel this only counts once data comes back from the upstream — merely writing back a 200 is not enough) |
| `[FAIL]` | the request failed, with the reason at the end of the line |
| `[ABORT]` | the request ended before a success or failure could be concluded (the client disconnected without sending data, neither side of the tunnel ever transferred data, the request was cancelled), and it is excluded from both the success and failure rates |

The `status` field is the HTTP status code written back to the client. Note that it can disagree with the outcome: an `[OK]` line records the status code the upstream returned as-is, so an upstream replying 4xx/5xx is still recorded as `[OK]`; an `[ABORT]` line keeps the status code already written back (200, say), but the outcome is neither success nor failure; while a `[FAIL]` such as a tunnel that was established but the upstream never sent data keeps no status code when the line is written, and the status shows as `-`. So **read the outcome column, not just the status code**.

### Access Statistics and Per-Request Detail

Switching the Logs tab to the **Access** category shows the access statistics table below. It aggregates by **upstream proxy**, and expanding a proxy reveals every host it has accessed:

```text
Exit address                    OK    Fail  Total  Rate   Last seen            Last failure reason
▼ socks5://13.125.44.24:80 [4]  6     0     6      100%   2026-09-14 21:26:33  --
     example.com                1     0     1      100%   2026-09-14 21:26:33  --
     www.baidu.com              2     0     2      100%   2026-09-14 21:26:32  --
```

The aggregation key is **host × upstream proxy**, not the host alone — the same host accessed through different proxies can turn out completely different, and grouping by host alone would flatten the most useful fact ("this proxy cannot reach this site"). Results are persisted to SQLite, so the cumulative figures survive a restart.

Besides the summary there is the **per-request detail**: one row per proxy request, filterable by time / upstream / target / outcome and exportable as CSV / JSON.

Retention for the access statistics and detail (domain statistics kept for 30 days; detail kept for 7 days with a cap of 200000 rows; `0` means no cleanup) is configured in [Configuration](Configuration-EN.md).

## FAQ

Q: Why does my XXX tool still not change proxies after ProxyCat is running?

A: ProxyCat is not a global proxy tool: the XXX tool must support using a proxy and send its traffic to ProxyCat's local listening port for it to go through the proxy pool.

Q: Why is the proxy not rotated when the countdown ends?

A: When an expired exit is replaced depends on the source and the run mode: with an API / pool source in Continuous mode, the background replaces expired exits on lifetime regardless of traffic; a local source and On request mode only handle expired exits while traffic is flowing (an expired exit is removed outright when idle, and the pool refetches to fill up when the next request arrives). That way an idle process never goes online to fetch — fewer resources are wasted, and one deployment stays usable long-term.

Q: When I fetch proxy addresses through getip, why does the first run report None / no usable proxy address?

A: To avoid wasted resources: the getip approach generally means paying for static short-lived IPs, and fetching at startup would burn a lot of money for nothing. Because of that, the default On request mode does not fetch at startup — just send traffic as you normally would, and ProxyCat fetches and uses proxies automatically. (If you switch the mode to Continuous in the panel, fetching is decoupled from traffic: the background fetches on lifetime, so it calls the endpoint shortly after startup.)

Q: I have my own static IP addresses — how do I use them?

A: Write fixed proxy addresses into `config/ip.txt` in the local list format shown under [From Source](#from-source), and set `proxy_source_mode` to `local`; each line is `protocol://[user:password@]host:port`. What `api_proxy_url` expects is "the URL of a fetch endpoint that returns proxy addresses one per line" — putting a single proxy address there makes ProxyCat request it as an endpoint and fetch nothing. If your addresses come from an endpoint, fill in `proxy_username` and `proxy_password` when you need to attach credentials uniformly. (In the panel the two are combined into one **Proxy auth** field, written as `username:password`.)

Q: Why do I run into XXX errors? Why doesn't it work?

A: Start with the [Investigation Manual](Investigation%20Manual-EN.md); if it cannot be fixed, you may ask the author — before asking, please pay ¥50 as a purchase fee for his time. If your question is something Baidu can answer or is covered in the manual, the fee is not refunded; if it turns out to be a tool bug or a feature suggestion, the fee is refunded in full and you will be added to this project's list of thanks. (Far too many people were asking very simple questions that were already answered in the help, wasting an enormous amount of time, and plenty of them had a very nasty attitude — this is not what I wanted.)

Q: The panel won't open — it returns 401 after the redirect?

A: The panel page itself is token-guarded, so with a token set you must open it with `?token=`. The token in the `config.ini` shipped in this repo is a public default — change it before exposing the panel (the panel has no token field; editing the file hot-reloads in about a second and the old token stops working right away). See [Four Things To Know Before Deploying](#four-things-to-know-before-deploying).

Q: Do I need to restart after changing configuration?

A: Only entries bound when the service starts, such as `port` / `web_port`, need a restart (`web_port` a whole-application restart plus a matching port mapping; `port` just a restart of the proxy service from the panel); every other setting hot-reloads, whether saved from the panel or edited in `config.ini` by hand. For the full boundaries see [Entry Points](#entry-points).

Q: After raising the log level, why have the successful records disappeared from the access log?

A: Successful access lines are INFO, so raising the level to WARNING or above filters them out and the access log keeps only failures and errors; the panel shows a hint in place when you save the level. To keep successful records, set the level back to INFO.
