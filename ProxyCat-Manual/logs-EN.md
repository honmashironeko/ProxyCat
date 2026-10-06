[Back to README](../README-EN.md)

### 2026/10/05 (ProxyCat V3.0.0)

**New Features**

- Credentials for the upstream proxy-fetch endpoint are now managed from the panel: multiple named credential sets (endpoint address + username and password) can be saved and deleted, and the active one switched at any time; switching writes the configuration immediately and takes effect on the running service, so changing API providers no longer means hand-editing `config.ini` (the sets are stored in the `[api_credentials]` section)

- Added the "Proxy Bypass Whitelist": matching target hosts / IPs connect directly from this machine instead of going through the upstream proxy (both HTTP and SOCKS5), with wildcards such as `*.baidu.com` and `192.168.1.*` supported; the list lives in `config/bypass_whitelist.txt` and is editable directly from the panel's Access Control tab

- Logs → Access gained a per-request detail view: every proxy request can be filtered by time range and conditions, paged through, exported as CSV / JSON (CSV carries a BOM, so Windows Excel opens it without mojibake) and cleared, with the records stored in SQLite so they survive a restart; retention days (7 by default), the row cap (200000 by default) and the memory buffer are all configurable, and the hot path writes to memory only with a background flush to the database in batches every 5 seconds — independent of the access statistics aggregated per proxy

- Geolocation now resolves through local offline databases: GeoLite2 (global, ISO codes plus Chinese and English names) and the Chunzhen library (Chinese provinces and cities plus carriers), with no more calls to online geolocation services; the geo databases section under Proxy Pool → Database Maintenance lists the data files and how many records are pending recompute, and offers **Update Geo Databases** (about 104 MB, downloaded only on demand) and **Recompute Geo**; when the databases are unavailable, regions are left empty — there is no fallback to an online lookup

- Bilingual geolocation: Chinese and English names are both stored, the UI language decides which one is shown and the other goes into the tooltip, and sorting by region follows the UI language too; a name with no translation in the current language is flagged as showing the original text, and can be recomputed

- Added a command palette and global keyboard shortcuts: `Ctrl/⌘+K` opens a searchable command palette (jump between views, start and stop the service, refresh exits, batch-validate, import and export, switch theme or language and more); `1–4` switch views, `r` refreshes, `/` focuses search and `?` shows the shortcut list; in tables `↑/↓` move row focus, Space selects and `Shift` extends the selection, and typing in an input always takes precedence

- Progress and cancellation for batch tasks: long jobs such as imports, batch validation and plugin fetches appear under Background tasks showing progress, rate, estimated time left and per-category counts (saved / unusable / unreachable / failed) for the current stage (Checking port reachability / Validating proxies), and a running task can be cancelled in one click (its status then reads Cancelled)

- Added a version check module: it checks once at startup and every 24 hours after that, persisting the check time so a restart within 24 hours does not check again (at most one outbound request per 24 hours); the panel's version API only reads the cached result, so opening the panel never blocks on the network, and a failed check keeps the last successfully fetched version
- The version check now reads the version from the GitHub repository's release history: it requests the official `releases.atom`, the gh-proxy mirror and the official API concurrently and takes the first usable version number, so a blocked or timing-out address does not slow the rest down; when all three fail it returns after roughly 8 seconds. The new `version_check_url` option uses the three built-ins when empty and makes that address the only source when set (point it at a mirror of your own); on save it is validated as a full http/https URL

- Added a promo / announcement slot to the panel: drop a JSON file (title, body, image, link, dwell time) into `config/ads/` and it is shown; users can dismiss it in one click and reopen it from the sidebar (the dismissal is not persisted, so it is back after a restart)

**UI and Interaction**

- Added a Check for updates now button next to the version chip in the sidebar: clicking it forces an immediate check (ignoring the 24-hour limit), the button spins and is disabled while it runs, and the result appears in place — Up to date, or New version: xxx with the version linking to the GitHub Releases page, or the specific reason on failure (hover for the full text). Previously there was no feedback at all unless the check succeeded

- The panel moved from a horizontal tab strip to a fixed left sidebar with four sections: Proxy Config, Proxy Pool, Access Control and Logs; the Proxy Pool section is split into the three sub-views Proxy Management / Pool Settings / Database Maintenance; the service and pool run states sit permanently in the sidebar, and the Chinese and English wording was filled in throughout

- The Proxy Config page was rearranged into grouped cards (Source, Listening ports, Exit rotation, Availability checks, Performance, Logging and records, Advanced), each option showing a short title plus a one-line hint and an ⓘ with the full text; numeric inputs take their lower and upper bounds from the server-side schema; proxy authentication was merged into a single "username:password" field, and entering a username without a colon now warns explicitly that this will not enable authentication

- Option presentation and the save bar: units moved to the right of the input box and titles were shortened to the short name; the save bar is greyed out while nothing has changed, gained **Discard changes**, shows a **Saved** receipt in the clean state and casts a shadow when pinned to the bottom; switching the language re-renders the form immediately

- Added a dark theme: light / dark, following the system's dark preference until switched by hand and remembering the choice after that; native dropdowns and scrollbars render with the theme (`color-scheme`), so dark-theme users no longer get a white flash when the page opens; the palette was redone against contrast standards, and in dark mode body text, buttons and coloured text all pass

- Logs and Access improvements: category tabs carry count badges, hovering the end of a line copies it, and the search box can be cleared; status codes in the access detail are coloured by 2xx / 3xx / 4xx / 5xx; the row detail drawer is divided into Connection / Quality / Timestamps and localises the timestamps; the table's right-click menu can copy an address or copy it as a curl command

- Dead-proxy visibility: invalid rows are dimmed throughout and carry an **Invalid** badge with a reason hint; the invalid card in the pool overview is coloured by the actual count (zero invalid proxies no longer display in red)

- When an exit's IP differs from the entry point (the proxy relays through another hop in between), the list shows a subtle warning-coloured hint; the various legal spellings of an IPv6 address are no longer mistaken for different addresses

- Table column widths can be dragged and are remembered (kept the next time the page opens), with a **Reset columns** button alongside

- Import and export interaction: the export dialog has three format tabs (txt / json / csv) and shows how many records will be exported; the import box counts entries live

- Controls and styling unified: dangerous actions such as delete and batch operations now use a custom confirmation dialog (replacing the browser's native `confirm`), and Esc closes the topmost open overlay first; select dropdowns have a custom arrow, their popups are no longer black-on-white in dark mode, and toggle switches are larger; toasts gained icons and can be clicked to dismiss; the version number in the page header now takes the real value from the API

- Removed Bootstrap and external JS scripts from the panel in favour of hand-written styles and a system font stack (with the Chinese fallbacks filled in)

- With the pool not running the panel no longer polls the pool APIs for nothing, and a failed load shows a message instead of looking like "no data"

- Internationalisation completed: the Pool Settings form re-renders immediately on a language switch, configuration validation errors come back in the UI language, option descriptions are bilingual (inside `config.ini` they stay Chinese), and dynamic content re-renders with the language

**Proxy Pool**

- The built-in pool went from a separately launched program shipped alongside to a subsystem inside the ProxyCat process: it no longer occupies port 8000 and the panel no longer spawns it as a child process; it shares the panel's web port, and the way in is the panel's Proxy Pool tab rather than the pool's own page; the pool's fetch and management APIs all hang off `/api/pool/*` under the panel port (still token-guarded). Pool configuration moved from `modules/proxypool/config.yaml` into the `[Pool]` section of `config/config.ini`, with old settings migrated automatically on first start (the old file is renamed `config.yaml.migrated`) — the panel and the config file now edit the same settings

- Upstream exit pool: instead of using one upstream proxy at a time, several exits are kept up at once (10 by default) and requests are spread across them by live load, each exit carrying its own concurrency quota and connection cap; every exit has its own lifetime — the two rules, `interval` in seconds (60 by default) and `request_interval` counted in assignments, are independent and both apply, and whichever comes first wins; a failing exit is retired by the failure share over its last 10 results rather than by a consecutive-failure count — a streak is wiped out by one chance success, whereas the share truthfully reflects how badly it has been failing recently; dead exits are replaced one by one, never as a wholesale swap, with standby candidates validated concurrently and used to fill the slots one at a time; with no usable exit at all, requests queue (30 seconds by default) before getting a 503; the panel's status cards list every exit with its remaining lifetime, and the old "manual switch" button became **Refresh exits**. The run mode is grouped by source — `local` uses `cycle` / `loadbalance` (which exit to pick), while `api` / `pool` use `continuous` (keep rotating) / `request` (rotate on demand, the shipped value — expired exits are removed outright while idle and the pool drains); switching sources normalises the mode to that group's default

- Elastic expansion of the exit pool: when listening-side concurrency hits the current capacity the exit count doubles on the spot and is filled in one go (capped at 2×), while the background adds exits one step at a time as a fallback, based on "the share of exits pinned at their per-exit quota"; after expansion stops, the surplus exits serve out their own lifetimes before being retired one by one, so nothing is dropped the moment it was fetched

- The pool's management console merged into the panel: the proxy list can be filtered and sorted by protocol, region, health score and anonymity, with batch validation / batch delete on a selection, favourites and import / export; the plugin list supports enable / disable, fetch-interval tuning, running at once and hot reload; the database can be backed up, restored and optimised, with long tasks appearing under Background tasks where they can be cancelled

- Pool proxies gained a quality profile: a 0-100 health score (delay 25%, success rate 25%, stability 15%, uptime 15%, anonymity 10% and longevity 10%; the success dimension uses the Wilson lower bound, so a new proxy is not dragged far down by one or two chance failures), an anonymity tier (Transparent / Anonymous / Elite), average delay and variance, and HTTPS-support probing; the health score drives sorting, filtering and automatic cleanup, the fetch API accepts `min_health_score` to return high-scoring proxies only, and the panel shows valid / invalid counts plus a hint when anonymity is a fallback value

- A usage-feedback loop: a bad exit found during real forwarding is confirmed by an independent probe and then reported back to the pool; once consecutive failures reach `use_feedback.invalid_threshold` (3 by default) the proxy is marked invalid and queued for the next automatic revalidation round, and a successful re-test restores it automatically; the feedback touches only "availability" and the check counter, never the health score — validation cannot tell "the proxy is broken" apart from "our own network hiccuped", and a chance failure should not irreversibly delete a good proxy

- Improved exit-IP and anonymity probing: a gateway-style exit is probed once for its real egress IP before being recorded (API source only, and each address costs one extra unit of proxied traffic); anonymity checking can be turned off (`check_anonymity`); this host's egress IP can be filled in by hand to remove that automatic outbound request entirely (`host_public_ip`, one entry per family on a dual-stack host); and plaintext echo endpoints the proxies can reach can be added (`plain_identity_echo_apis`), helping when anonymity keeps being judged as the fallback tier

- Per-plugin validation policy: each plugin can be set individually to take part in automatic revalidation or not, its revalidation interval, and whether to skip validation at ingest (meant for proxy sources billed per request whose validity the provider guarantees; skipped records have no exit IP, anonymity, delay or health score)

- Per-plugin test address: each plugin can specify its own address for liveness checks; leaving it empty inherits the global `test_url`, and the panel shows directly whether the global or a custom address is in use

- The pool's fetch API `/random` gained filters for health score, anonymity, favourite, HTTPS support and IP; the old `/best` "best recommendation" endpoint was removed and its capability folded into `/random`

- Batch validation tiers: **Check liveness** runs only the lightweight reachability test, **Full re-check** runs the complete quality evaluation; when no echo evidence is available for anonymity it falls back to Transparent and is explicitly marked as inferred, and selecting those rows allows a re-test

- Simplified import: the two switches "validate after import" and "look up geolocation automatically" were dropped; imported proxies are always validated one by one first and only confirmed-working ones are stored, keeping unvalidated records out of the pool; geolocation is looked up asynchronously after storing

- Scraper plugins slimmed down: six outdated plugins were removed — `代理获取1`, OpenProxy, ProxyScrape, PubProxy, Spys.me and free_proxy_list — leaving only GeoNode and GitHub

- Plugin scheduling fixes: a failed run still advances the next run time (previously a permanently failing plugin was picked up and retried by the scheduler round after round); a failed reload now removes the half-initialised module from `sys.modules`; plugin modules are registered under a `plugin.` prefix, so a plugin can no longer shadow a standard-library or main-program module of the same name

- Pool-source switching improved: no longer limited by the switch cooldown, and the redundant TCP pre-check is skipped (pool proxies have already been validated); a manual switch from the panel shows "Switching…" (after the new status cards arrived the button was renamed **Refresh exits**)

**Fixes**

- Fixed automatic revalidation failing for every single proxy: `auto_revalidator` used a constant it never imported, the `NameError` was swallowed by an `except` into a warning, and validation results never made it back into the pool; the same class of bug (`logger` undefined inside an exception branch) was fixed alongside it

- Fixed host egress-IP detection: IPv4 and IPv6 are each probed once (previously whichever endpoint answered first won, so the cached address family drifted and a transparent proxy was misjudged as anonymous); `validator.host_public_ip` now accepts up to two entries as well

- Fixed domain statistics: the switch, flush interval and retention now apply immediately after saving; clearing invalidates the batch currently being flushed, so it no longer "grows back after a clear"; retention cleanup no longer deletes combinations that are still being accessed

- Fixed tunnel failure attribution: direct (bypass-list) requests are no longer recorded as proxy failures; added an "upstream closed the connection without sending any data" abort reason, no longer lumped together with a client disconnecting deliberately

- Fixed ghost keys in the dedup cache: cleaning up invalid proxies now removes them from the dedup cache too, fixing "the plugin keeps scraping but dedup leaves 0 new proxies"; a failed batch write now degrades to per-row writes, discarding only the rows that really cannot be written (each named in the log), with an accurate count of what was discarded

- Database restore now writes to a temporary file and swaps it in atomically, clearing the old database's WAL sidecar files — a restore that fails halfway no longer leaves half a database behind, and a stale WAL can no longer bring deleted rows back

- Anonymity and HTTPS-support detection now verify the certificate: an untrusted third-party proxy can no longer forge echo responses to paint itself as elite / HTTPS-capable (both of these feed straight into the health score)

- Validation now confirms the test address is reachable directly first: with this machine offline or the target site blocked, a connection failure is no longer charged to the proxy

- Two pool hot-reload fixes: when the `[Pool]` section cannot be read the current configuration is kept and the next round retries, instead of silently applying a whole set of factory defaults; the pool log's file path, per-file size and keep-count now take effect immediately after a change (previously the handler was hung once and never re-hung, making the settings dead)

- Pool stop / restart protection: starting is refused while the previous stop has not finished (its thread is still alive), so two pool instances can no longer share one database; the exit path now decides on "is the thread alive" and retries after a failed stop, so the last batch of data is not lost

- API error feedback: invalid parameters now return 400 with a readable reason (most used to come back as a 500), and a full write queue returns 503 `queue_full`

- Static assets now use conditional caching: after changing CSS / JS a plain page refresh picks it up, no more `Ctrl+F5`

- `Ctrl+C` and termination signals now clean up connections and background threads and drain the logs and write queue before exiting, consistently across platforms (SIGINT only on Windows, with SIGTERM also registered elsewhere), with a hard 3-second timeout as a backstop

- Copy buttons gained a fallback: when the Clipboard API is unavailable they use a `textarea` + `execCommand`, so copying still works over plain HTTP (opening the panel by IP:port) and in older browsers

**Performance and Stability**

- Production startup now uses waitress instead of Flask's built-in development server (falling back automatically when it is not installed), for better concurrency and stability

- Listening connections are accepted by a dedicated thread: measured on Windows, the accept rate rose from about 825 to over 3000 connections per second, and a client disconnecting before accept completes no longer invalidates the listening socket

- Log file writes moved to an asynchronous queue (writing each line synchronously ate 4%-10% of short-request throughput; the in-memory ring and the console stay synchronous, so the panel's liveness is unchanged); frequent failure warnings are folded within a window and counted, so one sentence no longer floods the log under high concurrency (folding happens at the log layer only — an exit's failure accounting and scheduling are unaffected)

- The pool's write path was reworked: added an asynchronous SQLite connection pool (WAL, separate readers and writers) and an in-memory dedup cache for proxies (dedup lookups dropped from a full-table scan to O(1), and the defect of deduplicating by IP alone rather than ip:port was fixed); scraping now uses aiohttp; validation results and access records use "memory buffer + background batch flush", instead of every row fighting over SQLite

- Faster validation: a separate connection timeout (2 seconds by default, so black-hole proxies fail faster), a wall-clock budget for a whole validation batch (8 seconds by default), per-probe timeouts adapted to this machine's direct-connection latency, default concurrency raised to 400, and detection endpoints pre-screened by direct connection and raced by latency (usable endpoints are no longer truncated at 3)

- Stability fixes: transaction rollback in the connection pool now covers task cancellation (`CancelledError`), so a half-finished transaction is not committed by the next operation; draining the write queue has a 15-second cap and no longer drags the pool's stop past the host's timeout; chunked request-body reads have a timeout; and a client disconnecting while a success response is being written is no longer recorded as a proxy failure, nor does the client get two responses

- Scraping and validation sessions now carry a browser User-Agent, so public proxy-list sites (mostly behind Cloudflare) no longer reply 403 outright; a timeout caused by this machine's connection-pool queueing is no longer misread as "the proxy is slow", and queue congestion is logged (folded within a window)

- Windows event-loop shutdown noise suppressed: the spurious "after close complete" errors produced by a peer RST no longer flood error.log

**Deployment and Configuration**

- Configuration reworked: `config.ini` grew from 23 keys to 93 across four sections (`[Server]` / `[Users]` / `[api_credentials]` / `[Pool]`); the panel presents all of it grouped by purpose with tuning parameters collected under Advanced; configuration files from older versions can be used as they are

- Proxy validity checking split into two independent switches — "check at startup" and "check on use" — which can be turned off separately; the old `check_proxies` key is still honoured as a compatibility fallback for the startup check

- Docker deployment improvements: a slim base image running as a non-root user, with PUID / PGID aligned to the owner of the host-mounted directories (when the owner does not match, the pool cannot create its database and the panel cannot save configuration); the health check probes the actual `web_port` from `config.ini` (no more false unhealthy after a port change); a `stop_grace_period` of 60 seconds lets the application finish draining its write queue and flush threads before exiting; tzdata is installed so the `TZ` timezone setting really takes effect; and the build no longer forces a China-based pip mirror

- Deployment surface reduced: the default panel port moved from 5000 to 5001, the proxy pool no longer takes a second port, and a container exposes only 1080 (proxy listening) and 5001 (panel)

- Configuration read/write path: in web-panel mode a hand-edited `config.ini` is hot-reloaded by the second, so no restart is needed; `config.ini` and the three list files are written atomically (temporary file, then replace), so a reader never sees a half-written file

- Deprecated configuration keys are cleaned up automatically: at startup and on save, keys with no remaining consumer are removed — `check_proxies`, `getip_url`, `pool_autostart`, `pool_port`, `pool_proxy_url`, `pool_web_url` and `pool_proxy_count` in `[Server]`, as well as `validator.max_ip_retries`, `geoip.*` and `plugins.auto_validate_on_fetch` and the like in `[Pool]`

- Shipped defaults adjusted: run mode `request` (On request), exit lifetime 60 seconds, exit pool capacity 10, per-exit concurrency unlimited by default, validation concurrency 400, simultaneous-request cap 3000, 30 seconds of queueing when no exit is available, and lower check cooldowns and cache lifetimes; the proxy source is still `pool` out of the box

- The panel no longer shows parameters derived from other settings (connection-pool ceiling, idle recycling, max clients and the like; values raised in older configuration files still take effect for compatibility); newly added parameters — domain statistics, access records, log size / keep-count, tunnel timeout, use-time feedback and so on — are all written into `config.ini` with explanations, and the panel's option descriptions come from the same source as the `config.ini` comments

- The shipped `config.ini` has the maintainer's personal proxy API address and saved credentials cleared (`api_proxy_url`, `credential_sets` and `active_credential` left empty), so the released configuration no longer carries private keys

- Exported CSV carries a UTF-8 BOM, so Windows Excel opens it without mojibake; Windows console encoding issues no longer crash the program; configuration reading tolerates a BOM and falls back to the local encoding

- Added `API.md` in the repository root (2009 lines): a complete API reference for the panel's `/api/*` and the pool's `/api/pool/*` — parameters, response examples and error codes — for external programs to integrate against directly

### 2026/09/14

- Removed `[Pool] enabled`; the proxy pool now starts on demand: it comes up with the service **only when the proxy source is the pool and no remote pool address is configured**, so pulling proxies from a local file or an API no longer spends resources scraping and validating for nothing. Switching the source to the pool at runtime starts it automatically (otherwise you would get "pool mode with no pool"); switching back does not stop it, so a pool that is currently serving proxies is never shut down by mistake. The old switch's description said that turning it off made the pool source unselectable, but the code never had any such restriction; and since it only affected the next start, turning it off in the panel did nothing to the running pool — which made it look as though the switch had no effect. The key is cleared from older configuration files automatically on first start
- Fixed plaintext HTTP forwarding (non-CONNECT), which had never worked: the `httpx` `socks` extra was missing from the dependencies, so with a socks5 upstream every request returned 502 and nothing was written to the logs
- Fixed how a forwarded request body is detected: the client connection used to be treated as a body stream unconditionally, so a GET with no body left proxy and client waiting on each other until the read timed out; the read length now comes from `Content-Length` / `Transfer-Encoding`, and chunked bodies are de-chunked before being forwarded
- Fixed the CLI startup batch check crashing the moment it found a valid proxy: `ProxyCat.py` was missing the `from itertools import cycle` import
- Reworked logging: output is routed by purpose into `logs/main.log`, `logs/access.log`, `logs/proxy.log` and `logs/error.log`, each rotating on size (everything used to be mixed into `proxycat.log`, which had no rotation)
- Added an access log: every proxy request records the time, the client (IP and authenticated account), the upstream proxy used, the target host, success or failure, the duration and the failure reason; upstream proxy passwords are masked as `***`
- Added access statistics: success and failure counts, first and last access times and the latest failure reason are accumulated per "host × upstream proxy" and persisted to SQLite, so the history is still queryable after a restart
- The statistics table aggregates by upstream proxy, and expanding a proxy shows the hosts it visited; the table now lives in the Access category of the Logs page instead of a separate statistics panel
- Added category tabs, browsing of rotated historical log files, an auto-refresh pause toggle and the domain statistics table to the Logs page
- Fixed the "Important" filter always coming back empty (IMPORTANT was equality-matched as if it were a log level name)
- Fixed the log panel showing only the oldest 100 entries, hiding new logs
- Fixed a panel injection risk caused by log messages not being escaped
- Fixed dead proxies never being replaced: when an upstream accepted CONNECT and then neither sent data nor reported an error (playing dead, or reading the client's data and disconnecting outright), the old implementation never saw a failure signal — and with nothing triggering proxy failure handling, the health check never ran, so that proxy stayed in rotation and kept being picked, showing up as "every request stalls on the same bad proxy". The check now reads "the tunnel is established, the client has sent data, and the upstream has not returned a single byte": on timeout the tunnel is closed at once and the failure is reported
- Added `[Server] tunnel_idle_timeout` (default 10 seconds): once a tunnel is established and the client has sent data, this is how long the upstream may go without sending anything back before the tunnel is declared dead. `0` disables the timeout
- Fixed the success criterion for tunnel requests (CONNECT / SOCKS5): previously writing back `200 Connection Established` counted as success, and since upstreams that accept CONNECT but never send data are common, this produced the contradiction of "the log says success while curl reports SSL/TLS handshake failed". Success now requires data actually coming back to the client; otherwise the result is failure or aborted depending on whether the client sent any data
- Added an `[ABORT]` outcome to the access log: a client that connects, sends nothing and disconnects (liveness probes, port scans) counts as neither success nor failure, and is excluded from both the success and failure rates
- Fixed log level badges being squeezed until the text was clipped in a narrow window (`min-width: 0` removed the flex item's protection against shrinking below its content)
- Fixed the Logs tab rendering outside its card container (a stray `</div>` at the end of the Access Control tab closed `.tab-wrap` early)
- Fixed log files developing NUL holes after the logs were cleared (the file is now truncated through the handler's own stream)
- Fixed `[Server] log_level` being a dead setting: it could be validated and saved but had no effect at runtime; it now really controls log output and takes effect immediately when saved from the panel

### 2025/03/23

- Fixed a bug that made load balancing mode unusable
- Fixed SOCKS5 connection errors
- Fixed rotation not triggering normally under the HTTP and SOCKS5 listeners, where an error at the target site looked exactly like a dead proxy address
- Made proxy validation a configurable check: with it off no validity check runs, so special cases no longer cause constant rotation
- Fixed concurrency causing mass replacements and warnings; the operation is now locked to keep it atomic
- Fixed a large number of small logic errors and wording mistakes
- Proxy rotation now triggers on: the time interval elapsing, a proxy going dead (automatic switch), a manual switch from the Web panel, or automatic fetching on the first request in API mode

### 2025/03/17

- Fixed faulty logic that rotated the proxy when the target site itself was erroring
- Changed how connections are closed
- Improved the performance of the listening server
- Fixed several bugs

### 2025/03/14

- Fixed the `_last_used` error and corrected how connections are closed
- Fixed rotation logic failing when reading local proxies
- Setting the rotation interval to 0 now switches IP on every request

### 2025/03/03

- Polished the Web management interface
- Fixed a large number of bugs
- Added more helper scripts

### 2025/02/21

- Added the Web management interface

- Added multi-user mode

- Major overhaul of the code structure

- `config.ini` and related files now update dynamically without a restart

- Added control over the log display level
- Added logging of connecting clients, including their IP and the account and password used
- And a pile of other changes besides — this release was so big that I have honestly forgotten some of them

### 2025/02/06

- Docker now installs dependencies from a China-based package mirror
- Added an upfront notice in getip mode: you are in API mode, and a proxy address will be fetched automatically when a request comes in
- Reworked whitelisting to add entries automatically based on the request result

### 2025/01/14

- Added an automatic whitelisting mechanism for getip mode.
- Proxy addresses with a username and password are now supported for local reads, getip fetches and validity checks.
- Tidied up the code structure: merged some code and removed some leftovers.

### 2025/01/07

- Introduced a connection pool to improve performance.
- Improved some error handling and logging.
- Optimised the proxy rotation mechanism.

### 2025/01/03

- Centralised the configuration parameters in the config file for easier maintenance.
- Fixed several known bugs and improved stability and concurrency.

### 2025/01/02

- Reworked the software structure to be cleaner and easier to use.
- Added blacklist/whitelist-based authentication.
- In GetIP mode, a proxy is fetched only after the first request arrives, so a plain start no longer wastes money.
- Changed how the language is configured: no more separate builds — it now comes from a parameter in `config.ini`.
- Updated the configuration info panel so the address can be copied and used directly even with no username or password set.
- Added Docker deployment.

### **2024/10/23**

- Reworked the code structure, splitting parts of the code into separate files.
- If the proxy server suddenly goes dead while traffic is flowing, a new one is requested and swapped in automatically, and the rotation timer is reset.

### 2024/09/29

- Removed the rarely used single-cycle mode in favour of a custom mode, letting the rotation logic be tailored to your needs.
- Made proxy validity checks asynchronous for speed.
- Dropped SOCKS4 proxy support, which caused the most problems.
- Beautified the logging system.
- Improved the exception-handling logic.
- Added validation of the proxy address format.

### 2024/09/10

- Improved concurrency: the next request can be issued before a response has been received, raising throughput.
- Added load balancing mode, which sends requests to random proxy addresses concurrently to improve throughput.
- Made the proxy validity check asynchronous for efficiency.

### 2024/09/09

- Added an option to validate the proxy addresses in `ip.txt` on first start and use only the valid ones.
- Downgraded some functions to support older Python versions.

### 2024/09/03

- Added a local SOCKS5 listener to accommodate more software.
- Swapped out some functions to support older Python versions.
- Beautified the console output.

### 2024/08/31

- Major restructuring of the project.
- Beautified the output, which now keeps showing the time until the next proxy rotation.
- `Ctrl+C` now stops the program.
- Moved heavily to asynchronous requests, raising concurrency: measured at **1000** concurrent connections with **5000** packets in total, about **50** packets were lost — roughly **99%** stable — while **500** concurrent connections lost none.
- Dropped runtime command-line parameters in favour of reading a local `ini` config file, which is far easier to use.
- Added local no-authentication mode, accommodating more software's proxy setups.
- Added a version check that reports version information automatically.
- Added identity authentication for proxy addresses, local reads only; most APIs need whitelisting anyway, so the same was not provided for them.
- Added an option to refresh via `getip` only when a new request arrives, reducing IP consumption.
- Added automatic detection of the proxy protocol, to accommodate more providers.
- Added HTTPS and SOCKS4 proxy support; HTTP, HTTPS, SOCKS5 and SOCKS4 are now all covered.
- Replaced `asyncio.timeout()` with `asyncio.wait_for()` for compatibility with older Python versions.

### 2024/08/25

- Blank lines in `ip.txt` are now skipped automatically.
- Replaced `httpx` with a concurrency pool for better performance.
- Added a buffer dictionary to cut latency for repeat requests to the same site.
- The change-IP-per-request logic now picks a proxy at random.
- Used more efficient structures and algorithms to optimise request handling.

### 2024/08/24

- Adopted an asynchronous design to raise concurrency and reduce timeouts.
- Wrapped duplicated code for reuse.

### 2024/08/23

- Changed the concurrency logic.
- Added identity authentication.
- Added an IP retrieval API for permanent IP changes.
- Added change-IP-on-every-request.
