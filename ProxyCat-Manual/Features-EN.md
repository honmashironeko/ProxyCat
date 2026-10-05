# ProxyCat Features

> Documentation: [Back to README](../README-EN.md) · [Configuration](Configuration-EN.md) · [Operation Manual](Operation%20Manual-EN.md) · [Investigation Manual](Investigation%20Manual-EN.md) · [Changelog](logs-EN.md)

## Outbound Proxy Service

- **Dual Protocol Listening**: one port accepts both HTTP and SOCKS5 inbound requests.
- **Triple Upstream Types**: authenticated HTTP / HTTPS / SOCKS5 proxy servers.
- **Two Rotation Modes**: `cycle` works down the list in order (ignoring load — the next entry is
  used only once the previous one is full), `loadbalance` picks the least stressed exit by live load.
- **Three Proxy Sources**: `local` reads a local list, `api` fetches from an endpoint live, `pool`
  uses the built-in proxy pool directly.
- **Many Exits at Once**: several upstream proxies are fetched in one go and used simultaneously;
  requests are spread by each exit's live load by default (`local` with `cycle` picks down the list
  in order, ignoring load). An exit that fails is dropped from rotation and replaced automatically —
  so an upstream that rate-limits per exit IP scales concurrency with the number of exits (see
  [Upstream Exits and Concurrency](#upstream-exits-and-concurrency)).
- **Access Control**: client IP whitelist / blacklist, with `ip_auth_priority` deciding whether to
  admit or block a client that matches both; plus a bypass list whose matching targets connect
  directly, bypassing the upstream proxy entirely.
- **Outbound Authentication**: username / password authentication, disabled when the account table
  is empty.

Switching the source uses the source switcher at the top of the Proxy Config page; changing the
mode and lifetime and adjusting exit capacity happen in the Exit rotation group — saving applies
immediately:

![Exit rotation](../assets/screenshots/config-exits-en.png)

The screenshot above shows the Exit rotation group with the Pool source selected: the rotation mode,
exit lifetime (two independent rules, by time and by request count), exits kept in use, and how long
a request queues when no exit is available.

## Built-in Proxy Pool

- **Plugin-based Collection**: scrapers live in `modules/proxypool/plugins/` and are scanned and
  loaded when the pool service starts; a brand-new file requires a pool service restart, while a
  plugin already in the list can be hot-reloaded after edits by clicking Reload in the panel.
- **Verify Before Storing**: a port pre-screen drops addresses with nothing listening; surviving
  candidates then get full validation, and only confirmed-working proxies are written.
- **Three Validation Intensities**: `liveness` checks reachability only, `identity` also fills in
  identity data, `full` does a complete evaluation. Automatic revalidation picks among the three by
  strategy; batch validation on the panel can be run as `liveness` / `full`, and `auto` still
  follows the strategy (`identity` is not an option for the batch API).
- **Health Scoring**: a 0-100 score combining delay 25%, success rate 25%, stability 15%, uptime 15%,
  anonymity 10% and longevity 10%; the success dimension uses the Wilson lower bound, so it shrinks
  toward the low end when samples are few.
- **Offline Geolocation**: a local offline database returns both Chinese and English region names,
  with no external queries.
- **Auto Revalidation & Cleanup**: periodic re-testing, plus cleanup by health score, consecutive
  failures and how long invalid entries are retained.
- **Usage Feedback**: outcomes of real requests during runtime flow back into the pool, and a proxy
  is marked invalid once consecutive failures hit the threshold (see
  [How Usage Feedback Works](#how-usage-feedback-works)).

For when the pool starts and how it operates, see [Proxy Pool Mechanics](#proxy-pool-mechanics)
below; the complete plugin authoring contract is in
[modules/proxypool/README-EN.md](../modules/proxypool/README-EN.md).

## Panel and Operations

- **Web Management Panel**: status overview, configuration editing, proxy list, list management and
  service start/stop all on one screen; settings are grouped by purpose, with tuning parameters kept
  in a separate Advanced group rather than mixed onto the same screen as everyday switches.
- **Log Center**: four categories by purpose (access / proxy / main / pool), with level and keyword
  filtering, browsing of rotated historical files, export and clearing. Note that the log level and
  the access log are linked: successful access lines are INFO, so once the level is raised to
  WARNING or above the access log keeps only failures and errors — the panel warns you in place when
  that happens.
- **Access Records**: every proxy request recorded individually, filterable by time / upstream /
  target / outcome and exportable as CSV / JSON.
- **Domain Statistics**: success and failure counts accumulated per "target host × upstream proxy",
  with drill-down.
- **Bilingual UI**: the panel switches between Chinese and English; the language is a server-side
  setting, so the whole UI's text switches together.
- **Credential Management**: credentials for the upstream proxy-fetch endpoint can be stored as
  multiple sets and switched with one click.
- **Containerized Deployment**: one-command Docker deployment, with a built-in health check that
  probes the actual panel port.
- **Version Check**: compares against the latest release once at startup and then every 24 hours;
  the result is persisted, so restarting within 24 hours neither re-checks nor makes opening the
  panel wait on the network.

A tab-by-tab walkthrough of the panel's four tabs (Proxy Config / Proxy Pool / Access Control /
Logs), with screenshots, is in the [Operation Manual](Operation%20Manual-EN.md).

### Logs and Access Records

Logs are routed by purpose into four files under `logs/`, never mixed, each rotating on size:

| File | Contents |
|---|---|
| `logs/main.log` | Main program: startup, configuration, panel address, shutdown |
| `logs/access.log` | Proxy requests: time, client, upstream proxy, target host, outcome, duration |
| `logs/proxy.log` | Proxy lifecycle: loading, rotation, validation, retries |
| `logs/error.log` | Everything at ERROR and above across the categories — look here first when troubleshooting |

Each line of the access log ends in one of three outcomes, with distinct meanings:

| Outcome | Meaning |
|---|---|
| `[OK]` | The request really went through (for an HTTPS tunnel, only once the upstream returns data — writing back 200 alone does not count) |
| `[FAIL]` | The request failed; the reason is written at the end of the line |
| `[ABORT]` | The request ended before a success or failure could be decided (the client disconnected without sending data, neither side of a tunnel ever sent bytes, the request was cancelled); excluded from both the success and failure rates |

The status code at the end of the line is what was written back to the client, and it may disagree
with the outcome: an `[OK]` line records the upstream's own status code, so an upstream 4xx/5xx
still logs as `[OK]`; an `[ABORT]` line keeps whatever status was already written back (200, say)
even though the outcome counts as neither success nor failure; and a `[FAIL]` such as a tunnel that
was established but whose upstream never sent anything keeps no status code at all — it shows as
`-`. So **read the outcome column, not just the status code**.
Passwords in upstream proxy addresses are always masked as `***` before being written, so no
plaintext credentials are recorded. The proxy pool's own logs still go to
`modules/proxypool/logs/proxy_pool.log`.

Access statistics aggregate by **upstream proxy**, and expanding a proxy shows every host that proxy
visited. The aggregation key is "host × upstream proxy" rather than host alone — the same host can
behave completely differently through different proxies, and keying on the host alone would flatten
away the most useful fact, "this proxy cannot reach this site". The counters are persisted to
SQLite, so the cumulative totals survive a restart.

## Upstream Exits and Concurrency

ProxyCat maintains an **exit pool with a target size**: `exit_count` upstream proxies are kept in
use at all times — not one IP, and not a batch that gets swapped wholesale.

**How the pool is maintained**:

1. One source call is made; the addresses it returns go into a **standby queue** (with its own
   expiry and length cap).
2. Candidates are drawn from standby to enter the roster, **up to 4 probed concurrently per round**
   (not one at a time); those that pass enter the roster in order until it holds `exit_count`. A
   candidate that fails validation is discarded, and one that passes but is not needed this round
   goes back to standby.
3. When an exit is declared dead, **only that one** is replaced; the rest keep serving. Fetching and
   rotation are **request-driven**: only while requests are passing through the exits does the
   background task top up from the source or replace expired exits; a round that makes no progress
   does not spin on a retry — it backs the retry interval off (doubling it, up to 60 seconds) and
   tries again, and it always starts only while traffic is recent. Once traffic stops (after about a
   10-second grace period) nothing more is fetched: expired exits are **removed** rather than
   replaced (`continuous` does not depend on traffic — see the next point), so the pool can drain
   empty — a cold start pays one fetch plus validation on its first request.
4. **Every exit has its own lifetime** (every source, all four run modes): it expires `interval`
   seconds after entering the roster, and **all** expired exits are replaced (not one per interval —
   that would let the unluckiest exit live for `exits × interval`). Exits that entered together
   **expire together**, so the replacement happens in one burst; it is always add-before-drop, and
   when standby cannot supply a replacement the old exit is kept rather than swapped, so the roster
   never develops a gap. `request_interval` is the same lifetime counted in requests (each exit
   counts how many times it was handed out). It and `interval` are **two independent rules that
   both apply**: set both and whichever comes first wins — it is not either/or.

   **When** a replacement happens is decided by the run mode: `continuous` (Continuous) is
   independent of idleness — the background keeps replacing expired exits on their lifetime and
   refilling, holding the pool at `exit_count`; `request` (On request) fetches and rotates
   only when a new task arrives, and with no tasks at all expired exits are **removed outright** so
   the pool empties, until the next request arrives and fetches a fresh fill. The local source's two
   values (`cycle` / `loadbalance`) decide *which exit a request uses*; the timing of rotation is
   request-driven, just like `request` mode — the next entry from the file is swapped in, and when
   the file has no spare entry the exit is renewed in place (otherwise it would sit at
   "0 remaining" forever).

   If the source cannot supply replacements at that moment the pool briefly runs short: requests
   then **queue** (up to `exit_wait_timeout` seconds, below) instead of being rejected on the spot;
   they are served as soon as an exit lands, and only get a 503 once the wait runs out.

How many are fetched is decided by `exit_count`, independent of the source: every fetch
over-fetches **`min(shortfall × 8, 24)`** addresses into standby, and candidates are then drawn from
standby, validated, and used to fill the roster to `exit_count`. Both `api` and `pool` fetch by that
over-fetch figure — and on `api`, any rows beyond it are **truncated and discarded**, never entering
standby — while `local` uses the file itself with `exit_count` as the upper bound. The panel's Proxy
Status area lists every exit (address, in use / cap, **remaining lifetime**), and the gauge at the
top tracks the **soonest expiry**; the CLI prints `Upstream exits: N/target` plus one line per exit
with its own remaining lifetime. When an expiry falls due with no traffic (except in `continuous`
mode) the exit is not replaced: expired exits are dropped from the roster one by one, and only a new
request fetches replacements.

Requests are assigned by **each exit's live in-flight count** by default (not plain round-robin) —
tunnels live for very different durations, so counting requests would skew the load; `local` with
`cycle` picks down the list, ignoring load.

**How failures are counted**: every exit carries a **sliding window** (its last 10 results), and
decisions are read off the failure share in it, not a consecutive-failure count. The window does not
record successes from a "clean" period — until an exit has ever failed, successes do not enter the
window, so its first failure fills the share and sends it behind the healthy exits on the spot; only
once it has a failure on record do successes enter the window and dilute the share:

- **Mostly failing means someone else goes first** (share above half): when requests are assigned it
  queues behind the healthy exits, but it **remains usable** — when everything looks suspect they
  are all used anyway. There is no cooldown: every success is recorded back into the window and
  pushes the share down, and once the share is back below half it returns to the competition on its
  own (while failures still dominate the window, one success is not enough to flip it). **A share
  above half also gets it probed once on its own after a real failure**: if the probe fails it is
  dropped from the roster (its share can be far below 90% at that point, and the window may hold
  fewer than 5 results); if the probe passes it stays.
- **A 90% share with at least 5 results in the window** also retires it from the roster — that is
  the failure window's own retirement threshold, not the only path out of the roster. The gap is
  filled by the background replenisher (source fetches are rate-limited by `switch_cooldown`;
  filling from standby is not). Reading a share rather than a streak is what separates "one hiccup
  that cut several tunnels at once" from "this exit is broken": the former's failures get diluted by
  the successes that follow, while the latter keeps climbing. Conversely, a hiccup that cuts enough
  tunnels to fill the entire window with failures does retire it right away — at that moment it
  really did fail every one of dozens of requests.
- **The last exit in the roster is never retired.** Retiring it means a 503 for everything, and for
  the `local` source the "just retired" memory keeps a replacement out for minutes; leaving it in
  place beats having no exit at all.
- **Accounting is never folded; only the log is.** Within the `proxy_failure_cooldown` window a
  single warning is written per kind of event, noting how many were folded together. Every failure
  still enters the window as it is — folding the accounting would erase the very fact ("this exit
  keeps failing") that decides whether it still gets work.

**How checking works**: `check_proxies_on_use` controls the **validation performed while filling a
slot** — every candidate is really probed (one request) before it enters the roster, rather than
just having its port checked; a vendor address can expire within a minute, so an open port proves
little. It is not a per-request check: an exit that dies while serving is handled by the failure
retirement above.

Starting the service (the `ProxyCat.py` entry or starting it from the panel) also runs a full check
over the current roster (`check_proxies_on_startup`): failing exits are **dropped individually**, and
the gaps are left to replenishment. The check that follows a **proxy-file reload** only happens on
the CLI entry — `ProxyCat.py` notices `ip.txt` was modified externally, reloads it and checks along
the way — whereas saving the local proxy list in the panel only reloads the roster and triggers no
check (`app.py` does not watch `ip.txt` for changes either). The panel's Check button checks the
**source list** (for the `local` source, every entry in `ip.txt`), so exits already retired can
still be re-checked.

**How concurrency adds up**:

```text
requests actually hitting upstream ≈ min(max_concurrent_requests, exits × max_concurrent_per_proxy)
```

- `max_concurrent_per_proxy` defaults to `0` (unlimited), which leaves concurrency governed by
  `max_concurrent_requests` alone — identical to the single-upstream era. When **your upstream
  rate-limits per exit IP**, set it to what one IP can bear (say, 20); the excess queues instead of
  hammering the upstream.
- It counts **active** connections: an HTTP request counts while it is being forwarded, and a
  tunnel counts after establishment only while it is actually relaying data. Idle tunnels (browser
  keep-alive, a frozen client, a half-dead upstream) do not consume quota, so this is an
  **admission** control rather than "the number of upstream connections open at once" — when an
  idle tunnel starts relaying again the active count can briefly sit slightly above the cap,
  truthfully reflecting that many transfers in flight.
- `max_concurrent_requests` is the global semaphore applied to all three request kinds, sized in
  terms of tunnels rather than requests: it is the hard bound on how many tunnels this machine will
  carry at once, and it is what actually applies when the per-exit caps sum to far more than it.

![Performance and concurrency](../assets/screenshots/config-perf-en.png)

The screenshot above shows the panel's Proxy Config → Performance group: the global concurrency cap
and the per-exit concurrency cap. With the per-exit cap at `0` nothing is limited and auto-expansion
will not grow the pool — but an expansion already stretched out is still released as usual.

**How "in use" is counted**: the panel and the CLI report the active figure above — connections
currently serving a request plus tunnels that relayed data recently. An idle but still-open tunnel
is not shown (it still holds an upstream connection and a slot, it is just not moving bytes), so the
number falls back once requests stop without waiting for the peer to close.

**How resources come back**: when a transfer finishes (either end of a tunnel closes, or a response
is fully written) the exit slot is released immediately, not when the connection object is
eventually collected. Tunnels whose **client has vanished** (network drop, NAT timeout, killed
process) are reaped by minute-level TCP keepalive: the OS default is two hours, which would pin an
exit slot for two hours per abandoned tunnel and drain the pool under continuous traffic — now
probing starts after 60 s idle, every 10 s, so dead peers are detected and released by the kernel
within a minute or two. Connections that are alive but idle (keep-alive reuse) answer the probes
normally and are unaffected.

**Connection reuse**: plain HTTP forwarding uses a per-exit HTTP connection pool, and a connection's
idle recycling time is governed by `client_keepalive_expiry`; the client objects caching those
connections are recycled on a separate clock, `client_idle_timeout` (not shown in the panel).
CONNECT and SOCKS5 tunnels cannot reuse connections — once an upstream connection carries a tunnel
it belongs to that tunnel and cannot be handed to another request.

> `client_max_connections` (the per-exit connection cap) and `max_pool_size` (how many clients are
> cached) are no longer shown in the panel: the former is derived as `per-exit concurrency cap × 2`
> (falling back to the global concurrency cap when the per-exit cap is unlimited), the latter is
> taken as `max(value, roster × 2, exits × 4)`. Their values still live in config.ini and still win
> when set higher than the derived figures — you just no longer need to understand them.
> `client_max_keepalive` (keepalive connections per exit) has also been dropped from the panel; it
> defaults to 8 and values above 64 are rejected when saving (a hand-edited ini is not
> re-validated) — the more idle connections there are, the more expensive httpx's whole-pool scan
> gets when handing out a request, and raising it measurably cut throughput to a third.

**Auto-expansion under load (`auto_expand_enabled`, on by default, switchable off in the panel's
Performance group)**: when `max_concurrent_per_proxy` is set, there are two trigger paths:
① **immediate** — when the number of connections currently open on the listening port exceeds
"exits in use × per-exit quota", the exit count is doubled on the spot (up to 2×) and filled in one
go, without waiting for a watermark; ② **watermark fallback** — once 80% of exits reach that quota
for a full second, the background adds exits one step at a time, and a step only counts if it
actually added one. Expansion **only adds exits** (more upstream IPs sharing the load). The roster
tops out at `max(exit_count, min(exit_count × 2, max_concurrent_requests))`: more exits than
concurrent requests is pointless, and above that line no more exits get added — though **relaxing
the per-exit quota is not subject to that line** and still proceeds on its own (see below). Once
the peak passes the expansion is released **in one step**: pool-wide utilisation below half for 30
seconds restores the per-exit quota first, then withdraws the surplus exits; an exit still relaying
data is kept until it finishes its requests.

Growing and releasing look at **two different numbers**: growth asks "is it enough" (how many exits
are pinned at their quota), release asks "how much is in use" (pool-wide utilisation). Judging
release by the former backfires — once the load spreads out, no exit may be pinned any more while
the pool is exactly big enough; dropping one step brings the queue right back and the next tick has
to re-add it, so the exit count never stops floating.

Relaxing the per-exit quota (at most doubled) is a **last resort**: on the watermark path it **must
be earned** — the quota is raised only when this round really did fetch from the source, got an
answer, and still could not obtain a single usable new candidate. Not fetching because the fetch
cooldown had not elapsed, candidates that failed their check, and a fetch that failed outright
(timeout, source error) all mean "no conclusion this round" — the next round tries again. The
immediate path is not gated that way: when the listening side is already overloaded and the roster
is at its ceiling it raises the quota anyway (up to 2×) — adding exits spreads the load over more
IPs, whereas relaxing the quota pushes the same pressure back onto the existing ones, which is
exactly what `max_concurrent_per_proxy` exists to prevent. Conversely, **lowering the exit pool
size** withdraws the surplus exits right away (only those with no requests in flight, regardless of
the water line), while after a released expansion the surplus exits are not discarded immediately —
they are withdrawn one by one **only once their own lifetimes run out**.

The water line is measured against the **configured** quota, not the relaxed one — otherwise
relaxing it would itself depress the water line, the peak would immediately look over, and the pool
would oscillate. With `max_concurrent_per_proxy` at `0` (unlimited) nothing expands, but an existing
expansion is still released: unlimited per-exit concurrency is no reason to keep a stretched-out
pool around.

## Proxy Pool Mechanics

The proxy pool is not a standalone project — it runs inside the ProxyCat process, shares the same
web port as the panel, has no interface of its own, and is managed from the Proxy Pool tab in the
panel.

**Subsystem documentation**: [modules/proxypool/README-EN.md](../modules/proxypool/README-EN.md) — covers
scraper plugin development, validation strategy, anonymity detection, geolocation resolution and
automatic cleanup in depth. Consult it as needed.

> `validator.max_concurrent` ("how many proxies to validate at once" in the pool settings) is the
> resource knob for this subsystem: it also sets this machine's HTTP connection-pool ceiling and
> open-socket budget, since one validation fires a dozen-odd requests at once. Lower it on a
> constrained host or where `ulimit -n` is small. Timeouts caused by local pool queueing during the
> **liveness probe** are ruled "no conclusion this round" and are not charged to the proxy — but if
> the identity and plaintext probes that run **after liveness has passed** time out on queueing
> too, that counts as an unsuccessful probe sample and directly drags down the success-rate
> dimension of the health score.

### When Does It Start

The built-in pool **only starts when it is actually needed as the proxy source**, decided by
`[Server] proxy_source_mode`:

| `proxy_source_mode` | Does the pool start with the service? |
|---|---|
| `pool` (maintained pool) | Yes |
| `local` (local file) | No |
| `api` (API fetch) | No |

It also does not start when `pool_remote_url` is set (an external pool is in use) — in that case
the in-process pool is not used at all.

When proxies come from a local file or an API, a running pool would only burn resources scraping and
validating over the network, so it stays off by default. If you switch the source to Pool in the
panel while the pool is not running, it is **started automatically**; switching away does not stop
it, so a pool that is currently serving proxies is never stopped by mistake — stop it by hand from
the Proxy Pool tab when you want it stopped.

### In-Process vs. External Pool

The **in-process pool** is the default and works out of the box. If you already run another proxy
pool service, point `pool_remote_url` at it and the outbound proxy will use that external pool
instead:

- It is a **fetch endpoint, not a management API**: ProxyCat issues one GET to that address and
  **every line of the response body is a proxy address** (e.g. `http://1.2.3.4:8080`). A 200 with a
  valid format means "use these"; a 404 means "nothing available right now". Point it at another
  ProxyCat instance's `/api/pool/random?format=text&token=...` for a single exit; to **fetch many
  at once**, use `/api/pool/get?status=valid&limit=20&format=text&token=...` (you can also point it
  straight at the built-in pool's `/api/pool/get`, which then goes through the pool's API rather
  than calling in-process).
- It **only takes effect when `proxy_source_mode=pool`**.
- Setting it **stops the in-process pool from auto-starting** (the external pool replaces it).
- **Usage feedback does not apply in external-pool mode** — the pool is not in this process, so
  there is nowhere to report it.

### How Usage Feedback Works

When the outbound proxy finds an exit failing during **real forwarding**, it first charges that
failure to the exit itself. An exit whose failure share is above half is then **probed once on its
own**: if the probe fails it is taken out of rotation (its share can be far below 90% at that point,
and the window may hold fewer than 5 results); if the probe passes it keeps serving. A 90% share
with at least 5 results in the window is retired directly by the failure window instead (both paths
are described in [Upstream Exits and Concurrency](#upstream-exits-and-concurrency)). The probed
exit's result is reported to the pool; after `use_feedback.invalid_threshold` consecutive failures
(3 by default) the pool marks that proxy invalid, and any single success in between resets the
counter.

> Taking an exit out and marking a pool entry invalid are **two different things**: the former only
> changes which exits this process uses right now (refilled within seconds), the latter changes the
> stored availability of that proxy (persistent). The former is fast and cheap, the latter slow and
> heavy.

It **deliberately touches only two fields, availability and the total check count**, and never the
failure count, validation timestamp, probe counters or health score — those are the criteria for
automatic cleanup, and letting runtime hiccups pollute them would delete proxies irreversibly.
Resetting the total check count is exactly what puts the record back into the revalidation
candidates (the revalidator picks up records with a zero check counter regardless of
`only_valid_proxies`). Validation cannot tell "the proxy is broken" apart from "our own network
hiccuped", so the feedback only downgrades gently.

So: **a proxy marked invalid by usage feedback goes into the next automatic revalidation round**,
and a successful re-test flips it back to available. If you do not want to wait, click "Validate
invalid" in the panel's Proxy Management to re-test them immediately.

### Collection Plugins

Drop a plugin file into `modules/proxypool/plugins/` and it takes effect after a pool service
restart (the directory is scanned once, when the pool service starts); a plugin already in the list
can be hot-reloaded after a code change by clicking Reload in the panel's Proxy Pool → Proxy
Management plugin list. Two conventions bite people most often:

- **A failed fetch must raise an exception.** Returning an empty list counts as "the fetch
  succeeded, it just found nothing this round" — the error is swallowed, the schedule advances
  normally, and the symptom is simply that you never collect anything.
- **A plugin's file name (without the extension) is its identity** — configuration, scheduling and
  provenance records all use that name.

The full plugin authoring contract is in
[modules/proxypool/README-EN.md](../modules/proxypool/README-EN.md).

## Outbound Network Requests

ProxyCat is not a silent local process: besides carrying your clients' traffic, it makes a small,
fixed set of connections of its own, and the table below is the complete list of them — what triggers
each one, where it goes, whether it is sent directly from this host or through the upstream proxy, and
how to stop it. Direct connections are listed first.

| Trigger | Destination | Direct or through the upstream proxy | Related configuration | How to disable |
|---|---|---|---|---|
| A background thread starts with either entry point (`app.py`, `ProxyCat.py`) and fetches immediately when 24 hours have passed since the last attempt, when it has never checked, or when the version persisted in its state file differs from the running one; after that it ticks every 600 s and sends at most one request per 24 hours. The 24 hours counts from the last attempt, not the last success — a failed attempt still counts. | `y.shironekosan.cn` — the version announcement page on the author's site, hardcoded; the result is persisted to `logs/version_check.json`. | **Direct** | None — the URL is hardcoded in `modules/version_check.py`. | No switch at all; block the domain at the network layer (hosts file, firewall or DNS). The request uses httpx's default client (`trust_env=True`), so an `HTTP(S)_PROXY` environment variable routes it through that proxy — environment behaviour, not a ProxyCat setting. |
| The pool starts with the plugin enabled and no next run recorded, so it scrapes once immediately; after that the scheduler scans every 60 s and runs the plugin on its own interval (60 min for a new plugin), retrying failures with backoff (2 extra attempts by default, 10 s base delay). The **Fetch** button in the plugin table (`POST /api/pool/plugins/geonode_plugin/run`) triggers a fetch at once. | `proxylist.geonode.com` — the public REST API, paged 500 at a time up to 20 pages (hardcoded). | **Direct** | Enabled state and per-plugin interval live in the pool database (Proxy Pool → Proxy Management); the global defaults under `[Pool]` are `plugins.scan_interval_seconds=60`, `plugins.default_interval_minutes=60`, `plugins.execution_timeout_seconds=300`, `plugins.max_retries_on_failure=2` and `plugins.retry_base_delay_seconds=10.0`. | Disable `geonode_plugin` in Plugin Management (written to the pool database, so it survives restarts), or stop the pool service; the address is hardcoded and redirecting it needs a code change. |
| Same scheduling as the GeoNode plugin: one fetch as soon as the pool loads it, then every 60 min by default; the **Fetch** button (`POST /api/pool/plugins/github_proxy_plugin/run`) triggers it at once. | `raw.githubusercontent.com` — 12 hardcoded public proxy lists (6 http, 5 socks5, 1 https source). | **Direct** | The same `plugins.*` keys; enabled state and interval live in the pool database. | Disable `github_proxy_plugin` in Plugin Management, or stop the pool service; the addresses are hardcoded. |
| Before every validation: each proxy's validation runs the reachability pre-flight (one probe per 300 s cache), the automatic re-validator runs it once at the head of each round, and a `test_url` not covered by the cached results is probed singly on demand. | `test_url` (default `https://www.baidu.com`), `validator.identity_echo_apis`, the plaintext variants derived from them, `validator.plain_identity_echo_apis` (default `http://postman-echo.com/get`) and three hardcoded connectivity checks — `connectivitycheck.platform.hicloud.com`, `cp.cloudflare.com`, `detectportal.firefox.com`; the plaintext variants and the connectivity checks join only with `check_anonymity=true`. | **Direct** | `test_url` (drives `validator.target_url`), `validator.identity_echo_apis`, `validator.plain_identity_echo_apis`, `validator.check_anonymity`. | Not switchable as a whole — it is part of the validation flow. `check_anonymity=false` removes the plaintext group and the three hardcoded probes, but `test_url` and the identity list are still probed directly; point those at addresses you own; emptying `identity_echo_apis` falls back to the built-in defaults (`httpbin.org` / `httpbingo.org`), so it is not an off switch. |
| With `check_anonymity=true` and `validator.host_public_ip` left empty: the validation flow re-requests only once a 1800 s cache has expired, and both success and failure restart the timer. | `validator.ip_check_apis` — nine IP-echo endpoints (`icanhazip.com`, `checkip.amazonaws.com`, `api.ip.sb`, `realip.cc`, `httpbin.org/ip`, `api.ipify.org`, `ipinfo.io`, `ipwho.is`, `www.cloudflare.com/cdn-cgi/trace`); on failure the next endpoint is tried, family by family. | **Direct** | `validator.host_public_ip`, `validator.check_anonymity`, `validator.ip_check_apis`. | Set `host_public_ip` in Pool Settings (comma-separated for dual stack; an invalid value is treated as unset and the lookup continues) — the request is then never made; or `check_anonymity=false`; or empty `ip_check_apis` so there is nothing left to try. |
| ① startup pre-check when the source is `local` and `check_proxies_on_startup=true`; ② per-candidate probe before a standby entry enters the roster when `check_proxies_on_use=true` (all three sources); ③ confirmation probes before a suspected-dead exit is retired or a silent tunnel is declared dead — not gated by either switch; ④ the panel's **Check** button (`GET /api/check_proxies`). Results are also cached in-process for 10 s. | The candidate or in-use SOCKS5 exit's `host:port` (from the local file, the api fetch or the pool), over direct TCP; the CONNECT target is the host of `test_url` (default `www.baidu.com`). No HTTP data is sent — only the SOCKS5 handshake and CONNECT. | **Direct** | `test_url`, `check_proxies_on_startup` (`true`), `check_proxies_on_use` (`true`). | Both switches off plus not clicking Check removes the startup and admission probes, but the confirmation probes still fire whenever an exit fails; point `test_url` at an address you control to choose the CONNECT target; stopping the proxy service stops it all. |
| Every ingest — plugin scrapes and panel imports run the port pre-screen first; with the plugin's `skip_validation` on, this step and the validation are skipped together and the proxies are stored directly. | Each candidate proxy's `host:port` (from the scraped lists or the imported text — wherever those point). | **Direct** | No dedicated switch; a plugin's `skip_validation` (stored in the pool database, editable in the panel) skips both the pre-screen and validation. | Not running the scrapers and not importing anything avoids it; or turn on `skip_validation` for a plugin — at the cost of storing unvalidated proxies. |
| `proxy_source_mode=api` and the exit pool needs stock: an empty roster forces a fetch on the request path; the background top-up loop fetches while there is recent traffic, or in `continuous` mode; the panel's **Refresh exits** button (`/api/switch_proxy`) and peak auto-expansion fetch as well. With the shipped empty `api_proxy_url`, api mode fails with a configuration error before anything is sent. | `api_proxy_url` (`[Server]`, empty by default); the fallback `http://example.com/getip` is used only when the `[Server]` section is missing entirely, file included. | **Direct** | `api_proxy_url` (`[Server]`); `proxy_username` / `proxy_password` are only appended to the fetched addresses and are not used for this request. | Leave `api_proxy_url` empty (api mode then reports a configuration error without networking), or switch `proxy_source_mode` to `local` / `pool`. |
| `proxy_source_mode=pool` with `pool_remote_url` set, whenever the exit pool needs to top up or rotate (short roster, expiry, the request path, the **Refresh exits** button). With the shipped empty `pool_remote_url` nothing is sent — the in-process pool is used instead, which runs the scrapers and validation described in the rows above. | `pool_remote_url` (`[Server]`, empty by default). | **Direct** | `pool_remote_url` (`[Server]`); the request uses httpx with a 10 s timeout and `verify=False`, explicitly ignoring environment proxies (`trust_env=False`). | Clear `pool_remote_url` (falls back to the in-process pool). |
| Manual only: Proxy Pool → Database Maintenance → Update Geo Databases, or `python -m core.infrastructure.geodb` on the command line. Nothing triggers it automatically. | `cdn.jsdelivr.net` — the GeoLite2-City and qqwry.ipdb data files (hardcoded). | **Direct** | None — hardcoded, with no automatic trigger path; the download uses the default `requests` client, so `HTTP(S)_PROXY` environment variables apply. | Not clicking the button means it never runs. Note that Full check (`/api/pool/update-geo/all`) is not a download — it re-validates the pool; Recompute Geo (`/api/pool/geo/recompute`) is offline. |
| Any client request through the local proxy port whose target host matches a pattern in the bypass list; the plaintext HTTP, CONNECT tunnel and SOCKS5 paths all have this branch. | The target host the client asked for (this machine's IP is what its peer sees). | **Direct** | `bypass_whitelist_file` (default `config/bypass_whitelist.txt`, currently empty). | Empty the bypass list so everything goes through the upstream proxy; or do not point clients at this proxy. |
| Opening the panel in a browser (the browser calls `/api/ads` and then loads each ad image); clicking an ad link navigates to it. These requests come from your browser, not from the ProxyCat process. | The `image_url` / `link_url` in `config/ads/*.json`; of the two files enabled today, one loads an image from `camo.githubusercontent.com` and both link to `github.com`. | **Direct** (browser-side) | No config key; the `enabled` / `image_url` / `link_url` fields in the JSON files. | Delete the ads JSON files or set `enabled` to `false`; an empty `image_url` stops the image from loading. |
| ① startup pre-check when the source is `local` and `check_proxies_on_startup=true`; ② before a standby candidate enters the roster when `check_proxies_on_use=true` (all sources; subject to the 30 s result cache and the 5 s cooldown); ③ confirmation probes before a failing exit is retired or a silent tunnel is declared dead — not gated by either switch; ④ the panel's **Check** button (`GET /api/check_proxies`). Results are also cached in-process for 10 s. | `test_url` through the exit under test (default `https://www.baidu.com`); when the https attempt fails, one retry goes out over plaintext `http` through the same exit. | **Through the upstream proxy** | `test_url`, `check_proxies_on_startup`, `check_proxies_on_use`, `proxy_check_ttl` (30 s), `check_cooldown` (5 s). | Both switches off plus not clicking Check removes the startup and admission probes, but the confirmation probes still fire whenever an exit fails — there is no single master switch; point `test_url` at an address you control, or stop the proxy service. |
| ① plugin scrapes and panel imports (full validation); ② the panel's batch validation — **Check liveness**, **Validate valid** / **Validate invalid**, and **Full check** (`POST /api/pool/update-geo/all`) at full intensity; ③ automatic re-validation, every 360 min by default and immediately on pool start with `run_on_start=true`, choosing full when `quality_assessed_at` is missing or older than `full_recheck_interval_minutes`, identity when the real IP or anonymity is missing, and liveness on other rounds. | `test_url` plus `validator.identity_echo_apis`, `validator.ip_check_apis`, `validator.plain_identity_echo_apis` and the three hardcoded plaintext probe addresses — all through the exit under test; a plugin can override the global `test_url` with its own test address. | **Through the upstream proxy** | `validator.target_url` (derived from `test_url`), `identity_echo_apis`, `ip_check_apis`, `plain_identity_echo_apis`, `check_anonymity`, `timeout_seconds`, `connect_timeout_seconds`; `auto_revalidation.enabled` / `interval_minutes` (360) / `run_on_start` / `full_recheck_interval_minutes` (1440). | `auto_revalidation.enabled=false` stops the scheduled task; a plugin's `skip_validation` skips ingest validation; do not click the batch buttons. Once the pool runs and any validation happens, though — planned or manual — this group cannot be fully switched off with one key; point the endpoint lists at addresses you own. |
| `proxy_source_mode=api` and `access_records_real_ip_probe` true: the background top-up loop scans the roster every second and probes any exit that has no real-IP record, a record older than its roster entry, or a failure more than 600 s old; at most 3 new probes per tick, 5 s per request. (The inline comment in `config.ini` mentions gateway addresses only; in fact every api exit whose real IP is not yet known is probed.) | `validator.ip_check_apis` — its https entries — through the exit itself, trying them one after another until a 200 yields an IP. | **Through the upstream proxy** | `access_records_real_ip_probe` — code default `false`, shipped `config.ini` `true`. | Set it to `false`; or do not use the `api` source (`local` and `pool` never send it). |
| Any client request to `127.0.0.1:1080` whose target is not on the bypass list; a failed exit is retried at the connection stage up to 2 times, and with an empty roster the request path fetches first. | The target host the client asked for; the hop is the exit currently selected (from the local file, the api source or the pool). | **Through the upstream proxy** | No switch — this is the core function; `proxy_source_mode` decides where exits come from, `bypass_whitelist_file` decides which targets skip this path (see the bypass row above). | Stop the proxy service (panel Stop, or exit the program); or do not configure clients to use this proxy. Forwarding through an upstream is the tool's job and cannot be turned off. |

A row marked **Direct** is sent directly from this host without a proxy, so the destination sees this
machine's real public IP: the version check, both scraper plugins, the validation pre-flight, the host
public-IP lookup, the SOCKS5 liveness probe, the ingest pre-screen, the api and remote-pool fetches, the
geolocation-database download and the bypass-list branch (the panel ads load directly too, but from your
browser rather than from ProxyCat). The remaining rows go **through the upstream proxy**, so the
destination sees the exit's address instead — those are ProxyCat's own validation probes and the client
traffic it forwards for you.

## Performance and Benchmarks

Throughput on the forwarding path:

![Performance test](../assets/性能测试图.png)

The screenshot is a Yakit load test through `http://neko:123456@127.0.0.1:1080`: **3000 requests at
500 concurrency, 3000 succeeded / 0 failed, all HTTP 200, roughly 550-670 ms per request**. The
`user:password@host:port` form in that URL also demonstrates outbound authentication (the accounts
in the `[Users]` section).

> This measures **ProxyCat's own forwarding path**, not your upstream proxy's quality — a slow
> upstream is slow through ProxyCat too. Check upstream quality in the panel under Logs → Access
> Statistics, grouped by upstream.

**Loopback benchmark** (measured on the development machine):

| Scenario | Number |
|---|---|
| 2000 idle tunnels | ~148 KB RSS per connection; idle CPU < 0.5% |
| Single-tunnel throughput | ~520 MB/s (loopback) |
| Small-message round trip | p50 0.27 ms / p95 0.47 ms |
| Full connect (CONNECT → upstream 200) | ~380 conn/s with a hostname exit whose first address is unreachable; ~1100 conn/s with an IP-literal exit |

Numbers vary by machine and are meant **for before/after comparison on the same machine only**;
comparing these numbers across machines means nothing.

> One platform cost worth knowing: on Windows the Proactor event loop allocates a fixed 64 KiB read
> buffer **per socket** (hardcoded in CPython, not settable by applications), so a tunnel with two
> sockets carries ~128 KB of user-space buffering. At 20k tunnels that is ~2.5 GB — the dominant
> memory term for massive concurrency on this platform.

## Project Structure

```text
ProxyCat/
├── ProxyCat.py                 CLI entry: starts the outbound service and the proxy pool
├── app.py                      Web entry: panel + outbound service + proxy pool (the Docker CMD)
├── README.md / README-EN.md    Chinese and English READMEs
├── API.md / API-EN.md          Full API reference (panel /api/* and pool /api/pool/*)
├── config/
│   ├── config.ini              All configuration (with Chinese inline comments)
│   ├── getip.py                Endpoint-fetching logic for the `api` source; adapt it to your API
│   ├── ip.txt                  Proxy list for `local` mode
│   ├── ads/                    Panel ad slot data
│   └── *.txt                   IP whitelist / blacklist and the bypass list
├── modules/
│   ├── proxyserver.py          Outbound proxy service: inbound parsing, rotation, forwarding
│   ├── proxy_workers.py        Exit roster: picking, concurrency quotas, failure sliding window and the standby queue
│   ├── proxypool_service.py    Hosts the proxy pool inside this process (async core + sync facade)
│   ├── proxypool_api.py        Web adapter for the pool (a Flask blueprint)
│   ├── pool_config_ini.py      Mapping between the [Pool] section and the config object tree
│   ├── modules.py              Shared host base layer: config, i18n, startup banner, proxy checks
│   ├── logging_setup.py        Logging assembly and category routing
│   ├── access_log.py           Per-request recording and timing
│   ├── access_records.py       Access records (the per-request event stream)
│   ├── domain_stats.py         Domain statistics (aggregated counters)
│   ├── spool_store.py          Shared "in-memory buffer + background batch flush" skeleton
│   ├── config_validation.py    Validation and normalization for the [Server] section
│   ├── loop_noise_filter.py    Suppresses asyncio teardown noise on Windows
│   ├── version_check.py        Version check scheduling and its persisted state
│   └── proxypool/              The proxy pool subsystem (see its README.md / README-EN.md)
├── web/
│   ├── templates/index.html    Single-page panel
│   └── static/                 Front-end assets (bundled jQuery and Font Awesome)
├── ProxyCat-Manual/            Detailed documentation
│   ├── Features.md / Features-EN.md                          Features (CN / EN)
│   ├── Configuration.md / Configuration-EN.md                Configuration (CN / EN)
│   ├── Operation Manual.md / Operation Manual-EN.md          Operation Manual (CN / EN)
│   ├── Investigation Manual.md / Investigation Manual-EN.md  Troubleshooting (CN / EN)
│   └── logs.md / logs-EN.md                                  Changelog (CN / EN)
├── assets/                     Images used by the README and manuals (panel screenshots under assets/screenshots/)
└── LICENSE                     GPL-2.0
```
