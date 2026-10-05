# Proxy Pool Module

[Back to README](../../README-EN.md)

The proxy resource pool: scrapes public proxies, validates their usability, manages them by quality score, and supplies them to ProxyCat's outbound proxy service on demand.

**This module is not a standalone project.** It runs as part of ProxyCat inside the same process, has no port of its own, and no longer has a separate web UI either — its management pages are the three sub-views Proxy Management, Pool Settings and Database Maintenance under the Proxy Pool tab in the ProxyCat panel.

- How to use: see [README-EN.md](../../README-EN.md) in the repository root
- API documentation: see [API-EN.md](../../API-EN.md) in the repository root
- Configuration: the `[Pool]` section of `config/config.ini` (migrated automatically from the old `config.yaml` on first start)

## Directory Structure

```
proxypool/
├── core/                    Core implementation (layered)
│   ├── config.py            Configuration data model (the data structure of the [Pool] section)
│   ├── paths.py             Sub-project root anchor, so nothing depends on the process working directory
│   ├── database.py          Table creation and column migrations
│   ├── backup.py            Scheduled database backup and restore
│   ├── data_cleaner.py      Database optimization and statistics queries
│   ├── logger.py            Rotating file handler for the pool log
│   ├── domain/              Domain models and exceptions
│   ├── interfaces/          Abstract contracts (repositories, services, infrastructure)
│   ├── infrastructure/      Connection pool, dedup cache, HTTP client, DI container, configuration manager, offline geolocation database
│   ├── data/                Repository implementations and the asynchronous write queue
│   ├── services/            Validator, plugin manager, automatic revalidation, health scoring, GeoIP
│   └── application/         Service orchestration (Application), background tasks, business operations layer
├── plugins/                 Scrape plugins (put new plugins here)
├── data/proxies.db          SQLite database
├── data/backups/            Automatic database backups (expired ones are pruned automatically)
├── data/geodb/              Offline geolocation databases (~104 MB, not committed; pulled by the update command, see "Geolocation")
└── logs/proxy_pool.log      Pool log (also fed into the panel's Logs)
```

## Scrape Plugin Development

A plugin is a `.py` file in the `plugins/` directory; the file name is the plugin name (and also the `source_plugin` of the proxies it collects). Plugins are scanned and loaded when the pool service starts, so a newly added file only appears after the pool service is restarted; for a plugin already in the list, after its code is changed, click **Reload** under Proxy Pool → Plugin Management in the panel to hot-reload it without a restart.

### Option 1: Implement IProxyPlugin (Recommended)

```python
"""Example: scrape proxies from an API."""

import json
from typing import List

from core.domain.exceptions import PluginExecutionException
from core.interfaces.services import IProxyPlugin, PluginContext


class ExamplePlugin(IProxyPlugin):
    """Plugin description. It is written to the log and also shown in the plugin list."""

    API_URL = "https://example.com/api/proxies"

    async def fetch_proxies(self, context: PluginContext) -> List[str]:
        """Return a list of proxy URLs, each in the form protocol://ip:port or protocol://user:pass@ip:port."""
        response = await context.http_client.get(self.API_URL)
        if response.status != 200:
            # Raise when the fetch fails: returning an empty list is taken by the
            # scheduler as "this source has no proxies right now" — it neither
            # retries nor reports an error in the plugin list.
            raise PluginExecutionException(
                f"Request to {self.API_URL} failed, HTTP status code: {response.status}"
            )

        items = json.loads(response.text).get("data", [])
        return [f"http://{item['ip']}:{item['port']}" for item in items]

    @property
    def name(self) -> str:
        return "example"

    @property
    def version(self) -> str:
        return "1.0.0"
```

`PluginContext` provides three things:

| Member | Description |
|---|---|
| `http_client` | Asynchronous HTTP client. A single request's default timeout is `plugins.request_timeout_seconds`, and a whole fetch is additionally bounded by `plugins.execution_timeout_seconds`; no need to manage a connection pool yourself |
| `logger` | A logger already named after the plugin |
| `config` | The configuration object currently in effect, from which `[Pool]` options can be read |

### Option 2: Provide Only a fetch_proxies Function

The old style is still supported: just define a `fetch_proxies` function in the module (synchronous or asynchronous both work; the synchronous version is executed in a thread pool):

```python
def fetch_proxies():
    return ["http://1.2.3.4:8080", "socks5://5.6.7.8:1080"]
```

### Conventions and Caveats

- Return a `list[str]`; every element must be `protocol://[user:pass@]ip:port`; entries that fail to parse are skipped one by one with a log line.
- Only the `http`, `https` and `socks5` protocols are supported.
- A plugin **does not** need to store anything itself, nor deduplicate or validate — the plugin manager deduplicates fetch results by `ip:port` and hands them to the ingest pipeline (only proxies that pass validation are stored).
- An exception raised by one plugin does not affect the other plugins; a failure is retried with exponential backoff up to `plugins.max_retries_on_failure` times (the total number of attempts is that value + 1).
- The number of plugins running at the same time is capped by `plugins.max_parallel_plugins`; a change takes effect immediately.
- The fetch interval and test URL are set per plugin and stored in the database — there is no need to write them into the configuration file.

## How Proxies Enter the Pool

```
Fetch (plugins)     ─┐
Run plugin manually ─┼─► Deduplicate ─► Port pre-screen ─► Validation ─► Store only "confirmed working" ones ─► Resolve geolocation asynchronously
Batch import        ─┘
```

- **Only working proxies are stored** (`core/application/ingest.py`): this is the only entry point through which proxies enter the pool. **Conclusively unusable** ones (cannot connect to the proxy, the proxy refuses to forward) and ones **inconclusive for this round** (our check endpoints are broken, this host has no network) are not written to the database; a proxy that survives the liveness probe but fails to obtain an egress IP in a way attributable to the proxy is likewise not written (failures attributable to our side are still stored, pending a later re-test). The cost is that proxies collected while the check chain is flapping get discarded; the benefit is that every record in the pool really did pass validation — otherwise the question "how many usable proxies are in the pool" simply cannot be answered. (Note that this does not conflict with the "inconclusive results are not punished" point below: that one is about not deleting **existing** records.)
- **Port pre-screen**: fully validating a black-hole proxy — one that accepts connections but never forwards — burns the whole timeout (about 6.5 seconds), while public proxy lists run to hundreds of thousands of entries, the vast majority of which have nothing listening at all. The pre-screen does a single TCP connect: anything that cannot connect is out immediately and **never enters validation**. It touches no proxy protocol and requests no external site, so it can run at several times the validation concurrency (4× by default; floor 64, ceiling 2000).
  - Measured: 3000 unroutable addresses dropped from 64 seconds to 17, without sending a single validation request.
  - Known limitation: the pre-screen cannot stop black-hole proxies that accept connections but never forward; those can only be caught by the validation timeout. So a large scrape of hundreds of thousands of addresses is still a wait measured in minutes — the progress bar shows the live rate and estimated time remaining, and the task can be cancelled at any time.
- **The test URL is per plugin**: the default is `[Server] test_url`, and each plugin can specify its own test URL under Proxy Pool → Plugin Management (`PUT /api/pool/plugins/<name>/test-url`; leaving it empty restores inheritance of the global one).
- **Batch validation has two levels** (the `mode` of `POST /api/pool/proxies/batch/validate`): `liveness` only judges "is it still reachable" (it touches neither the egress IP nor anonymity, and does not advance the full-evaluation time; the liveness probe itself records the protocols that carried the test URL as supported), `full` refreshes identity and capability together, and `auto` keeps the original "choose per record state". The panel's **Check liveness** / **Full check** buttons correspond to the first two respectively.
- **Per-plugin validation policy** (`PUT /api/pool/plugins/<name>/validation`): the revalidation switch, the revalidation interval and **skip ingest validation** are submitted together in one call. The last one is aimed at proxy sources billed per request whose validity the provider guarantees — once turned on, proxies scraped by that plugin go straight into the database without pre-screening or validation, neither connecting to the proxy nor sending probe requests. The cost is that these records have no egress IP, delay or protocol support, their anonymity stays at `unverified`, and their health score is computed from the defaults for missing data (`total_checks` is 0); all of that is only filled in once automatic revalidation has actually run a check. It is therefore independent of the revalidation switch: turning off ingest validation alone does not stop the later scheduled checks.

## Validation

- **Three intensities** (`ValidationMode`, chosen centrally by `validation_policy`):

  | Intensity | Probes | When it is used |
  |---|---|---|
  | `LIVENESS` | Liveness | Routine rounds |
  | `IDENTITY` | Liveness + **HTTPS identity** + **plaintext identity** | A full evaluation already exists, but **identity data is incomplete** (no egress IP, or anonymity unknown — the latter can only be old data) |
  | `FULL` | The three above + plaintext forwarding capability | Full checks, first-time ingest, and when the last full evaluation is more than `auto_revalidation.full_recheck_interval_minutes` ago |

  - A "probe" is not the same as a request: inside each probe, several candidate endpoints are **dispatched one after another** according to direct-connect latency (see the race below), so the actual request count depends on how many endpoints are reachable. The counts in the table are lower bounds.
  - **`IDENTITY` has two identity probes**, not one: the HTTPS one yields the egress IP, and the plaintext one **yields anonymity only** (the reason is under "Both the plaintext and HTTPS paths are evidence" below). Anonymity prefers plaintext evidence, so filling in identity data updates anonymity along the way.
  - `FULL`'s fourth probe is sent only when **the test URL is not plaintext http**: when the test URL is itself http, the liveness probe has already proved that plaintext forwarding works, so there is no need to probe again. The default test URL is https, so count it as four probes.

- **The liveness probe is the gate**: the test URL is requested through the proxy first (answering "does it work, and how fast"), and **if it fails, that is the end of it**; only after it passes are the remaining probes sent **concurrently** (the wall clock is the slowest of them, not their sum).
  - Why it has the final say: it is the **only** probe that can answer "can this proxy open the site you want". If a success in "some other probe" were allowed to certify usability, the pool would take in a string of records "judged usable, but with delay / egress IP / anonymity / region all empty" — all four of those fields come from the later probes. In a real database, all 9 such records arose exactly this way.
  - It also saves a great deal of work: failed candidates are the vast majority in a large scrape, and they now cost **just 1 request** (previously the identity and plaintext probes were fired off along with it). Measured: a single black-hole proxy went from 7.6 seconds to 5.4, throughput from 57 to 67 per second, and the number of requests sent to external sites dropped to a third.
  - The probes after the gate are **independent of one another and therefore sent concurrently** (`IDENTITY` has the HTTPS identity and plaintext identity probes; `FULL` adds the plaintext capability probe). The HTTPS identity and plaintext capability probes together form a "protocol × target protocol" capability matrix: an `http://` target goes over plaintext forwarding while an `https://` target goes through a CONNECT tunnel; in testing there are proxies that only handle one of the two, so the two are recorded separately.
- **The egress IP is detected only when needed**: it goes through HTTPS check endpoints (`validator.identity_echo_apis` / `ip_check_apis`, which **only accept https** — plaintext echoes can be forged by the proxy, and identity data feeds both the geolocation and the anonymity decisions). The last hop of the `origin` chain is taken, **preferring IPv4**; IPv6 is accepted only when the whole chain has no IPv4.
  - **No truncation by count**: candidates are ordered by **our** direct-connect latency, but "can this proxy reach a given endpoint" depends on **its** network — the ones at the front being blocked on its side is the norm. Truncating would leave usable proxies permanently unable to obtain an egress IP, and therefore permanently without a region.
  - Taking part in full does not slow the failure path: the dispatch window has a total cap (1.5 seconds), so even a dozen candidates are all sent within 1.5 seconds and the cost of failure is still "window + timeout". On success, the first one returns.
  - The endpoints must **span providers**: same-family mirrors tend to be blocked together. The default list contains both the httpbin family (which returns an `origin` chain → anonymity falls out of it too) and pure IP echoes (icanhazip / ipinfo / ipwho.is / Cloudflare trace); supported response shapes include plain text, `{"ip": ...}` and line-by-line `key=value`.
  - When a reachable proxy cannot reach any echo endpoint, a WARNING is logged — that is exactly the root cause of an "empty egress IP and region" record, and it should not be silent.
  - **Anonymity is judged by "what the target actually received"** (`_judge_anonymity`): transparent (the target can tell who we are) / anonymous (it can tell a proxy is in between) / elite (neither is visible). The criterion is not the proxy's protocol type but what the target actually received when it forwarded.
    - **The evidence has two carriers, and both are needed.** In testing, the four default endpoints behaved in completely different ways:

      | Endpoint (fronted by) | `origin` | `X-Forwarded-For` in the echoed headers | What it can be judged by |
      |---|---|---|---|
      | httpbin.org / eu.httpbin.org (AWS ALB) | Present, **with the XFF folded in** | **Stripped** (`Via` too) | `origin` only |
      | httpbingo.org (fly.io) | Present, but **only the peer**, without XFF | **Kept** | Headers only |
      | postman-echo (Cloudflare) | **Absent** | **Stripped** | Only the `Via` it echoes back |

      Relying on headers alone would judge nothing on httpbin, and relying on origin alone would judge nothing on httpbingo — the two are **two presentations of the same evidence** and must be used together. Look at this table before swapping or adding endpoints.
    - **The test**: ① this host's egress IP appears in the `origin` chain or in any header value → transparent (**no baseline subtraction**: the question is precisely "does what the target received after this proxy include us"); ② proxy traces appear → anonymous — the `origin` chain is longer than the direct-connection baseline, or a **proxy-added** header carries an address, or a header matches the known proxy-header list while being absent from the baseline; ③ anything else → elite.
    - **Judging "proxy smuggling" looks at "does the baseline hold an IP", not "did the value change".** A CDN-fronted endpoint writes the peer address into XFF itself: on a direct connection it is our IP, through a proxy it becomes the proxy's IP — the name is unchanged while the value changes. Judging by "the value changed" would mark **every** clean proxy as anonymous (this is exactly what httpbingo did in testing). So headers the endpoint writes itself (whose baseline holds an IP) are excluded wholesale, while a header it does not write IPs into (such as its own `Via`) can be caught the moment the proxy slips an address in.
    - **Both the plaintext and the HTTPS paths are evidence**: plaintext takes priority (it also reflects plaintext forwarding behaviour); when it is unavailable, the HTTPS path is used. Inside a tunnel the proxy forwards bytes, but if it wants to smuggle an address it can do so through a tunnel just as well.
    - **socks5 gets no shortcut**: the protocol itself injects no headers, but a node speaking SOCKS5 may be an HTTP-aware gateway, or other proxies may sit further along the path — it is judged by the same tests as every other protocol.
    - **Cases where no conclusion is drawn** (the stored old value is kept rather than guessed): the `validator.check_anonymity` switch is off; this host's egress IP cannot be obtained (no basis for comparison); no identity probe was run at all this round (a lightweight LIVENESS round); or the failure is attributable to our side because the echo endpoints are unreachable. Only "the probe ran, yet not one usable echo came back" falls back to transparent with the `anonymity_fallback` flag, which the UI uses to tell it apart from a measured result.
    - The plaintext endpoints are **derived at the same addresses** from the HTTPS echo endpoint list (httpbingo's plaintext variant is the only one that can obtain XFF evidence), and can additionally be supplemented via `validator.plain_identity_echo_apis`.
  - **This host's public egress IP** (`ValidationEndpoints.ensure_host_ip`): the comparison baseline for judging transparent, obtained by visiting IP-query sites **without going through a proxy** (the `validator.ip_check_apis` set); it stops at the first success, caches for a 30-minute TTL, and backs off for the same TTL on failure. A user can put their egress IP straight into `validator.host_public_ip` and then not a single request is sent — the UI shows the value currently in effect and where it came from (manually set / auto-detected / not obtained).
  - **Anonymity is optional overhead**: with `validator.check_anonymity` off, no more plaintext identity probes are sent and anonymity is no longer judged; existing levels are kept as they are and new records stay at `unverified`; the endpoint pre-screen loses the plaintext batch of candidates as well (under the default configuration, requests per round drop from 11 to 4).
- **Failure attribution**: every failure carries a conclusion category. Only "cannot connect to the proxy" and "the proxy does not forward" count as the proxy's fault; our check endpoints being unreachable, the test URL being unreachable and this host losing its network are all recorded as **inconclusive**, and no field is written then — the proxy is neither judged invalid nor charged a failure, so flapping check infrastructure never triggers automatic cleanup.
- **Timeouts are fixed values**: every request uses `validator.timeout_seconds`, and the connection phase additionally caps the TCP handshake with `validator.connect_timeout_seconds` (this maps to aiohttp's `sock_connect`, not `connect`; the latter would include establishing a CONNECT tunnel and would wrongly fail usable proxies whose tunnels are slow) — black-hole proxies thus fail fast within the connect timeout, and that is the main source of the pool's speed. There used to be a mechanism of "dynamically deriving a per-request timeout from this host's direct-connect timings" plus a "whole-wave wall-clock budget"; it has been removed: combined, the two would starve identity probes of budget whenever the liveness probe was running a little slow, making "never measured" and "measured as failed" indistinguishable in the database.
- **Endpoint pre-screening and the race**: before validation, each endpoint is probed directly from this host, and unreachable ones are dropped automatically (blocked or reset endpoints need not be hit through every proxy). Each endpoint's direct response is recorded as a baseline, used both to cancel out the response headers the endpoint **itself** injects and to order candidates — during the race, candidates are **dispatched one after another** by direct-connect latency (hedging) rather than all at once, so a slow proxy is no longer hammered by seven or eight concurrent tunnels at the same time. The **total dispatch time is capped** (1.5 seconds), so the cost on the failure path is "window + timeout" rather than "candidates × interval + timeout": with 5 candidates for an identity probe, this took a single black-hole proxy's validation from 12 seconds down to 6.5.
- **Health scoring**: delay 25% + success rate 25% + stability 15% + uptime 15% + anonymity 10% + longevity 10%. The success-rate dimension uses the **Wilson lower confidence bound of the success rate**, shrinking toward the low end when samples are few, so a proxy "validated only once or twice" cannot collect an inflated score; samples are counted **per probe** (each probe that reaches a definite conclusion casts one vote — at most 3 votes per round: liveness, HTTPS identity, plaintext forwarding capability; candidate endpoint requests sent as race hedges do not each get a vote), which is up to 3× denser than "one vote per round" and converges the estimate faster. The delay mean and variance are clamped against outlier samples, so one bout of congestion cannot drag the whole score down.
- **Identity fields are sticky**: the egress IP and protocol support are written to the database only when actually measured this time; otherwise the last known value is kept. Anonymity works the same — the only case where a projected value is written is when the probe really ran but no echo evidence came back, in which case the fallback level is written with the `anonymity_fallback` flag, and the UI can tell it apart from a measured result. Otherwise a single failure would wipe out a known egress IP. Delay works the same way, and the "last full evaluation time" advances only when every probe reached a definite conclusion — a round that did not ask everything does not keep the proxy from being re-probed within the redo interval.
- **Re-scraping does not wipe history**: when the same `ip:port` is stored again it is merged by upsert; `delay_variance`, uptime, the favorite flag and first-ingest time are all preserved, and only the fields this scrape actually obtained are refreshed.

## Geolocation

Geolocation **goes entirely through the local offline databases**: a single lookup returns both the Chinese and English sets of names along with the canonical ISO codes, and makes no external request. This section covers where the names come from, and what to change when a name looks wrong.

(It used to go through the online ip-api service only, one request each for Chinese and English, and that service's Chinese coverage of first-level administrative divisions was incomplete — where a translation existed it returned Chinese, where none existed it returned the local original, so the database ended up with one Chinese cell and one English cell side by side. That path has been removed entirely, and the four `geoip.*` options are void along with it.)

### How the Two Offline Databases Divide the Work

| Data file | Coverage | What it provides | Where it is used |
|---|---|---|---|
| `GeoLite2-City.mmdb` (~65 MB) | Worldwide | ISO 3166-1 country codes, ISO 3166-2 subdivision codes, and names in 8 languages | Country decisions and subdivisions outside China |
| `qqwry.ipdb` (Chunzhen, ~39 MB) | China | Province / city / district names (Chinese) | **Supplements mainland-China province and city levels only** |

- **Why GeoLite2**: a single lookup gives both name sets and the canonical codes at once. This saves "two requests for one IP" (one per language in the online-API era) and removes any API quota limit entirely — the latter was one of the main motivations for adopting the offline databases.
- **Why Chunzhen as well**: its city-level coverage in China is clearly stronger — over the same batch of 8 Chinese IPs, Chunzhen returned a city for 7, GeoLite2 for only 3.
- **Chunzhen only takes part when `country_code == "CN"`**: its country decisions outside China are not trustworthy — in testing it judged Hong Kong as the United States and the Netherlands as Ukraine. So non-Chinese records always follow GeoLite2's conclusion; for them even Chunzhen's province and city data is not used.
- **GeoLite2's Chinese names have gaps**: over a sample of 4000 public IPs, a first-level administrative division was found for 46.8%, and 70.5% of those carried a Chinese name; a city was found for 46.1%, of which 63.0% carried a Chinese name. When a translated name is missing, the value **falls back to the original text and is marked as "original"** (see below), instead of letting the two languages blend silently into one cell — which was exactly the previous version's behaviour: the two sets were requested separately from the API, a Chinese name came back where a translation existed and the local original where none did, so the database held one Chinese cell and one English cell with no way to tell why.
- **The two databases may disagree** on the city for the same IP (in testing, `183.62.176.46` was Shenzhen in Chunzhen and Guangzhou in GeoLite2); in that case GeoLite2's existing `zh-CN` name wins, Chunzhen only fills levels where GeoLite2 lacks a `zh-CN` name, and the provenance of the conclusion is recorded in `geo_source` for later review.

### Names Are Rendered from Codes and Lookup Tables

What the offline databases return is not strings but **canonical codes** (ISO 3166-1 country codes + ISO 3166-2 subdivision codes) plus a "language → name" mapping. The values written to the database — `country/province/city` (the Chinese set) and `country_en/province_en/city_en` (the English set) — are **derived data** rendered from those codes:

- The Chinese set: `zh-CN` from the database → first-level-division lookup table → the original English text
- The English set: `en` from the database → China province/city lookup table → the original Chinese text

**Why store the codes**: names change with the data sources and the lookup tables, codes do not; the display name is rendered at lookup time from the table as it stands then, while the code is what selects records that can still be recomputed (only those missing codes — see below). The provenance of the conclusion (`geolite2` / `geolite2+qqwry`) is recorded as well, to make troubleshooting and later re-judging easier.

**The lookup tables are a best-effort finite set**: the 34 province-level divisions of China + 156 major cities (the ones proxy exits concentrate in), plus the first-level divisions of 13 countries/regions. Areas not covered fall back to the original text — an accurate original beats an invented wrong translation.

**"Original" is marked in the UI**: a light-coloured asterisk after the region name, with a tooltip reading "No translated name in this language yet - showing the original text". The test **is deterministic**: the Chinese and English columns are compared field by field, and a level whose values are equal on both sides was not translated (the API exposes both sets as separate columns precisely to make this decidable, rather than guessing from whether the string contains Latin letters). Missing translations are expected and can improve cumulatively; marking them is what makes them discoverable.

Known limitation: an original text in a third language whose Chinese and English columns **differ to begin with** cannot be detected — for example, the Japanese 千葉県 has the English Chiba and the two columns differ, yet Chinese and Japanese share characters, so string comparison alone cannot tell. Such values can only come from merged, preserved old data; first-level divisions of Japan and Korea have Chinese names in the offline databases and are "overwritten with the new value" rather than preserved, so this is rarely encountered in practice.

### Data Files

- **Location**: `modules/proxypool/data/geodb/`; the two files total about 104 MB and are **not committed** (the whole directory is excluded in `.gitignore`). **These two files are the sole source of geolocation data**: without downloading them there is no geolocation (see below).
- **Update command**: run `python -m core.infrastructure.geodb` from the `modules/proxypool/` directory (optionally `--dir` to set the data directory). Both databases go through jsDelivr's `@latest` — Chunzhen updates weekly and GeoLite2 twice a week, and a pinned version number would keep pulling the same old database forever. Either one failing does not affect the other; when done, the command reports item by item, with exit code 1 if anything failed.
- **Panel entry**: Proxy Pool → Database Maintenance → **Update Geo Databases** in the Geo Databases section (`POST /api/pool/geo/update`). It creates a background task; the download takes several minutes and the progress is shown under the button. The command line suits first-time deployment, the panel suits routine updates.
- **When files are missing**: the subsystem as a whole is judged "offline databases unavailable" and every lookup returns "unknown" — **there is no fallback anymore**. The pool still starts as usual (scraping, validation and exit forwarding do not depend on it), but regions will be empty; the startup log records a WARNING pointing at the remedy, and the panel's Geo Databases section shows "not downloaded". Using "whichever database is present" is deliberately avoided here: with partial availability, "this IP cannot be found" could mean the database does not have it or merely that one file is missing, and that is far more expensive to troubleshoot than simply declaring the subsystem unavailable.
- The panel shows each file's presence, size and modification time, plus the number of records pending recompute.

### Caching

- **Cached per IP** (`core/services/geoip.py`): a result with both the Chinese and English sets is cached for 24 hours; one with only a single set or a failed lookup is cached for 1 hour (so that a "half-missing" result is not locked in as complete for a whole day); the entry cap is 10000. The cache is in-process memory; a restart re-queries.
- **Nothing is written for what was not found**: only the languages that were resolved are written. A failed lookup writes no field at all — this used to overwrite an already-resolved region with "unknown", the exact opposite of the "write only what was measured" policy used for the other identity fields.
- **Recompute only touches records without codes** (`country_code IS NULL`): they were either never looked up, or looked up in the "online API only" version (when canonical codes were unavailable, so names could not be re-rendered per language). The panel's **Recompute Geo** (`POST /api/pool/geo/recompute`) does exactly this; the startup backfill enqueues at most 5000 records at a time (the queue only has capacity for 2000, and filling it would crowd out lookups triggered along the validation path), and the excess is left to that button. Records already resolved through the offline databases are not recomputed — to refresh them after a data-file update you would first have to clear their `country_code` (no such operation is currently provided).

### Resolution Is Asynchronous

- **Asynchronous resolution** (`core/services/geo_resolver.py`): the validation stage is only responsible for asking "what is the egress IP"; once it has the answer it drops the IP into the queue and returns — the lookup, retries and database write all happen in the background and consume none of the validation's wall clock. It used to be awaited record by record inside the validation coroutine at five call sites, directly stretching every round's wall clock.
- **A few concurrent workers do the lookups**: the queue and workers exist to decouple geolocation from validation — validation just drops the egress IP into the queue and returns, while the background does the writing at its own pace. The lookup itself is now a local table read (microseconds), no longer the "online-API timeout plus ten-plus seconds of retries" it used to be, so the concurrency level (4) today mainly smooths out the write pace rather than reducing lookup latency.
- **Startup backfill**: the queue is in-memory, so a restart loses whatever was not looked up. On startup, therefore, records that are currently valid, have an egress IP, but have no region (when the offline databases are available, missing canonical codes count too) are re-enqueued — otherwise these proxies would have to wait for their next full evaluation (24 hours by default) to be looked up again, with an empty region in the meantime.
- **The attempt cap is per time window**: the same egress IP is attempted at most 3 times within 30 minutes. It used to be a one-shot counter — after 3 failures that IP was never looked up again, so a single API blip condemned its geolocation permanently.
- **Where the two sets come from**: `country/province/city/region` is the Chinese set and `country_en/province_en/city_en/region_en` is the English set. With the offline databases, **a single lookup yields both sets at once** (neither translated from the other, nor fetched by two requests).
  - Region search hits either side (`region LIKE ? OR region_en LIKE ?`): searching 美国 and searching `United States` return the same records.
  - What the UI displays **follows the UI language**: the English interface shows `region_en` and puts the other set in the tooltip; sorting by region also switches to the matching column, otherwise the list order would not match the place names on screen. When one set is missing it falls back to the other ("unknown" counts as missing and is not shown as a place name).
- **Deduplicated by egress IP**: a batch of proxies on the same egress IP shares one lookup and one write (updating by `real_ip`), so freshly inserted records having no id yet causes no trouble.
- **Known limitation**: the two databases only guarantee that a conclusion is traceable, not that it matches physical location — most pool IPs are datacenter/cloud hosts, for which the "location" is essentially a registration place rather than a physical one; in testing, the same IP was judged as Japan, the United States, Singapore and the United States by four different sources. This is an inherent disagreement between data sources, not a resolution problem.

## Automatic Cleanup

A proxy is deleted when it meets any of these conditions: its health score is below the threshold and it has enough validations; its consecutive failure count is over the limit; or **it has remained invalid for longer than the retention days** (`auto_cleanup.max_age_days_if_invalid`; the test is the number of days since `validated_at`, falling back to the ingest time when it is missing — every conclusive validation refreshes it whether it passed or failed, so what it measures is "how long since it was last validated", not "how long since it last passed"). **Favorited proxies are never deleted.** Deletion is irreversible, which is why the "inconclusive results are not punished" rule above is its first line of defence.

Deletion happens in exactly this one place. There used to be a second, parallel deletion path (the `performance.*` group of keys, computing retention from `validated_at`); the two used different criteria, and which one removed a given row depended on timing, so both have been merged into `auto_cleanup`.
