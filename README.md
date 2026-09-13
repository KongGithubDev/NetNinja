# NetNinja

High-performance Go forward proxy with CGNAT keepalive for mobile devices.

![Preview](preview.png)

## Features

- HTTP/HTTPS forward proxy with CONNECT tunneling
- CGNAT keepalive page (maintains NAT mapping via periodic pings)
- Ad blocking (191K+ domains from hagezi blocklist)
- SOCKS5 hop for blocked domains (bilibili, cloudflare)
- Thai egress pool: several Thai nodes + backups, auto-rotating on death or slowdown
- Geo sessions — the site *and* its ad slots egress Thai, so ads come out Thai too
- Domain lists are data (file/URL, hot reloaded), never compiled into the binary
- Keepalive page that reports Thailand status and which server you are on (address masked)
- PAC (Auto) support — iPadOS Wi-Fi proxy without installing anything
- Per-user auth & quota management
- Admin dashboard
- Cross-platform (Linux, Windows)

## Architecture

```
iPad (Wi-Fi proxy:5988) ──→ Azure VM (proxy:5988) ──→ Internet
                                    │
                                    ├── Caddy (HTTPS:443) ──→ keepalive server (:8080)
                                    │     ↑
                                    │     └── https://<YOUR_DOMAIN>
                                    │         (periodic fetch keeps CGNAT mapping alive)
                                    │
                                    └── Forward proxy (:5988)
                                          └── CONNECT tunnels to external sites
```

## Components

| Component | Source | Port | Purpose |
|-----------|--------|------|---------|
| Forward proxy | `cmd/proxy` | 5988 | CONNECT + HTTP proxy, geo routing, admin dashboard |
| Keepalive page | `cmd/keepalive` | 8080 | CGNAT keepalive page + Thailand status |
| Caddy | — | 443 | HTTPS termination + reverse proxy |

## Repository layout

```
cmd/proxy/       the forward proxy      — go build ./cmd/proxy
cmd/keepalive/   the keepalive page     — go build ./cmd/keepalive
scripts/         netninja-deploy.sh / .ps1, the Thai pool supervisor + its offline test
examples/        templates to copy: th-pool.conf, netninja.local.ps1
.github/         ci.yml — gofmt + vet + tests + shell syntax on every push
Makefile         make · test · selftest · check · clean
data/            geo-domains.txt — the geo domain list itself, served over GEO_DOMAINS_URL
dist/            build output, git-ignored — `make` regenerates it
```

Secrets, per-deployment data and local notes — `azure-sg.key`, `netninja.local.ps1`, `geo-nodes.txt`,
`geo-domains.txt`, `TROUBLESHOOTING.md` — live **untracked in the repository root**, next to the
Makefile (see [Moving to another machine](#moving-to-another-machine)).

## Quick Start

### Build

```bash
make                 # linux binaries -> dist/proxy_linux, dist/keepalive_linux
make host            # the same two for the machine you are on (quick run)
make test            # offline unit tests
make selftest        # offline test of the Thai pool supervisor
make check           # gofmt + vet + test
make clean           # drop dist/

# or, without make:
GOOS=linux GOARCH=amd64 go build -trimpath -o dist/proxy_linux ./cmd/proxy
GOOS=linux GOARCH=amd64 go build -trimpath -o dist/keepalive_linux ./cmd/keepalive
go test ./cmd/...
```

The build stamp is compiled in, so `/geo-check` and the dashboard print exactly which binary is
running.

### Continuous integration

`.github/workflows/ci.yml` runs the same gates on **every push and pull request**, so a broken build
or an unformatted file never waits for the next deploy:

- `gofmt -l cmd` — checked, never applied; the job fails and names the files instead of rewriting them
- `go vet ./cmd/...`
- `go test -count=1 ./cmd/...` — `-count=1` defeats the test result cache
- `bash -n` over every tracked `*.sh` — the deploy, pool and vpngate scripts
- every tracked `*.ps1` must stay pure ASCII — Windows PowerShell 5.1 reads a BOM-less `.ps1` with the
  system ANSI codepage, so a single UTF-8 dash (or Thai character) decodes into a curly quote and stops
  the deploy helper from parsing at all, while PowerShell 7 still reports it as fine

It is a syntax gate only: CI never runs a deploy, a pool script or anything that touches the server,
and it only needs `contents: read`. Run the same gates by hand with `make check`, `bash -n
scripts/*.sh` and an ASCII check over `*.ps1`.

### Deploy to Azure VM

```bash
# Copy binaries
scp -i azure-sg.key dist/proxy_linux <USER>@<SERVER_IP>:/tmp/proxy_linux
scp -i azure-sg.key dist/keepalive_linux <USER>@<SERVER_IP>:/tmp/keepalive_server

# Deploy
ssh -i azure-sg.key <USER>@<SERVER_IP> "
  sudo systemctl stop netninja-proxy
  sudo cp /tmp/proxy_linux /opt/netninja/proxy_linux
  sudo chmod +x /opt/netninja/proxy_linux
  sudo systemctl start netninja-proxy

  sudo systemctl stop netninja-keepalive
  sudo cp /tmp/keepalive_server /opt/netninja/keepalive_server
  sudo chmod +x /opt/netninja/keepalive_server
  sudo systemctl start netninja-keepalive
"
```

## iPad Configuration

1. Wi-Fi settings → HTTP Proxy → Manual
2. Server: `<YOUR_SERVER_IP>`, Port: `5988`
3. Open Safari → `https://<YOUR_DOMAIN>`
4. Tap **Start Keepalive** → keeps CGNAT mapping alive

## CGNAT Keepalive

TOT FTTH uses CGNAT with ~4-5 min idle timeout. The keepalive page sends periodic HTTP pings through the proxy tunnel to maintain the NAT mapping.

- **Method**: Periodic fetch every 5 seconds (more resilient than SSE on iOS)
- **Audio loop**: Keeps Safari JS alive when backgrounded
- **Auto-reconnect**: Resumes on `visibilitychange` / `pageshow`

### What the page reports

Beyond the keepalive loop the page shows **which server** you are going through and whether geo traffic
is exiting Thailand right now:

- 🇹🇭 **Thailand Connected** — the pool's current node is verified as `GEO_EXPECT_COUNTRY`
- **Thai egress unavailable (CC)** — the current node drifted to another country, or is down
- **Direct connection** — no Thai egress configured yet

The address is always partial (`20.24.xxx.xxx`): `MASK_KEEP_OCTETS` (default 2) decides how many IPv4 octets
stay visible, and masking happens **on the server**, so the full address never reaches the
browser. Nothing is compiled in — the address comes from `PROXY_ADDR` / `SERVER_ADDR` when set and is
otherwise looked up once per `SERVER_LOOKUP_TTL`. The Thai state comes from the proxy's cached
`/geo-status.json` (one `127.0.0.1` call per `GEO_STATUS_TTL`, never a dial or a country lookup), because
only the proxy knows which egress node is current — the page itself deliberately never travels the Thai
path.

## Geo Routing — stable Thai egress via a Thai egress pool

A forward proxy always shows the destination the **proxy's own IP**, so a server in Malaysia looks
Malaysian to OmeTV and only matches Malaysian peers. Hosts on the **geo list** are dialled through the
Thai egress pool instead, so the destination sees Thailand.

```
OmeTV ──TLS/WS──> proxy (MY) ──SOCKS5──> Thai pool ──> OmeTV sees TH
```

### 1. Thai egress pool — several nodes + backups + auto-rotate

`GEO_SOCKS5_POOL` takes several SOCKS5 egress entries (each one is a Thai tunnel on the server), and the proxy

- **probes every node** every `GEO_POOL_PROBE` (default 20s) and measures real RTT
- **verifies the country each node really exits from** through ip-api every `GEO_POOL_GEOCHECK`
  (default 5m) — a node exiting anywhere else is **never used**, so there is no silent cross-country rotation
- **stays on the current node** for as long as it is fast and still exits Thailand
  (so OmeTV conversations are not cut in the middle)
- **rotates immediately** when a node dies (`GEO_POOL_FAIL_STRIKES` in a row) or is slower than
  `GEO_POOL_MAX_RTT` for `GEO_POOL_SLOW_STRIKES` in a row, and **fails over inside a single dial**,
  so a dead node costs one round trip instead of a timeout
- **never charges a dial the client canceled to a node** — closing the tab or refreshing mid-handshake is
  the browser going away, not the tunnel failing; counting it retired a healthy node and cut every session
  riding on it, which is how a live chat dropped and came back on a different egress
- calls `GEO_ROTATE_CMD` to have the server build a new tunnel when no Thai node is usable at all
  (with cooldown/backoff)
- `GEO_STRICT=1` (default) — **fails** instead of leaking out through the server's own country
  when no Thai egress is available

The node list is **data**: `/opt/netninja/geo-nodes.txt` (one `host:port` per line) is hot reloaded every
~20 seconds, so a tunnel that comes up later joins the pool with no redeploy. It can also come straight
from the environment, e.g. `GEO_SOCKS5_POOL="<node1-host:port>,<node2-host:port>"`.

#### Supply side: `scripts/netninja-th-pool.sh`

The proxy looks after the destination end (probe/rotate) but **never builds a tunnel itself** —
`scripts/netninja-th-pool.sh` is the other half: it keeps the tunnels *underneath* `/opt/netninja/geo-nodes.txt`
alive on its own, every `CHECK_INTERVAL` (default 60s).

1. checks the endpoint (is SOCKS5 reachable?) and **which country it really exits from**
   (asks ip-api **through that tunnel**)
2. replaces a dead slot or one exiting the wrong country by running that slot's `SLOT_<n>_REPLACE`
   (cooldown **per slot** plus a shared hourly cap, so a broken slot cannot become a rotate storm)
3. **publishes only endpoints that just verified** as the expected country, atomically, and writes the
   pool file only when its content actually changes — with no healthy node at all it **leaves the old
   file untouched** (exit 3, so monitoring can alert on it)

Nothing about the VPN stack is assumed: a slot is one endpoint plus an optional command that (re)creates
it — leave the command out if the tunnel already exists. Configuration lives in
`/etc/netninja/th-pool.conf`; start from `examples/netninja-th-pool.conf.example`, which carries three
patterns (tunnels already exist / rebuild each slot / discover listeners that are up).

```bash
sudo ./scripts/netninja-th-pool.sh --status          # every slot, its country, the published file
sudo ./scripts/netninja-th-pool.sh --dry-run --once  # report only — no replace, no write
sudo ./scripts/netninja-th-pool.sh --once            # check → repair → publish (systemd timer)
sudo ./scripts/netninja-th-pool.sh --daemon          # keep checking every CHECK_INTERVAL (service)
```

On the server it is installed as `/opt/netninja/netninja-th-pool.sh` by the deploy script, which also
uploads `examples/netninja-th-pool.conf.example` and — with `--th-pool` — creates and enables
`netninja-th-pool.service`. When `/etc/netninja/th-pool.conf` does not exist yet it writes a
discovery-mode one (no slots: every SOCKS5 listener that is up and really exits `EXPECT_COUNTRY` is
published, which is the zero-config path), and then runs one pass immediately so
`/opt/netninja/geo-nodes.txt` exists *before* the proxy restarts.

It can be tested offline, with no real tunnel: `make selftest` (stub probe + stub replace commands).

#### The other half of the supply side: `scripts/vpngate/`

The supervisor decides *what* to publish; `scripts/vpngate/` is the machinery underneath it — the OpenVPN
`--up`/`--down` hooks that give each slot its own tun, source address, routing table and SOCKS5 listener, the
failover and watchdog for the legacy slot 1, the per-slot rebuild command (`SLOT_<n>_REPLACE`), the systemd
template for numbered slots, and the installer that puts them all in place. Slot 1 stays the pre-existing
`vpngate-th.service`; numbered slots are installed and then owned by the supervisor.

```bash
scp -r scripts/vpngate <user>@<vm>:/tmp/netninja-slots
ssh <user>@<vm> 'sudo bash /tmp/netninja-slots/install-slots.sh'    # SLOTS="2 3" to add slots
```

These scripts only lived on the server before, so a rebuilt VM had to be reverse-engineered from its running
config. See [`scripts/vpngate/README.md`](scripts/vpngate/README.md) for the install map and for the handful
of invariants that each cost an outage to learn (success means *exits the expected country*, not *answers 200*;
one rotation at a time; kill by address rather than by binary name; test tunnels must not outlive their
attempt).

#### Health check: `scripts/netninja-pool-health.sh`

A pool is only as good as its spare: with two verified nodes one can die and traffic keeps leaving Thai; with
one there is nothing behind it. The check asks the proxy's own `/geo-check` how many nodes are `CURRENT` or
`ok` **and** really exit `EXPECT_COUNTRY` — a node that is configured but dead is not a spare and never
counts — and alerts when that drops below `MIN_NODES` (default 2).

```bash
sudo ./scripts/netninja-pool-health.sh --status   # what it sees right now, no alert
sudo ./scripts/netninja-pool-health.sh            # check + alert (exit 1 when thin)
MIN_NODES=99 sudo -E ./scripts/netninja-pool-health.sh   # prove the alert path works
```

The journal and `/var/log/netninja-pool-health.log` always receive the alert; `ALERT_CMD` in
`/etc/netninja/pool-health.conf` (0600, because it can hold a webhook URL or a bot token) sends it off the box,
with ready-made ntfy / Telegram / webhook lines in `examples/netninja-pool-health.conf.example`. Only
`ALERT_AFTER` consecutive bad checks are allowed to page anyone — right after a proxy restart the egress country
reads `unverified` for ~20s, and a blip is not a lost spare — then it repeats at most every `ALERT_REPEAT_MIN`
minutes while the pool stays thin, and once when it recovers. The deploy script installs it as
`/opt/netninja/netninja-pool-health.sh` behind `netninja-pool-health.timer` (every 2 minutes), and a thin pool
leaves `netninja-pool-health.service` **failed**, so `systemctl --failed` shows it too.

The same path carries the one finding the pool cannot see: the proxy's `missing siblings` — a listed site's
mirror on another TLD that is still exiting this server's country. It alerts on its own transition (body:
the host and the domain to add), repeats with `ALERT_REPEAT_MIN`, clears itself when the list gains the entry,
and `SIBLING_ALERT=0` silences just that alert while the pool alerts keep working. `ALERT_CMD` also receives
`POOL_HEALTH_MISSING_SIBLINGS`.

### 2. Geo session — Thai ads as well

One web page pulls in dozens of third-party domains (ad slots, captcha, analytics) and no list covers
them all — and the **ad slot is where the country shows most clearly**, because the ad network picks ads
from the IP it sees. When a client visits a geo domain the proxy **marks that client's session**
(`GEO_SESSION_TTL`, default 15m) and everything the page loads afterwards egresses Thai too, except for

- domains the PAC already sends `DIRECT` (speedtest/apple/googlevideo, plus Google's ad stack) and video/CDN — full speed kept
- the server itself (keepalive/dashboard) — never pushed through the VPN
- hosts listed in `GEO_SESSION_EXCLUDE`

**Ads:** what counts as an "ad host" is the **real blocklist the proxy already loads**
(`ADBLOCK_URL` / `ADBLOCK_PATH`, e.g. HaGeZi), not a hardcoded list — an ad host inside a geo session is
**not blocked but egressed Thai**, which is what makes Thai ads appear (set `GEO_ADS_EGRESS=1` to route
ads Thai for every client, or `GEO_SESSION=ads|off` to pick the mode).

**Google's ad stack is the exception — it stays direct.** `doubleclick.net`, `googlesyndication.com`,
`googleadservices.com`, `googletagservices.com` and `adservice.google.*` are on the built-in direct set,
so the PAC hands them straight to the client and the session router never sends them Thai. Google fills a
slot from the edge closest to the requesting IP, and a VPN edge is the wrong kind of close: it often
answers with an empty slot, at tunnel latency. The clients this proxy serves are already on a Thai last
mile, so direct still means Thai ads. While the ad flow is active those hosts are let through the blocker
instead of being refused; outside it they are blocked like any other ad host. Add more with
`PAC_DIRECT_DOMAINS` — no rebuild needed.

### 3. Geo domain list — nothing is built into the code

**No domain is compiled into the binary.** The proxy merges its list from

| Source | Details |
|---|---|
| `GEO_DOMAINS` | domains separated by comma/newline (env) |
| `GEO_DOMAINS_FILE` | one domain per line (default `/opt/netninja/geo-domains.txt`), hot reloaded ~20s |
| `GEO_DOMAINS_URL` | fetched remotely at boot + refreshed every `GEO_REFRESH_HOURS` (default 24h), cached on disk |

A source that fails to load **does not wipe what is already there** (the cache / last known list stays
in use). The list this deployment ships lives in `data/geo-domains.txt`; the deploy helper uploads it, or copy it to `/opt/netninja/geo-domains.txt` and edit it directly. It
accepts adblock/hosts formats (`||example.com^`, `*.example.com`, `example.com:8080`), matches subdomains
automatically, and rejects single-label entries (so `tv` cannot match half the internet).

#### A missing entry reports itself — siblings on other TLDs

A geo session can only fix what the list names, and the failure it hides is the quiet one: run `ometv.chat`
while the list holds just `ometv.com` and every connection of that site leaves with the server's own country —
the page looks Thai while the peer matching runs on the wrong country. No pool check can see that, because it
looks exactly like ordinary traffic. So every dial the route *cannot* carry is compared against the names the
list already knows (`ometv` from `ometv.com`, `ome` from `ome.tv`); a hit is a listed site's mirror on another
TLD:

```
[GEO][missing] api.ometv.chat left with this server's country while ometv.com is on the geo list
               — same name "ometv" on another TLD; add api.ometv.chat if that site should exit TH
```

It is logged once per host, shown in `/geo-check` as `missing siblings` and in `/geo-status.json` as
`missing_siblings` (so the keepalive page or any scraper can read it), and `netninja-pool-health.sh` turns it
into an alert on the box's usual channel. Findings disappear on their own once the list gains the entry — a
reload drops the ones the new list covers. The check is one map probe (~50ns, no allocation) on the direct
dial path and never changes routing: the entry is still added by hand, because it is a guess about someone
else's infrastructure. `GEO_SIBLING_DISABLE=1` turns the detection off.

DNS still resolves at the proxy (with a DoH fallback), so Cisco Umbrella on the client side never sees
the queries.

Check everything at `http://<server>:5988/geo-check` (from outside the machine it asks for admin
credentials — see *Endpoint access*) — it shows every node (`CURRENT` / `ok` / `unusable`, country, RTT,
fails), the session mode, the origin/count of the domain list, and the country of the real egress both
direct and through the pool.

### Performance (measured)

- **the dial path of every connection costs only ~211 ns and 0 allocations** (benchmark: a 100k-domain
  geo list + a 50k ad list, `go test -run '^$' -bench GeoEgressForDialPath -benchmem ./cmd/proxy`) —
  millions of times less than the dial RTT (ms)
- a connection that actually egresses Thai adds ~1 µs — insignificant next to a handshake
- a dead node costs one round trip (failover happens inside the dial), not a long timeout
- probing is 1 TCP connect / node / 20s + a country check / node / 5m — a tiny load
  (a few requests per 5 minutes, easy on the ip-api free tier)
- what is really slow is **the tunnel, not the proxy** — measure it at `http://<server>:5988/geo-bench`
  (a table of direct vs each node: `tcp` / `connect` / `total` + country) without disturbing pool state
- video/CDN and the domains the PAC sends `DIRECT` always stay off the Thai path, so YouTube/Netflix are
  never pulled through the VPN

### Country guard

The country guard is still there, but its job changed: the pool now rotates between live nodes by
itself, so the guard only wakes up when there is **no healthy Thai node at all** (and calls
`GEO_ROTATE_CMD` to have the server build a new tunnel). It has cooldown/backoff against rotation
storms and records every rotation in `admin_logs`.

## PAC — iPad Auto mode (no app to install)

```
Wi-Fi → (i) → Configure Proxy → Automatic → URL: http://<SERVER_IP>:5988/proxy.pac
```

- served with `Content-Type: application/x-ns-proxy-autoconfig` and `no-store` — with a wrong content
  type iPadOS silently ignores Auto mode, and a cached PAC keeps pointing at the old address after
  `PROXY_ADDR` changes
- the PAC returns `PROXY <server>:5988` by default and `DIRECT` only for LAN/loopback and the domains in
  `PAC_DIRECT_DOMAINS` (speedtest/apple/googlevideo and Google's ad stack by default) — **the proxy picks the Thai egress
  itself, so the PAC needs to know nothing about geo**
- the alias `/wpad.dat` serves the same file
- the PAC affects HTTP/HTTPS (Safari and any app using CFNetwork) exactly like Manual mode — everything
  goes through the proxy
- the PAC file must be reachable **without** a proxy: open `http://<SERVER_IP>:5988/proxy.pac` in Safari
  on the iPad and you should see the script before you configure anything (seeing it means Auto will work)

## Endpoint access (closed by default)

The endpoints the proxy serves itself leak real operational data (egress IP/country, open tunnels,
client IPs, visited hosts, domain lists), so they are **closed by default**:

| Path | Who may use it |
|---|---|
| `/proxy.pac`, `/wpad.dat` | public — iPadOS fetches the PAC file before a proxy exists and cannot authenticate |
| `/welcome` | public (it only echoes the client's own address) |
| `/geo-check`, `/geo-status.json`, `/geo-bench`, `/logs`, `/ws`, `/`, `/status` | local requests, admin credentials, or `DIAG_TOKEN` |
| `/admin*`, `/settings` | admin credentials / proxy user (as before) |

- A request made **on the server** (the deploy script curls `http://127.0.0.1:5988/geo-check`) always
  passes — but a request carrying `X-Forwarded-For` / `X-Real-Ip` / `Forwarded` came through a reverse
  proxy, so it is *not* treated as local even though its socket is.
- `DIAG_TOKEN=<secret>` lets a script in: `curl -H "Authorization: Bearer <secret>" …` (or `?token=`).
- `DIAG_PUBLIC=1` opens them all again — not recommended while the port is reachable from the internet.
- Unknown paths need credentials too (fail-closed), so a new endpoint cannot leak by accident.
- The dashboard hands its own query string to the live socket, so `http://<server>:5988/?token=<DIAG_TOKEN>`
  also opens `/ws` when the browser does not resend cached credentials.
- `/geo-bench` answers one request at a time (single-flight) so it cannot be used to hammer the
  tunnels or the country lookup.

### Which password opens which page

Two unrelated credential sets, and using the wrong one looks like a login loop rather than a
authorisation failure:

| Browser prompt | Username | Password |
|---|---|---|
| `NetNinja Diagnostics` — `/`, `/status`, `/geo-check`, `/logs`, `/ws` | `ADMIN_USER` (default `admin`) | `ADMIN_PASS` |
| `NetNinja Admin` — `/admin*` | `ADMIN_USER` | `ADMIN_PASS` |
| `NetNinja Settings` — `/settings` | a `PROXY_USERS` name | that user's password, or `ADMIN_PASS` |

`PROXY_AUTH_ENABLED=0` does **not** mean "no credentials anywhere": it stops the proxy asking the
*client* for a username, and `PROXY_USERS` is discarded while it boots (so `/settings` then accepts
only the admin pair) — the dashboard keeps its own gate either way. It also means **the forward proxy
port accepts anyone**, including traffic to geo-listed hosts that leaves through the Thai pool, so
keep that port closed to the internet (firewall or an allowlist) whenever auth is off.

## Bandwidth Management

- `BW_GLOBAL_MBPS` / `BW_USER_MBPS` — token bucket pacing on both upload and download
  (per-user keys off the username, or the client IP in no-auth mode)
- `BW_BURST_KB` (default `256`) — burst allowance
- `MAX_CONNS_PER_IP` — caps concurrent tunnels per IP so one device cannot take the box down

## Deploy

```bash
make check                                   # offline: list parsing, pool rotation, ads routing, PAC
make                                         # -> dist/proxy_linux + dist/keepalive_linux

# the script must land at /tmp/netninja-deploy.sh, the binaries at the names the
# script expects (/tmp/proxy_linux_new, /tmp/keepalive_server_new)
scp -i azure-sg.key dist/proxy_linux     <USER>@<SERVER_IP>:/tmp/proxy_linux_new
scp -i azure-sg.key dist/keepalive_linux <USER>@<SERVER_IP>:/tmp/keepalive_server_new
scp -i azure-sg.key scripts/netninja-deploy.sh <USER>@<SERVER_IP>:/tmp/netninja-deploy.sh
ssh -i azure-sg.key <USER>@<SERVER_IP> 'sudo bash /tmp/netninja-deploy.sh [--th-egress]'

# ...and hand the server its Thai pool / domain list in the same run:
ssh -i azure-sg.key <USER>@<SERVER_IP> \
  'sudo bash /tmp/netninja-deploy.sh --th-nodes "<node1-host:port>,<node2-host:port>" --th-pool'

# ...or let the pool be discovered on the server (--th-pool writes a discovery
# config the first time) and keep the domain list in the repository:
ssh -i azure-sg.key <USER>@<SERVER_IP> \
  'sudo bash /tmp/netninja-deploy.sh --th-pool \
     --geo-url https://raw.githubusercontent.com/<you>/<repo>/main/data/geo-domains.txt'
```

One run updates **both** services: the geo data is written *first* (the pool file has to be on disk
before the proxy starts, because its pool loop only follows edits while it is running), then the proxy
and the keepalive binary are installed and restarted — each one rolled back on its own if it fails to
come up. `--no-keepalive` deploys the proxy only; `--geo-url` writes
`/etc/systemd/system/netninja-proxy.service.d/geo-url.conf` so `GEO_DOMAINS_URL` survives unit edits.

On Windows there is a PowerShell helper (`scripts\netninja-deploy.ps1`) that scp's `dist\proxy_linux`
**and** `dist\keepalive_linux` (plus `geo-nodes.txt` and `geo-domains.txt` — an untracked root copy wins,
otherwise it uploads the tracked `data\geo-domains.txt` — and the pool supervisor) and runs the same script over ssh. It carries **no server address**: the target comes from `NETNINJA_SERVER` / `NETNINJA_USER` or
from a git-ignored `netninja.local.ps1` in the repository root — so the public host never ends up in this
repository (or its history).

Pool and domain list are plain files on the server, so a tunnel that comes up later only needs its
`host:port` appended to `/opt/netninja/geo-nodes.txt` — the proxy joins it within ~20s. Or let the
supervisor do that: it uploads `scripts/netninja-th-pool.sh` and
`examples/netninja-th-pool.conf.example` along with the binary, and `--th-pool` installs and enables the
service (see *Supply side: `scripts/netninja-th-pool.sh`* above).

### Moving to another machine

Nothing deployment-specific is tracked in this repository, so a new machine just needs the local files
copied across (all git-ignored) and a `make` to rebuild `dist/`:

| File | Why |
|---|---|
| `netninja.local.ps1` | server host/user for the deploy helper — start from `examples/netninja.local.example.ps1` |
| `azure-sg.key` | SSH key for the VM |
| `geo-nodes.txt` | Thai egress pool, one `host:port` per line |
| `geo-domains.txt` | geo domain list |
| `TROUBLESHOOTING.md` | local notes (deliberately not in the repo) |

```bash
tar czf netninja-local.tgz netninja.local.ps1 azure-sg.key geo-nodes.txt geo-domains.txt TROUBLESHOOTING.md
```

The proxy's own runtime settings live on the **server**, not in this repo: copy
`/etc/systemd/system/netninja-proxy.service` (plus everything in
`/etc/systemd/system/netninja-proxy.service.d/` and any `EnvironmentFile=` it points at) so
`GEO_SOCKS5_POOL`, `GEO_DOMAINS_FILE`/`GEO_DOMAINS_URL`, `KEEPALIVE_HOST` and the bandwidth limits
survive the move — and `/etc/netninja/th-pool.conf` for the pool supervisor.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `5988` | Proxy listen port(s), comma-separated |
| `PROXY_AUTH_ENABLED` | `0` | Enable user authentication |
| `PROXY_USERS` | - | `user:pass` pairs, comma-separated |
| `ADMIN_USER` | `admin` | Dashboard username (the `NetNinja Diagnostics` / `NetNinja Admin` realm) |
| `ADMIN_PASS` | - | Dashboard password — also opens `/geo-check`, `/logs`, `/ws`, `/status` |
| `HOP_SOCKS5` | - | SOCKS5 proxy for blocked domains |
| `HOP_DOMAINS` | - | Domains to route via SOCKS5 |
| `GEO_SOCKS5_POOL` | - | Thai egress pool entries, `host:port` comma separated |
| `GEO_SOCKS5_POOL_FILE` | `/opt/netninja/geo-nodes.txt` | Pool file (one entry per line, hot reloaded ~20s) |
| `GEO_SOCKS5` | - | Single egress; joins the pool, or is used alone when no pool is set |
| `GEO_DOMAINS` | - | Geo domains from the environment (comma/newline). Nothing is built in |
| `GEO_DOMAINS_FILE` | `/opt/netninja/geo-domains.txt` | Geo list file, hot reloaded |
| `GEO_DOMAINS_URL` | - | Remote geo list (fetched at boot, cached, refreshed) |
| `GEO_DOMAINS_CACHE` | `<file>.cache` | Where the fetched list is cached |
| `GEO_REFRESH_HOURS` | `24` | Refresh interval for `GEO_DOMAINS_URL` |
| `GEO_EXPECT_COUNTRY` | `TH` | Country every pool node must exit from |
| `GEO_STRICT` | `1` | Fail instead of egressing from this server's own country |
| `GEO_POOL_PROBE` | `20s` | Node liveness/latency probe interval |
| `GEO_POOL_TIMEOUT` | `1500ms` | TCP probe timeout |
| `GEO_POOL_MAX_RTT` | `1500ms` | Slower than this counts as slow |
| `GEO_POOL_SLOW_STRIKES` | `3` | Consecutive slow dials before rotating away |
| `GEO_POOL_FAIL_STRIKES` | `2` | Consecutive failures before marking a node down |
| `GEO_POOL_PENALTY` | `45s` | How long a failed node is left out |
| `GEO_POOL_GEOCHECK` | `5m` | How often each node's country is re-verified |
| `GEO_POOL_ATTEMPTS` | `3` | Nodes tried inside one dial (fast failover) |
| `GEO_SESSION` | `all` | What follows a geo session: `all` / `ads` / `off` |
| `GEO_SESSION_TTL` | `15m` | How long a client stays marked after a geo visit |
| `GEO_SESSION_EXCLUDE` | - | Extra hosts kept on the direct path |
| `GEO_ADS_EGRESS` | `0` | `1` = route ad hosts Thai for every client, not just sessions |
| `GEO_DOMAINS_DISABLE` | `0` | `1` = turn geo routing off |
| `GEO_SIBLING_DISABLE` | `0` | `1` = stop reporting a listed site's mirror on another TLD that still egresses direct |
| `PAC_DIRECT_DOMAINS` | built-in set | Extra hosts sent DIRECT by the PAC file and the session router |
| `GEO_GUARD` | `1` | Re-check the hop's country and rotate the egress when it drifts (`0` = off) |
| `GEO_ROTATE_CMD` | `/bin/bash /opt/vpngate/vpngate-rotate.sh --force` | Command used to rotate the egress |
| `GEO_GUARD_INTERVAL` | `5m` | How often the hop's country is checked |
| `GEO_GUARD_COOLDOWN` | `3m` | Minimum gap between rotations |
| `GEO_GUARD_MAX_PER_HOUR` | `6` | Back off 30m after this many rotations in an hour |
| `BW_GLOBAL_MBPS` | `0` | Aggregate bandwidth cap (`0` = unlimited) |
| `BW_USER_MBPS` | `0` | Per-user bandwidth cap (`0` = unlimited) |
| `MAX_CONNS_PER_IP` | `0` | Concurrent tunnels allowed per client IP (`0` = unlimited) |
| `ADBLOCK_URL` | - | URL to ad blocklist |
| `PROXY_ADDR` | - | Server public address |
| `KEEPALIVE_HOST` | - | Hostname logged specially as a keepalive ping (keeps real domains out of the source) |
| `PROXY_ADDR` / `SERVER_ADDR` | - | (keepalive page) address to show, already masked — no lookup at all |
| `SERVER_LOOKUP_URL` | `http://ip-api.com/json/?fields=query,countryCode` | (keepalive page) where to ask when neither address is set |
| `SERVER_LOOKUP_TTL` | `10m` | (keepalive page) how long that lookup is reused |
| `GEO_STATUS_URL` | `http://127.0.0.1:5988/geo-status.json` | (keepalive page) where to read the Thai state from |
| `GEO_STATUS_TTL` | `15s` | (keepalive page) how long a proxy answer is reused |
| `MASK_KEEP_OCTETS` | `2` | (keepalive page) IPv4 octets left visible, max 3 |
| `DIAG_TOKEN` | - | Bearer/`?token=` secret that may read the diagnostics endpoints |
| `DIAG_PUBLIC` | `0` | `1` = serve `/geo-check`, `/geo-bench`, `/logs`, `/ws`, `/` without credentials |
| `TH_ROTATE_CMD` | `/opt/vpngate/vpngate-rotate.sh --force` | (deploy script) command used to rotate the egress on the server |
| `HOP_SOCKS5` / `GEO_SOCKS5` | - | (server env) address the deploy script probes after rotating |
| `TH_POOL_CONF` | `/etc/netninja/th-pool.conf` | (supervisor) where the slot definitions live |
| `SLOTS` / `SLOT_<n>_SOCKS` / `SLOT_<n>_REPLACE` | - | (supervisor) slot count, its endpoint, and the command that rebuilds it |
| `CHECK_INTERVAL` / `CHECK_TIMEOUT` | `60` / `12` | (supervisor) how often to check, and how long a probe may take |
| `EXPECT_COUNTRY` | `TH` | (supervisor) country every published node must exit from |
| `REPLACE_COOLDOWN` / `MAX_REPLACES_PER_HOUR` | `180` / `6` | (supervisor) per-slot cooldown and the hourly rotation budget |

## Troubleshooting

Measure before you change anything: `http://<server>:5988/geo-bench` (needs credentials — see *Endpoint
access*; read each node's `total` against `direct` — more than 2-3× means dropping that node or lowering
`GEO_POOL_MAX_RTT`). From the server itself no credential is needed:
`curl -s http://127.0.0.1:5988/geo-bench`

`TROUBLESHOOTING.md` is kept **local only** (not tracked in this repository), so the quick checks live
here:

- **OmeTV matches the wrong country** — `http://<server>:5988/geo-check` must show a node marked
  `CURRENT` with `country=TH`. If every node reads `unusable`, bring up another tunnel and append its
  `host:port` to `/opt/netninja/geo-nodes.txt` (the proxy picks it up within ~20s). Then check that the
  host is really on the server's list: `grep -c ometv /opt/netninja/geo-domains.txt`. A session that only
  half-egresses (the page is Thai, the peer matching is not) is a missing entry; a session that never
  changes at all is usually a list that was edited in the repository but never uploaded — the deploy
  script prints which list it installed, and keeps the old one when this run brought none. `missing siblings`
  in the same geo-check output names the entry to add (e.g. `api.ometv.chat` while `ometv.com` is listed),
  and clears itself on the next list reload.
- **a domain-list edit changed nothing** — the proxy reads `/opt/netninja/geo-domains.txt`, not the
  repository. Run the deploy helper again (it uploads the list and reports `domains: <n>`), or edit the
  file on the server directly; either way it reloads within ~20s and `geo-check` prints the list size.
- **nothing egresses Thai at all** — in geo-check, a `domain list` line reading `idle` means there is no
  list yet: set `GEO_DOMAINS_FILE` or `GEO_DOMAINS_URL`.
- **ads are not Thai** — the client has to be inside a geo session (visit a listed site first), or set
  `GEO_ADS_EGRESS=1`.
- **iPad Auto (PAC) does not work** — open `http://<server>:5988/proxy.pac` in Safari first. If you can
  see the script but traffic still does not go through, toggle the Wi-Fi proxy setting off and on
  (iPadOS caches it).
- **slow egress / dead node** — `journalctl -u netninja-proxy -n 120 | grep GEO` logs every pool
  rotation with its reason and RTT.

## License

MIT
