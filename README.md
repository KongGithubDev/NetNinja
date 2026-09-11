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

| Component | Port | Purpose |
|-----------|------|---------|
| `proxy.go` | 5988 | Forward proxy (CONNECT + HTTP) |
| Caddy | 443 | HTTPS termination + reverse proxy |
| `keepalive_server.go` | 8080 | CGNAT keepalive page |

## Quick Start

### Build

```bash
# Linux binary
$env:GOOS="linux"; $env:GOARCH="amd64"; go build -o netninja-proxy-linux proxy.go keepalive_linux.go ansi_other.go

# Keepalive server
$env:GOOS="linux"; $env:GOARCH="amd64"; go build -o netninja-keepalive-linux keepalive_server.go
```

### Deploy to Azure VM

```bash
# Copy binaries
scp -i azure-sg.key netninja-proxy-linux <USER>@<SERVER_IP>:/tmp/proxy_linux
scp -i azure-sg.key netninja-keepalive-linux <USER>@<SERVER_IP>:/tmp/keepalive_server

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
- calls `GEO_ROTATE_CMD` to have the server build a new tunnel when no Thai node is usable at all
  (with cooldown/backoff)
- `GEO_STRICT=1` (default) — **fails** instead of leaking out through the server's own country
  when no Thai egress is available

The node list is **data**: `/opt/netninja/geo-nodes.txt` (one `host:port` per line) is hot reloaded every
~20 seconds, so a tunnel that comes up later joins the pool with no redeploy. It can also come straight
from the environment, e.g. `GEO_SOCKS5_POOL="<node1-host:port>,<node2-host:port>"`.

#### Supply side: `netninja-th-pool.sh`

The proxy looks after the destination end (probe/rotate) but **never builds a tunnel itself** —
`netninja-th-pool.sh` is the other half: it keeps the tunnels *underneath* `/opt/netninja/geo-nodes.txt`
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
`/etc/netninja/th-pool.conf`; start from `netninja-th-pool.conf.example`, which carries three patterns
(tunnels already exist / rebuild each slot / discover listeners that are up).

```bash
sudo ./netninja-th-pool.sh --status          # every slot, its verified country, the published file
sudo ./netninja-th-pool.sh --dry-run --once  # report only — no replace, no write
sudo ./netninja-th-pool.sh --once            # check → repair → publish (good for a systemd timer)
sudo ./netninja-th-pool.sh --daemon          # keep checking every CHECK_INTERVAL (systemd service)
```

The deploy script installs it too — scp `netninja-th-pool.sh` and `netninja-th-pool.conf.example` to
`/tmp` and run `sudo bash /tmp/netninja-deploy.sh --th-pool` (it places
`/opt/netninja/netninja-th-pool.sh`, installs the example config, and creates + enables
`netninja-th-pool.service` — but only once `/etc/netninja/th-pool.conf` exists).

It can be tested offline, with no real tunnel: `bash netninja-th-pool.selftest.sh`
(stub probe + stub replace commands).

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
in use). Copy `geo-domains.example.txt` to `/opt/netninja/geo-domains.txt` and edit it directly. It
accepts adblock/hosts formats (`||example.com^`, `*.example.com`, `example.com:8080`), matches subdomains
automatically, and rejects single-label entries (so `tv` cannot match half the internet).

DNS still resolves at the proxy (with a DoH fallback), so Cisco Umbrella on the client side never sees
the queries.

Check everything at `http://<server>:5988/geo-check` (from outside the machine it asks for admin
credentials — see *Endpoint access*) — it shows every node (`CURRENT` / `ok` / `unusable`, country, RTT,
fails), the session mode, the origin/count of the domain list, and the country of the real egress both
direct and through the pool.

### Performance (measured)

- **the dial path of every connection costs only ~211 ns and 0 allocations** (benchmark: a 100k-domain
  geo list + a 50k ad list, `go test -run '^$' -bench GeoEgressForDialPath -benchmem …`) — millions of
  times less than the dial RTT (ms)
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

## Bandwidth Management

- `BW_GLOBAL_MBPS` / `BW_USER_MBPS` — token bucket pacing on both upload and download
  (per-user keys off the username, or the client IP in no-auth mode)
- `BW_BURST_KB` (default `256`) — burst allowance
- `MAX_CONNS_PER_IP` — caps concurrent tunnels per IP so one device cannot take the box down

## Deploy

```bash
# tests first (offline: list parsing, pool rotation, session/ads routing, PAC)
go test proxy.go ansi_windows.go keepalive_windows.go proxy_geo_test.go

go build -o /tmp/proxy_linux_new proxy.go keepalive_linux.go ansi_other.go
scp -i azure-sg.key /tmp/proxy_linux_new netninja-deploy.sh <USER>@<SERVER_IP>:/tmp/
ssh -i azure-sg.key <USER>@<SERVER_IP> 'sudo bash /tmp/netninja-deploy.sh [--th-egress]'

# ...and hand the server its Thai pool / domain list in the same run:
ssh -i azure-sg.key <USER>@<SERVER_IP> \
  'sudo bash /tmp/netninja-deploy.sh --th-nodes "<node1-host:port>,<node2-host:port>" --th-pool'

```

On Windows there is a PowerShell helper (`netninja-deploy.ps1`) that scp's `dist\proxy_linux`
(plus `geo-nodes.txt` / `geo-domains.txt` when present) and runs the same script over ssh. It carries
**no server address**: the target comes from `NETNINJA_SERVER` / `NETNINJA_USER` or from a git-ignored
`netninja.local.ps1` next to the script — so the public host never ends up in this repository (or its
history).

Pool and domain list are plain files on the server, so a tunnel that comes up later only needs its
`host:port` appended to `/opt/netninja/geo-nodes.txt` — the proxy joins it within ~20s. Or let the
supervisor do that: scp `netninja-th-pool.sh` / `netninja-th-pool.conf.example` along with the binary
and add `--th-pool` (see *Supply side: `netninja-th-pool.sh`* above).

### Moving to another machine

Nothing deployment-specific is tracked in this repository, so a new machine just needs the local files
copied across (all git-ignored):

| File | Why |
|---|---|
| `netninja.local.ps1` | server host/user for the deploy helper — start from `netninja.local.example.ps1` |
| `azure-sg.key` | SSH key for the VM |
| `geo-nodes.txt` | Thai egress pool, one `host:port` per line |
| `geo-domains.txt` | geo domain list |
| `TROUBLESHOOTING.md` | local notes (deliberately not in the repo) |

```bash
tar czf netninja-local.tgz netninja.local.ps1 azure-sg.key geo-nodes.txt geo-domains.txt TROUBLESHOOTING.md
```

The proxy's own runtime settings live on the **server**, not in this repo: copy
`/etc/systemd/system/netninja-proxy.service` (plus any `EnvironmentFile=` it points at) so
`GEO_SOCKS5_POOL`, `GEO_DOMAINS_FILE`/`GEO_DOMAINS_URL`, `KEEPALIVE_HOST` and the bandwidth limits
survive the move.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `5988` | Proxy listen port(s), comma-separated |
| `PROXY_AUTH_ENABLED` | `0` | Enable user authentication |
| `PROXY_USERS` | - | `user:pass` pairs, comma-separated |
| `ADMIN_USER` | `admin` | Dashboard username |
| `ADMIN_PASS` | - | Dashboard password |
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
  `host:port` to `/opt/netninja/geo-nodes.txt` (the proxy picks it up within ~20s).
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
