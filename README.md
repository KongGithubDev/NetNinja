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

## Geo Routing — ออกไทยเสถียรด้วย Thai egress pool

Forward proxy ทำให้ปลายทางเห็น **IP ของ proxy** เสมอ server ที่มาเลเซียจึงดูเป็นมาเลเซียต่อ
OmeTV → จับคู่ได้แต่คนมาเลเซีย โดเมนที่อยู่ใน **geo list** จะถูก dial ผ่าน Thai egress pool
แทน ปลายทางจึงเห็นเป็นไทย

```
OmeTV ──TLS/WS──> proxy (MY) ──SOCKS5──> Thai pool ──> OmeTV เห็นเป็น TH
```

### 1. Thai egress pool — หลาย node + node สำรอง + auto-rotate

`GEO_SOCKS5_POOL` รับ SOCKS5 egress หลายตัว (แต่ละตัวคือ tunnel ไทยหนึ่งเส้นบน server) แล้ว proxy จะ

- **probe ทุก node** ทุก `GEO_POOL_PROBE` (ค่าเริ่มต้น 20s) วัด RTT จริง
- **ยืนยันประเทศจริง**ของแต่ละ node ผ่าน ip-api ทุก `GEO_POOL_GEOCHECK` (ค่าเริ่มต้น 5m) —
  node ที่ออกประเทศอื่นจะ **ไม่ถูกใช้เลย** ไม่มีการหมุนข้ามชาติแบบเงียบ ๆ
- **เกาะ node ปัจจุบันไว้** ตราบใดที่ยังเร็วและยังออกไทย (OmeTV จึงไม่ถูกตัดกลางบทสนทนา)
- **หมุนทันที** เมื่อ node ตาย (`GEO_POOL_FAIL_STRIKES` ครั้งติด) หรือช้ากว่า `GEO_POOL_MAX_RTT`
  ติดกัน `GEO_POOL_SLOW_STRIKES` ครั้ง และ **failover ภายใน dial เดียว** จึงเสียแค่ round trip เดียว
- ถ้าไม่มี node ไทยที่ใช้ได้เลย จะเรียก `GEO_ROTATE_CMD` ให้ server สร้าง tunnel ใหม่ (มี cooldown/backoff)
- `GEO_STRICT=1` (ค่าเริ่มต้น) — ถ้าไม่มี egress ไทย จะ **fail** แทนที่จะหลุดออกจาก IP ของ server เอง

รายชื่อ node เป็น **data**: `/opt/netninja/geo-nodes.txt` (บรรทัดละ `host:port`) proxy
hot reload ทุก ~20 วินาที → tunnel ที่ server เพิ่งเปิดจะเข้าร่วม pool เองโดยไม่ต้อง deploy ซ้ำ
(หรือส่งผ่าน `GEO_SOCKS5_POOL="<TH_EGRESS_1>:1080,<TH_EGRESS_2>:1080"` ก็ได้)

### 2. Geo session — ให้ ad slot ออกไทยด้วย

หน้าเว็บหนึ่งหน้าดึง third-party มาหลายสิบโดเมน (ad slot, captcha, analytics) ซึ่งไม่มีลิสต์ไหนไล่ครบ
และ **ad slot คือจุดที่ประเทศโผล่ชัดที่สุด** เพราะ ad network ยิงโฆษณาตาม IP ที่มันเห็น
พอ client เข้าโดเมนใน geo list แล้ว proxy จะ **mark session ของ client นั้น** (`GEO_SESSION_TTL`
ค่าเริ่มต้น 15m) แล้วทุกอย่างที่โหลดตามมาในหน้านั้นออกไทยตามไปด้วย เว้นแต่

- โดเมนที่ PAC ส่ง `DIRECT` อยู่แล้ว (speedtest/apple/googlevideo) และ video/CDN → คงความเร็วเดิม
- ตัว server เอง (keepalive/dashboard) → ไม่ถูกดันผ่าน VPN
- โฮสต์ใน `GEO_SESSION_EXCLUDE` ที่กำหนดเพิ่ม

**โฆษณา:** ตัวตัดสินว่าโฮสต์ไหน "เป็นโฆษณา" คือ **blocklist จริงที่ proxy โหลดอยู่แล้ว**
(`ADBLOCK_URL` / `ADBLOCK_PATH` เช่น HaGeZi) ไม่ใช่ลิสต์ที่ hardcode ในโค้ด — โฮสต์ที่ถูกตัดสินว่าเป็น
โฆษณาและอยู่ใน geo session จะ **ไม่ถูกบล็อก แต่ถูกส่งออกไทย** จึงได้โฆษณาไทยในหน้านั้น
(ตั้ง `GEO_ADS_EGRESS=1` ถ้าอยากให้โฆษณาออกไทยทุก client, `GEO_SESSION=ads|off` เพื่อเลือกโหมด)

### 3. Geo domain list — ไม่มีลิสต์ในโค้ด

**ไม่มีโดเมนใดถูก compile เข้าไปใน binary** เลย proxy รวมรายการจาก

| Source | รายละเอียด |
|---|---|
| `GEO_DOMAINS` | โดเมนคั่นด้วย comma/newline (env) |
| `GEO_DOMAINS_FILE` | ไฟล์บรรทัดละโดเมน (ค่าเริ่มต้น `/opt/netninja/geo-domains.txt`) hot reload ~20s |
| `GEO_DOMAINS_URL` | ดึงระยะไกลตอนบูต + refresh ทุก `GEO_REFRESH_HOURS` (ค่าเริ่มต้น 24h) cache ลงดิสก์ |

แหล่งที่ดึงไม่สำเร็จจะ **ไม่ล้างของเดิมทิ้ง** (ใช้ cache/รายการล่าสุดต่อ) ไฟล์ตัวอย่างอยู่ที่
`geo-domains.example.txt` — copy ไปเป็น `/opt/netninja/geo-domains.txt` แล้วแก้ได้ทันที
รองรับรูปแบบ adblock/hosts (`||example.com^`, `*.example.com`, `example.com:8080`),
subdomain match อัตโนมัติ และ entry ที่มี label เดียวจะถูกปฏิเสธ (กัน `tv` ไปแมตช์ครึ่งเน็ต)

DNS ยัง resolve ที่ proxy (มี DoH fallback) ดังนั้น Cisco Umbrella ฝั่ง client ไม่เห็น query

ตรวจทุกอย่างได้ที่ `http://<server>:5988/geo-check` — แสดง node แต่ละตัว
(`CURRENT` / `ok` / `unusable`, ประเทศ, RTT, fails), โหมด session, ที่มา/จำนวนโดเมน
และประเทศของ egress จริงทั้ง direct และผ่าน pool

### Country guard

Country guard ยังอยู่ แต่เปลี่ยนหน้าที่: pool หมุนระหว่าง node ที่ยัง live เองอยู่แล้ว guard จึง
ตื่นมาเฉพาะตอนที่ **ไม่มี node ไทยที่ healthy เลย** (และเรียก `GEO_ROTATE_CMD` ให้ server สร้าง tunnel ใหม่)
มี cooldown/backoff กันหมุนรัว และบันทึกทุกครั้งลง `admin_logs`

## PAC — ตั้ง iPad แบบ Auto (ไม่ต้องลงแอป)

```
Wi-Fi → (i) → Configure Proxy → Automatic → URL: http://<SERVER_IP>:5988/proxy.pac
```

- จ่ายด้วย `Content-Type: application/x-ns-proxy-autoconfig` + `no-store` — ถ้า content type ผิด
  iPadOS จะไม่ยอมใช้ Auto mode แบบเงียบ ๆ และ PAC ที่ cache ไว้จะค้างหลังย้าย `PROXY_ADDR`
- PAC คืน `PROXY <server>:5988` เป็นค่าเริ่มต้น และ `DIRECT` เฉพาะ LAN/loopback กับโดเมนใน
  `PAC_DIRECT_DOMAINS` (ค่าเริ่มต้น speedtest/apple/googlevideo) — **proxy เป็นคนเลือก Thai egress
  เอง PAC จึงไม่ต้องรู้เรื่อง geo เลย**
- alias `/wpad.dat` ชี้ไปไฟล์เดียวกัน
- PAC มีผลกับ HTTP/HTTPS (Safari และแอปที่ใช้ CFNetwork) เหมือนโหมด Manual ทุกอย่างที่วิ่งผ่าน proxy
- ไฟล์ PAC ต้องโหลดได้ **โดยไม่ผ่าน proxy** — เปิด `http://<SERVER_IP>:5988/proxy.pac`
  ใน Safari บน iPad ควรเห็นสคริปต์ก่อนตั้งค่า (ถ้าเห็น = Auto ใช้ได้แน่นอน)

## Bandwidth Management

- `BW_GLOBAL_MBPS` / `BW_USER_MBPS` — token bucket pacing ทั้ง upload และ download
  (per-user นับตาม username หรือ client IP ในโหมด no-auth)
- `BW_BURST_KB` (default `256`) — burst allowance
- `MAX_CONNS_PER_IP` — cap tunnel พร้อมกันต่อ IP กันอุปกรณ์ตัวเดียวลากเครื่องล่ม

## Deploy

```bash
# tests first (offline: list parsing, pool rotation, session/ads routing, PAC)
go test proxy.go ansi_windows.go keepalive_windows.go proxy_geo_test.go

go build -o /tmp/proxy_linux_new proxy.go keepalive_linux.go ansi_other.go
scp -i azure-sg.key /tmp/proxy_linux_new netninja-deploy.sh <USER>@<SERVER_IP>:/tmp/
ssh -i azure-sg.key <USER>@<SERVER_IP> 'sudo bash /tmp/netninja-deploy.sh [--th-egress]'

# ...and hand the server its Thai pool / domain list in the same run:
ssh -i azure-sg.key <USER>@<SERVER_IP> \
  'sudo bash /tmp/netninja-deploy.sh --th-nodes "<TH_EGRESS_1>:1080,<TH_EGRESS_2>:1080"'

```

On Windows there is a PowerShell helper (`netninja-deploy.ps1`) that scp's `dist\proxy_linux`
(plus `geo-nodes.txt` / `geo-domains.txt` when present) and runs the same script over ssh.
It carries **no server address**: the target comes from `NETNINJA_SERVER` / `NETNINJA_USER`
or from a git-ignored `netninja.local.ps1` next to the script — so the public host never
ends up in this repository (or its history).

Pool and domain list are plain files on the server, so a tunnel that comes up later only needs
its `host:port` appended to `/opt/netninja/geo-nodes.txt` — the proxy joins it within ~20s.

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

## Troubleshooting

`TROUBLESHOOTING.md` is kept **local only** (not tracked in this repository), so the quick checks
live here:

- **OmeTV จับคู่ผิดประเทศ** — `http://<server>:5988/geo-check` ต้องมี node ที่ขึ้น `CURRENT` และ
  `country=TH` ถ้าขึ้น `unusable` หมด: เปิด tunnel เพิ่มแล้ว append `host:port`
  ลง `/opt/netninja/geo-nodes.txt` (proxy รับเองภายใน ~20s)
- **geo ไม่ออกไทยเลย** — ใน geo-check ถ้าบรรทัด `domain list` ขึ้น `idle` = ยังไม่มีรายการ:
  ตั้ง `GEO_DOMAINS_FILE` หรือ `GEO_DOMAINS_URL`
- **โฆษณาไม่ขึ้นเป็นไทย** — ต้องอยู่ใน geo session (เข้าเว็บในลิสต์ก่อน) หรือตั้ง `GEO_ADS_EGRESS=1`
- **iPad ใช้ Auto (PAC) ไม่ได้** — เปิด `http://<server>:5988/proxy.pac` ใน Safari ก่อน
  ถ้าเห็นสคริปต์แต่ยังไม่ออก ให้ปิด/เปิด proxy ในการตั้งค่า Wi-Fi ใหม่ (iPad cache การตั้งค่าไว้)
- **egress ช้า / node ตาย** — `journalctl -u netninja-proxy -n 120 | grep GEO` แสดงทุกครั้งที่ pool
  หมุน node พร้อมเหตุผลและ RTT

## License

MIT
