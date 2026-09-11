#!/bin/bash
# NetNinja deploy helper — run as root on the proxy VM.
#
#   bash netninja-deploy.sh                        # install /tmp/proxy_linux_new +
#                                                  # /tmp/keepalive_server_new, restart both, verify
#   bash netninja-deploy.sh --no-keepalive         # proxy only
#   bash netninja-deploy.sh --th-egress            # ...and rotate the VPNGate egress to a Thai node
#   bash netninja-deploy.sh --th-nodes "a:1080,b:1080"
#                                                  # ...and (re)write the Thai egress pool file
#   bash netninja-deploy.sh --th-pool               # ...and enable the pool supervisor service
#   bash netninja-deploy.sh --geo-url "https://raw.githubusercontent.com/<you>/<repo>/main/data/geo-domains.txt"
#                                                  # ...and point GEO_DOMAINS_URL at a remote list
#
# The new binaries are expected at /tmp/proxy_linux_new and /tmp/keepalive_server_new
# (scp them first), or set NEW_BIN= / KEEPALIVE_BIN=. Each previous binary is kept as
# <name>.bak-<timestamp> and restored automatically if its service fails to start.
#
# Geo data is written first and the services are restarted last, so a fresh proxy
# always boots with its domain list and egress pool already on disk — the pool file
# is only re-read by a pool loop that has to be running, so it must exist at boot.
#
# The Thai pool is data, not code: /opt/netninja/geo-nodes.txt lists one host:port
# SOCKS5 egress per line and the proxy hot reloads it, so a tunnel that comes up on
# the server joins the pool without a redeploy. With --th-pool the supervisor below
# publishes that file by itself (discovering live listeners, or the slots you define).
set -euo pipefail

DEST=/opt/netninja/proxy_linux
NEW=${NEW_BIN:-/tmp/proxy_linux_new}
KEEP_DEST=/opt/netninja/keepalive_server
KEEP_NEW=${KEEPALIVE_BIN:-/tmp/keepalive_server_new}
TH_EGRESS=0
TH_NODES=""
TH_POOL=0
KEEPALIVE=1
GEO_URL=""

while [ $# -gt 0 ]; do
  case "$1" in
    --th-egress)     TH_EGRESS=1 ;;
    --th-nodes)      shift; TH_NODES="${1:-}" ;;
    --th-pool)       TH_POOL=1 ;;
    --geo-url)       shift; GEO_URL="${1:-}" ;;
    --no-keepalive)  KEEPALIVE=0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
  shift || true
done

# A pool file scp'd next to this script wins over the flag.
if [ -z "$TH_NODES" ] && [ -f /tmp/geo-nodes.txt ]; then
  TH_NODES=$(cat /tmp/geo-nodes.txt)
fi

if [ "$(id -u)" != "0" ]; then
  echo "must run as root on the server (ยืนยันตัวตนก่อนรัน)" >&2
  exit 1
fi
if [ ! -f "$NEW" ]; then
  echo "missing $NEW — scp the freshly built binary there first" >&2
  exit 1
fi

STAMP=$(date +%Y%m%d-%H%M%S)

# ---------------------------------------------------------------------------
# geo data first: it has to be on disk before the proxy starts
# ---------------------------------------------------------------------------

if [ -n "$GEO_URL" ]; then
  echo "== proxy drop-in: GEO_DOMAINS_URL =="
  install -d -m 0755 /etc/systemd/system/netninja-proxy.service.d
  cat > /etc/systemd/system/netninja-proxy.service.d/geo-url.conf <<CONF
[Service]
Environment=GEO_DOMAINS_URL=$GEO_URL
CONF
  chmod 0644 /etc/systemd/system/netninja-proxy.service.d/geo-url.conf
  systemctl daemon-reload
  echo "GEO_DOMAINS_URL=$GEO_URL"
  echo "(a list that fails to fetch never wipes the list already on disk)"
fi

if [ -n "$TH_NODES" ]; then
  echo
  echo "== Thai egress pool file =="
  install -d -m 0755 /opt/netninja
  printf '%s\n' "$TH_NODES" | tr ',' '\n' | sed 's/^ *//; s/ *$//' | grep -v '^$' > /opt/netninja/geo-nodes.txt
  chmod 0644 /opt/netninja/geo-nodes.txt
  cat /opt/netninja/geo-nodes.txt
  echo "(proxy picks these up within ~20s — /geo-check shows each node's country and RTT)"
fi

if [ -f /tmp/geo-domains.txt ]; then
  echo
  echo "== geo domain list =="
  install -d -m 0755 /opt/netninja
  if [ -f /opt/netninja/geo-domains.txt ]; then
    cp -a /opt/netninja/geo-domains.txt "/opt/netninja/geo-domains.txt.bak-$(date +%Y%m%d-%H%M%S)"
  fi
  install -m 0644 /tmp/geo-domains.txt /opt/netninja/geo-domains.txt
  echo -n "domains: "
  grep -cvE '^\s*(#|$)' /opt/netninja/geo-domains.txt || true
  echo "(edit this file directly — it reloads in ~20s; or set GEO_DOMAINS_URL for a shared list)"
fi

# The pool *supervisor* is optional: install it when it was scp'd along with the
# binary. It keeps the tunnels under /opt/netninja/geo-nodes.txt alive on its
# own, so the pool stops depending on someone appending host:port by hand.
if [ -f /tmp/netninja-th-pool.sh ]; then
  echo
  echo "== Thai pool supervisor (netninja-th-pool.sh) =="
  install -d -m 0755 /opt/netninja
  install -d -m 0755 /etc/netninja
  install -m 0755 /tmp/netninja-th-pool.sh /opt/netninja/netninja-th-pool.sh
  [ -f /tmp/netninja-th-pool.conf.example ] && \
    install -m 0644 /tmp/netninja-th-pool.conf.example /etc/netninja/th-pool.conf.example
  if [ ! -f /etc/netninja/th-pool.conf ]; then
    echo "-- no /etc/netninja/th-pool.conf — writing the auto-discovery one"
    cat > /etc/netninja/th-pool.conf <<'CONF'
# written by netninja-deploy.sh — discovery mode.
# No slot is managed here: every SOCKS5 listener that is up AND really exits
# EXPECT_COUNTRY (proven through the tunnel itself) is published to POOL_FILE.
# Add SLOT_<n>_SOCKS= and SLOT_<n>_REPLACE= to have the script rebuild tunnels
# too — /etc/netninja/th-pool.conf.example carries the patterns.
POOL_FILE=/opt/netninja/geo-nodes.txt
STATE_DIR=/var/lib/netninja-th-pool
LOG_FILE=/var/log/netninja-th-pool.log
CHECK_INTERVAL=60
CHECK_TIMEOUT=12
EXPECT_COUNTRY=TH
PROBE_URL="http://ip-api.com/json/?fields=query,country,countryCode,city,isp"
REPLACE_COOLDOWN=180
MAX_REPLACES_PER_HOUR=6
# \$4 is escaped on purpose: this file is *sourced*, so a bare $4 would be
# expanded away (and trip `set -u`) before the command is ever run.
DISCOVER_CMD="ss -ltn | awk 'NR>1 {print \$4}' | grep -E ':(1080|1081|1082)$'"
CONF
    chmod 0644 /etc/netninja/th-pool.conf
    echo "(--th-pool will enable the service that publishes /opt/netninja/geo-nodes.txt)"
  fi
  SLOTS=$(grep -cE '^[[:space:]]*SLOT_[0-9]+_SOCKS=' /etc/netninja/th-pool.conf || true)
  echo "config: /etc/netninja/th-pool.conf (${SLOTS:-0} managed slot(s))"
fi

if [ "$TH_POOL" = "1" ]; then
  echo
  echo "== enable netninja-th-pool.service =="
  if [ ! -x /opt/netninja/netninja-th-pool.sh ]; then
    echo "!! /opt/netninja/netninja-th-pool.sh missing — scp netninja-th-pool.sh to /tmp first (service not enabled)"
  elif [ ! -f /etc/netninja/th-pool.conf ]; then
    echo "!! --th-pool needs /etc/netninja/th-pool.conf first (start from the .example) — service not enabled"
  else
    cat > /etc/systemd/system/netninja-th-pool.service <<'UNIT'
[Unit]
Description=NetNinja Thai egress pool supervisor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/netninja/netninja-th-pool.sh --daemon
Restart=always
RestartSec=15

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable --now netninja-th-pool
    sleep 3
    echo -n "netninja-th-pool: "
    systemctl is-active netninja-th-pool || true
    echo "(log: /var/log/netninja-th-pool.log — หรือ journalctl -u netninja-th-pool)"
    # Publish once now so the pool file exists *before* the proxy restarts: the
    # proxy only follows pool edits while its pool loop is running, and that loop
    # starts only when the pool was non-empty at boot.
    /opt/netninja/netninja-th-pool.sh --once || true
    /opt/netninja/netninja-th-pool.sh --status || true
  fi
fi

# ---------------------------------------------------------------------------
# binaries — install and restart, rolling each service back on failure
# ---------------------------------------------------------------------------

deploy_bin() {
  local svc="$1" dest="$2" src="$3"
  echo
  echo "== $svc: install $(basename "$src") =="
  if [ -f "$dest" ]; then
    cp -a "$dest" "$dest.bak-$STAMP"
    ls -l "$dest" "$dest.bak-$STAMP"
  else
    echo "($dest does not exist yet — no backup taken)"
  fi
  systemctl stop "$svc" || true
  install -m 0755 "$src" "$dest"
  systemctl start "$svc"
  sleep 3
  if [ "$(systemctl is-active "$svc")" != "active" ]; then
    echo "!! $svc failed to start with the new binary — rolling back"
    journalctl -u "$svc" -n 40 --no-pager || true
    if [ -f "$dest.bak-$STAMP" ]; then
      cp -a "$dest.bak-$STAMP" "$dest"
      systemctl start "$svc" || true
      sleep 2
    fi
    echo -n "after rollback $svc: "
    systemctl is-active "$svc" || true
    echo "rollback done — binary reverted"
    exit 1
  fi
  echo "$svc: active"
}

deploy_bin netninja-proxy "$DEST" "$NEW"

if [ "$KEEPALIVE" = "1" ]; then
  if [ -f "$KEEP_NEW" ]; then
    deploy_bin netninja-keepalive "$KEEP_DEST" "$KEEP_NEW"
    echo -n "keepalive http check: "
    curl -fsS -o /dev/null -w '%{http_code}\n' --max-time 8 http://127.0.0.1:8080/ || echo "(no answer — journalctl -u netninja-keepalive)"
  else
    echo
    echo "!! $KEEP_NEW missing — keepalive left as it is (scp it first, or set KEEPALIVE_BIN=...)"
  fi
else
  echo
  echo "(keepalive deploy skipped by --no-keepalive)"
fi

if [ "$TH_EGRESS" = "1" ]; then
  # No egress address is hardcoded here: take it from HOP_SOCKS5, from the geo
  # pool file, or from GEO_SOCKS5 in the proxy's own environment.
  EGRESS="${HOP_SOCKS5:-${GEO_SOCKS5:-}}"
  if [ -z "$EGRESS" ] && [ -s /opt/netninja/geo-nodes.txt ]; then
    EGRESS=$(grep -vE '^[[:space:]]*(#|$)' /opt/netninja/geo-nodes.txt | head -1 | tr -d ' \r\n')
  fi
  ROTATE_CMD="${TH_ROTATE_CMD:-/opt/vpngate/vpngate-rotate.sh --force}"
  echo
  echo "== rotate egress, preferring Thailand ($ROTATE_CMD) =="
  # shellcheck disable=SC2086
  $ROTATE_CMD || true
  sleep 2
  if [ -n "$EGRESS" ]; then
    echo -n "egress ($EGRESS) now: "
    curl -s --max-time 12 --socks5-hostname "$EGRESS" https://ipinfo.io/json | tr -d '\n ' | head -c 220
    echo
  else
    echo "(no egress address known — ตั้ง HOP_SOCKS5 หรือใส่ node ลง /opt/netninja/geo-nodes.txt ก่อน)"
  fi
  echo "(ดู log ของสคริปต์หมุน (ค่าเริ่มต้น /var/log/vpngate-rotate.log) ถ้ามันไม่ยอมออกไทย — VPNGate ไม่มี node ไทยที่ใช้ได้เสมอ)"
  echo "สำหรับ pool หลาย node: ให้สคริปต์ฝั่ง server ของคุณ append host:port ลง /opt/netninja/geo-nodes.txt"
fi

echo
echo "== proxy geo / bandwidth log =="
journalctl -u netninja-proxy -n 120 --no-pager | grep -E "GEO|HOP|BW|LIMIT|PANIC" || true

echo
echo "== geo-check (จากในเครื่อง server) =="
# local request → ไม่ต้องมี credential (diagnostics ถูกปิดจากข้างนอกแล้ว)
curl -s --max-time 40 http://127.0.0.1:5988/geo-check || true

echo
echo "== geo-bench (วัดความเร็วจริง: direct vs pool) =="
curl -s --max-time 60 http://127.0.0.1:5988/geo-bench || true

echo
echo "== เสร็จแล้ว: ตรวจซ้ำจากเครื่องคุณได้ที่ http://<SERVER_IP>:5988/geo-check =="
