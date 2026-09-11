#!/bin/bash
# NetNinja deploy helper — run as root on the proxy VM.
#
#   bash netninja-deploy.sh                        # install /tmp/proxy_linux_new + restart + verify
#   bash netninja-deploy.sh --th-egress            # ...and rotate the VPNGate egress to a Thai node
#   bash netninja-deploy.sh --th-nodes "a:1080,b:1080"
#                                                  # ...and (re)write the Thai egress pool file
#
# The new binary is expected at /tmp/proxy_linux_new (scp it first), or set
# NEW_BIN=/path/to/binary. The previous binary is kept as proxy_linux.bak-<timestamp>
# and is restored automatically if the new one fails to start.
#
# The Thai pool is data, not code: /opt/netninja/geo-nodes.txt lists one
# host:port SOCKS5 egress per line and the proxy hot reloads it, so a tunnel
# that comes up on the server joins the pool without a redeploy.
set -euo pipefail

DEST=/opt/netninja/proxy_linux
NEW=${NEW_BIN:-/tmp/proxy_linux_new}
TH_EGRESS=0
TH_NODES=""

while [ $# -gt 0 ]; do
  case "$1" in
    --th-egress) TH_EGRESS=1 ;;
    --th-nodes)  shift; TH_NODES="${1:-}" ;;
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
echo "== backup =="
cp -a "$DEST" "$DEST.bak-$STAMP"
ls -l "$DEST" "$DEST.bak-$STAMP"

echo
echo "== install new binary =="
systemctl stop netninja-proxy || true
install -m 0755 "$NEW" "$DEST"
systemctl start netninja-proxy
sleep 3

if [ "$(systemctl is-active netninja-proxy)" != "active" ]; then
  echo "!! new binary failed to start — rolling back"
  journalctl -u netninja-proxy -n 40 --no-pager || true
  cp -a "$DEST.bak-$STAMP" "$DEST"
  systemctl start netninja-proxy || true
  sleep 2
  echo -n "after rollback service: "
  systemctl is-active netninja-proxy || true
  echo "rollback done — binary reverted, geo changes not applied"
  exit 1
fi
echo "service: active"

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

if [ "$TH_EGRESS" = "1" ]; then
  echo
  echo "== rotate VPNGate egress, preferring Thailand =="
  /opt/vpngate/vpngate-rotate.sh --force || true
  sleep 2
  echo -n "hop egress now: "
  curl -s --max-time 12 --socks5-hostname <TH_EGRESS_1>:1080 https://ipinfo.io/json | tr -d '\n ' | head -c 220
  echo
  echo "(ดู /var/log/vpngate-rotate.log ถ้ามันไม่ยอมออกไทย — VPNGate ไม่มี node ไทยที่ใช้ได้เสมอ)"
  echo "สำหรับ pool หลาย node: ให้สคริปต์ฝั่ง server ของคุณ append host:port ลง /opt/netninja/geo-nodes.txt"
fi

echo
echo "== proxy geo / bandwidth log =="
journalctl -u netninja-proxy -n 120 --no-pager | grep -E "GEO|HOP|BW|LIMIT|PANIC" || true

echo
echo "== geo-check (จากในเครื่อง server) =="
curl -s --max-time 40 http://127.0.0.1:5988/geo-check || true

echo
echo "== เสร็จแล้ว: ตรวจซ้ำจากเครื่องคุณได้ที่ http://<SERVER_IP>:5988/geo-check =="
