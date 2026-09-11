#!/bin/bash
# install-slots.sh — install the numbered Thai egress slots on the proxy VM.
#
#   scp -r scripts/vpngate <user>@<vm>:/tmp/netninja-slots
#   sudo bash /tmp/netninja-slots/install-slots.sh
#
# Idempotent, and deliberately additive: slot 1 stays the legacy
# vpngate-th.service (rotated by the proxy's geo guard). This adds
# vpngate-th@<N> for N >= 2 — each with its own tun, source address, routing
# table and SOCKS5 listener — and hands them to the pool supervisor, whose
# SLOT_<n>_REPLACE brings them up and repairs them from then on.
#
# It returns in seconds: the (slow) VPN handshakes happen in the supervisor, so
# watch them with `netninja-th-pool.sh --status` and the per-slot logs.
#
# SLOTS: declare only as many slots as there are usable Thai nodes, otherwise
# the supervisor spends its rotation budget rebuilding a slot that cannot exist.
set -euo pipefail

SRC=${SRC:-/tmp/netninja-slots}
SLOTS=${SLOTS:-"2"}            # one slot per usable Thai node VPNGate offers
CONF=/etc/netninja/th-pool.conf

[ "$(id -u)" = "0" ] || { echo "run as root" >&2; exit 1; }

echo "== hooks, picker and systemd template =="
install -m 0755 "$SRC/slot-up.sh"   /opt/vpngate/slot-up.sh
install -m 0755 "$SRC/slot-down.sh" /opt/vpngate/slot-down.sh
install -d -m 0755 /usr/local/sbin
install -m 0755 "$SRC/netninja-th-slot-up.sh" /usr/local/sbin/netninja-th-slot-up.sh
install -m 0644 "$SRC/vpngate-th@.service" /etc/systemd/system/vpngate-th@.service
if [ -f /tmp/netninja-th-pool.sh ]; then
  install -m 0755 /tmp/netninja-th-pool.sh /opt/netninja/netninja-th-pool.sh
  echo "   supervisor updated from /tmp/netninja-th-pool.sh"
fi
systemctl daemon-reload

echo
echo "== reset the extra slots (clear anything an earlier run left behind) =="
for n in $SLOTS; do
  ip="172.30.77.$((n + 1))"
  table=$((309 + n))
  pidf="/run/vpngate-slot-$n.pid"
  systemctl stop "vpngate-th@$n" 2>/dev/null || true
  SLOT=$n bash /opt/vpngate/slot-down.sh "tun$n" 2>/dev/null || true
  rm -f "$pidf"
  ip rule del from "$ip" lookup "$table" 2>/dev/null || true
  ip route flush table "$table" 2>/dev/null || true
  ( ip -o addr show to "$ip/32" 2>/dev/null || true ) | awk '{print $2}' | while read -r d; do
    ip addr del "$ip/32" dev "$d" 2>/dev/null || true
  done
  rm -f "/opt/vpngate/slot$n.ovpn"
  : > "/var/log/netninja-th-slot-$n.log"
  chmod 0644 "/var/log/netninja-th-slot-$n.log"
  echo "   slot $n reset ($ip / table $table)"
done

echo
echo "== pool supervisor: declare the extra slots =="
if [ -f "$CONF" ]; then
  cp -a "$CONF" "$CONF.bak-$(date +%Y%m%d-%H%M%S)"
  sed -i '/^# --- netninja slots (managed) ---$/,$d' "$CONF"
  {
    echo "# --- netninja slots (managed) ---"
    echo "# Slot 1 is the legacy vpngate-th.service, rotated by the proxy's geo guard;"
    echo "# the supervisor owns the extra slots below. Each has its own tun, routing"
    echo "# table and SOCKS5 listener, so one dying never touches another."
    for n in $SLOTS; do
      echo "SLOT_${n}_SOCKS=172.30.77.$((n + 1)):1080"
      echo "SLOT_${n}_REPLACE=\"/usr/local/sbin/netninja-th-slot-up.sh $n\""
    done
  } >> "$CONF"
  # A rebuild must not be blocked by earlier churn, and one unfillable slot
  # should not eat the whole hourly budget.
  if grep -qE '^MAX_REPLACES_PER_HOUR=' "$CONF"; then
    sed -i 's/^MAX_REPLACES_PER_HOUR=.*/MAX_REPLACES_PER_HOUR=12/' "$CONF"
  else
    echo 'MAX_REPLACES_PER_HOUR=12' >> "$CONF"
  fi
  install -d -m 0755 /var/lib/netninja-th-pool
  : > /var/lib/netninja-th-pool/replaces
  grep -E '^SLOT_|^# --- netninja slots|^MAX_REPLACES' "$CONF" | sed 's/^/   /'
else
  echo "   !! $CONF is missing — run the deploy script with --th-pool first (slots not declared)"
fi

echo
echo "== hand the slots to the supervisor =="
systemctl restart netninja-th-pool
sleep 5
echo -n "   netninja-th-pool: "
systemctl is-active netninja-th-pool || true
echo "   (it rebuilds each slot now — VPN handshakes take 1-3 min per node)"

echo
echo "== watch =="
echo "   /opt/netninja/netninja-th-pool.sh --status"
echo "   tail -f /var/log/netninja-th-slot-2.log"
echo
echo "== current listeners =="
ss -ltn | grep ':1080' || echo "   (none)"
