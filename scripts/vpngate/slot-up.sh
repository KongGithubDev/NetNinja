#!/bin/bash
# OpenVPN --up hook for a numbered Thai egress slot (vpngate-th@<N>).
#
# OpenVPN passes the tun device it just created as $1, and the unit forces
# --dev tun<N>, so the slot number comes from the device name itself. (SLOT is
# only a fallback: OpenVPN does not pass the unit's environment through to the
# hook, which is exactly how two slots once ended up on the same address.)
#
# Each slot owns one source address, one routing table and one SOCKS5 listener,
# so a slot can be torn down or rebuilt without touching its neighbours.
dev=$1
N=${SLOT:-}
if [ -z "$N" ]; then
  N=$(printf '%s' "$dev" | sed -n 's/^tun\([0-9]\+\)$/\1/p')
fi
case "$N" in
  ''|*[!0-9]*) echo "slot-up: cannot determine the slot (dev='$dev')" >&2; exit 1 ;;
esac

IP=172.30.77.$((N + 1))
TABLE=$((309 + N))
LOG=/var/log/vpngate-socks-$N.log
PIDF=/run/vpngate-slot-$N.pid

# Start from a clean slate *for this slot only*: a previous run may have left an
# address, a stale rule or a listener behind.
if [ -f "$PIDF" ]; then
  kill "$(cat "$PIDF" 2>/dev/null)" 2>/dev/null || true
  rm -f "$PIDF"
fi
ip -o addr show to "$IP/32" 2>/dev/null | awk '{print $2}' | while read -r d; do
  ip addr del "$IP/32" dev "$d" 2>/dev/null || true
done
ip rule del from "$IP" lookup "$TABLE" 2>/dev/null || true

ip addr add "$IP/32" dev "$dev"
ip rule add from "$IP" lookup "$TABLE"
ip route replace default dev "$dev" table "$TABLE"

# The SOCKS5 listener binds the slot's tunnel address, so a client connecting to
# $IP:1080 leaves through this tunnel and nothing else does.
LISTEN="$IP:1080" DEV="$dev" nohup /opt/vpngate/socks5ns >>"$LOG" 2>&1 &
echo $! > "$PIDF"
exit 0
