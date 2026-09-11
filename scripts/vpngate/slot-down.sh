#!/bin/bash
# OpenVPN --down hook / ExecStopPost for a numbered Thai egress slot.
# Tears down only this slot; the neighbours keep their tun, table and listener.
dev=${1:-}
N=${SLOT:-}
if [ -z "$N" ]; then
  N=$(printf '%s' "$dev" | sed -n 's/^tun\([0-9]\+\)$/\1/p')
fi
case "$N" in
  ''|*[!0-9]*) echo "slot-down: cannot determine the slot (dev='$dev')" >&2; exit 0 ;;
esac

IP=172.30.77.$((N + 1))
TABLE=$((309 + N))
PIDF=/run/vpngate-slot-$N.pid

# 1) the listener we started, by pid file
if [ -f "$PIDF" ]; then
  kill "$(cat "$PIDF" 2>/dev/null)" 2>/dev/null || true
  rm -f "$PIDF"
fi

# 2) fallback: whatever still holds this slot's address (e.g. after a hard kill)
pid=$(ss -ltnp "sport = :1080" 2>/dev/null | awk -v want="$IP:1080" '$4 == want {print $NF}' \
      | sed -n 's/.*pid=\([0-9]\+\).*/\1/p' | head -1)
[ -n "$pid" ] && kill "$pid" 2>/dev/null || true

ip -o addr show to "$IP/32" 2>/dev/null | awk '{print $2}' | while read -r d; do
  ip addr del "$IP/32" dev "$d" 2>/dev/null || true
done
ip rule del from "$IP" lookup "$TABLE" 2>/dev/null || true
ip route flush table "$TABLE" 2>/dev/null || true
exit 0
