#!/bin/bash
# Called by OpenVPN after tun is up (args: $1=dev $4=local).
# Everything confined to custom routing table 310 - host main table untouched.
DEV=$1
IP=172.30.77.2
ip addr add $IP/32 dev $DEV 2>/dev/null
ip rule add from $IP lookup 310 2>/dev/null
ip route replace default dev $DEV table 310 2>/dev/null
# Reclaim our own port first: a listener left over from a previous run makes the
# new one fail to bind, which looks exactly like a dead Thai egress. Never pkill
# by binary name here - that takes the numbered slots' listeners down with it.
old=$(ss -ltnp "sport = :1080" 2>/dev/null | awk -v want="$IP:1080" '$4 == want {print $NF}' \
      | sed -n 's/.*pid=\([0-9]\+\).*/\1/p' | head -1)
[ -n "$old" ] && kill "$old" 2>/dev/null && sleep 1
LISTEN=$IP:1080 DEV=tun0 nohup /opt/vpngate/socks5ns >>/var/log/vpngate-socks.log 2>&1 &
exit 0
