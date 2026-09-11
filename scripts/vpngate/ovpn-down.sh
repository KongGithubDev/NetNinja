#!/bin/bash
# OpenVPN --down hook for the legacy Thai egress (slot 1, 172.30.77.2).
#
# Only slot 1's own listener may be killed here. This used to be
#   pkill -f '/opt/vpngate/socks5ns'
# which matches *every* slot's listener on the box: vpngate-rotate.sh calls this
# hook twice per failover attempt, so each rotation silently killed slot 2's
# SOCKS5 port. Slot 2's openvpn stayed up and never rebuilt it, the pool fell to
# one node, and it stayed there until something restarted the slot by hand.
#
# Scope the kill to this slot's own address, the same way slot-down.sh does for
# the numbered slots.
DEV=${1:-tun0}
IP=172.30.77.2
TABLE=310

pid=$(ss -ltnp "sport = :1080" 2>/dev/null | awk -v want="$IP:1080" '$4 == want {print $NF}' \
      | sed -n 's/.*pid=\([0-9]\+\).*/\1/p' | head -1)
[ -n "$pid" ] && kill "$pid" 2>/dev/null || true

ip rule del from "$IP" lookup "$TABLE" 2>/dev/null
ip route flush table "$TABLE" 2>/dev/null
ip addr del "$IP/32" dev "$DEV" 2>/dev/null
exit 0
