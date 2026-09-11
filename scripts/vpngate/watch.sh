#!/bin/bash
# Watchdog for the VPNGate egress tunnel (dynamic failover).
# escalation: dead once -> bounce; still dead next cycle -> rotate (fresh pick)
#
# "Dead" includes "up but exiting the wrong country": a tunnel to Japan answers
# HTTP 200, but the Thai pool ignores it, so leaving the watchdog happy with it
# kept the legacy slot outside Thailand indefinitely. The reachability check was
# the only thing it looked at.
set -u
EXPECT_COUNTRY=${EXPECT_COUNTRY:-${GEO_EXPECT_COUNTRY:-TH}}
SOCKS=172.30.77.2:1080

country() {
  curl -s --max-time 6 --socks5-hostname "$SOCKS" \
    "http://ip-api.com/json/?fields=countryCode" 2>/dev/null \
    | sed -n 's/.*"countryCode":"\([A-Za-z]*\)".*/\1/p'
}

ts=$(date +%s)
code=$(curl -sS --max-time 8 -o /dev/null -w '%{http_code}' --socks5-hostname "$SOCKS" https://ifconfig.me/ 2>/dev/null || echo 000)

reason="no egress (code=$code)"
if [ "$code" = "200" ]; then
  cc=$(country)
  if [ -z "$EXPECT_COUNTRY" ] || [ "$cc" = "$EXPECT_COUNTRY" ]; then
    rm -f /tmp/vpngate-fail1
    exit 0
  fi
  # Reachable but a foreign exit: fine for HOP_SOCKS5, useless as the Thai
  # egress. Do not bounce it every 30s cycle - VPNGate gains Thai nodes slowly,
  # so look again every WRONG_CC_RETRY and leave the working tunnel alone in
  # between (each hunt costs an API call plus minutes of probing).
  wlast=$(cat /tmp/vpngate-last-wrongcc 2>/dev/null || echo 0)
  if [ $((ts - wlast)) -lt ${WRONG_CC_RETRY:-1800} ]; then
    exit 0
  fi
  echo "$ts" > /tmp/vpngate-last-wrongcc
  rm -f /tmp/vpngate-fail1
  logger -t vpngate-watch "egress is up but exits ${cc:-unknown}, expected $EXPECT_COUNTRY - rotating"
  /opt/vpngate/vpngate-rotate.sh >>/var/log/vpngate-watch.log 2>&1
  exit 0
fi

last=$(cat /tmp/vpngate-last-restart 2>/dev/null || echo 0)
if [ $((ts - last)) -lt 60 ]; then
  exit 0
fi
echo "$ts" > /tmp/vpngate-last-restart

if [ -f /tmp/vpngate-fail1 ]; then
  rm -f /tmp/vpngate-fail1
  logger -t vpngate-watch "unhealthy twice ($reason) - running dynamic rotate"
  /opt/vpngate/vpngate-rotate.sh >>/var/log/vpngate-watch.log 2>&1
else
  echo "$ts" > /tmp/vpngate-fail1
  logger -t vpngate-watch "unhealthy ($reason) - bouncing vpngate-th"
  systemctl restart vpngate-th
fi
exit 0
