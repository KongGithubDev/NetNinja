#!/bin/bash
# netninja-th-slot-up.sh <N> — (re)build Thai egress slot N from VPNGate.
#
# Used by the pool supervisor as SLOT_<n>_REPLACE (and by hand) when a slot is
# dead or has drifted out of Thailand. It walks the Thai nodes VPNGate offers,
# best score first, skipping the ones another slot already holds and the ones
# that failed recently, and only reports success once the slot's own SOCKS5
# really exits TH — a free VPN list is mostly dead entries, so trusting the
# first pick just burns the supervisor's rotation budget.
#
# Slot 1 is the legacy vpngate-th.service, rotated by the proxy's geo guard —
# this script does nothing for it.
#
# Exit codes: 0 = slot is up and exits TH (or nothing needed doing),
#             1 = no usable Thai node right now.
set -u

N="${1:-}"
case "$N" in
  ''|*[!0-9]*) echo "usage: $0 <slot-number>" >&2; exit 2 ;;
esac
if [ "$N" -lt 2 ]; then
  echo "slot 1 is the legacy vpngate-th.service (rotated by the proxy geo guard) — nothing to do"
  exit 0
fi

DIR=/opt/vpngate
IP=172.30.77.$((N + 1))
CONF="$DIR/slot$N.ovpn"
API=https://www.vpngate.net/api/iphone/
LOG="/var/log/netninja-th-slot-$N.log"
STATE="${STATE_DIR:-/var/lib/netninja-th-pool}"
DEAD="$STATE/dead-nodes"
DEAD_TTL=${DEAD_TTL:-3600}        # how long a node that failed is skipped
VERIFY_STEPS=${VERIFY_STEPS:-20}  # 20 x 3s per candidate
MAX_TRIES=${MAX_TRIES:-3}

log() { echo "[$(date '+%F %T')] slot $N: $*" | tee -a "$LOG"; }
mkdir -p "$STATE" 2>/dev/null || true

# Node addresses the other slots are already connected to.
used_nodes() {
  local f
  for f in "$DIR"/active.ovpn "$DIR"/slot*.ovpn; do
    [ -f "$f" ] || continue
    [ "$f" = "$CONF" ] && continue
    grep -h '^remote ' "$f" 2>/dev/null | awk '{print $2}'
  done | sort -u
}

prune_dead() {
  local cut
  [ -f "$DEAD" ] || return 0
  cut=$(( $(date +%s) - DEAD_TTL ))
  awk -v cut="$cut" '$1 >= cut' "$DEAD" > "$DEAD.tmp" 2>/dev/null && mv "$DEAD.tmp" "$DEAD"
  return 0
}

is_dead() { [ -f "$DEAD" ] && awk -v n="$1" '$2 == n { found = 1 } END { exit !found }' "$DEAD"; }
mark_dead() { printf '%s %s\n' "$(date +%s)" "$1" >> "$DEAD"; }

country() {
  curl -s --max-time 6 --socks5-hostname "$IP:1080" \
    "http://ip-api.com/json/?fields=countryCode" 2>/dev/null \
    | sed -n 's/.*"countryCode":"\([A-Za-z]*\)".*/\1/p'
}

list=$(curl -sS --max-time 25 "$API" 2>/dev/null)
if [ -z "$list" ]; then
  log "VPNGate API unreachable — keeping the current config"
  exit 1
fi

# columns: HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,...,Message,Base64
th=$(printf '%s\n' "$list" | awk -F, '
  { sub(/\r$/, "") }
  /^#/ || /^\*/ { next }
  $2 !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { next }
  $7 != "TH" { next }
  NF >= 15 { print $3 "\t" $2 "\t" $NF }' | sort -rn)

used="$(used_nodes)"
prune_dead

tries=0
while IFS="$(printf '\t')" read -r score ip b64; do
  [ -n "$ip" ] || continue
  if printf '%s\n' "$used" | grep -qx "$ip"; then
    continue
  fi
  if is_dead "$ip"; then
    log "skipping $ip — it failed within the last ${DEAD_TTL}s"
    continue
  fi
  tries=$((tries + 1))
  if [ "$tries" -gt "$MAX_TRIES" ]; then
    break
  fi

  log "trying Thai node $ip (score $score)"
  if ! printf '%s' "$b64" | base64 -d > "$CONF.tmp" 2>/dev/null; then
    rm -f "$CONF.tmp"
    log "  bad base64 for $ip — next"
    continue
  fi
  # the unit supplies --auth-user-pass, so a bare directive would make it prompt
  sed -i '/^auth-user-pass/d' "$CONF.tmp"
  mv "$CONF.tmp" "$CONF"
  chmod 0600 "$CONF"
  log "  target $(sed -n 's/^remote //p' "$CONF" | head -1)"

  systemctl restart "vpngate-th@$N"

  cc=""
  for i in $(seq 1 "$VERIFY_STEPS"); do
    sleep 3
    cc=$(country)
    if [ "$cc" = "TH" ]; then
      log "up on $ip — $IP:1080 exits TH (after $((i * 3))s)"
      exit 0
    fi
  done
  log "  node $ip did not come up (last country=${cc:-none}) — next"
  mark_dead "$ip"
done <<EOF
$th
EOF

log "no usable Thai node for this slot right now — leaving it down"
exit 1
