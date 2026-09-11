#!/bin/bash
# vpngate-rotate.sh - dynamic VPNGate failover for the NetNinja Thai egress.
# Strategy:
#   1. try to revive the CURRENT active.ovpn first (no API call)
#   2. only if that fails, fetch a fresh list and PREFER Thailand (TH), then any
# Usage: vpngate-rotate.sh [--force]
#
# "Works" means "exits EXPECT_COUNTRY". A tunnel that drifted to another country
# answers HTTP 200 just the same, so reviving one and calling that a success is
# how the Thai pool ends up permanently a node short: the pool ignores a non-TH
# exit, so the slot looks alive and is worth nothing.
set -u

DIR=/opt/vpngate
ACTIVE=$DIR/active.ovpn
AUTH=$DIR/auth.txt
CAND=$DIR/candidate.ovpn
LOG=/var/log/vpngate-rotate.log
API=https://www.vpngate.net/api/iphone/
API_COOLDOWN=$DIR/.api-cooldown
API_COOLDOWN_SEC=120
MAX_TH=3
MAX_TOTAL=6
DEAD="$DIR/.th-dead"                # Thai nodes that just failed, with a TTL
DEAD_TTL=${DEAD_TTL:-1800}
SOCKS=172.30.77.2:1080
EXPECT_COUNTRY=${EXPECT_COUNTRY:-${GEO_EXPECT_COUNTRY:-TH}}

printf 'vpn\nvpn\n' > "$AUTH"

log() { echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }

# One rotation at a time. vpngate-watch.timer fires every 30s while a rotation
# takes minutes, and the two used to share $CAND and /tmp/vpngate-try.log: run A
# would write its Thai config, run B would overwrite it with a Japanese one, and A
# would then print "SUCCESS TH ..." while copying B's file into active.ovpn. That
# is how the legacy tunnel kept ending up outside Thailand with a success line in
# the log saying otherwise.
LOCK=/run/vpngate-rotate.lock
if command -v flock >/dev/null 2>&1; then
  exec 9>"$LOCK"
  if ! flock -n 9; then
    log "another rotation is already running - nothing to do"
    exit 0
  fi
fi

# Per-run scratch files, so a second run cannot clobber this one's candidate.
CAND=$(mktemp -p "$DIR" candidate.XXXXXX.ovpn 2>/dev/null || echo "$DIR/candidate.ovpn")
TRYLOG=$(mktemp -p /tmp vpngate-try.XXXXXX.log 2>/dev/null || echo /tmp/vpngate-try.log)
trap 'rm -f "$CAND" "$TRYLOG"; cleanup_test_tunnels' EXIT

# Only configs named candidate.* come from a test attempt, so this cannot touch
# the real service (active.ovpn) or a numbered slot (slot<N>.ovpn).
cleanup_test_tunnels() {
  pkill -f "openvpn .*--config /opt/vpngate/candidate" 2>/dev/null || true
  return 0
}
cleanup_test_tunnels
sleep 1

egress_country() {
  curl -s --max-time 6 --socks5-hostname "$SOCKS" \
    "http://ip-api.com/json/?fields=countryCode" 2>/dev/null \
    | sed -n 's/.*"countryCode":"\([A-Za-z]*\)".*/\1/p'
}

# Reachable *and* from the country this box exists to provide. Reachability alone
# is not enough: a config that drifted to another country answers 200 too.
egress_ok() {
  local code
  code=$(curl -sS --max-time 6 -o /dev/null -w '%{http_code}' --socks5-hostname "$SOCKS" https://ifconfig.me/ 2>/dev/null || echo 000)
  [ "$code" = "200" ] || return 1
  [ -z "$EXPECT_COUNTRY" ] && return 0
  [ "$(egress_country)" = "$EXPECT_COUNTRY" ]
}

stop_all() {
  systemctl stop vpngate-th 2>/dev/null
  sleep 1
  bash "$DIR/ovpn-down.sh" 2>/dev/null
}

start_service() {
  systemctl start vpngate-th 2>/dev/null
  sleep 5
}

# try connecting a given ovpn config (optionally with auth). returns egress ok=0/1
try_config() {
  local cfg="$1"; local use_auth="$2"; local tag="$3"
  local args_auth=()
  if [ "$use_auth" = "1" ]; then args_auth=(--auth-user-pass "$AUTH"); fi
  /usr/sbin/openvpn --config "$cfg" "${args_auth[@]}" \
    --route-nopull --script-security 2 \
    --up "$DIR/ovpn-up.sh" --down "$DIR/ovpn-down.sh" \
    --connect-retry 1 --connect-timeout 10 --ping 10 --ping-restart 30 \
    --verb 1 >"$TRYLOG" 2>&1 &
  local pid=$!
  local ok=0
  # 30 x 2s, matching the numbered slots' own verifier (VERIFY_STEPS=20 x 3s).
  # 30s was too short for the Thai nodes: they do come up, just slowly, and
  # giving up early is what kept the legacy slot on a Japanese exit.
  for i in $(seq 1 30); do
    sleep 2
    if egress_ok; then ok=1; break; fi
    kill -0 "$pid" 2>/dev/null || break
  done
  kill -TERM "$pid" 2>/dev/null; sleep 1; kill -KILL "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
  # SIGTERM is not always enough: a test tunnel that survives keeps re-running
  # ovpn-up.sh on every reconnect, rewriting slot 1's address and SOCKS5 listener
  # under the real service (and keeping a rejected candidate's routing alive).
  cleanup_test_tunnels
  sleep 1; bash "$DIR/ovpn-down.sh" 2>/dev/null
  [ "$ok" = "1" ]
}

# --- step 1: revive current active config (no API) --------------------------
if ! systemctl is-active --quiet vpngate-th; then
  systemctl start vpngate-th 2>/dev/null
else
  systemctl restart vpngate-th 2>/dev/null
fi
sleep 6
if egress_ok; then
  log "revived existing active.ovpn (no API) - egress OK ($EXPECT_COUNTRY)"
  exit 0
fi
# Answered but from the wrong country? Then the tunnel is fine for what else uses
# it (HOP_SOCKS5 points at 172.30.77.2), it just is not a Thai egress - keep that
# distinction, because it decides whether we may leave the config alone below.
revived_cc=$(egress_country)
revived_reachable=0
[ -n "$revived_cc" ] && revived_reachable=1
log "active.ovpn is not a $EXPECT_COUNTRY egress right now (country=${revived_cc:-none}, reachable=$revived_reachable) - looking for one"

# Thai nodes that just failed are skipped for a while: the list re-offers the
# same dead entries, and spending a minute on each one every cycle is what made
# the hunt look endless.
prune_dead() {
  [ -f "$DEAD" ] || return 0
  local cut
  cut=$(( $(date +%s) - DEAD_TTL ))
  awk -v cut="$cut" '$1 >= cut' "$DEAD" > "$DEAD.tmp" 2>/dev/null && mv "$DEAD.tmp" "$DEAD"
  return 0
}
is_dead() { [ -f "$DEAD" ] && awk -v n="$1" '$2 == n { found = 1 } END { exit !found }' "$DEAD"; }
mark_dead() { printf '%s %s\n' "$(date +%s)" "$1" >> "$DEAD"; }

# --- api cooldown gate -------------------------------------------------------
if [ "${1:-}" != "--force" ] && [ -f "$API_COOLDOWN" ]; then
  age=$(( $(date +%s) - $(cat "$API_COOLDOWN") ))
  if [ "$age" -lt "$API_COOLDOWN_SEC" ]; then
    log "API cooldown (${age}s old < ${API_COOLDOWN_SEC}s) - bounce only"
    start_service
    [ "$(systemctl is-active vpngate-th)" = "active" ] && exit 0
    exit 1
  fi
fi
date +%s > "$API_COOLDOWN"

# --- step 2: fetch fresh list ------------------------------------------------
log "fetching server list from VPNGate"
LIST=$(curl -sS --max-time 25 "$API" 2>/dev/null)
if [ -z "$LIST" ]; then
  log "API unreachable - bounce only"
  start_service; exit 1
fi

# columns: HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,...,Message,Base64
# note: Message may contain commas -> base64 is ALWAYS the last field ($NF); strip CR
CANDLINES=$(printf '%s\n' "$LIST" | awk -F, '
  { sub(/\r$/, "") }
  /^#/ || /^*/ { next }
  $2 !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { next }
  NF >= 15 { print $3"\t"$7"\t"$1"\t"$2"\t"$NF }' | sort -t "$(printf '\t')" -k1,1nr)

# A node another slot already holds is a bad pick: two tunnels to the same free
# server split its bandwidth and die together. Slot 1's own config is left out
# on purpose - this run is replacing it, not competing with it.
USED_NODES=$(for f in "$DIR"/slot*.ovpn; do
  [ -f "$f" ] && grep -h '^remote ' "$f" 2>/dev/null | awk '{print $2}'
done | sort -u)

THONLY=$(printf '%s\n' "$CANDLINES" | awk -F '\t' -v want="$EXPECT_COUNTRY" -v used="$USED_NODES" '
  $2 != want { next }
  { n = split(used, u, "\n"); for (i = 1; i <= n; i++) if (u[i] == $4) next; print }')
OTHERS=$(printf '%s\n' "$CANDLINES" | awk -F '\t' -v want="$EXPECT_COUNTRY" '$2 != want')

prune_dead
if [ -n "$EXPECT_COUNTRY" ]; then
  THONLY=$(printf '%s\n' "$THONLY" | while read -r line; do
    [ -n "$line" ] || continue
    ip=$(printf '%s' "$line" | awk -F '\t' '{print $4}')
    if is_dead "$ip"; then
      log "skipping $ip - it failed within the last ${DEAD_TTL}s"
    else
      printf '%s\n' "$line"
    fi
  done)
fi

TH_PICK=$(printf '%s\n' "$THONLY" | head -n "$MAX_TH")

# Nothing Thai to try at all? Then do not tear down a tunnel that works: this box
# is waiting for VPNGate to offer a Thai node, and the current exit still serves
# HOP_SOCKS5. Bouncing in place is all this cycle needs to do.
if [ "$revived_reachable" = "1" ] && [ -z "$(printf '%s\n' "$TH_PICK" | grep -v '^$')" ]; then
  log "no usable $EXPECT_COUNTRY candidate right now - keeping the current tunnel"
  exit 1
fi
OTH_PICK=$(printf '%s\n' "$OTHERS" | head -n $(( MAX_TOTAL - $(printf '%s\n' "$TH_PICK" | grep -c .) )))
POOL=$(printf '%s\n' "$TH_PICK" "$OTH_PICK" | grep -v '^$')

N=$(printf '%s\n' "$POOL" | grep -c .)
log "candidates: $N ($EXPECT_COUNTRY first, then any country)"
if [ "$N" = "0" ]; then
  log "no candidates - bounce current"
  start_service; exit 1
fi

# --- step 3: try each candidate ----------------------------------------------
stop_all
tried=0
while IFS="$(printf '\t')" read -r score cc host ip cfg; do
  tried=$((tried + 1)); [ -z "$cfg" ] && continue
  log "T[$tried/$N] $cc $host ($ip) score=$score"
  printf '%s' "$cfg" | base64 -d > "$CAND" 2>/dev/null || { log "  bad base64, skip"; continue; }

  if try_config "$CAND" 1 "test-auth"; then
    log "SUCCESS $cc $host ($ip) -> active.ovpn"
    cp "$CAND" "$ACTIVE"
    start_service
    if egress_ok; then
      logger -t vpngate-rotate "switched to $cc $host ($ip)"
      exit 0
    fi
    log "  service lost egress on $cc $host - next candidate"
  else
    if grep -q 'AUTH_FAILED' "$TRYLOG" 2>/dev/null; then
      log "  AUTH_FAILED - retrying without auth"
      if try_config "$CAND" 0 "test-noauth"; then
        log "SUCCESS(no-auth) $cc $host ($ip) -> active.ovpn"
        cp "$CAND" "$ACTIVE"
        start_service
        if egress_ok; then
          logger -t vpngate-rotate "switched to $cc $host ($ip) [no-auth]"
          exit 0
        fi
      fi
    fi
    log "  FAIL $cc $host - no usable egress (need $EXPECT_COUNTRY)"
    # Only Thai failures are remembered: the non-Thai ones are tried on purpose
    # so the tunnel still has somewhere to go for HOP traffic.
    [ "$cc" = "$EXPECT_COUNTRY" ] && mark_dead "$ip"
  fi
done <<EOF
$POOL
EOF

log "all candidates failed - bouncing current active.ovpn"
start_service
exit 1