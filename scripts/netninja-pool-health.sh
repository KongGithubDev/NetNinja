#!/usr/bin/env bash
# netninja-pool-health.sh — alert when the Thai egress pool loses its spare.
#
#   ./netninja-pool-health.sh             # check + alert on a transition (timer)
#   ./netninja-pool-health.sh --status    # show what it sees, alert nothing
#
# "Verified" means a node the *proxy* currently accepts: an endpoint in
# /geo-check's pool that is marked CURRENT or ok AND really reports
# EXPECT_COUNTRY. A node that is configured but dead is not a spare, so it does
# not count — the number that matters is how many Thai egresses work right now.
#
# The alert always lands in the journal and in LOG_FILE; when ALERT_CMD is set it
# is also handed to that command (ntfy, Telegram, a webhook — see the .example).
# It fires on a transition, then at most every ALERT_REPEAT_MIN minutes while the
# pool stays thin, and once when it recovers.
#
# Configuration: /etc/netninja/pool-health.conf. Every value can also come from
# the environment, which is also how to exercise the alert path by hand.
#
# Exit codes: 0 healthy, 1 below MIN_NODES, 2 could not determine.
set -uo pipefail

CONF=${POOL_HEALTH_CONF:-/etc/netninja/pool-health.conf}
if [ -f "$CONF" ]; then
  if [ -r "$CONF" ]; then
    # shellcheck disable=SC1090
    . "$CONF"
  else
    # 0600 root-only: reading it as anyone else would just print "Permission
    # denied" and then quietly run on the defaults, which is worse than saying so.
    printf '%s: %s is not readable (running on the built-in defaults; run as root for the configured values)\n' \
      "${0##*/}" "$CONF" >&2
  fi
fi

PROXY_URL=${PROXY_URL:-http://127.0.0.1:5988/geo-check}
MIN_NODES=${MIN_NODES:-2}
EXPECT_COUNTRY=${EXPECT_COUNTRY:-TH}
ALERT_CMD=${ALERT_CMD:-}
ALERT_REPEAT_MIN=${ALERT_REPEAT_MIN:-60}
ALERT_AFTER=${ALERT_AFTER:-2}
STATE_DIR=${STATE_DIR:-/var/lib/netninja-pool-health}
LOG_FILE=${LOG_FILE:-/var/log/netninja-pool-health.log}
MODE=${1:-check}
STATE_FILE="$STATE_DIR/state"

log_line() {
  local line
  line="$(date -Is) $*"
  printf '%s\n' "$line"
  { printf '%s\n' "$line" >> "$LOG_FILE"; } 2>/dev/null || true
  if command -v logger >/dev/null 2>&1; then
    logger -t netninja-pool-health "$*" 2>/dev/null || true
  fi
  return 0
}

# alert <subject> <body> — journal + log file always, ALERT_CMD when configured.
alert() {
  local subject="$1" body="$2"
  log_line "ALERT $subject :: $body"
  if [ -n "$ALERT_CMD" ]; then
    if ALERT_SUBJECT="$subject" ALERT_BODY="$body" \
       POOL_HEALTH_VERIFIED="${verified:-0}" POOL_HEALTH_MIN="$MIN_NODES" \
       POOL_HEALTH_NODES="${nodes:-}" \
       sh -c "$ALERT_CMD" >> "$LOG_FILE" 2>&1; then
      log_line "alert delivered via ALERT_CMD"
    else
      log_line "!! ALERT_CMD failed — the alert is only in this log"
    fi
  fi
}

raw=$(curl -s --max-time 15 "$PROXY_URL" 2>/dev/null)
verified=0
configured=0
nodes=""
detail=""

if [ -z "$raw" ]; then
  status=unknown
  detail="proxy did not answer $PROXY_URL"
else
  configured=$(printf '%s\n' "$raw" | sed -n 's/^egress pool (\([0-9][0-9]*\) node.*/\1/p' | head -1)
  parsed=$(printf '%s\n' "$raw" | awk -v want="$EXPECT_COUNTRY" '
    /^egress pool/ { inpool = 1; next }
    inpool && /^[[:space:]]/ {
      st = $2; cc = "-"
      for (i = 3; i <= NF; i++) if ($i ~ /^country=/) cc = substr($i, 9)
      list = list " " $1 "(" st "," cc ")"
      if ((st == "CURRENT" || st == "ok") && cc == want) n++
      next
    }
    { inpool = 0 }
    END { printf "%d\t%s", n + 0, (list == "" ? "(none published)" : list) }')
  verified=${parsed%%$'\t'*}
  nodes=${parsed#*$'\t'}
  if [ "$verified" -ge "$MIN_NODES" ]; then
    status=healthy
  else
    status=unhealthy
    detail="only $verified verified $EXPECT_COUNTRY node(s), need $MIN_NODES — the pool has no spare"
  fi
fi

if [ "$MODE" = "--status" ]; then
  printf 'pool health : %s\n' "$status"
  printf 'source      : %s\n' "$PROXY_URL"
  printf 'configured  : %s node(s)\n' "${configured:-?}"
  printf 'verified    : %s node(s) out of %s required (%s)\n' "$verified" "$MIN_NODES" "$EXPECT_COUNTRY"
  printf 'nodes       :%s\n' "${nodes:- (unknown)}"
  printf 'alert after : %s bad check(s), then every %s min\n' "$ALERT_AFTER" "$ALERT_REPEAT_MIN"
  [ -z "$detail" ] || printf 'detail      : %s\n' "$detail"
  [ "$status" = healthy ] && exit 0
  [ "$status" = unhealthy ] && exit 1
  exit 2
fi

# --- transition + repeat budget ---------------------------------------------
# A pool that is briefly unreadable is not a pool that lost its spare: right
# after a proxy restart the egress countries read "unverified" for ~20s, so only
# ALERT_AFTER consecutive bad checks are allowed to page anyone.
prev_status=""
prev_count=0
prev_epoch=0
if [ -f "$STATE_FILE" ]; then
  read -r prev_status prev_count prev_epoch < "$STATE_FILE" 2>/dev/null || true
  [ -n "$prev_count" ] || prev_count=0
  [ -n "$prev_epoch" ] || prev_epoch=0
fi
now=$(date +%s)
mkdir -p "$STATE_DIR" 2>/dev/null || true

count=0
if [ "$status" != "healthy" ]; then
  if [ "$prev_status" = "$status" ]; then
    count=$((prev_count + 1))
  else
    count=1
  fi
fi

rc=0
case "$status" in
  healthy)
    if [ "$prev_count" -ge "$ALERT_AFTER" ]; then
      alert "Thai egress pool recovered" \
        "$verified verified $EXPECT_COUNTRY egress node(s) — the spare is back."
    fi
    ;;
  unhealthy)
    rc=1
    ;;
  *)
    rc=2
    ;;
esac

if [ "$status" != "healthy" ]; then
  if [ "$count" -eq "$ALERT_AFTER" ] || \
     { [ "$count" -gt "$ALERT_AFTER" ] && [ $((now - prev_epoch)) -ge $((ALERT_REPEAT_MIN * 60)) ]; }; then
    case "$status" in
      unhealthy) alert "Thai egress pool thin" "$detail" ;;
      *)         alert "Thai egress pool unknown" "$detail" ;;
    esac
    prev_epoch=$now
  fi
fi

log_line "pool $status: $verified/$MIN_NODES verified $EXPECT_COUNTRY node(s), configured=${configured:-?}"
printf '%s %s %s\n' "$status" "$count" "$prev_epoch" > "$STATE_FILE" 2>/dev/null || true
exit "$rc"
