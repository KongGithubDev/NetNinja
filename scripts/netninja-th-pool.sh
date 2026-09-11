#!/usr/bin/env bash
# netninja-th-pool.sh — supply side of the proxy's Thai egress pool.
#
# The proxy reads GEO_SOCKS5_POOL_FILE (default /opt/netninja/geo-nodes.txt):
# one SOCKS5 endpoint per line, hot reloaded every ~20s. It probes every node,
# verifies the country each one really exits from and rotates on its own.
#
# This script is the other half: it keeps the *tunnels* underneath that list
# alive. For every slot it
#
#   1. checks the endpoint (SOCKS5 reachable?) and the country it exits from,
#   2. replaces the slot when it is dead or exits the wrong country
#      (only if the slot has a replace command — with cooldown and an hourly cap),
#   3. publishes ONLY the endpoints that just verified as the expected country
#      into the pool file, atomically and only when the content actually changes.
#
# Nothing about the VPN stack is assumed: a slot is an endpoint plus an optional
# command that (re)creates it. Configure slots in /etc/netninja/th-pool.conf
# (start from netninja-th-pool.conf.example).
#
# Usage:
#   netninja-th-pool.sh --once            # check + publish + exit (systemd timer)
#   netninja-th-pool.sh --daemon          # check every CHECK_INTERVAL (service)
#   netninja-th-pool.sh --status          # print the state of every slot
#   netninja-th-pool.sh --dry-run --once  # report only: no replace, no write
#
# Exit codes: 0 = at least one slot healthy, 3 = none healthy (left as-is),
#             4 = configuration problem, 2 = bad arguments.
set -uo pipefail

CONF="${TH_POOL_CONF:-/etc/netninja/th-pool.conf}"
if [ -f "$CONF" ]; then
  # shellcheck disable=SC1090
  . "$CONF"
fi

POOL_FILE="${POOL_FILE:-/opt/netninja/geo-nodes.txt}"
STATE_DIR="${STATE_DIR:-/var/lib/netninja-th-pool}"
LOG_FILE="${LOG_FILE:-/var/log/netninja-th-pool.log}"
CHECK_INTERVAL="${CHECK_INTERVAL:-60}"
CHECK_TIMEOUT="${CHECK_TIMEOUT:-12}"
EXPECT_COUNTRY="${EXPECT_COUNTRY:-TH}"
REPLACE_COOLDOWN="${REPLACE_COOLDOWN:-180}"
MAX_REPLACES_PER_HOUR="${MAX_REPLACES_PER_HOUR:-6}"
HEALTHY_TTL="${HEALTHY_TTL:-120}"        # how long a check stays valid for --status
SLOTS="${SLOTS:-}"
DISCOVER_CMD="${DISCOVER_CMD:-}"         # optional: print extra endpoints, one per line
CHECK_CMD="${CHECK_CMD:-}"               # test hook; %ENDPOINT% is substituted
PROBE_URL="${PROBE_URL:-http://ip-api.com/json/?fields=query,country,countryCode,city,isp}"

DRY_RUN=0
MODE="once"

log() {
  local line
  line="$(date -Is) $*"
  printf '%s\n' "$line"
  [ "$DRY_RUN" = "1" ] || printf '%s\n' "$line" >> "$LOG_FILE" 2>/dev/null || true
}

die() { printf 'th-pool: %s\n' "$*" >&2; exit 4; }

# ---------------------------------------------------------------------------
# slots
# ---------------------------------------------------------------------------

# slot_ids prints the configured slot numbers, e.g. "1 2 3".
slot_ids() {
  if [ -n "$SLOTS" ]; then
    local i=1
    while [ "$i" -le "$SLOTS" ]; do printf '%s\n' "$i"; i=$((i + 1)); done
    return
  fi
  compgen -A variable | sed -n 's/^SLOT_\([0-9]\+\)_SOCKS$/\1/p' | sort -n
}

slot_endpoint() {
  local i="$1" var="SLOT_${1}_SOCKS"
  printf '%s' "${!var:-}"
}

slot_replace_cmd() {
  local i="$1" var="SLOT_${1}_REPLACE"
  printf '%s' "${!var:-}"
}

# extra_endpoints are endpoints nobody manages (already running tunnels).
extra_endpoints() {
  [ -n "$DISCOVER_CMD" ] || return 0
  sh -c "$DISCOVER_CMD" 2>/dev/null | sed -e 's/#.*//' -e 's/[[:space:]]//g' -e '/^$/d'
}

# ---------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------

country_of_endpoint() {   # echoes the country code, or nothing when unreachable
  local ep="$1" out cc
  if [ -n "$CHECK_CMD" ]; then
    out=$(eval "${CHECK_CMD//%ENDPOINT%/$ep}" 2>&1)
  else
    command -v curl >/dev/null 2>&1 || die "curl is required (or set CHECK_CMD)"
    out=$(curl -s --max-time "$CHECK_TIMEOUT" --socks5-hostname "$ep" "$PROBE_URL" 2>&1)
  fi
  cc=$(printf '%s' "$out" | sed -n 's/.*"countryCode"[[:space:]]*:[[:space:]]*"\([A-Za-z]*\)".*/\1/p' | head -1)
  if [ -z "$cc" ]; then
    LAST_DETAIL="$(printf '%s' "$out" | tr -d '\n' | cut -c1-160)"
    return 1
  fi
  LAST_DETAIL="$(printf '%s' "$out" | sed -n 's/.*"query"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
  printf '%s' "$(printf '%s' "$cc" | tr '[:lower:]' '[:upper:]')"
}

state_file() { printf '%s/slot-%s.state' "$STATE_DIR" "$1"; }
replaces_file() { printf '%s/replaces' "$STATE_DIR"; }

record_state() {  # id endpoint country state detail
  mkdir -p "$STATE_DIR" 2>/dev/null || true
  {
    printf 'checked=%s\n' "$(date +%s)"
    printf 'endpoint=%s\n' "$2"
    printf 'country=%s\n' "$3"
    printf 'state=%s\n' "$4"
    printf 'detail=%s\n' "$5"
  } > "$(state_file "$1")" 2>/dev/null || true
}

# replace_allowed applies the budget so a broken slot cannot turn into a rotate
# storm: the hourly cap is shared (total replacements), while the cooldown is
# per slot — one slot that keeps failing must not block another slot's repair.
replace_allowed() {   # $1 = slot id
  local id="$1" f now cut count last
  mkdir -p "$STATE_DIR" 2>/dev/null || true
  f="$(replaces_file)"
  now="$(date +%s)"
  touch "$f" 2>/dev/null || true
  cut=$((now - 3600))
  awk -v cut="$cut" '$1 >= cut' "$f" 2>/dev/null > "${f}.tmp" && mv "${f}.tmp" "$f" 2>/dev/null || true
  count=$(awk -v cut="$cut" '$1 >= cut' "$f" 2>/dev/null | wc -l | tr -d ' ')
  [ -n "$count" ] || count=0
  if [ "$count" -ge "$MAX_REPLACES_PER_HOUR" ]; then
    LAST_BLOCK="hourly budget used ($count/$MAX_REPLACES_PER_HOUR replacements in the last hour)"
    return 1
  fi
  last=$(awk -v id="$id" '$2 == id { l = $1 } END { print l }' "$f" 2>/dev/null)
  if [ -n "$last" ] && [ $((now - last)) -lt "$REPLACE_COOLDOWN" ]; then
    LAST_BLOCK="slot $id cooldown: $((REPLACE_COOLDOWN - (now - last)))s left"
    return 1
  fi
  printf '%s %s\n' "$now" "$id" >> "$f"
  return 0
}

replace_slot() {   # id reason
  local id="$1" reason="$2" cmd
  cmd="$(slot_replace_cmd "$1")"
  if [ -z "$cmd" ]; then
    log "slot $id: $reason — no replace command configured (tunnel must be fixed by hand)"
    return 1
  fi
  if [ "$DRY_RUN" = "1" ]; then
    log "slot $id: $reason — would replace with: $cmd (dry-run)"
    return 0
  fi
  if ! replace_allowed "$id"; then
    log "slot $id: $reason — replace skipped, $LAST_BLOCK"
    return 1
  fi
  log "slot $id: $reason — replacing: $cmd"
  if sh -c "$cmd" >> "$LOG_FILE" 2>&1; then
    sleep 2
    return 0
  fi
  log "slot $id: replace command failed (see $LOG_FILE)"
  return 1
}

# ---------------------------------------------------------------------------
# publish
# ---------------------------------------------------------------------------

publish() {   # endpoints...
  local tmp content
  mkdir -p "$(dirname "$POOL_FILE")" 2>/dev/null || true
  tmp="$(mktemp "${POOL_FILE}.XXXXXX")" || die "cannot create a temp file next to $POOL_FILE"
  {
    printf '# managed by netninja-th-pool.sh — the proxy hot reloads this file\n'
    # A configured slot and the discovery pass can both hand over the same
    # endpoint, so the same address must not be published twice.
    local ep seen=" "
    for ep in "$@"; do
      case "$seen" in *" $ep "*) continue ;; esac
      seen="$seen$ep "
      printf '%s\n' "$ep"
    done
  } > "$tmp"
  if [ -f "$POOL_FILE" ] && cmp -s "$tmp" "$POOL_FILE"; then
    rm -f "$tmp"
    log "pool unchanged ($# healthy node(s))"
    return 0
  fi
  if [ "$DRY_RUN" = "1" ]; then
    log "would publish $# node(s): $* (dry-run)"
    rm -f "$tmp"
    return 0
  fi
  chmod 0644 "$tmp"
  mv "$tmp" "$POOL_FILE"
  log "published $# node(s) to $POOL_FILE: $*"
}

# ---------------------------------------------------------------------------
# main passes
# ---------------------------------------------------------------------------

run_once() {
  local healthy=() ids id ep cc state detail replaced=0
  ids="$(slot_ids)"

  for id in $ids; do
    ep="$(slot_endpoint "$id")"
    if [ -z "$ep" ]; then
      log "slot $id: no SLOT_${id}_SOCKS configured — skipped"
      continue
    fi
    if cc="$(country_of_endpoint "$ep")"; then
      if [ "$cc" = "$EXPECT_COUNTRY" ]; then
        record_state "$id" "$ep" "$cc" ok "${LAST_DETAIL:-}"
        healthy+=("$ep")
        continue
      fi
      record_state "$id" "$ep" "$cc" wrong-country "${LAST_DETAIL:-}"
      if replace_slot "$id" "exits $cc and $EXPECT_COUNTRY is required"; then
        replaced=1
        ep="$(slot_endpoint "$id")"
        if cc="$(country_of_endpoint "$ep")" && [ "$cc" = "$EXPECT_COUNTRY" ]; then
          record_state "$id" "$ep" "$cc" ok "${LAST_DETAIL:-}"
          healthy+=("$ep")
        fi
      fi
      continue
    fi
    record_state "$id" "$ep" "" unreachable "${LAST_DETAIL:-}"
    if replace_slot "$id" "unreachable"; then
      replaced=1
      ep="$(slot_endpoint "$id")"
      if cc="$(country_of_endpoint "$ep")" && [ "$cc" = "$EXPECT_COUNTRY" ]; then
        record_state "$id" "$ep" "$cc" ok "${LAST_DETAIL:-}"
        healthy+=("$ep")
      fi
    fi
  done

  local extra
  while IFS= read -r extra; do
    [ -n "$extra" ] || continue
    if cc="$(country_of_endpoint "$extra")" && [ "$cc" = "$EXPECT_COUNTRY" ]; then
      healthy+=("$extra")
      log "discovered $extra exits $EXPECT_COUNTRY — adding to the pool"
    else
      log "discovered $extra does not verify as $EXPECT_COUNTRY — ignored"
    fi
  done < <(extra_endpoints)

  if [ "${#healthy[@]}" -eq 0 ]; then
    log "no healthy $EXPECT_COUNTRY egress right now — leaving $POOL_FILE untouched (the proxy will keep probing what it has)"
    return 3
  fi
  publish "${healthy[@]}"
  [ "$replaced" = "1" ] && log "a slot was replaced this pass"
  return 0
}

print_status() {
  local ids id f ep cc st detail age
  ids="$(slot_ids)"
  if [ -z "$ids" ]; then
    printf 'no slots configured (see %s)\n' "$CONF"
  fi
  printf '%-5s %-26s %-8s %-14s %-6s %s\n' SLOT ENDPOINT COUNTRY STATE AGE DETAIL
  for id in $ids; do
    f="$(state_file "$id")"
    ep="-"; cc="-"; st="never-checked"; detail=""; age="-"
    if [ -f "$f" ]; then
      ep=$(sed -n 's/^endpoint=//p' "$f"); [ -n "$ep" ] || ep="-"
      cc=$(sed -n 's/^country=//p' "$f"); [ -n "$cc" ] || cc="-"
      st=$(sed -n 's/^state=//p' "$f"); [ -n "$st" ] || st="-"
      detail=$(sed -n 's/^detail=//p' "$f" | cut -c1-40)
      local checked; checked=$(sed -n 's/^checked=//p' "$f")
      [ -n "$checked" ] && age="$(( $(date +%s) - checked ))s"
    else
      ep="$(slot_endpoint "$id")"; [ -n "$ep" ] || ep="-"
    fi
    printf '%-5s %-26s %-8s %-14s %-6s %s\n' "$id" "$ep" "$cc" "$st" "$age" "$detail"
  done
  printf '\npool file : %s\n' "$POOL_FILE"
  if [ -f "$POOL_FILE" ]; then
    printf 'published : %s node(s)\n' "$(grep -cvE '^[[:space:]]*(#|$)' "$POOL_FILE" 2>/dev/null || echo 0)"
    grep -vE '^[[:space:]]*(#|$)' "$POOL_FILE" 2>/dev/null | sed 's/^/            /'
  else
    printf 'published : (file does not exist yet)\n'
  fi
  printf 'last rotations: %s in the last hour (cap %s)\n' \
    "$(awk -v cut=$(( $(date +%s) - 3600 )) '$1 >= cut' "$(replaces_file)" 2>/dev/null | wc -l | tr -d ' ')" "$MAX_REPLACES_PER_HOUR"
}

usage() {
  # print the header comment block, whatever its length, and stop at the first
  # line of real code
  awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --once) MODE="once" ;;
    --daemon) MODE="daemon" ;;
    --status) MODE="status" ;;
    --dry-run) DRY_RUN=1 ;;
    --conf) shift; CONF="${1:-}"; [ -f "$CONF" ] || die "config not found: $CONF"; . "$CONF" ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
  shift
done

[ -n "$POOL_FILE" ] || die "POOL_FILE is empty"

case "$MODE" in
  status) print_status; exit 0 ;;
  once) run_once; exit $? ;;
  daemon)
    log "watching slots every ${CHECK_INTERVAL}s (expect $EXPECT_COUNTRY, pool $POOL_FILE)"
    while :; do
      run_once || true
      sleep "$CHECK_INTERVAL"
    done
    ;;
esac
