#!/usr/bin/env bash
# netninja-th-pool.selftest.sh — offline test for netninja-th-pool.sh.
#
# Runs the supervisor in a temporary sandbox with stub probe/replace commands, so
# the publishing rules can be tested without a single real tunnel:
#
#   * only endpoints that verify as EXPECT_COUNTRY are published
#   * a slot exiting another country is reported and replaced (but never published)
#   * an unreachable slot triggers its replace command
#   * an empty healthy set leaves the published file untouched (exit 3)
#   * --dry-run changes nothing at all
#
#   ./netninja-th-pool.selftest.sh
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
POOL="$HERE/netninja-th-pool.sh"
[ -f "$POOL" ] || { echo "cannot find netninja-th-pool.sh next to this test" >&2; exit 1; }
command -v bash >/dev/null || { echo "bash is required" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

FAILS=0
check() { # description expected actual
  if [ "$2" = "$3" ]; then
    printf '  ok   %s\n' "$1"
  else
    printf '  FAIL %s\n       expected: %s\n       actual:   %s\n' "$1" "$2" "$3"
    FAILS=$((FAILS + 1))
  fi
}

# --- stub probe: answers come from $ANSWERS, one "endpoint country" per line ---
cat > "$WORK/stub-check.sh" <<'STUB'
#!/usr/bin/env bash
ep="$1"
ans=""
if [ -f "$ANSWERS" ]; then
  ans=$(awk -v ep="$ep" '$1 == ep { print $2; exit }' "$ANSWERS")
fi
[ -n "$ans" ] || exit 0                     # nothing printed = unreachable
printf '{"query":"203.0.113.7","country":"Thailand","countryCode":"%s","city":"Bangkok","isp":"Example"}\n' "$ans"
STUB
chmod +x "$WORK/stub-check.sh"

cat > "$WORK/answers" <<'ANS'
th1:1080 TH
jp1:1080 JP
ANS

cat > "$WORK/conf" <<CONF
POOL_FILE=$WORK/geo-nodes.txt
STATE_DIR=$WORK/state
LOG_FILE=$WORK/log
EXPECT_COUNTRY=TH
CHECK_CMD="$WORK/stub-check.sh %ENDPOINT%"
SLOTS=3
SLOT_1_SOCKS=th1:1080
SLOT_2_SOCKS=jp1:1080
SLOT_2_REPLACE="touch $WORK/replaced-2"
SLOT_3_SOCKS=dead:1080
SLOT_3_REPLACE="touch $WORK/replaced-3"
CONF

run() { ANSWERS="$WORK/answers" TH_POOL_CONF="$WORK/conf" bash "$POOL" "$@"; }

echo "1. check + publish (one good slot, one wrong country, one dead)"
run --once > "$WORK/out1" 2>&1
check "exit code is 0 (a healthy slot exists)" "0" "$?"
check "pool file published" "yes" "$([ -f "$WORK/geo-nodes.txt" ] && echo yes || echo no)"
check "published endpoints" "th1:1080" "$(grep -vE '^#|^$' "$WORK/geo-nodes.txt" | tr '\n' ' ' | sed 's/ $//')"
check "wrong-country slot was replaced" "yes" "$([ -f "$WORK/replaced-2" ] && echo yes || echo no)"
check "dead slot was replaced in the same pass" "yes" "$([ -f "$WORK/replaced-3" ] && echo yes || echo no)"
check "wrong country logged" "yes" "$(grep -q 'exits JP' "$WORK/out1" && echo yes || echo no)"

echo "2. --dry-run never writes or replaces"
rm -f "$WORK/geo-nodes.txt" "$WORK/replaced-2" "$WORK/replaced-3"
run --dry-run --once > "$WORK/out2" 2>&1
check "pool file untouched" "no" "$([ -f "$WORK/geo-nodes.txt" ] && echo yes || echo no)"
check "no replace happened" "no" "$([ -f "$WORK/replaced-3" ] && echo yes || echo no)"
check "would publish is reported" "yes" "$(grep -q 'would publish' "$WORK/out2" && echo yes || echo no)"

echo "3. nothing healthy: keep the last published file, exit 3"
run --once > /dev/null 2>&1
printf 'jp1:1080 JP\n' > "$WORK/answers"
run --once > "$WORK/out3" 2>&1
check "exit code is 3" "3" "$?"
check "previously published node kept" "th1:1080" "$(grep -vE '^#|^$' "$WORK/geo-nodes.txt" | tr '\n' ' ' | sed 's/ $//')"
check "left-untouched message logged" "yes" "$(grep -q 'leaving .* untouched' "$WORK/out3" && echo yes || echo no)"

echo "4. back to healthy: a node that returns is published again"
printf 'th1:1080 TH\njp1:1080 TH\n' > "$WORK/answers"
run --once > "$WORK/out4" 2>&1
check "both slots published" "th1:1080 jp1:1080" "$(grep -vE '^#|^$' "$WORK/geo-nodes.txt" | tr '\n' ' ' | sed 's/ $//')"

echo "5. discovery hook adds an unmanaged endpoint"
cat >> "$WORK/conf" <<CONF
DISCOVER_CMD="printf 'extra:1080\\\\n'"
CONF
printf 'th1:1080 TH\njp1:1080 TH\nextra:1080 TH\n' > "$WORK/answers"
run --once > "$WORK/out5" 2>&1
check "discovered node published" "th1:1080 jp1:1080 extra:1080" "$(grep -vE '^#|^$' "$WORK/geo-nodes.txt" | tr '\n' ' ' | sed 's/ $//')"

echo "6. the hourly budget blocks further replacements"
cat > "$WORK/conf-budget" <<CONF
POOL_FILE=$WORK/geo-nodes.txt
STATE_DIR=$WORK/state-budget
LOG_FILE=$WORK/log-budget
EXPECT_COUNTRY=TH
CHECK_CMD="$WORK/stub-check.sh %ENDPOINT%"
REPLACE_COOLDOWN=0
MAX_REPLACES_PER_HOUR=1
SLOTS=1
SLOT_1_SOCKS=dead:1080
SLOT_1_REPLACE="printf x >> $WORK/budget-marker"
CONF
printf '\n' > "$WORK/answers"
run --conf "$WORK/conf-budget" --once > "$WORK/out7a" 2>&1
run --conf "$WORK/conf-budget" --once > "$WORK/out7b" 2>&1
check "first replace ran" "1" "$(tr -cd 'x' < "$WORK/budget-marker" | wc -c | tr -d ' ')"
check "second pass blocked by the hourly budget" "yes" "$(grep -q 'hourly budget used' "$WORK/out7b" && echo yes || echo no)"

# back to the main config for the remaining checks (the budget case above used
# its own conf file, so $WORK/conf still holds the stub probe untouched)
printf 'th1:1080 TH\njp1:1080 TH\nextra:1080 TH\n' > "$WORK/answers"

echo "7. --status prints the slot table"
run --status > "$WORK/out6" 2>&1
check "status exit code" "0" "$?"
check "status lists slots" "yes" "$(grep -q '^SLOT' "$WORK/out6" && grep -q 'th1:1080' "$WORK/out6" && echo yes || echo no)"
check "status shows the country it verified" "yes" "$(grep -q 'TH' "$WORK/out6" && echo yes || echo no)"

echo "8. one slot stuck in cooldown does not block another slot's repair"
printf '\n' > "$WORK/answers"
# pass 1 sees only slot 1, which consumes its own cooldown window
cat > "$WORK/conf-c1a" <<CONF
POOL_FILE=$WORK/geo-nodes-c.txt
STATE_DIR=$WORK/state-c
LOG_FILE=$WORK/log-c
EXPECT_COUNTRY=TH
REPLACE_COOLDOWN=9999
MAX_REPLACES_PER_HOUR=10
CHECK_CMD="$WORK/stub-check.sh %ENDPOINT%"
SLOTS=1
SLOT_1_SOCKS=dead1:1080
SLOT_1_REPLACE="printf x >> $WORK/c-marker-1"
CONF
# pass 2 adds slot 2 on top of the same state
cat > "$WORK/conf-c2" <<CONF
POOL_FILE=$WORK/geo-nodes-c.txt
STATE_DIR=$WORK/state-c
LOG_FILE=$WORK/log-c
EXPECT_COUNTRY=TH
REPLACE_COOLDOWN=9999
MAX_REPLACES_PER_HOUR=10
CHECK_CMD="$WORK/stub-check.sh %ENDPOINT%"
SLOTS=2
SLOT_1_SOCKS=dead1:1080
SLOT_1_REPLACE="printf x >> $WORK/c-marker-1"
SLOT_2_SOCKS=dead2:1080
SLOT_2_REPLACE="printf x >> $WORK/c-marker-2"
CONF
run --conf "$WORK/conf-c1a" --once > "$WORK/out8a" 2>&1
check "slot 1 was replaced once" "1" "$(tr -cd 'x' < "$WORK/c-marker-1" | wc -c | tr -d ' ')"
# pass 2 adds slot 2: it must be repaired even though slot 1 is still in cooldown
run --conf "$WORK/conf-c2" --once > "$WORK/out8b" 2>&1
check "slot 2 got replaced despite slot 1's cooldown" "yes" "$([ -f "$WORK/c-marker-2" ] && echo yes || echo no)"
check "slot 1 stayed inside its own cooldown" "1" "$(tr -cd 'x' < "$WORK/c-marker-1" | wc -c | tr -d ' ')"
check "cooldown was reported for slot 1 only" "yes" "$(grep -q 'slot 1: unreachable — replace skipped, slot 1 cooldown' "$WORK/out8b" && echo yes || echo no)"

echo
if [ "$FAILS" -eq 0 ]; then
  echo "all checks passed"
  exit 0
fi
echo "$FAILS check(s) failed"
exit 1
