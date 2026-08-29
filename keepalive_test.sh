#!/bin/bash
echo "=== Keepalive Stability Test — 5 min ==="
echo "Testing: 10 connections x 30 rounds (10s interval)"
echo ""

PASS=0
FAIL=0
START=$(date +%s)

for round in $(seq 1 30); do
  NOW=$(date +%s)
  ELAPSED=$((NOW - START))
  echo "--- round $round (${ELAPSED}s elapsed) ---"
  
  for i in $(seq 1 10); do
    (
      result=$(curl -s -o /dev/null -w '%{http_code} %{time_total}s' \
        -x http://127.0.0.1:443 \
        --connect-timeout 5 --max-time 15 \
        https://www.google.com/ 2>&1)
      
      code=$(echo "$result" | awk '{print $1}')
      if [ "$code" = "200" ]; then
        echo "  [conn-$i] OK $result"
      else
        echo "  [conn-$i] FAIL $result"
      fi
    ) &
  done
  wait
  sleep 10
done

echo ""
echo "=== TEST COMPLETE ==="
echo "Total time: ~300s"
