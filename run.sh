#!/bin/sh
/home/konguser/proxy_linux &
while true; do
    echo "=== Starting bore tunnel (trying fixed port 5988) ==="
    /home/konguser/bore local 8300 --to bore.pub --port 5988
    echo "=== bore fixed 5988 unavailable, trying 8300 ==="
    /home/konguser/bore local 8300 --to bore.pub --port 8300
    echo "=== bore fixed ports unavailable, using random port ==="
    /home/konguser/bore local 8300 --to bore.pub
done