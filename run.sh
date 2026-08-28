#!/bin/sh
/home/<SSH_USER>/proxy_linux &
while true; do
    echo "=== Starting bore tunnel (trying fixed port 5988) ==="
    /home/<SSH_USER>/bore local 8300 --to bore.pub --port 5988
    echo "=== bore fixed 5988 unavailable, trying 8300 ==="
    /home/<SSH_USER>/bore local 8300 --to bore.pub --port 8300
    echo "=== bore fixed ports unavailable, using random port ==="
    /home/<SSH_USER>/bore local 8300 --to bore.pub
done