@echo off
title NetNinja SSH-over-WS Server [NITRO-ULTRA]

set NET_PORT=443
set NET_SSH_USER=vpn
set NET_SSH_PASS=vpn
rem set NET_SSH_HOST_KEY=ssh_host_ed25519

set NET_WEB_PORT=8443
set NET_WEB_SNI=kpstore.online,www.kpstore.online,api.kpstore.online,gta-career.com,www.gta-career.com,api.gta-career.com,cdn.gta-career.com,careercity.gta-career.com,n8n.kongwatcharapong.in.th
set NET_PROXY_ADDR=speedtest.net

rem GC Tuning: reduce GC frequency for consistent throughput
set NET_GOGC=200
set NET_MEMLIMIT=536870912

echo ========================================
echo       NetNinja SSH-over-WS Launcher
echo            [NITRO-ULTRA]
echo ========================================
echo Starting net_server on port %NET_PORT% (SSH user: %NET_SSH_USER%)...

net_server.exe -cert "fullchain.pem" -key "privkey.pem" -ssh-user %NET_SSH_USER% -ssh-pass %NET_SSH_PASS%

pause
