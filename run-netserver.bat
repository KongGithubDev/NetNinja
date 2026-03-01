@echo off
title NetNinja VLESS Server

set NET_PORT=443
set NET_UUID=b831381d-6324-4d53-ad4f-8cda48b30811
set NET_PATH=/

set NET_WEB_PORT=8443
set NET_WEB_SNI=kpstore.online,www.kpstore.online,api.kpstore.online,gta-career.com,www.gta-career.com,api.gta-career.com,cdn.gta-career.com,careercity.gta-career.com,n8n.kongwatcharapong.in.th

echo Starting net_server on port %NET_PORT%...
net_server.exe
pause
