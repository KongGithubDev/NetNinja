@echo off
title NetNinja VLESS Server

set NET_PORT=8080
set NET_UUID=b831381d-6324-4d53-ad4f-8cda48b30811
set NET_PATH=/netninja-vpn

echo Starting net_server on port %NET_PORT%...
net_server.exe
pause
