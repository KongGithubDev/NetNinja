@echo off
title NetNinja WS-Tunnel Server

if "%PORT%"=="" set PORT=443

set NET_WEB_SNI=kpstore.online,www.kpstore.online,api.kpstore.online,gta-career.com,www.gta-career.com,api.gta-career.com,cdn.gta-career.com,careercity.gta-career.com,n8n.kongwatcharapong.in.th

echo ========================================
echo   NetNinja WS-Tunnel Server
echo ========================================
echo   Port : %PORT%
echo   Mode : EMBEDDED SSH
echo ========================================

ws-tunnel.exe -port %PORT% -embed -user vpn -pass vpn
