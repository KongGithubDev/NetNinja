@echo off
echo ========================================
echo   NetNinja WS-Tunnel Server
echo ========================================
if "%PORT%"=="" set PORT=443
echo   Port : %PORT%
echo   Mode : EMBEDDED SSH
echo ========================================

ws-tunnel.exe -port %PORT% -embed -user vpn -pass vpn
