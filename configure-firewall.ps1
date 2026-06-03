param(
    [ValidateSet("apply", "remove", "list")]
    [string]$Action = "apply",

    [int]$VLESSPort = 443,
    [int]$ProxyPort = 8080,
    [int]$WebPort = 8443,

    [string]$Profile = "any",

    [switch]$AdminCheck
)

$ErrorActionPreference = "Stop"

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Apply-Rules {
    Write-Host "[FIREWALL] Applying NetNinja firewall rules..." -ForegroundColor Yellow

    # Remove existing NetNinja rules first
    Remove-Rules

    $rules = @(
        @{
            Name = "NetNinja-VLESS-TCP"
            Dir = "in"
            Action = "allow"
            Protocol = "TCP"
            LocalPort = $VLESSPort
            Program = "$PSScriptRoot\net_server.exe"
            Desc = "VLESS VPN inbound TCP (SNI multiplexer)"
        },
        @{
            Name = "NetNinja-VLESS-UDP"
            Dir = "in"
            Action = "allow"
            Protocol = "UDP"
            LocalPort = $VLESSPort
            Program = "$PSScriptRoot\net_server.exe"
            Desc = "VLESS VPN inbound UDP (QUIC/HTTP3 relay)"
        },
        @{
            Name = "NetNinja-Proxy-TCP"
            Dir = "in"
            Action = "allow"
            Protocol = "TCP"
            LocalPort = $ProxyPort
            Program = "$PSScriptRoot\proxy.exe"
            Desc = "HTTP/HTTPS forward proxy"
        },
        @{
            Name = "NetNinja-Web-TCP"
            Dir = "in"
            Action = "allow"
            Protocol = "TCP"
            LocalPort = $WebPort
            Program = "C:\nginx\nginx.exe"
            Desc = "Upstream web server (if sharing port 443)"
        }
    )

    foreach ($rule in $rules) {
        $name = "NetNinja-$($rule.Name)"
        Write-Host "[FIREWALL] Adding rule: $name" -ForegroundColor Gray
        $ruleArgs = @(
            "advfirewall", "firewall", "add", "rule",
            "name=$name",
            "dir=$($rule.Dir)",
            "action=$($rule.Action)",
            "protocol=$($rule.Protocol)",
            "localport=$($rule.LocalPort)",
            "profile=$Profile"
        )
        if ($rule.Program -and (Test-Path $rule.Program)) {
            $ruleArgs += "program=`"$($rule.Program)`""
        }
        & netsh $ruleArgs 2>$null
    }

    Write-Host "[FIREWALL] Rules applied successfully" -ForegroundColor Green
    List-Rules
}

function Remove-Rules {
    Write-Host "[FIREWALL] Removing existing NetNinja rules..." -ForegroundColor Yellow
    $existing = netsh advfirewall firewall show rule name=all 2>$null | findstr "NetNinja-"
    if ($existing) {
        netsh advfirewall firewall delete rule name=all program="$PSScriptRoot\net_server.exe" 2>$null
        netsh advfirewall firewall delete rule name=all program="$PSScriptRoot\proxy.exe" 2>$null
        # Remove by name pattern
        netsh advfirewall firewall delete rule name="NetNinja-VLESS-TCP" 2>$null
        netsh advfirewall firewall delete rule name="NetNinja-VLESS-UDP" 2>$null
        netsh advfirewall firewall delete rule name="NetNinja-Proxy-TCP" 2>$null
        netsh advfirewall firewall delete rule name="NetNinja-Web-TCP" 2>$null
    }
    Write-Host "[FIREWALL] Old rules removed" -ForegroundColor Green
}

function List-Rules {
    Write-Host "`n[FIREWALL] Current NetNinja firewall rules:" -ForegroundColor Cyan
    $rules = netsh advfirewall firewall show rule name=all 2>$null | findstr "NetNinja-"
    if ($rules) {
        $rules | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    } else {
        Write-Host "  No NetNinja rules found" -ForegroundColor Yellow
    }

    # Also show listening ports
    Write-Host "`n[FIREWALL] Listening ports on NetNinja processes:" -ForegroundColor Cyan
    $listening = netstat -an 2>$null | findstr ":$VLESSPort |:$ProxyPort "
    if ($listening) {
        $listening | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    } else {
        Write-Host "  No NetNinja ports currently listening" -ForegroundColor Yellow
    }
}

# --- Main ---

if (-not (Test-Admin)) {
    Write-Host "[FIREWALL] ERROR: Administrator privileges required." -ForegroundColor Red
    Write-Host "[FIREWALL] Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    exit 1
}

switch ($Action) {
    "apply" { Apply-Rules }
    "remove" { Remove-Rules }
    "list" { List-Rules }
}
