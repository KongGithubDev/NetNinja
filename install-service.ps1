param(
    [ValidateSet("install", "uninstall", "start", "stop", "restart", "status")]
    [string]$Action = "install",

    [ValidateSet("net_server", "proxy")]
    [string]$Component = "net_server",

    [string]$ServiceName = "NetNinja-Server",

    [string]$Port = "443",
    [string]$CertFile = "fullchain.pem",
    [string]$KeyFile = "privkey.pem",
    [string]$WebPort = "8443",
    [string]$WebSNI = "",
    [string]$UUID = "b831381d-6324-4d53-ad4f-8cda48b30811",
    [string]$LogDir = ""
)

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($LogDir -eq "") { $LogDir = Join-Path $ProjectRoot "logs" }

# Ensure log directory exists
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

# Check if NSSM is available
$nssmPaths = @(
    Join-Path $ProjectRoot "nssm.exe",
    "C:\nssm\win64\nssm.exe",
    "C:\nssm\win32\nssm.exe"
)

$nssmPath = $null
foreach ($p in $nssmPaths) {
    if (Test-Path $p) { $nssmPath = $p; break }
}

if (-not $nssmPath) {
    Write-Host "[DEPLOY] NSSM not found. Downloading..." -ForegroundColor Yellow
    $nssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
    $zipPath = Join-Path $env:TEMP "nssm-2.24.zip"
    $extractPath = Join-Path $env:TEMP "nssm"

    try {
        Invoke-WebRequest -Uri $nssmUrl -OutFile $zipPath -UseBasicParsing
        Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
        $arch = if ([Environment]::Is64BitOperatingSystem) { "win64" } else { "win32" }
        Copy-Item (Join-Path $extractPath "nssm-2.24\$arch\nssm.exe") (Join-Path $ProjectRoot "nssm.exe") -Force
        $nssmPath = Join-Path $ProjectRoot "nssm.exe"
        Write-Host "[DEPLOY] NSSM downloaded to $nssmPath" -ForegroundColor Green
    } catch {
        Write-Host "[DEPLOY] Failed to download NSSM: $_" -ForegroundColor Red
        Write-Host "[DEPLOY] Download manually from: https://nssm.cc/download" -ForegroundColor Yellow
        exit 1
    }
}

# Build arguments for net_server
if ($Component -eq "net_server") {
    $appArgs = "-port $Port -tls true"
    if ($CertFile -ne "") { $appArgs += " -cert `"$CertFile`"" }
    if ($KeyFile -ne "") { $appArgs += " -key `"$KeyFile`"" }
    if ($WebPort -ne "8443") { $appArgs += " -webport $WebPort" }
    if ($WebSNI -ne "") { $appArgs += " -web-sni `"$WebSNI`"" }
    if ($UUID -ne "") { $appArgs += " -uuid $UUID" }

    $exePath = Join-Path $ProjectRoot "net_server.exe"
    $logFile = Join-Path $LogDir "net_server.log"
} else {
    $exePath = Join-Path $ProjectRoot "proxy.exe"
    $appArgs = ""
    $logFile = Join-Path $LogDir "proxy.log"
    $ServiceName = "NetNinja-Proxy"
}

if (-not (Test-Path $exePath)) {
    Write-Host "[DEPLOY] Binary not found: $exePath" -ForegroundColor Red
    Write-Host "[DEPLOY] Build first with: .\build.ps1" -ForegroundColor Yellow
    exit 1
}

function Install-Service {
    Write-Host "[DEPLOY] Installing service: $ServiceName" -ForegroundColor Yellow

    # Remove existing service if present
    & $nssmPath stop $ServiceName 2>$null
    Start-Sleep -Seconds 2
    & $nssmPath remove $ServiceName confirm 2>$null
    Start-Sleep -Seconds 1

    # Install
    & $nssmPath install $ServiceName $exePath $appArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[DEPLOY] Service installation failed" -ForegroundColor Red
        exit 1
    }

    # Configure auto-restart
    & $nssmPath set $ServiceName AppExit Default Exit
    & $nssmPath set $ServiceName AppThrottle 5000
    & $nssmPath set $ServiceName AppStdout $logFile
    & $nssmPath set $ServiceName AppStderr $logFile
    & $nssmPath set $ServiceName AppRotateFiles 1
    & $nssmPath set $ServiceName AppRotateSeconds 86400
    & $nssmPath set $ServiceName AppRotateBytes 10485760  # 10MB

    # Set environment variables for GC tuning
    & $nssmPath set $ServiceName AppEnvironmentExtra NET_GOGC=200 NET_MEMLIMIT=536870912

    # Set service description
    & $nssmPath set $ServiceName Description "NetNinja $Component - VLESS VPN server with SNI multiplexing and QUIC/HTTP3 UDP relay"

    # Set recovery options (restart on failure)
    & $nssmPath set $ServiceName AppRestartDelay 5000

    Write-Host "[DEPLOY] Service installed: $ServiceName" -ForegroundColor Green
    Write-Host "[DEPLOY] Executable: $exePath" -ForegroundColor Gray
    Write-Host "[DEPLOY] Arguments: $appArgs" -ForegroundColor Gray
    Write-Host "[DEPLOY] Log file: $logFile" -ForegroundColor Gray

    # Start the service
    Start-NetNinjaService
}

function Uninstall-Service {
    Write-Host "[DEPLOY] Stopping and removing service: $ServiceName" -ForegroundColor Yellow
    & $nssmPath stop $ServiceName 2>$null
    Start-Sleep -Seconds 2
    & $nssmPath remove $ServiceName confirm
    Write-Host "[DEPLOY] Service removed: $ServiceName" -ForegroundColor Green
}

function Start-NetNinjaService {
    Write-Host "[DEPLOY] Starting service: $ServiceName" -ForegroundColor Yellow
    & $nssmPath start $ServiceName
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[DEPLOY] Service started successfully" -ForegroundColor Green
        Start-Sleep -Seconds 2
        $status = Get-ServiceStatus
        Write-Host "[DEPLOY] Status: $status" -ForegroundColor Gray

        # Verify port is listening
        if ($Component -eq "net_server") {
            $listening = netstat -an 2>$null | findstr ":$Port "
            if ($listening) {
                Write-Host "[DEPLOY] Port $Port is listening" -ForegroundColor Green
            } else {
                Write-Host "[DEPLOY] Port $Port NOT listening - check logs" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "[DEPLOY] Failed to start service" -ForegroundColor Red
        if (Test-Path $logFile) {
            Get-Content $logFile -Tail 20
        }
    }
}

function Stop-NetNinjaService {
    Write-Host "[DEPLOY] Stopping service: $ServiceName" -ForegroundColor Yellow
    & $nssmPath stop $ServiceName
    Write-Host "[DEPLOY] Service stopped" -ForegroundColor Green
}

function Restart-NetNinjaService {
    Write-Host "[DEPLOY] Restarting service: $ServiceName" -ForegroundColor Yellow
    & $nssmPath restart $ServiceName
    Write-Host "[DEPLOY] Service restarted" -ForegroundColor Green
}

function Get-ServiceStatus {
    $result = & $nssmPath status $ServiceName 2>&1
    return $result.Trim()
}

function Show-Status {
    $status = Get-ServiceStatus
    Write-Host "[DEPLOY] Service: $ServiceName" -ForegroundColor Cyan
    Write-Host "[DEPLOY] Status: $status" -ForegroundColor Cyan
    Write-Host "[DEPLOY] Executable: $exePath" -ForegroundColor Gray
    Write-Host "[DEPLOY] Log file: $logFile" -ForegroundColor Gray

    if ($status -eq "SERVICE_RUNNING") {
        if ($Component -eq "net_server") {
            $listening = netstat -an 2>$null | findstr ":$Port "
            if ($listening) { Write-Host "[DEPLOY] Port $Port: listening" -ForegroundColor Green }
        }
        # Show last 3 log lines
        if (Test-Path $logFile) {
            Write-Host "[DEPLOY] Recent log output:" -ForegroundColor Gray
            Get-Content $logFile -Tail 3 | ForEach-Object { Write-Host "  $_" }
        }
    }
}

# Execute action
switch ($Action) {
    "install" { Install-Service }
    "uninstall" { Uninstall-Service }
    "start" { Start-NetNinjaService }
    "stop" { Stop-NetNinjaService }
    "restart" { Restart-NetNinjaService }
    "status" { Show-Status }
}
