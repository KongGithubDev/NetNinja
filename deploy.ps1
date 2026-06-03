param(
    [switch]$SkipBuild,
    [switch]$SkipFirewall,
    [switch]$SkipService,
    [switch]$DryRun,
    [string]$CertPath = "fullchain.pem",
    [string]$KeyPath = "privkey.pem"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$StartTime = Get-Date

function Write-Step {
    param([string]$Message, [string]$Color = "White")
    Write-Host "`n========================================" -ForegroundColor $Color
    Write-Host "  $Message" -ForegroundColor $Color
    Write-Host "========================================" -ForegroundColor $Color
}

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# --- Pre-flight checks ---

Write-Step "NetNinja Deployment Script" -Color Cyan
Write-Host "  Project: $ProjectRoot" -ForegroundColor Gray
Write-Host "  Started: $($StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
Write-Host "  Dry run: $($DryRun.IsPresent)" -ForegroundColor Gray
Write-Host ""

if (-not (Test-Admin)) {
    Write-Host "[WARN] Not running as Administrator." -ForegroundColor Yellow
    Write-Host "[WARN] TCP tuning, firewall, and service installation require admin rights." -ForegroundColor Yellow
    if (-not $DryRun) {
        Write-Host "[WARN] Restart as Administrator for full deployment." -ForegroundColor Yellow
    }
}

if (-not (Get-Command "go" -ErrorAction SilentlyContinue)) {
    Write-Host "[ERR] Go is not installed or not in PATH." -ForegroundColor Red
    Write-Host "[HINT] Install Go from https://go.dev/dl/" -ForegroundColor Yellow
    exit 1
}

# --- Step 1: TCP Stack Optimization ---

Write-Step "Step 1: TCP Stack Optimization" -Color Green

$tcpSettings = @(
    "netsh int tcp set global autotuninglevel=normal",
    "netsh int tcp set global fastopen=enabled",
    "netsh int tcp set global timestamps=disabled",
    "netsh int tcp set global ecncapability=enabled",
    "netsh int tcp set global initialRto=2000",
    "netsh int tcp set global rss=enabled"
)

foreach ($cmd in $tcpSettings) {
    if ($DryRun) {
        Write-Host "  [DRY-RUN] $cmd" -ForegroundColor Gray
    } else {
        $result = Invoke-Expression $cmd 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  [OK] $($cmd -replace '^netsh int tcp set global ', '')" -ForegroundColor Green
        } else {
            Write-Host "  [WARN] $($result.Trim())" -ForegroundColor Yellow
        }
    }
}

# --- Step 2: Build Binaries ---

Write-Step "Step 2: Build Binaries" -Color Green

if ($SkipBuild) {
    Write-Host "  Skipped (-SkipBuild)" -ForegroundColor Yellow
    # Verify binaries exist
    foreach ($bin in @("net_server.exe", "proxy.exe")) {
        $path = Join-Path $ProjectRoot $bin
        if (Test-Path $path) {
            $info = Get-Item $path
            Write-Host "  Found: $bin ($([math]::Round($info.Length/1KB)) KB)" -ForegroundColor Gray
        } else {
            Write-Host "  Missing: $bin" -ForegroundColor Red
        }
    }
} else {
    if ($DryRun) {
        Write-Host "  [DRY-RUN] .\build.ps1" -ForegroundColor Gray
    } else {
        Push-Location $ProjectRoot
        & .\build.ps1
        Pop-Location
    }
}

# --- Step 3: Certificate Check ---

Write-Step "Step 3: Certificate Verification" -Color Green

$certFullPath = Join-Path $ProjectRoot $CertPath
$keyFullPath = Join-Path $ProjectRoot $KeyPath

if (Test-Path $certFullPath -and Test-Path $keyFullPath) {
    $certInfo = Get-Item $certFullPath
    $keyInfo = Get-Item $keyFullPath
    Write-Host "  Certificate: $CertPath ($([math]::Round($certInfo.Length/1KB)) KB)" -ForegroundColor Green
    Write-Host "  Private key: $KeyPath ($([math]::Round($keyInfo.Length/1KB)) KB)" -ForegroundColor Green

    # Check certificate expiry
    $certData = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    try {
        $certData.Import($certFullPath)
        $daysLeft = ($certData.NotAfter - (Get-Date)).Days
        if ($daysLeft -gt 30) {
            Write-Host "  Expires: $($certData.NotAfter.ToString('yyyy-MM-dd')) ($daysLeft days)" -ForegroundColor Green
        } elseif ($daysLeft -gt 0) {
            Write-Host "  Expires: $($certData.NotAfter.ToString('yyyy-MM-dd')) ($daysLeft days - RENEW SOON)" -ForegroundColor Yellow
        } else {
            Write-Host "  EXPIRED: $($certData.NotAfter.ToString('yyyy-MM-dd'))" -ForegroundColor Red
        }
    } catch {
        Write-Host "  Could not parse certificate: $_" -ForegroundColor Yellow
    }
} else {
    Write-Host "  Certificate not found at: $certFullPath" -ForegroundColor Yellow
    Write-Host "  net_server will use a self-signed certificate (not recommended for production)" -ForegroundColor Yellow
}

# --- Step 4: Firewall Configuration ---

Write-Step "Step 4: Firewall Configuration" -Color Green

if ($SkipFirewall) {
    Write-Host "  Skipped (-SkipFirewall)" -ForegroundColor Yellow
} else {
    if ($DryRun) {
        Write-Host "  [DRY-RUN] .\configure-firewall.ps1 -Action apply" -ForegroundColor Gray
    } else {
        Push-Location $ProjectRoot
        & .\configure-firewall.ps1 -Action apply
        Pop-Location
    }
}

# --- Step 5: Windows Service Installation ---

Write-Step "Step 5: Windows Service Installation" -Color Green

if ($SkipService) {
    Write-Host "  Skipped (-SkipService)" -ForegroundColor Yellow
} else {
    if ($DryRun) {
        Write-Host "  [DRY-RUN] .\install-service.ps1 -Action install" -ForegroundColor Gray
    } else {
        Push-Location $ProjectRoot
        & .\install-service.ps1 -Action install
        Pop-Location
    }
}

# --- Summary ---

$EndTime = Get-Date
$Duration = ($EndTime - $StartTime).TotalSeconds

Write-Step "Deployment Summary" -Color Cyan
Write-Host "  Status: $([System.Environment]::NewLine)" -NoNewline
if ($DryRun) {
    Write-Host "  DRY RUN - No changes applied" -ForegroundColor Yellow
} else {
    Write-Host "  Completed in $([math]::Round($Duration, 1)) seconds" -ForegroundColor Green
}
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor Cyan
Write-Host "    1. Verify service: sc query NetNinja-Server" -ForegroundColor Gray
Write-Host "    2. Check dashboard: curl -k https://localhost:443/" -ForegroundColor Gray
Write-Host "    3. Monitor logs: Get-Content logs\net_server.log -Tail 20" -ForegroundColor Gray
Write-Host "    4. Configure client VLESS import" -ForegroundColor Gray
