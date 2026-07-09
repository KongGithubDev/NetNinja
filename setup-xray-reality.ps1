<#
.SYNOPSIS
    Xray REALITY Setup Script for Windows — NetNinja
.DESCRIPTION
    Download Xray-core, generate REALITY keypair, create config, install as Windows service
    Run with: PowerShell -ExecutionPolicy Bypass -File setup-xray-reality.ps1
#>

$ErrorActionPreference = "Stop"
$XRAY_VERSION = "1.8.24"  # Latest stable — check https://github.com/XTLS/Xray-core/releases
$XRAY_URL = "https://github.com/XTLS/Xray-core/releases/download/v$XRAY_VERSION/Xray-windows-64.zip"
$INSTALL_DIR = "$env:ProgramFiles\Xray-Reality"
$ZIP_FILE = "$env:TEMP\xray-reality.zip"
$CONFIG_SRC = "$PSScriptRoot\xray-reality-config.json"
$CONFIG_DST = "$INSTALL_DIR\config.json"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   Xray REALITY Setup — NetNinja" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ─── Step 1: Create install directory ───
Write-Host "[1/5] Creating install directory..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $INSTALL_DIR | Out-Null
Write-Host "  → $INSTALL_DIR" -ForegroundColor Green

# ─── Step 2: Download Xray-core ───
Write-Host "[2/5] Downloading Xray-core v$XRAY_VERSION..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri $XRAY_URL -OutFile $ZIP_FILE -UseBasicParsing
    Write-Host "  → Downloaded to $ZIP_FILE" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Download failed. Trying alternative URL..." -ForegroundColor Yellow
    # Fallback: use latest release
    $XRAY_URL = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-windows-64.zip"
    Invoke-WebRequest -Uri $XRAY_URL -OutFile $ZIP_FILE -UseBasicParsing
    Write-Host "  → Downloaded latest release" -ForegroundColor Green
}

# ─── Step 3: Extract ───
Write-Host "[3/5] Extracting..." -ForegroundColor Yellow
Expand-Archive -Path $ZIP_FILE -DestinationPath $INSTALL_DIR -Force
Remove-Item $ZIP_FILE -Force
Write-Host "  → Extracted to $INSTALL_DIR" -ForegroundColor Green

# ─── Step 4: Generate REALITY keys ───
Write-Host "[4/5] Generating REALITY X25519 keys..." -ForegroundColor Yellow
$XRAY_EXE = "$INSTALL_DIR\xray.exe"
$KEY_OUTPUT = & $XRAY_EXE x25519
Write-Host ""
Write-Host "  ╔══════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "  ║         REALITY KEYPAIR              ║" -ForegroundColor Magenta
Write-Host "  ╚══════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host ""
$KEY_OUTPUT | ForEach-Object { Write-Host "  $_" -ForegroundColor White }

# Parse keys
$PRIVATE_KEY = ($KEY_OUTPUT | Select-String "Private key:" | ForEach-Object { $_ -replace '.*Private key:\s*', '' } | ForEach-Object { $_.Trim() })
$PUBLIC_KEY = ($KEY_OUTPUT | Select-String "Public key:" | ForEach-Object { $_ -replace '.*Public key:\s*', '' } | ForEach-Object { $_.Trim() })

# Generate UUID
$UUID = & $XRAY_EXE uuid
Write-Host "  UUID       : $UUID" -ForegroundColor White
Write-Host ""

# ─── Step 5: Create config.json ───
Write-Host "[5/5] Creating REALITY config..." -ForegroundColor Yellow
$CONFIG_CONTENT = Get-Content -Path $CONFIG_SRC -Raw
$CONFIG_CONTENT = $CONFIG_CONTENT.Replace("__PRIVATE_KEY__", $PRIVATE_KEY)
$CONFIG_CONTENT = $CONFIG_CONTENT.Replace("__UUID__", $UUID.Trim())
Set-Content -Path $CONFIG_DST -Value $CONFIG_CONTENT -Encoding UTF8
Write-Host "  → Config created at $CONFIG_DST" -ForegroundColor Green

# ─── Save generated info for client ───
$INFO_FILE = "$INSTALL_DIR\client-info.txt"
@"
╔══════════════════════════════════════════════════════╗
║           Xray REALITY — Client Connection Info      ║
╚══════════════════════════════════════════════════════╝

Server Address:  [YOUR_VPS_IP]
Server Port:     443
Protocol:        VLESS
UUID:            $($UUID.Trim())
Flow:            xtls-rprx-vision
Security:        reality

--- REALITY Settings ---
Password/PublicKey: $PUBLIC_KEY
Server Names:       dl.google.com
Fingerprint:        chrome
Short ID:           6ba85179e30d4fc2
PublicKey:          $PUBLIC_KEY

=== v2rayNG CONFIG ===
vless://$($UUID.Trim())@[YOUR_VPS_IP]:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=dl.google.com&fp=chrome&pbk=$PUBLIC_KEY&sid=6ba85179e30d4fc2&type=tcp&headerType=none#NetNinja-REALITY

⚠️ แก้ [YOUR_VPS_IP] เป็น IP จริงของ VPS ก่อนใช้งาน!
"@ | Out-File -FilePath $INFO_FILE -Encoding UTF8

Write-Host ""
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  ✅ SETUP COMPLETE!" -ForegroundColor Green
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "  📁 Xray installed at : $INSTALL_DIR" -ForegroundColor White
Write-Host "  📄 Config            : $CONFIG_DST" -ForegroundColor White
Write-Host "  📄 Client info       : $INFO_FILE" -ForegroundColor White
Write-Host ""
Write-Host "  ⚡ REALITY Share Link (copy this to v2rayNG):" -ForegroundColor Yellow
Write-Host "  vless://$($UUID.Trim())@YOUR_VPS_IP:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=dl.google.com&fp=chrome&pbk=$PUBLIC_KEY&sid=6ba85179e30d4fc2&type=tcp&headerType=none#NetNinja-REALITY" -ForegroundColor White
Write-Host ""
Write-Host "  ⚠️  แก้ YOUR_VPS_IP เป็น IP จริงของ VPS" -ForegroundColor Red
Write-Host ""

# ─── Optional: Install as Windows Service ───
Write-Host ""
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  RUN OPTIONS" -ForegroundColor Cyan
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "  [1] Run now (manual test):" -ForegroundColor Yellow
Write-Host "      $XRAY_EXE run -c $CONFIG_DST" -ForegroundColor White
Write-Host ""
Write-Host "  [2] Install as Windows Service" -ForegroundColor Yellow
Write-Host "      sc create Xray-Reality binPath=\"$XRAY_EXE run -c $CONFIG_DST\" start=auto" -ForegroundColor White
Write-Host "      sc start Xray-Reality" -ForegroundColor White
Write-Host ""
Write-Host "  [3] Use NSSM (better service manager):" -ForegroundColor Yellow
Write-Host "      nssm install Xray-Reality \"$XRAY_EXE\" \"run -c $CONFIG_DST\"" -ForegroundColor White
Write-Host "      nssm start Xray-Reality" -ForegroundColor White
Write-Host ""

# ─── Test run prompt ───
$RUN_NOW = Read-Host "Run Xray now for test? (y/n)"
if ($RUN_NOW -eq "y") {
    Write-Host ""
    Write-Host "Starting Xray in test mode... (Ctrl+C to stop)" -ForegroundColor Green
    Write-Host ""
    & $XRAY_EXE run -c $CONFIG_DST
}
