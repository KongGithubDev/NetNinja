param(
    [string]$ServerIP = "",
    [string]$UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
)

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   NetNinja Xray REALITY Setup Wizard   " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ── 1. Download Xray-core ───────────────────────────────────────────
$XrayDir = Join-Path $PSScriptRoot "xray-core"
$XrayZip = Join-Path $PSScriptRoot "xray.zip"
$XrayExe = Join-Path $XrayDir "xray.exe"

if (!(Test-Path $XrayExe)) {
    Write-Host "[1/4] Downloading Xray-core..." -ForegroundColor Yellow
    $url = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-windows-64.zip"
    try {
        Invoke-WebRequest -Uri $url -OutFile $XrayZip -UseBasicParsing
        Expand-Archive -Path $XrayZip -DestinationPath $XrayDir -Force
        Remove-Item $XrayZip -Force
        Write-Host "      Downloaded to: $XrayDir" -ForegroundColor Green
    } catch {
        Write-Host "      Download failed: $_" -ForegroundColor Red
        Write-Host "      Download manually from: https://github.com/XTLS/Xray-core/releases" -ForegroundColor Yellow
        Write-Host "      Extract to: $XrayDir" -ForegroundColor Yellow
        exit 1
    }
} else {
    Write-Host "[1/4] Xray-core already exists at: $XrayExe" -ForegroundColor Green
}

# ── 2. Generate REALITY key pair ────────────────────────────────────
Write-Host "[2/4] Generating REALITY key pair..." -ForegroundColor Yellow
if (!(Test-Path $XrayExe)) {
    Write-Host "      xray.exe not found at: $XrayExe" -ForegroundColor Red
    Write-Host "      Download manually from: https://github.com/XTLS/Xray-core/releases" -ForegroundColor Yellow
    Write-Host "      Extract to: $XrayDir" -ForegroundColor Yellow
    exit 1
}
$output = & $XrayExe x25519 2>&1
$outputStr = $output | Out-String
$privateKey = ""
$publicKey = ""
if ($outputStr -match "Private key:\s*(\S+)") {
    $privateKey = $Matches[1]
}
if ($outputStr -match "Public key:\s*(\S+)") {
    $publicKey = $Matches[1]
}
if ([string]::IsNullOrEmpty($privateKey) -or [string]::IsNullOrEmpty($publicKey)) {
    Write-Host "      xray x25519 output was:" -ForegroundColor Yellow
    Write-Host "      $outputStr" -ForegroundColor Gray
    Write-Host "      Failed to extract keys. Possible version mismatch." -ForegroundColor Red
    Write-Host "      Generating fallback keys with PowerShell..." -ForegroundColor Yellow
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $privBytes = new-object byte[] 32
    $rng.GetBytes($privBytes)
    $privateKey = [System.Convert]::ToBase64String($privBytes)
    $pubBytes = new-object byte[] 32
    $rng.GetBytes($pubBytes)
    $publicKey = [System.Convert]::ToBase64String($pubBytes)
    Write-Host "      ⚠  Fallback keys generated (not REALITY-valid, just placeholder)" -ForegroundColor Red
    Write-Host "      You MUST run 'xray x25519' manually on VPS and update configs" -ForegroundColor Red
}

Write-Host "      Private Key: $privateKey" -ForegroundColor Green
Write-Host "      Public Key : $publicKey" -ForegroundColor Green

# ── 3. Patch server config ──────────────────────────────────────────
Write-Host "[3/4] Generating server config..." -ForegroundColor Yellow
$serverConfig = @"
{
    "log": {
        "loglevel": "warning"
    },
    "inbounds": [
        {
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$UUID",
                        "flow": "xtls-rprx-vision"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "dest": "www.microsoft.com:443",
                    "serverNames": [
                        "www.microsoft.com",
                        "www.bing.com"
                    ],
                    "privateKey": "$privateKey",
                    "shortIds": [
                        "6ba85179e30d4fc2"
                    ]
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls",
                    "quic"
                ]
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        },
        {
            "protocol": "blackhole",
            "tag": "block"
        }
    ],
    "routing": {
        "rules": [
            {
                "type": "field",
                "ip": [
                    "geoip:private"
                ],
                "outboundTag": "block"
            }
        ]
    }
}
"@

$ServerConfigPath = Join-Path $PSScriptRoot "xray-reality-server.json"
$serverConfig | Set-Content -Path $ServerConfigPath -Encoding ASCII
Write-Host "      Saved: $ServerConfigPath" -ForegroundColor Green

# ── 4. Generate client config ───────────────────────────────────────
if ([string]::IsNullOrEmpty($ServerIP)) {
    $ServerIP = Read-Host "      Enter your VPS IP address"
    if ([string]::IsNullOrEmpty($ServerIP)) {
        Write-Host "      No IP provided. You'll need to edit the client config manually." -ForegroundColor Yellow
    }
}

Write-Host "[4/4] Generating client config..." -ForegroundColor Yellow
$clientConfig = @"
{
    "log": {
        "loglevel": "warning"
    },
    "inbounds": [
        {
            "port": 1080,
            "protocol": "socks",
            "settings": {
                "auth": "noaccount",
                "udp": true
            },
            "tag": "socks-in"
        },
        {
            "port": 1081,
            "protocol": "http",
            "settings": {},
            "tag": "http-in"
        }
    ],
    "outbounds": [
        {
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": "$ServerIP",
                        "port": 443,
                        "users": [
                            {
                                "id": "$UUID",
                                "flow": "xtls-rprx-vision",
                                "encryption": "none"
                            }
                        ]
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverName": "www.microsoft.com",
                    "fingerprint": "chrome",
                    "publicKey": "$publicKey",
                    "shortId": "6ba85179e30d4fc2"
                }
            }
        }
    ]
}
"@

$ClientConfigPath = Join-Path $PSScriptRoot "xray-reality-client.json"
$clientConfig | Set-Content -Path $ClientConfigPath -Encoding ASCII
Write-Host "      Saved: $ClientConfigPath" -ForegroundColor Green

# ── 5. Summary ──────────────────────────────────────────────────────
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "              SETUP COMPLETE             " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ├── SERVER ──────────────────────────────────────────────────────
Write-Host "═══ SERVER (VPS - Linux/Windows) ═══" -ForegroundColor Magenta
Write-Host ""
Write-Host "1. Upload xray-core to your VPS"
Write-Host "2. Copy this config to server:" -ForegroundColor Yellow
Write-Host "   $ServerConfigPath" -ForegroundColor White
Write-Host "3. Run on server:"
Write-Host "   xray run -c xray-reality-server.json" -ForegroundColor Green
Write-Host ""

# ├── CLIENT ──────────────────────────────────────────────────────
Write-Host "═══ CLIENT (Windows) ═══" -ForegroundColor Magenta
Write-Host ""
Write-Host "1. Config ready at:" -ForegroundColor Yellow
Write-Host "   $ClientConfigPath" -ForegroundColor White
Write-Host "2. Run client:"
Write-Host "   $XrayExe run -c xray-reality-client.json" -ForegroundColor Green
Write-Host "3. Set browser/system proxy to:"
Write-Host "   SOCKS5 : 127.0.0.1:1080" -ForegroundColor Cyan
Write-Host "   HTTP   : 127.0.0.1:1081" -ForegroundColor Cyan
Write-Host ""

# ├── NTHIDE (Android) ─────────────────────────────────────────────────
Write-Host "═══ NTHIDE / ANDROID ═══" -ForegroundColor Magenta
Write-Host ""
Write-Host "Use NTHIDE (or v2rayNG) with these params:"
Write-Host "  Address      : $ServerIP" -ForegroundColor White
Write-Host "  Port         : 443" -ForegroundColor White
Write-Host "  UUID         : $UUID" -ForegroundColor White
Write-Host "  Flow         : xtls-rprx-vision" -ForegroundColor White
Write-Host "  Network      : tcp" -ForegroundColor White
Write-Host "  Security     : reality" -ForegroundColor White
Write-Host "  Fingerprint  : chrome" -ForegroundColor White
Write-Host "  ServerName   : www.microsoft.com" -ForegroundColor White
Write-Host "  PublicKey    : $publicKey" -ForegroundColor White
Write-Host "  ShortId      : 6ba85179e30d4fc2" -ForegroundColor White
Write-Host ""
Write-Host "═══ NTHIDE Config (Tap to import) ═══" -ForegroundColor Magenta
Write-Host "vmess://vvows... (use NTHIDE scan feature with above params)" -ForegroundColor Yellow
Write-Host ""

Write-Host "⚠  IMPORTANT: On VPS, open firewall port 443 (TCP)" -ForegroundColor Red
Write-Host "   sudo ufw allow 443/tcp  # Ubuntu" -ForegroundColor Yellow
Write-Host "   firewall-cmd --add-port=443/tcp  # CentOS" -ForegroundColor Yellow
Write-Host ""
Write-Host "Public Key (share with clients): $publicKey" -ForegroundColor Green
Write-Host ""
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
