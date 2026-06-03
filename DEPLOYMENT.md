# NetNinja Deployment Checklist

## Prerequisites

- [ ] Windows Server 2019/2022 or Windows 10/11 Pro (for port 443 binding)
- [ ] Go 1.21+ installed and added to PATH
- [ ] Git installed
- [ ] Administrator access (required for port 443, firewall, and TCP tuning)
- [ ] Domain name with DNS A record pointing to the VPS IP
- [ ] SSL certificate (optional but recommended)

---

## Step 1: TCP Stack Optimization

Run the following in PowerShell **as Administrator** to optimize the Windows TCP stack for high-throughput proxy traffic:

```powershell
# Apply all TCP optimizations
netsh int tcp set global autotuninglevel=normal
netsh int tcp set global fastopen=enabled
netsh int tcp set global timestamps=disabled
netsh int tcp set global ecncapability=enabled
netsh int tcp set global initialRto=2000
netsh int tcp set global rss=enabled
netsh int tcp set global chimney=disabled

# Verify settings
netsh int tcp show global
```

**Expected output:**
```
Receive-Side Scaling State          : enabled
Chimney Offload State               : disabled
NetDMA State                        : enabled
Direct Cache Acess (DCA)            : enabled
Receive Window Auto-Tuning Level    : normal
Add-On Congestion Control Provider  : default
ECN Capability                      : enabled
RFC 1323 Timestamps                 : disabled
Initial RTO                         : 2000
Non Sack Rtt Resiliency             : disabled
Max SYN Retransmissions             : 2
Fast Open                           : enabled
Fast Open Fallback                  : enabled
Hybrid Slow Start                   : enabled
Proactive Connection Rate Estimate  : disabled
Proactive Initial RTO               : disabled
```

---

## Step 2: Build Binaries

```powershell
# Clone or copy source
cd C:\NetNinja

# Build both components with PGO
.\build.ps1

# Verify binaries exist
dir net_server.exe, proxy.exe
```

Expected output:
```
net_server.exe  11.4 MB
proxy.exe        9.8 MB
```

---

## Step 3: Certificate Placement

### Option A: Real SSL Certificate (Recommended)

Place certificate files in the same directory as net_server.exe:

```
C:\NetNinja\
├── net_server.exe
├── proxy.exe
├── fullchain.pem      # Public certificate chain
├── privkey.pem         # Private key (keep secure!)
├── default.pgo         # PGO profile (optional)
├── run-netserver.bat
└── run-proxy.bat
```

**Security:** Restrict private key permissions:
```powershell
icacls privkey.pem /inheritance:r /grant "SYSTEM:(R)" /grant "Administrators:(R)"
```

### Option B: Cloudflare Origin Certificate

1. Log in to Cloudflare Dashboard
2. Navigate to SSL/TLS > Origin Server
3. Create a new certificate (let Cloudflare generate the private key)
4. Save the certificate as `fullchain.pem` and key as `privkey.pem`
5. Set Cloudflare SSL/TLS mode to **Full (strict)**

### Option C: Let's Encrypt (with acme.sh)

```powershell
# Install acme.sh
git clone https://github.com/acmesh-official/acme.sh.git
cd acme.sh
.\acme.sh --install

# Issue certificate
.\acme.sh --issue --standalone -d your-domain.com

# Install certificate
.\acme.sh --install-cert -d your-domain.com `
    --fullchain-file C:\NetNinja\fullchain.pem `
    --key-file C:\NetNinja\privkey.pem

# Schedule renewal (runs daily via Windows Task Scheduler)
.\acme.sh --install-cronjob
```

---

## Step 4: Firewall Configuration

### Windows Defender Firewall

```powershell
# Run as Administrator

# Allow VLESS VPN traffic (port 443 TCP + UDP)
netsh advfirewall firewall add rule name="NetNinja-VLESS-TCP" `
    dir=in action=allow protocol=TCP localport=443 `
    program="C:\NetNinja\net_server.exe" profile=any

netsh advfirewall firewall add rule name="NetNinja-VLESS-UDP" `
    dir=in action=allow protocol=UDP localport=443 `
    program="C:\NetNinja\net_server.exe" profile=any

# Allow Proxy traffic (port 8080 or custom)
netsh advfirewall firewall add rule name="NetNinja-Proxy-TCP" `
    dir=in action=allow protocol=TCP localport=8080 `
    program="C:\NetNinja\proxy.exe" profile=any

# Optional: restrict management dashboard to local network only
netsh advfirewall firewall add rule name="NetNinja-Management" `
    dir=in action=allow protocol=TCP localport=8443 profile=private

# Verify rules
netsh advfirewall firewall show rule name="NetNinja-*"
```

### Cloud/Hypervisor Firewall (Required)

In your VPS control panel, add inbound rules for:

| Protocol | Port | Source | Purpose |
|----------|------|--------|---------|
| TCP | 443 | 0.0.0.0/0 | VLESS VPN + SNI Multiplexer |
| UDP | 443 | 0.0.0.0/0 | QUIC/HTTP3 relay |
| TCP | 8080 | your-ip | Proxy admin (restrict if possible) |
| TCP | 8443 | 0.0.0.0/0 | Upstream web server (if used) |

---

## Step 5: NGINX/Caddy Upstream Web Server (Optional)

If using the SNI multiplexer with an upstream web server:

### NGINX Configuration

```nginx
# C:\nginx\conf\nginx.conf
server {
    listen 127.0.0.1:8443 ssl http2;
    server_name your-domain.com;

    ssl_certificate C:\NetNinja\fullchain.pem;
    ssl_certificate_key C:\NetNinja\privkey.pem;

    root C:\nginx\html;
    index index.html;
}
```

### Caddy Configuration

```caddyfile
your-domain.com:8443 {
    root * C:\caddy\site
    file_server
}
```

---

## Step 6: Install as Windows Service (Auto-Restart)

### Using NSSM (Non-Sucking Service Manager)

```powershell
# Download NSSM
curl -L -o nssm.zip https://nssm.cc/release/nssm-2.24.zip
Expand-Archive nssm.zip -DestinationPath C:\nssm

# Install net_server as service
C:\nssm\win64\nssm.exe install NetNinja-Server "C:\NetNinja\net_server.exe" `
    "-cert fullchain.pem -key privkey.pem"

# Configure auto-restart
C:\nssm\win64\nssm.exe set NetNinja-Server AppExit Default Exit
C:\nssm\win64\nssm.exe set NetNinja-Server AppThrottle 5000
C:\nssm\win64\nssm.exe set NetNinja-Server AppStdout C:\NetNinja\logs\net_server.log
C:\nssm\win64\nssm.exe set NetNinja-Server AppStderr C:\NetNinja\logs\net_server.log

# Set environment variables for the service
C:\nssm\win64\nssm.exe set NetNinja-Server AppEnvironmentExtra `
    NET_GOGC=200 `
    NET_MEMLIMIT=536870912

# Start the service
C:\nssm\win64\nssm.exe start NetNinja-Server

# Verify service is running
C:\nssm\win64\nssm.exe status NetNinja-Server
sc query NetNinja-Server
```

### Alternative: Using install-service.ps1 (included)

```powershell
.\install-service.ps1 -Action install
```

---

## Step 7: Verify Deployment

### Check service health

```powershell
# Check service status
sc query NetNinja-Server

# Check listening ports
netstat -an | findstr ":443"
netstat -an | findstr ":8080"
```

Expected output for `netstat`:
```
TCP    0.0.0.0:443     0.0.0.0:0     LISTENING
UDP    0.0.0.0:443     *:*                     (if QUIC/HTTP3 relay enabled)
```

### Verify dashboard

```powershell
# Test dashboard responds (PowerShell)
Invoke-WebRequest -Uri https://localhost:443/ -UseBasicParsing | Select-Object -ExpandProperty StatusCode

# Test dashboard responds (cmd.exe)
curl -k -s -o NUL -w "%%{http_code}" https://localhost:443/
```

Expected: `200`

### Test DNS resolution

```powershell
# net_server uses Google DNS (8.8.8.8) and DoH fallback
# Verify by checking a YouTube domain
nslookup googlevideo.com 8.8.8.8
```

### Test client connection

From a remote machine, import the VLESS URI into a compatible client:
```
vless://[UUID]@[SERVER_IP]:443?encryption=none&security=none&type=ws&host=[SNI_BUG_DOMAIN]&path=%2F#NetNinja
```

---

## Step 8: Monitoring Setup

### Built-in Dashboard

Access the real-time dashboard at:
```
https://[SERVER_IP]:443/
```

Features:
- Real-time bandwidth chart (5 min history)
- Active VPN connections and total requests
- Throughput (upload/download) in bps
- Video CDN node detection and access counts
- Active destination tracking
- UDP relay count for QUIC/HTTP3
- PAC auto-config URL

### Windows Performance Monitor

```powershell
# Create a data collector set for NetNinja
logman create counter NetNinja-Metrics `
    -c "\Process(net_server)\*" `
    -o "C:\NetNinja\logs\NetNinja-Metrics" `
    -f bin -v mmddhhmm -max 500

logman start NetNinja-Metrics
```

### Scheduled Log Cleanup

Create `C:\NetNinja\scripts\cleanup-logs.ps1`:
```powershell
# Keep only last 7 days of logs
Get-ChildItem "C:\NetNinja\logs\*.log" | Where-Object {
    $_.LastWriteTime -lt (Get-Date).AddDays(-7)
} | Remove-Item -Force

# Keep only last 30 days of metrics
Get-ChildItem "C:\NetNinja\logs\*.blg" | Where-Object {
    $_.LastWriteTime -lt (Get-Date).AddDays(-30)
} | Remove-Item -Force
```

Add to Task Scheduler:
```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-File C:\NetNinja\scripts\cleanup-logs.ps1"
$trigger = New-ScheduledTaskTrigger -Daily -At 3am
Register-ScheduledTask -TaskName "NetNinja-LogCleanup" `
    -Action $action -Trigger $trigger -RunLevel Highest
```

---

## Quick Reference

### Service Management

```powershell
# Service control
nssm start NetNinja-Server
nssm stop NetNinja-Server
nssm restart NetNinja-Server
nssm status NetNinja-Server

# Windows native
sc start NetNinja-Server
sc stop NetNinja-Server
sc query NetNinja-Server
```

### Log Locations

| Component | Log Path |
|-----------|----------|
| net_server stdout | C:\NetNinja\logs\net_server.log |
| net_server stderr | C:\NetNinja\logs\net_server.log |
| PGO profile | C:\NetNinja\default.pgo |
| proxy SQLite cache | C:\NetNinja\proxy_cache.db |

### Common Fixes

**Port 443 already in use:**
```powershell
netstat -ano | findstr :443
# Kill the conflicting process
taskkill /PID [PID] /F
```

**Service fails to start:**
```powershell
# Check logs
Get-Content C:\NetNinja\logs\net_server.log -Tail 20

# Verify certificate paths
Test-Path C:\NetNinja\fullchain.pem
Test-Path C:\NetNinja\privkey.pem
```

**No UDP relay:**
- Check if another process is listening on UDP port 443
- Verify port availability: `netstat -an | findstr ":443"`
- The relay is non-fatal -- net_server runs without it

**High memory usage:**
- Reduce `NET_MEMLIMIT` (default 512MB)
- Increase `NET_GOGC` (default 200) to reduce GC frequency
- Monitor with: `tasklist /FI "IMAGENAME eq net_server.exe"`
