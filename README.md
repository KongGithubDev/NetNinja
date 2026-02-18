# NetNinja Proxy

High-performance DNS-bypass proxy written in Go. Routes traffic through Google/Cloudflare DNS to bypass DNS filters while allowing specific domains (e.g. GeForce Now) to connect directly.

## Features

- **DNS Bypass** — Uses Google (8.8.8.8) / Cloudflare (1.1.1.1) DNS
- **HTTPS CONNECT** — Full HTTPS tunneling support
- **PAC File** — Auto-generated proxy auto-config for selective routing
- **HTTPS/TLS** — Optional Let's Encrypt auto-cert
- **GFN Bypass** — GeForce Now / NVIDIA traffic goes DIRECT (no proxy overhead)
- **Zero Dependencies** — Single Go binary, cross-platform

## Quick Start

### Local (HTTP)
```bash
# Build
go build -o proxy.exe proxy.go

# Run
PORT=5987 ./proxy.exe
```

### VPS (HTTPS with Let's Encrypt)
```bash
DOMAIN=proxy.yourdomain.com ./proxy
```
Requires port 80 + 443 open. DNS A record must point to VPS IP (Cloudflare DNS-only/gray cloud).

## Endpoints

| Path | Description |
|------|-------------|
| `/proxy.pac` | PAC file for auto-proxy config |
| `/status` | Status page + connectivity test |
| `/` | Health check |

## iPad Setup

1. **Settings** → **Wi-Fi** → **(i)** → **Configure Proxy** → **Automatic**
2. URL: `http://YOUR_IP:5987/proxy.pac`
3. Save

## Files

| File | Description |
|------|-------------|
| `proxy.go` | Main proxy server (Go) — HTTP/HTTPS |
| `proxy.js` | Node.js proxy with PAC support |
| `debug.js` | Debug proxy with detailed IN/OUT logging |
| `dns.go` | DNS-over-HTTPS forwarder |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP listen port |
| `DOMAIN` | _(empty)_ | Set to enable HTTPS with Let's Encrypt |
| `CERT_DIR` | `certs` | TLS certificate cache directory |

## PAC Bypass Domains

Domains in `directDomains` go DIRECT (skip proxy):
- `*.geforcenow.nvidiagrid.net`
- `*.nvidia.com`
- `*.nvidiagrid.net`

Edit `directDomains` in `proxy.go` to add/remove.

## Deploy

### Windows VPS
```powershell
git clone https://github.com/KongGithubDev/NetNinja.git
cd NetNinja
go build -o proxy.exe proxy.go
$env:DOMAIN="proxy.yourdomain.com"; .\proxy.exe
```

### Linux VPS
```bash
git clone https://github.com/KongGithubDev/NetNinja.git
cd NetNinja
go build -o proxy proxy.go
sudo DOMAIN=proxy.yourdomain.com ./proxy
```

### Systemd Service (Linux)
```ini
[Unit]
Description=NetNinja Proxy
After=network.target

[Service]
Type=simple
Environment=DOMAIN=proxy.yourdomain.com
ExecStart=/home/ubuntu/NetNinja/proxy
Restart=always

[Install]
WantedBy=multi-user.target
```
