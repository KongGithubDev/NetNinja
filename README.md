# NetNinja Proxy

High-performance DNS-bypass proxy written in Go. Routes traffic through Google/Cloudflare DNS to bypass DNS filters while allowing specific domains (e.g. GeForce Now) to connect directly.

## Features

- **DNS Bypass** — Uses Google (8.8.8.8) / Cloudflare (1.1.1.1) DNS
- **HTTPS CONNECT** — Full HTTPS tunneling support
- **PAC File** — Auto-generated proxy auto-config for selective routing
- **GFN Bypass** — GeForce Now / NVIDIA traffic goes DIRECT
- **Zero Dependencies** — Single Go binary, cross-platform

## Quick Start

```bash
go build -o proxy.exe proxy.go
PORT=5988 ./proxy.exe
```

## Endpoints

| Path | Description |
|------|-------------|
| `/proxy.pac` | PAC file for auto-proxy config |
| `/status` | Dashboard with stats & setup info |
| `/` | Same as /status |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP listen port |
| `PROXY_ADDR` | _(auto)_ | Override proxy address in PAC file (for Caddy/nginx setup) |

## Deploy with Caddy (HTTPS)

Proxy runs HTTP on port 5988, Caddy handles TLS:

**run.bat:**
```bat
@echo off
set PORT=5988
set PROXY_ADDR=proxy.netninja.kongwatcharapong.in.th:5988
proxy.exe
pause
```

**Caddyfile:**
```caddy
https://proxy.netninja.kongwatcharapong.in.th {
    tls /path/to/cert.pem /path/to/key.pem
    reverse_proxy 127.0.0.1:5988
}
```

**Cloudflare DNS:**
- Type: `A` | Name: `proxy.netninja` | IP: VPS IP | Proxy: DNS only (gray)

**Firewall:**
```powershell
netsh advfirewall firewall add rule name="NetNinja Proxy" dir=in action=allow protocol=tcp localport=5988
```

## iPad Setup

1. Settings → Wi-Fi → **(i)** → Configure Proxy → **Automatic**
2. URL: `https://proxy.netninja.kongwatcharapong.in.th/proxy.pac`

## PAC Bypass Domains

These domains skip the proxy (DIRECT):
- `*.geforcenow.nvidiagrid.net`
- `*.nvidia.com`
- `*.nvidiagrid.net`

Edit `directDomains` in `proxy.go` to customize.

## Files

| File | Description |
|------|-------------|
| `proxy.go` | Main proxy server (Go) |
| `proxy.js` | Node.js proxy with PAC |
| `debug.js` | Debug proxy with detailed logging |
| `dns.go` | DNS-over-HTTPS forwarder |
