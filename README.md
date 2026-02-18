# NetNinja Proxy

High-performance HTTP/HTTPS forward proxy built in Go. Bypasses DNS filters using Google & Cloudflare DNS servers.

## Features

- ⚡ **Go-powered** — goroutine-per-connection, handles thousands of concurrent connections
- 🌐 **HTTP Forwarding** — with connection pooling (200 idle conns)
- 🔒 **HTTPS CONNECT Tunneling** — full TLS passthrough
- 🛡️ **Custom DNS** — Google (8.8.8.8) & Cloudflare (1.1.1.1), bypasses DNS-level blocking
- 📦 **Single binary** — no dependencies, no `npm install`
- 🚀 **Render.com ready** — deploy with one click

## Quick Start

### Windows
```batch
run.bat
```

### Manual
```bash
# Build
go build -o proxy.exe proxy.go

# Run (default port 8080)
set PORT=5987
proxy.exe
```

### Use as Proxy
Set your Wi-Fi / browser proxy settings to:
```
HTTP Proxy: localhost
Port: 5987
```

## Deploy (Render.com)

1. Push to GitHub
2. Connect repo on [Render.com](https://render.com)
3. `render.yaml` auto-configures everything (Go runtime, port 10000)

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT`   | `8080`  | Proxy listen port |

## Architecture

```
Client ──► NetNinja Proxy ──► Custom DNS (8.8.8.8/1.1.1.1) ──► Target Server
              │
              ├─ HTTP:    Forward with connection pooling
              └─ HTTPS:   CONNECT tunnel (TCP pipe)
```

## Tech Stack

- **Go** (stdlib only, zero dependencies)
- `net/http` — HTTP server & transport
- `net` — TCP tunneling with `TCP_NODELAY`
- Custom `net.Resolver` — DNS bypass
