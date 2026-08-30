# NetNinja

High-performance Go forward proxy with CGNAT keepalive for mobile devices.

![Preview](preview.png)

## Features

- HTTP/HTTPS forward proxy with CONNECT tunneling
- CGNAT keepalive page (maintains NAT mapping via periodic pings)
- Ad blocking (191K+ domains from hagezi blocklist)
- SOCKS5 hop for blocked domains (bilibili, cloudflare)
- Per-user auth & quota management
- Admin dashboard
- Cross-platform (Linux, Windows)

## Architecture

```
iPad (Wi-Fi proxy:5988) ──→ Azure VM (proxy:5988) ──→ Internet
                                    │
                                    ├── Caddy (HTTPS:443) ──→ keepalive server (:8080)
                                    │     ↑
                                    │     └── https://<YOUR_DOMAIN>
                                    │         (periodic fetch keeps CGNAT mapping alive)
                                    │
                                    └── Forward proxy (:5988)
                                          └── CONNECT tunnels to external sites
```

## Components

| Component | Port | Purpose |
|-----------|------|---------|
| `proxy.go` | 5988 | Forward proxy (CONNECT + HTTP) |
| Caddy | 443 | HTTPS termination + reverse proxy |
| `keepalive_server.go` | 8080 | CGNAT keepalive page |

## Quick Start

### Build

```bash
# Linux binary
$env:GOOS="linux"; $env:GOARCH="amd64"; go build -o netninja-proxy-linux proxy.go keepalive_linux.go ansi_other.go

# Keepalive server
$env:GOOS="linux"; $env:GOARCH="amd64"; go build -o netninja-keepalive-linux keepalive_server.go
```

### Deploy to Azure VM

```bash
# Copy binaries
scp -i azure-sg.key netninja-proxy-linux <USER>@<SERVER_IP>:/tmp/proxy_linux
scp -i azure-sg.key netninja-keepalive-linux <USER>@<SERVER_IP>:/tmp/keepalive_server

# Deploy
ssh -i azure-sg.key <USER>@<SERVER_IP> "
  sudo systemctl stop netninja-proxy
  sudo cp /tmp/proxy_linux /opt/netninja/proxy_linux
  sudo chmod +x /opt/netninja/proxy_linux
  sudo systemctl start netninja-proxy

  sudo systemctl stop netninja-keepalive
  sudo cp /tmp/keepalive_server /opt/netninja/keepalive_server
  sudo chmod +x /opt/netninja/keepalive_server
  sudo systemctl start netninja-keepalive
"
```

## iPad Configuration

1. Wi-Fi settings → HTTP Proxy → Manual
2. Server: `<YOUR_SERVER_IP>`, Port: `5988`
3. Open Safari → `https://<YOUR_DOMAIN>`
4. Tap **Start Keepalive** → keeps CGNAT mapping alive

## CGNAT Keepalive

TOT FTTH uses CGNAT with ~4-5 min idle timeout. The keepalive page sends periodic HTTP pings through the proxy tunnel to maintain the NAT mapping.

- **Method**: Periodic fetch every 5 seconds (more resilient than SSE on iOS)
- **Audio loop**: Keeps Safari JS alive when backgrounded
- **Auto-reconnect**: Resumes on `visibilitychange` / `pageshow`

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `5988` | Proxy listen port(s), comma-separated |
| `PROXY_AUTH_ENABLED` | `0` | Enable user authentication |
| `PROXY_USERS` | - | `user:pass` pairs, comma-separated |
| `ADMIN_USER` | `admin` | Dashboard username |
| `ADMIN_PASS` | - | Dashboard password |
| `HOP_SOCKS5` | - | SOCKS5 proxy for blocked domains |
| `HOP_DOMAINS` | - | Domains to route via SOCKS5 |
| `ADBLOCK_URL` | - | URL to ad blocklist |
| `PROXY_ADDR` | - | Server public address |

## Troubleshooting

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md)

## License

MIT
