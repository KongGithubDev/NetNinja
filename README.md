# NetNinja

NetNinja is a lightweight, high-performance networking toolkit written in Go. It provides a VLESS VPN server with SNI multiplexing and an HTTP/HTTPS forward proxy, designed for low-latency streaming and firewall evasion.

## Components

### 1. net_server (VLESS VPN + SNI Multiplexer)

A VLESS server with built-in SNI multiplexer that listens on a single port (default 443) and transparently shares it with an existing web server. It inspects incoming TLS ClientHello packets:

- Recognized SNI domains are proxied to the upstream web server (e.g. Nginx on port 8443) preserving the original TLS handshake.
- Unrecognized traffic (e.g. VPN clients using an SNI bug) triggers a dynamically generated in-memory certificate, TLS termination, and VLESS VPN session.

**Key Features:**

- Real SSL support via `-cert` / `-key` flags or auto-generated self-signed certificates
- ALPN stealth advertising h2 and http/1.1
- Concurrent-safe WebSocket with mutex-protected writes
- WebSocket Ping/Pong heartbeat for unstable mobile networks
- Dual-mode buffer pools: 512KB for TCP streaming, 4KB for UDP
- TCP socket tuning: SetNoDelay, KeepAlive, 512KB socket buffers
- sync.Pool buffer reuse for minimal GC pressure

### 2. proxy (HTTP/HTTPS Forward Proxy)

A forward proxy with domain-based filtering and Cisco Umbrella SSE unwrapping. Includes a low-overhead status dashboard.

**Key Features:**

- Cisco Umbrella SSE detection and transparent unwrapping
- Dual DNS resolution (standard + DoH) for bypassing filtered resolvers
- SQLite-backed persistent DNS cache and domain rule store
- Real-time dashboard with active user tracking and connection metrics

---

## Performance Optimizations

### DNS Resolver Chain

1. In-memory cache (with video CDN-aware TTL)
2. Standard DNS via Google/Cloudflare resolvers (8.8.8.8, 1.1.1.1)
3. DNS over HTTPS (Cloudflare + Google) as fallback
4. IPv6 (AAAA record) support with automatic fallback

Video streaming CDN domains (googlevideo.com, youtube.com, fbcdn.net, etc.) use a reduced TTL of 30 seconds to ensure optimal edge node selection.

### QUIC/HTTP3 UDP NAT Relay

net_server includes a UDP NAT relay on the same port as the TCP listener, enabling QUIC/HTTP3 traffic to pass through the tunnel. This reduces latency for YouTube live streams and other services that prefer QUIC over TCP.

- NAT mapping keyed by client IP:port
- Automatic stale entry cleanup after 5 minutes
- Race-condition-safe entry creation with isWinner pattern
- 64KB buffer pool for large UDP datagrams

### Garbage Collection Tuning

Both components support GC tuning via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| NET_GOGC | 200 | Go GC percentage target (higher = less frequent GC) |
| NET_MEMLIMIT | 536870912 (512MB) | Soft memory limit to prevent OOM |

---

## Installation

### Prerequisites

- Go 1.21 or later
- Git

### Build

```bash
# Build both components
go build -o net_server.exe net_server.go
go build -o proxy.exe proxy.go

# Build with version injection (proxy.go only)
powershell -File build.ps1
```

---

## Usage

### 1. VPN Edge Server (net_server)

This component runs on a VPS as the tunnel exit node.

#### Basic (Self-Signed Certificate)

```bash
./net_server.exe -port 443 -tls true -web-port 8443 -web-sni example.com
```

#### With Real SSL Certificate

```bash
./net_server.exe -port 443 -cert fullchain.pem -key privkey.pem -web-port 8443 -web-sni example.com
```

#### Command-Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| -port | 443 | Listen port |
| -uuid | b831381d-6324-4d53-ad4f-8cda48b30811 | VLESS UUID |
| -path | / | WebSocket path for VLESS |
| -tls | true | Enable internal TLS termination |
| -cert | | Path to SSL certificate (PEM) |
| -key | | Path to SSL private key (PEM) |
| -web-sni | | Comma-separated SNI domains to forward to web server |
| -webport | 8443 | Local web server port |
| -pac | /proxy.pac | PAC file path |
| -proxy-addr | | Override proxy address in PAC |
| -udp-port | *auto | UDP port for QUIC/HTTP3 relay (*auto = same as -port) |

#### Environment Variables

The following flags support environment variables: `NET_PORT`, `NET_UUID`, `NET_PATH`, `NET_TLS`, `NET_CERT`, `NET_KEY`, `NET_WEB_SNI`, `NET_WEB_PORT`, `NET_PROXY_ADDR`, `NET_GOGC`, `NET_MEMLIMIT`. Flags `-pac` and `-udp-port` are flag-only.

#### Dashboard

The control dashboard is accessible at `https://[SERVER_IP]:443/` and features:

- Real-time bandwidth chart (5-minute history)
- Active VPN connection count and total requests
- Throughput upload/download display
- Video CDN node detection and access counts
- Active destination tracking
- UDP relay count for QUIC/HTTP3 tunneling
- PAC auto-config URL (one-click copy)

#### Client Configuration

Import the following URI into a compatible client (v2rayN, v2box, Shadowrocket, etc.):

```
vless://[UUID]@[SERVER_IP]:443?encryption=none&security=none&type=ws&host=[SNI_BUG_DOMAIN]&path=%2F#NetNinja
```

Note: Allow insecure certificates in the client, as the server uses dynamically generated certificates for non-matched SNI traffic.

### 2. Traffic Filter (proxy)

A forward proxy for routing local traffic with Cisco Umbrella detection.

```bash
# Default port 8080
proxy.exe

# Custom port
set PORT=5988 && proxy.exe
```

#### Dashboard

Accessible at `http://127.0.0.1:[PORT]/` or `http://127.0.0.1:8080/` by default.

#### PAC Auto-Config

The proxy automatically serves a PAC file at `/proxy.pac`. Configure your browser to use this PAC URL for automatic proxy routing.

---

## VPS Tuning (Windows)

For optimal performance on Windows VPS, run the following in PowerShell (Administrator):

```powershell
netsh int tcp set global autotuninglevel=normal
netsh int tcp set global fastopen=enabled
netsh int tcp set global timestamps=disabled
netsh int tcp set global ecncapability=enabled
```

For maximum throughput, a Linux VPS with BBR congestion control is recommended over Windows Server.

---

## Architecture

### Port Sharing

net_server uses an in-memory listener pattern. The main TCP listener accepts all connections on port 443, then:

1. Reads the first 5 bytes to detect TLS ClientHello or plain HTTP.
2. Extracts the SNI from TLS handshakes.
3. Routes recognized SNIs to the upstream web server via a new TCP connection.
4. Upgrades unrecognized TLS connections to HTTP for VLESS WebSocket handling.
5. Plain HTTP requests are handled directly by the built-in HTTP server.

### DNS Resolution

Both components implement a multi-layered DNS resolution strategy:

- **Standard DNS**: Go's native resolver configured to use Google/Cloudflare.
- **DNS over HTTPS**: Fallback to Cloudflare DNS over HTTPS and Google DNS over HTTPS when standard DNS is blocked or fails.
- **Caching**: In-memory cache with configurable TTL. proxy.go additionally persists to SQLite for cross-session caching.
- **Cisco Umbrella Bypass**: Detects and unwraps Cisco SSE-wrapped domain names before resolution.

---

## Disclaimer

This project is built for educational purposes, including network packet analysis and firewall evasion research. The developers are not responsible for any misuse or policy violations if deployed on unauthorized networks.
