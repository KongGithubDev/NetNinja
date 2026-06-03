# NetNinja

NetNinja is a lightweight, high-performance networking toolkit written in Go. It provides a VLESS VPN server with SNI multiplexing, an HTTP/HTTPS forward proxy with Cisco Umbrella bypass, and a suite of deployment and benchmarking tools.

## Components

### net_server (VLESS VPN + SNI Multiplexer)

A VLESS server with built-in SNI multiplexer that listens on a single TCP/UDP port (default 443) and transparently shares it with an existing web server. It inspects incoming TLS ClientHello packets to route traffic:

- Recognized SNI domains are proxied to the upstream web server (e.g. Nginx on port 8443) preserving the original TLS handshake.
- Unrecognized traffic (e.g. VPN clients using an SNI bug) triggers a dynamically generated in-memory certificate, TLS termination, and VLESS VPN session.
- QUIC/HTTP3 UDP NAT relay runs on the same port for low-latency streaming.

**Features:**
- Real SSL support via `-cert` / `-key` flags or auto-generated self-signed certificates
- ALPN stealth advertising h2 and http/1.1
- Concurrent-safe WebSocket with mutex-protected writes
- WebSocket Ping/Pong heartbeat for unstable mobile networks
- Dual-mode buffer pools: 512KB for TCP streaming, 4KB for UDP
- TCP socket tuning: SetNoDelay, KeepAlive, 512KB socket buffers
- sync.Pool buffer reuse for minimal GC pressure
- Real-time dashboard with bandwidth chart, CDN monitoring, and connection tracking
- PAC auto-config server for browser proxy configuration
- Profile-Guided Optimization (PGO) support

### proxy (HTTP/HTTPS Forward Proxy)

A forward proxy with domain-based filtering and Cisco Umbrella SSE unwrapping. Includes a low-overhead status dashboard.

**Features:**
- Cisco Umbrella SSE detection and transparent domain/IP unwrapping
- Dual DNS resolution (standard + DoH) for bypassing filtered resolvers
- SQLite-backed persistent DNS cache and domain rule store
- Real-time dashboard with active user tracking and connection metrics
- PAC auto-config file served at `/proxy.pac`

---

## Performance Optimizations

### DNS Resolver Chain

1. In-memory cache with video CDN-aware TTL (30s for googlevideo.com, youtube.com, etc.)
2. Standard DNS via Google/Cloudflare resolvers (8.8.8.8, 1.1.1.1)
3. DNS over HTTPS (Cloudflare + Google) as fallback
4. IPv6 (AAAA record) support with automatic IPv4 preference

### QUIC/HTTP3 UDP NAT Relay

UDP NAT relay on the same port as the TCP listener, enabling QUIC/HTTP3 traffic passthrough:
- NAT mapping keyed by client IP:port
- Automatic stale entry cleanup after 5 minutes (check every 2 minutes)
- Race-condition-safe entry creation with isWinner pattern
- 64KB buffer pool for large UDP datagrams

### Garbage Collection Tuning

| Variable | Default | Description |
|----------|---------|-------------|
| NET_GOGC | 200 | Go GC percentage (higher = less frequent GC) |
| NET_MEMLIMIT | 536870912 (512MB) | Soft memory limit to prevent OOM |

### Profile-Guided Optimization

PGO improves throughput by 2-7% on CPU-bound workloads. The `default.pgo` profile file is auto-detected by `go build`. Regenerate with:

```powershell
go build -o profiling-load-gen.exe profiling-load-gen.go
./profiling-load-gen.exe
go build -pgo=default.pgo -o net_server.exe net_server.go
```

---

## Installation

### Prerequisites

- Go 1.21 or later

### Build

```powershell
# Build all components
.\build.ps1

# Or build individually
go build -pgo=default.pgo -o net_server.exe net_server.go
go build -o proxy.exe proxy.go
go build -o load-tester.exe load-tester.go
```

---

## Usage

### 1. VPN Edge Server (net_server)

Runs on a VPS as the tunnel exit node.

```powershell
# With real SSL certificate (recommended)
net_server.exe -port 443 -cert fullchain.pem -key privkey.pem -web-port 8443 -web-sni example.com

# With self-signed certificate
net_server.exe -port 443 -tls true

# Without TLS (for testing)
net_server.exe -port 8444 -tls false
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

NET_PORT, NET_UUID, NET_PATH, NET_TLS, NET_CERT, NET_KEY, NET_WEB_SNI, NET_WEB_PORT, NET_PROXY_ADDR, NET_GOGC, NET_MEMLIMIT

#### Dashboard

Access the real-time control center at `https://[SERVER_IP]:443/`:
- Real-time bandwidth chart (5-minute history)
- Active VPN connections and total requests
- Throughput upload/download in bps
- Video CDN node detection and access counts
- Active destination tracking
- UDP relay count for QUIC/HTTP3
- PAC auto-config URL (click to copy)

#### Client Configuration

```text
vless://[UUID]@[SERVER_IP]:443?encryption=none&security=none&type=ws&host=[SNI_BUG_DOMAIN]&path=%2F#NetNinja
```

Note: Allow insecure certificates (AllowInsecure: true) in the client for self-signed certificate scenarios.

### 2. Traffic Filter (proxy)

A forward proxy for routing local traffic with Cisco Umbrella detection.

```powershell
# Default port 8080
proxy.exe

# Custom port
set PORT=5988 && proxy.exe
```

Dashboard at `http://127.0.0.1:[PORT]/`. PAC file at `/proxy.pac`.

---

## Deployment

```powershell
# One-command deployment (TCP tuning, build, firewall, service install)
.\deploy.ps1

# Dry run to preview changes
.\deploy.ps1 -DryRun

# Deploy with NSSM Windows service
.\install-service.ps1 -Action install

# Configure firewall rules
.\configure-firewall.ps1 -Action apply

# Full deployment checklist: see DEPLOYMENT.md
```

---

## Load Testing

```powershell
# Run all benchmarks (10s per test)
.\run-loadtest.ps1

# Extended test for stable results
.\run-loadtest.ps1 -Duration 30

# Run load-tester directly
load-tester.exe -proxy 127.0.0.1:8444 -direct 127.0.0.1:8444 -duration 10
```

Benchmarks measure: HTTP proxy throughput (1/10/50 concurrency), CONNECT tunnels (5/25), large file transfer bandwidth, PAC/dashboard response time, and P50/P90/P99 latency percentiles.

---

## Project Structure

```
NetNinja/
├── net_server.go          # VLESS VPN + SNI Multiplexer (main component)
├── proxy.go               # HTTP/HTTPS Forward Proxy
├── build.ps1              # Build script with PGO support
├── deploy.ps1             # One-command deployment orchestrator
├── install-service.ps1    # Windows service installer (NSSM)
├── configure-firewall.ps1 # Firewall rule configuration
├── run-loadtest.ps1       # Load test orchestrator
├── load-tester.go         # Benchmark program
├── collect-pgo.ps1        # PGO profile collection
├── profiling-load-gen.go  # PGO workload generator
├── run-netserver.bat      # Quick launcher for net_server
├── run-proxy.bat          # Quick launcher for proxy
├── default.pgo            # PGO profile (auto-detected by Go compiler)
├── DEPLOYMENT.md          # Full deployment checklist
├── BENCHMARKS.md          # Benchmark interpretation guide
└── xray-server-config.json # Xray/V2Ray configuration reference
```

---

## Architecture

### Port Sharing

net_server uses an in-memory listener pattern. The main TCP listener accepts all connections on port 443, then:

1. Reads the first 5 bytes to detect TLS ClientHello or plain HTTP.
2. Extracts the SNI from TLS handshakes.
3. Routes recognized SNIs to the upstream web server via a new TCP connection.
4. Upgrades unrecognized TLS connections to HTTP for VLESS WebSocket handling.
5. Plain HTTP requests are handled directly or forwarded through the built-in proxy.

### DNS Resolution

Multi-layered approach: in-memory cache (with video CDN-aware TTL) -> standard DNS via Google/Cloudflare -> DNS over HTTPS fallback -> IPv6 support with automatic fallback. Detects and unwraps Cisco Umbrella SSE-wrapped domain names.

---

## Disclaimer

This project is built for educational purposes, including network packet analysis and firewall evasion research. The developers are not responsible for any misuse or policy violations if deployed on unauthorized networks.
