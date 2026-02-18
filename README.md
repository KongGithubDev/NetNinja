<p align="center">
  <h1 align="center">NetNinja</h1>
  <p align="center">Forward proxy with DNS bypass · Written in Go</p>
</p>

---

NetNinja is a high-performance HTTP/HTTPS forward proxy that routes traffic through public DNS resolvers (Google, Cloudflare) to bypass network-level DNS filtering. It supports PAC-based selective routing, allowing specific domains to connect directly while proxying everything else.

## Architecture

```
Client → PAC file → NetNinja Proxy → Custom DNS (8.8.8.8 / 1.1.1.1) → Destination
                         ↓
                  Direct domains (GFN, NVIDIA) → DIRECT connection
```

## Performance

| Feature | Detail |
|---------|--------|
| DNS resolution | In-memory cache with 5-min TTL via `sync.Map` |
| Data transfer | Zero-alloc `sync.Pool` with 64KB buffers |
| Connection reuse | Pool of 500 idle connections, 50 per host |
| Protocol | HTTP/2 enabled, TCP_NODELAY set |
| I/O | 64KB read/write socket buffers, `io.CopyBuffer` |

## Quick Start

```bash
go build -o proxy proxy.go
PORT=5988 ./proxy
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Proxy listen port |
| `PROXY_ADDR` | `r.Host` | Override the proxy address returned in PAC responses |

## Endpoints

```
GET /            Status dashboard
GET /status      Status dashboard
GET /proxy.pac   Proxy auto-configuration file
```

## Deployment

### Standalone

```bash
PORT=5988 ./proxy
```

### Behind Caddy (TLS termination)

```caddyfile
https://proxy.example.com {
    tls /path/to/cert.pem /path/to/key.pem
    reverse_proxy 127.0.0.1:5988
}
```

Set `PROXY_ADDR=proxy.example.com:5988` so the PAC file returns the correct proxy address for CONNECT tunneling.

> **Note:** Caddy handles TLS for the dashboard and PAC file. HTTPS CONNECT tunneling goes directly to port 5988 — this is expected behavior for forward proxies.

### DNS Record

| Type | Name | Value | Proxy |
|------|------|-------|-------|
| A | `proxy` | VPS IP | DNS only ☁️ |

## Client Setup (iOS / iPadOS)

1. **Settings** → **Wi-Fi** → tap **(i)** → **Configure Proxy** → **Automatic**
2. Enter PAC URL:
   ```
   https://proxy.example.com/proxy.pac
   ```

## Direct Bypass

The following domains bypass the proxy and connect directly. This is configured via `directDomains` in `proxy.go`:

```
*.geforcenow.nvidiagrid.net
*.nvidia.com
*.nvidiagrid.net
```

## Project Structure

```
proxy.go    Main proxy server
debug.js    Debug proxy with request logging
dns.go      DNS-over-HTTPS local forwarder
run.bat     Windows launcher
```

## Author

**Watcharapong Namsaeng** — [@KongGithubDev](https://github.com/KongGithubDev)

## License

[MIT](LICENSE)
