# NetNinja Go

A lightweight, high-performance networking tool written in Go. This repository contains components for setting up secure forward proxies and WebSocket-based tunnels (VLESS).

## Architecture

* **`proxy.go` (NetNinja Proxy)**: A standard HTTP/HTTPS forward proxy implementation. It features basic traffic auditing, request caching, and domain filtering capabilities (e.g., matching known malicious domains).
* **`net_server.go` (NetServer Tunnel)**: A minimalist WebSocket server. It implements a subset of the VLESS protocol to provide a secure tunnel point for authorized clients. 

---

## Deployment Data

### 1. Building the WebSocket Tunnel (`net_server.go`)
This service acts as the endpoint for your tunneled traffic.

```bash
go build -o net_server.exe net_server.go
```

**Running the Tunnel:**
Use the provided batch script or run it manually.

```bash
run-netserver.bat
```
*Note: The default port is `8080`. Adjust `NET_PORT`, `NET_UUID`, and `NET_PATH` in the `.bat` file according to your network requirements.*

**Client Connection Details:**
Compatible clients (e.g., v2ray-core, v2box, etc.) can connect using standard VLESS JSON structures or URI links. Format:

```text
vless://[UUID]@[SERVER_IP]:[PORT]?encryption=none&security=none&type=ws&host=[HOST_HEADER]&path=%2F#NetTunnel
```

### 3. Deploying to Render.com (Free Tier)
`net_server.go` is fully compatible with platform-as-a-service providers like Render.com. 

**Features added for Cloud Deployment:**
- **Dynamic Port Binding**: Automatically detects the `$PORT` environment variable required by Render.
- **Keep-Alive Endpoint**: Includes a `/healthz` HTTP endpoint that always returns HTTP 200 OK. You can use a free cron-job service (like cron-job.org) to ping `https://[your-render-url].onrender.com/healthz` every 10 minutes to prevent the free tier from spinning down (sleeping).

**Deployment Steps:**
1. Upload this codebase to a GitHub repository.
2. In Render.com, create a new **Web Service**.
3. Connect your GitHub repository.
4. Render Configuration:
   - **Environment:** `Go`
   - **Build Command:** `go build -o net_server net_server.go`
   - **Start Command:** `./net_server`
5. Click **Deploy**. Render will allocate a URL (e.g., `https://netninja-tunnel.onrender.com`), and automatically handle the SSL/TLS/Port 443 termination for you!

*(Alternatively, you can just use the provided `render-netserver.yaml` Blueprint file)*

---

### 4. Building the Forward Proxy (`proxy.go`)
This service is intended for localized network routing and filtering.

```bash
go build -o proxy.exe proxy.go
```

**Running the Proxy:**
```bash
proxy.exe
```
Access the local monitoring dashboard via standard HTTP at `http://127.0.0.1:8080/`.

---

## Disclaimer
This project is intended strictly for educational purposes, network routing studies, and personal privacy enhancement on authorized networks. The maintainers are not responsible for any misuse, policy violations, or damages caused by deploying this software in unauthorized environments.
