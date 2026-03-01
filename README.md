# NetNinja 🥷🏽

**NetNinja** is a lightweight, multipurpose networking toolkit written in Go. It's built specifically to deploy fast forward proxies and bypass firewalls using WebSocket (VLESS) tunnels. It's designed to be fast, minimal, and very light on system resources.

## Core Tools

1. **`net_server.go` (VLESS VPN + SNI Multiplexer)** 🔥  
   This is the real star of the show. It's a VLESS server upgraded with a built-in **SNI Multiplexer**. This allows your server to listen on port `443` while seamlessly sharing the same port with your existing web server (like Nginx or Caddy). It works by sniffing the incoming TLS ClientHello packets:
   - If someone visits your normal website, it proxies the raw traffic straight to your real web server (so your SSL stays intact).
   - If the incoming traffic is from a VPN client using an **SNI Bug** (like `line.me` etc.), it automatically generates a temporary in-memory Dummy Certificate, terminates the TLS, and smoothly transitions into providing a VLESS VPN connection!
   - ⚠️ **Important Note:** Because `net_server` relies on intercepting SNI handshakes, it **ONLY works on port 443**.

2. **`proxy.go` (NetNinja HTTP/HTTPS Proxy)**  
   A straightforward Forward Proxy that you can use to route local traffic or deploy basic domain filtering. It even comes with a low-overhead dashboard to monitor status at `http://127.0.0.1:8080/`.

---

## Installation & Usage

### 1. The VPN Edge Server (`net_server.go`)

This is what you run on your VPS to act as your exit node. You can build it straight from source:

```bash
go build -o net_server.exe net_server.go
```

To run it, you can use the provided batch script (`run-netserver.bat`) or run it manually. 

If you want to share port `443` with your existing website (putting `net_server` in the front), run it with these parameters:
```bash
./net_server.exe -port 443 -tls true -web-port 8443 -web-sni your-domain.com
```
In short, you just need to reconfigure Nginx/Caddy to listen on an internal port like `8443` instead of 443. `net_server` will take over 443; if someone asks for `your-domain.com`, it kicks them over to 8443. Any other weird domains get handled as VPN traffic!

**Client App Setup:**
Copy this URI and paste it directly into your favorite client (V2Ray, v2box, Shadowrocket). 
*(Make sure to enable `allowInsecure: true` or "Skip Cert Verify" in your app, since we use dynamically generated Dummy Certs!)*
```text
vless://[UUID]@[SERVER_IP]:443?encryption=none&security=none&type=ws&host=[YOUR_SNI_BUG]&path=%2F#NetNinjaTunnel
```

### 2. The Traffic Filter (`proxy.go`)

Useful if you want to test filtering or set up a local network proxy.

```bash
go build -o proxy.exe proxy.go
```

Just run it:
```bash
proxy.exe
```

---

*Disclaimer: This project was built strictly for educational purposes, learning how to manipulate network packets, and studying firewall evasion techniques. The developers are not responsible for any misuse or policy violations if deployed on unauthorized networks! 🙏🏼*
