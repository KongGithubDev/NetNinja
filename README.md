# NetNinja 🥷
**The Ultimate Stealth Browser & High-Speed Proxy Tunnel**

NetNinja is a dual-mode content access solution designed to bypass DNS filters, firewalls, and network restrictions while maintaining high performance for gaming (y8.com) and streaming.

## 🚀 Modes

### 1. HTTP/HTTPS Proxy Tunnel (Best for Gaming)
A lightweight, high-performance proxy that offloads DNS resolution to the server while allowing your local device (iPad/PC) to render content natively.
*   **Zero Lag**: Games run on your device's GPU.
*   **Stealth**: Looks like normal HTTPS traffic.
*   **Multi-User**: Share access with friends via unique credentials.

### 2. Remote Browser (Best for Privacy/Security)
A full cloud-hosted Chrome instance that streams the display to your device.
*   **Total Isolation**: No code runs on your device.
*   **Persistent Session**: Downloads/Games continue even if you disconnect.
*   **480p Turbo**: Optimized for low-bandwidth connections.

---

## 🛠️ Quick Start (Proxy Mode)

### Prerequisites
*   Node.js (v18+)
*   A VPS or PC to run the server

### Installation
1.  Clone the repository
2.  Install dependencies:
    ```bash
    npm install
    ```
3.  Configure `.env` (Create file if not exists):
    ```env
    PORT=8080
    # Format: user:pass,user2:pass2
    PROXY_USERS=admin:1234,friend:5678
    ```
4.  Run the proxy:
    ```bash
    node proxy.js
    ```

### Client Setup (iPad/iPhone)
1.  Go to **Settings** > **Wi-Fi**.
2.  Tap **(i)** next to your Wi-Fi name.
3.  Scroll to **HTTP Proxy** > **Configure Proxy**.
4.  Select **Manual**:
    *   **Server**: `<YOUR_SERVER_IP>`
    *   **Port**: `8080`
    *   **Authentication**: On
    *   **Username/Password**: (Use values from `.env`)

---

## 🖥️ Quick Start (Remote Browser Mode)

### Usage
1.  Run the browser server:
    ```bash
    node server.js
    ```
2.  Open `http://<YOUR_SERVER_IP>:3000` in any browser.
3.  Enjoy full persistent browsing!

---

## ☁️ Deployment (Render.com / VPS)

### Render.com
1.  Push code to GitHub.
2.  Create new **Web Service**.
3.  Set Start Command: `node proxy.js`.
4.  Add Environment Variables from `.env`.

### VPS (DigitalOcean / AWS)
Use PM2 to keep it running 24/7:
```bash
npm install -g pm2
pm2 start proxy.js --name "netninja-proxy"
pm2 save
pm2 startup
```

## ⚠️ Disclaimer
This tool is for educational purposes and authorized network testing only.
