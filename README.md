# NetNinja Proxy 🥷 
**The High-Speed Stealth Proxy Tunnel with Built-in DNS Security**

NetNinja is a lightweight, high-performance proxy solution designed to bypass DNS filters and network restrictions. It's optimized for stability, lower latency, and ease of use on devices like iPads and iPhones.

## ✨ Key Features

*   **⚡ High-Speed Connection**: Optimization for lower latency (Nagle's Algorithm off), making it ideal for gaming and streaming.
*   **🔒 Secure DNS**: Automatically bypasses local DNS filters by using **Google DNS (8.8.8.8)** and **Cloudflare (1.1.1.1)** for all name resolutions.
*   **🔓 Open Access**: No authentication required! Just connect and browse instantly without any password prompts.
*   **🕵️ Stealth Mode**: Offloads DNS resolution to the server, so your local device only makes simple proxy connections.

## 🛠️ Quick Start

### Prerequisites
*   Node.js (v18+)

### Installation & Run
1.  Clone the repository.
2.  Install dependencies:
    ```bash
    npm install
    ```
3.  Run the proxy:
    ```bash
    node proxy.js
    ```

---

## 📱 Client Setup (iPad/iPhone)

1.  Go to **Settings** > **Wi-Fi**.
2.  Tap the **(i)** next to your connected Wi-Fi.
3.  Scroll down to **HTTP Proxy** and select **Configure Proxy**.
4.  Choose **Manual**:
    *   **Server**: `<YOUR_SERVER_IP>`
    *   **Port**: `8080` (or the port displayed in the console)
    *   **Authentication**: **OFF**
5.  Save and start browsing!

---

## ☁️ Deployment

### VPS (DigitalOcean / AWS)
Use PM2 to keep it running 24/7:
```bash
npm install -g pm2
pm2 start proxy.js --name "netninja-proxy"
pm2 save
pm2 startup
```

---

## ⚠️ Disclaimer
This tool is for educational purposes and authorized network testing only.
