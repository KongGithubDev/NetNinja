package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// ANSI colors for terminal output
const (
	colorReset  = "\033[0m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorRed    = "\033[31m"
	colorGray   = "\033[90m"
)

// Connection counter
var activeConns int64
var totalRequests int64

// Custom DNS resolver using Google & Cloudflare DNS
var customResolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		servers := []string{"8.8.8.8:53", "1.1.1.1:53", "8.8.4.4:53", "1.0.0.1:53"}
		var lastErr error
		for _, server := range servers {
			conn, err := net.DialTimeout("udp", server, 3*time.Second)
			if err == nil {
				log.Printf("%s[DNS]%s Using DNS server: %s", colorCyan, colorReset, server)
				return conn, nil
			}
			lastErr = err
		}
		log.Printf("%s[DNS]%s All DNS servers failed!", colorRed, colorReset)
		return nil, lastErr
	},
}

// Custom dialer that uses our DNS resolver
var customDialer = &net.Dialer{
	Timeout:   10 * time.Second,
	KeepAlive: 30 * time.Second,
	Resolver:  customResolver,
}

// Custom transport with connection pooling for HTTP forwarding
var proxyTransport = &http.Transport{
	DialContext:           customDialer.DialContext,
	MaxIdleConns:          200,
	MaxIdleConnsPerHost:   20,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   5 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
	DisableCompression:    false,
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	proxy := &http.Server{
		Addr:         "0.0.0.0:" + port,
		Handler:      http.HandlerFunc(handleRequest),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	fmt.Println()
	fmt.Println("=== NetNinja Go Proxy Running on Port " + port + " ===")
	fmt.Println("DNS: Google 8.8.8.8 / Cloudflare 1.1.1.1")
	fmt.Println("Engine: Go (High-Performance Goroutine-based)")
	fmt.Println("==============================================")
	fmt.Println()

	log.Fatal(proxy.ListenAndServe())
}

func getClientIP(r *http.Request) string {
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

// Domains that go DIRECT (not through proxy) — for GFN streaming etc.
var directDomains = []string{
	"*.geforcenow.nvidiagrid.net",
	"*.nvidia.com",
	"*.nvidiagrid.net",
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&totalRequests, 1)

	if r.Method == http.MethodConnect {
		handleConnect(w, r)
	} else if r.URL.Host != "" {
		handleHTTP(w, r)
	} else if r.URL.Path == "/proxy.pac" {
		servePAC(w, r)
	} else if r.URL.Path == "/status" || r.URL.Path == "/" {
		active := atomic.LoadInt64(&activeConns)
		total := atomic.LoadInt64(&totalRequests)

		proxyAddr := os.Getenv("PROXY_ADDR")
		if proxyAddr == "" {
			proxyAddr = r.Host
		}
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		pacURL := fmt.Sprintf("%s://%s/proxy.pac", scheme, r.Host)

		var bypassHTML string
		for _, d := range directDomains {
			bypassHTML += fmt.Sprintf(`<span class="tag">%s</span>`, d)
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetNinja Proxy</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0f;color:#e0e0e0;font-family:'Segoe UI',system-ui,-apple-system,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center}
.container{max-width:520px;width:100%%;padding:20px}
.card{background:linear-gradient(145deg,#12121a,#1a1a2e);border:1px solid rgba(255,255,255,0.06);border-radius:16px;padding:32px;margin-bottom:16px;box-shadow:0 8px 32px rgba(0,0,0,0.4)}
.header{text-align:center;margin-bottom:24px}
.logo{font-size:42px;margin-bottom:8px}
h1{font-size:22px;font-weight:600;background:linear-gradient(135deg,#00d4aa,#7c4dff);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.status-badge{display:inline-flex;align-items:center;gap:6px;background:rgba(0,212,170,0.1);border:1px solid rgba(0,212,170,0.3);color:#00d4aa;padding:6px 14px;border-radius:20px;font-size:13px;font-weight:500;margin-top:12px}
.pulse{width:8px;height:8px;background:#00d4aa;border-radius:50%%;animation:pulse 2s infinite}
@keyframes pulse{0%%,100%%{opacity:1}50%%{opacity:0.3}}
.stats{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:20px 0}
.stat{background:rgba(255,255,255,0.03);border-radius:12px;padding:16px;text-align:center}
.stat-value{font-size:28px;font-weight:700;color:#fff}
.stat-label{font-size:11px;color:#888;text-transform:uppercase;letter-spacing:1px;margin-top:4px}
.section{margin-top:20px}
.section-title{font-size:12px;color:#666;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:10px;font-weight:600}
.pac-url{background:rgba(124,77,255,0.08);border:1px solid rgba(124,77,255,0.2);border-radius:10px;padding:12px 16px;display:flex;align-items:center;justify-content:space-between;gap:10px}
.pac-url code{font-size:12px;color:#b388ff;word-break:break-all;flex:1}
.copy-btn{background:rgba(124,77,255,0.2);border:1px solid rgba(124,77,255,0.3);color:#b388ff;padding:6px 12px;border-radius:8px;cursor:pointer;font-size:12px;white-space:nowrap;transition:all 0.2s}
.copy-btn:hover{background:rgba(124,77,255,0.4)}
.copy-btn:active{transform:scale(0.95)}
.tags{display:flex;flex-wrap:wrap;gap:6px}
.tag{background:rgba(255,152,0,0.1);border:1px solid rgba(255,152,0,0.2);color:#ffb74d;padding:4px 10px;border-radius:6px;font-size:11px;font-family:monospace}
.info{background:rgba(255,255,255,0.02);border-radius:10px;padding:14px 16px;margin-top:12px}
.info-row{display:flex;justify-content:space-between;padding:4px 0;font-size:13px}
.info-label{color:#666}
.info-value{color:#aaa;font-family:monospace;font-size:12px}
.setup{margin-top:16px;padding:16px;background:rgba(0,212,170,0.04);border:1px solid rgba(0,212,170,0.1);border-radius:10px}
.setup p{font-size:12px;color:#888;line-height:1.6}
.setup b{color:#00d4aa}
footer{text-align:center;margin-top:16px;font-size:11px;color:#333}
</style>
</head>
<body>
<div class="container">
<div class="card">
 <div class="header">
  <div class="logo">🥷</div>
  <h1>NetNinja Proxy</h1>
  <div class="status-badge"><span class="pulse"></span> Online</div>
 </div>
 <div class="stats">
  <div class="stat"><div class="stat-value">%d</div><div class="stat-label">Active</div></div>
  <div class="stat"><div class="stat-value">%d</div><div class="stat-label">Total</div></div>
 </div>
 <div class="section">
  <div class="section-title">PAC Auto-Proxy URL</div>
  <div class="pac-url">
   <code id="pac">%s</code>
   <button class="copy-btn" onclick="navigator.clipboard.writeText(document.getElementById('pac').textContent);this.textContent='Copied!';setTimeout(()=>this.textContent='Copy',1500)">Copy</button>
  </div>
 </div>
 <div class="section">
  <div class="section-title">Bypass Domains (DIRECT)</div>
  <div class="tags">%s</div>
 </div>
 <div class="info">
  <div class="info-row"><span class="info-label">Proxy Address</span><span class="info-value">%s</span></div>
  <div class="info-row"><span class="info-label">DNS</span><span class="info-value">8.8.8.8 / 1.1.1.1</span></div>
  <div class="info-row"><span class="info-label">Engine</span><span class="info-value">Go (Goroutine)</span></div>
 </div>
 <div class="setup">
  <div class="section-title">📱 iPad Setup</div>
  <p>Settings → Wi-Fi → <b>(i)</b> → Configure Proxy → <b>Automatic</b><br>URL: paste the PAC URL above</p>
 </div>
</div>
<footer>NetNinja Proxy — High Performance DNS Bypass</footer>
</div>
</body>
</html>`, active, total, pacURL, bypassHTML, proxyAddr)))
	}
}

// servePAC — default PROXY, GFN domains go DIRECT
func servePAC(w http.ResponseWriter, r *http.Request) {
	// PROXY_ADDR overrides the proxy address in PAC (useful when behind Caddy/nginx)
	proxyHost := os.Getenv("PROXY_ADDR")
	if proxyHost == "" {
		proxyHost = r.Host
	}
	if proxyHost == "" {
		proxyHost = "localhost"
	}

	var conditions []string
	for _, domain := range directDomains {
		if strings.HasPrefix(domain, "*.") {
			bare := domain[2:]
			conditions = append(conditions,
				fmt.Sprintf(`    if (dnsDomainIs(host, "%s")) return "DIRECT";`, bare))
		} else {
			conditions = append(conditions,
				fmt.Sprintf(`    if (host == "%s") return "DIRECT";`, domain))
		}
	}

	pac := fmt.Sprintf(`function FindProxyForURL(url, host) {
    if (isPlainHostName(host) ||
        shExpMatch(host, "10.*") ||
        shExpMatch(host, "172.16.*") ||
        shExpMatch(host, "192.168.*") ||
        host == "127.0.0.1" ||
        host == "localhost") {
        return "DIRECT";
    }
%s
    return "PROXY %s; DIRECT";
}
`, strings.Join(conditions, "\n"), proxyHost)

	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write([]byte(pac))

	log.Printf("%s[PAC]%s Served to %s",
		colorCyan, colorReset, getClientIP(r))
}

// handleHTTP forwards standard HTTP requests
func handleHTTP(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	start := time.Now()

	log.Printf("%s[HTTP]%s %s %s%s%s %s← %s%s",
		colorGreen, colorReset,
		r.Method,
		colorYellow, r.URL.Host, colorReset,
		colorGray, clientIP, colorReset)

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
	if err != nil {
		log.Printf("%s[ERR]%s Bad request from %s: %s", colorRed, colorReset, clientIP, err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	copyHeaders(outReq.Header, r.Header)
	outReq.Header.Set("Host", r.URL.Hostname())
	removeHopHeaders(outReq.Header)

	resp, err := proxyTransport.RoundTrip(outReq)
	if err != nil {
		log.Printf("%s[ERR]%s %s → %s: %s", colorRed, colorReset, clientIP, r.URL.Host, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	removeHopHeaders(w.Header())

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)

	log.Printf("%s[HTTP]%s %s %s → %d %s(%s)%s",
		colorGreen, colorReset,
		r.Method, r.URL.Host,
		resp.StatusCode,
		colorGray, time.Since(start).Round(time.Millisecond), colorReset)
}

// handleConnect handles HTTPS CONNECT tunneling
func handleConnect(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	host := r.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}

	log.Printf("%s[TLS]%s CONNECT %s%s%s ← %s%s%s",
		colorCyan, colorReset,
		colorYellow, host, colorReset,
		colorGray, clientIP, colorReset)

	atomic.AddInt64(&activeConns, 1)

	destConn, err := customDialer.DialContext(r.Context(), "tcp", host)
	if err != nil {
		atomic.AddInt64(&activeConns, -1)
		log.Printf("%s[ERR]%s CONNECT %s failed: %s", colorRed, colorReset, host, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		atomic.AddInt64(&activeConns, -1)
		destConn.Close()
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		atomic.AddInt64(&activeConns, -1)
		destConn.Close()
		http.Error(w, "Hijack failed", http.StatusServiceUnavailable)
		return
	}

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	if tc, ok := clientConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	if tc, ok := destConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}

	log.Printf("%s[TLS]%s %s ↔ %s %s(tunnel established)%s",
		colorGreen, colorReset,
		clientIP, host,
		colorGray, colorReset)

	go func() {
		transfer(destConn, clientConn)
		atomic.AddInt64(&activeConns, -1)
		log.Printf("%s[TLS]%s %s ✕ %s %s(closed)%s",
			colorGray, colorReset,
			clientIP, host,
			colorGray, colorReset)
	}()
	go transfer(clientConn, destConn)
}

// transfer pipes data between two connections
func transfer(dst, src net.Conn) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}

// copyHeaders copies HTTP headers
func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// removeHopHeaders removes hop-by-hop headers (not forwarded by proxies)
func removeHopHeaders(h http.Header) {
	hopHeaders := []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailer",
		"Transfer-Encoding", "Upgrade",
	}
	for _, hdr := range hopHeaders {
		h.Del(hdr)
	}
}
