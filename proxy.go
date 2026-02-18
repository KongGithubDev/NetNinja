package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// Buffer pool — reuse 64KB buffers to reduce GC pressure
var bufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 64*1024)
		return &buf
	},
}

// DNS cache — avoid repeated lookups for same host
type dnsEntry struct {
	ip     string
	expiry time.Time
}

var dnsCache sync.Map // map[string]dnsEntry

func cachedResolve(ctx context.Context, host string) (string, error) {
	// check cache
	if v, ok := dnsCache.Load(host); ok {
		entry := v.(dnsEntry)
		if time.Now().Before(entry.expiry) {
			return entry.ip, nil
		}
		dnsCache.Delete(host)
	}
	// resolve
	ips, err := customResolver.LookupHost(ctx, host)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("dns: %s: %v", host, err)
	}
	// cache for 5 min
	dnsCache.Store(host, dnsEntry{ip: ips[0], expiry: time.Now().Add(5 * time.Minute)})
	return ips[0], nil
}

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
			conn, err := net.DialTimeout("udp", server, 2*time.Second)
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		log.Printf("%s[DNS]%s All DNS servers failed!", colorRed, colorReset)
		return nil, lastErr
	},
}

// Custom dialer — fast timeouts for snappy connections
var customDialer = &net.Dialer{
	Timeout:   5 * time.Second,
	KeepAlive: 30 * time.Second,
	Resolver:  customResolver,
}

// Custom transport — aggressive connection pooling
var proxyTransport = &http.Transport{
	DialContext:           customDialer.DialContext,
	MaxIdleConns:          500,
	MaxIdleConnsPerHost:   50,
	IdleConnTimeout:       120 * time.Second,
	TLSHandshakeTimeout:   3 * time.Second,
	ExpectContinueTimeout: 500 * time.Millisecond,
	ResponseHeaderTimeout: 15 * time.Second,
	DisableCompression:    false,
	ForceAttemptHTTP2:     true,
	WriteBufferSize:       64 * 1024,
	ReadBufferSize:        64 * 1024,
}

func enableWindowsANSI() {
	if runtime.GOOS != "windows" {
		return
	}
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	setMode := kernel32.NewProc("SetConsoleMode")
	getMode := kernel32.NewProc("GetConsoleMode")
	handle, _ := syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE)
	var mode uint32
	getMode.Call(uintptr(handle), uintptr(unsafe.Pointer(&mode)))
	setMode.Call(uintptr(handle), uintptr(mode|0x0004)) // ENABLE_VIRTUAL_TERMINAL_PROCESSING
}

func main() {
	enableWindowsANSI()

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

		var bypassList string
		for _, d := range directDomains {
			bypassList += fmt.Sprintf(`<li>%s</li>`, d)
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>netninja proxy</title>
<style>
body{background:#111;color:#ccc;font:14px/1.6 'Courier New',monospace;margin:0;padding:40px 20px}
.w{max-width:480px;margin:0 auto}
h1{color:#fff;font-size:18px;margin:0 0 4px;font-weight:normal}
h1 span{color:#0a0}
.sub{color:#555;font-size:12px;margin-bottom:30px}
hr{border:0;border-top:1px solid #222;margin:20px 0}
.row{display:flex;justify-content:space-between;padding:3px 0}
.row .k{color:#777}
.row .v{color:#eee}
.num{color:#0f0;font-size:20px;font-weight:bold}
.pac{background:#1a1a1a;border:1px solid #333;padding:10px 14px;margin:10px 0;word-break:break-all;font-size:12px;color:#7af;cursor:pointer;border-radius:3px}
.pac:hover{border-color:#7af}
.pac:active{background:#222}
ul{margin:6px 0;padding-left:20px;color:#886}
ul li{font-size:12px}
.help{color:#555;font-size:11px;margin-top:30px;line-height:1.5}
.help b{color:#888}
.tag{display:inline-block;background:#1a1a1a;border:1px solid #333;color:#aaa;padding:2px 8px;font-size:11px;margin:2px}
</style>
</head>
<body>
<div class="w">
<h1><span>></span> netninja proxy</h1>
<div class="sub">dns bypass proxy // go</div>

<div class="row"><span class="k">status</span><span class="v" style="color:#0a0">running</span></div>
<div class="row"><span class="k">active connections</span><span class="v num">%d</span></div>
<div class="row"><span class="k">total requests</span><span class="v num">%d</span></div>
<div class="row"><span class="k">proxy</span><span class="v">%s</span></div>
<div class="row"><span class="k">dns</span><span class="v">8.8.8.8, 1.1.1.1</span></div>

<hr>
<div class="row"><span class="k">pac url</span></div>
<div class="pac" onclick="navigator.clipboard.writeText(this.textContent)">%s</div>

<div class="row"><span class="k">bypass (direct)</span></div>
<ul>%s</ul>

<div class="help">
<b>ipad:</b> settings > wifi > (i) > proxy > automatic<br>
paste the pac url above
</div>
</div>
</body>
</html>`, active, total, proxyAddr, pacURL, bypassList)))
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

	// extract hostname and port for cached DNS
	hostname := host
	port := "443"
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		hostname = host[:idx]
		port = host[idx+1:]
	}

	// resolve via cache
	ip, err := cachedResolve(r.Context(), hostname)
	if err != nil {
		atomic.AddInt64(&activeConns, -1)
		log.Printf("%s[ERR]%s DNS %s failed: %s", colorRed, colorReset, hostname, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	destConn, err := net.DialTimeout("tcp", ip+":"+port, 5*time.Second)
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

// transfer pipes data between two connections using pooled buffers
func transfer(dst, src net.Conn) {
	defer dst.Close()
	defer src.Close()
	bufp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufp)
	io.CopyBuffer(dst, src, *bufp)
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
