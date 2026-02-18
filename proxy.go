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
	fmt.Println("Security: Open Bypass (No Authentication Required)")
	fmt.Println("DNS: Specialized (Google 8.8.8.8 / Cloudflare 1.1.1.1)")
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
	} else if r.URL.Path == "/status" {
		// Status page — open from iPad Safari to verify connectivity
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body style="font-family:sans-serif;text-align:center;padding:50px;background:#121212;color:#e0e0e0">
			<h1 style="color:#4caf50">✅ NetNinja Proxy Active</h1>
			<p>PAC URL: <code>http://` + r.Host + `/proxy.pac</code></p>
			<p>Set this in iPad Wi-Fi > Auto Proxy</p>
		</body></html>`))
	} else {
		active := atomic.LoadInt64(&activeConns)
		total := atomic.LoadInt64(&totalRequests)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf("NetNinja Proxy: Active\nConnections: %d\nRequests: %d", active, total)))
	}
}

// servePAC — default PROXY, GFN domains go DIRECT
func servePAC(w http.ResponseWriter, r *http.Request) {
	proxyHost := r.Host
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
