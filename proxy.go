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

func handleRequest(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&totalRequests, 1)

	if r.Method == http.MethodConnect {
		handleConnect(w, r)
	} else if r.URL.Host != "" {
		handleHTTP(w, r)
	} else {
		// Direct access = health check
		active := atomic.LoadInt64(&activeConns)
		total := atomic.LoadInt64(&totalRequests)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf("NetNinja Proxy: Active (Open Mode)\nActive Connections: %d\nTotal Requests: %d", active, total)))
	}
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
