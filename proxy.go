package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"database/sql"

	"github.com/gorilla/websocket"
	_ "modernc.org/sqlite"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

var db *sql.DB
var openedForIPs sync.Map // map[string]bool

// Proxy Basic Auth — loaded from PROXY_USERS="user:pass,user2:pass2"
var proxyUsers = map[string]string{}

func authRequired(w http.ResponseWriter, r *http.Request) bool {
	if len(proxyUsers) == 0 {
		return true
	}
	auth := r.Header.Get("Proxy-Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		w.Header().Set("Proxy-Authenticate", `Basic realm="NetNinja"`)
		http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		w.Header().Set("Proxy-Authenticate", `Basic realm="NetNinja"`)
		http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
		return false
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		w.Header().Set("Proxy-Authenticate", `Basic realm="NetNinja"`)
		http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
		return false
	}
	if want, ok := proxyUsers[parts[0]]; ok && want == parts[1] {
		return true
	}
	w.Header().Set("Proxy-Authenticate", `Basic realm="NetNinja"`)
	http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
	return false
}

// DNS cache — avoid repeated lookups for same host
type dnsEntry struct {
	ip     string
	expiry time.Time
}

var dnsCache sync.Map // map[string]dnsEntry

var localIPs = make(map[string]bool)
var localIPsMu sync.RWMutex

func updateLocalIPs() {
	newIPs := make(map[string]bool)
	newIPs["127.0.0.1"] = true
	newIPs["::1"] = true
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, address := range addrs {
			if ipnet, ok := address.(*net.IPNet); ok {
				newIPs[ipnet.IP.String()] = true
			}
		}
	}
	localIPsMu.Lock()
	localIPs = newIPs
	localIPsMu.Unlock()
}

type ruleEntry struct {
	rule  string
	cisco bool
}

var ruleCache sync.Map // map[string]ruleEntry

func cachedResolve(ctx context.Context, host string) (string, error) {
	// 0. If it's already an IP, return as is
	if net.ParseIP(host) != nil {
		return host, nil
	}

	// 1. check in-memory cache
	if v, ok := dnsCache.Load(host); ok {
		entry := v.(dnsEntry)
		if time.Now().Before(entry.expiry) {
			atomic.AddInt64(&dnsHits, 1)
			return entry.ip, nil
		}
		dnsCache.Delete(host)
	}
	atomic.AddInt64(&dnsMisses, 1)

	// 2. check SQLite persistent cache
	var ip string
	var expiry time.Time
	err := db.QueryRow("SELECT ip, expiry FROM dns_records WHERE host = ?", host).Scan(&ip, &expiry)
	if err == nil && time.Now().Before(expiry) {
		dnsCache.Store(host, dnsEntry{ip: ip, expiry: expiry}) // Put back to memory
		return ip, nil
	}

	// 3. resolve via custom Go resolver (Standard DNS)
	ips, err := customResolver.LookupHost(ctx, host)
	if err == nil && len(ips) > 0 {
		ip = ips[0]
	} else {
		// 4. resolve via DoH (DNS over HTTPS) — bypass Cisco filters
		log.Printf("%s[BLOCK-BYPASS]%s DNS failed for %s, switching to DoH...", colorRed, colorReset, host)
		ip, err = resolveDoH(host)
		if err != nil {
			return "", fmt.Errorf("dns total failure: %s: %v", host, err)
		}
	}

	// cache results (5 min) - Nitro: Async DB write
	exp := time.Now().Add(5 * time.Minute)
	dnsCache.Store(host, dnsEntry{ip: ip, expiry: exp})
	go func() {
		_, _ = db.Exec("INSERT OR REPLACE INTO dns_records (host, ip, expiry) VALUES (?, ?, ?)", host, ip, exp)
	}()
	return ip, nil
}

// hyperResolve resolves via standard DNS and DoH simultaneously
func hyperResolve(ctx context.Context, host string) (string, error) {
	if net.ParseIP(host) != nil {
		return host, nil
	}

	// 1. Check Cache
	if v, ok := dnsCache.Load(host); ok {
		entry := v.(dnsEntry)
		if time.Now().Before(entry.expiry) {
			atomic.AddInt64(&dnsHits, 1)
			return entry.ip, nil
		}
	}
	atomic.AddInt64(&dnsMisses, 1)

	type res struct {
		ip  string
		err error
	}
	ch := make(chan res, 2)
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	go func() {
		ips, err := customResolver.LookupHost(ctx, host)
		if err == nil && len(ips) > 0 {
			// Prefer IPv4 for stability (IPv6 often breaks naive ip:port joins / no route)
			for _, ip := range ips {
				if ip4 := net.ParseIP(ip); ip4 != nil && ip4.To4() != nil {
					ch <- res{ip: ip, err: nil}
					return
				}
			}
			ch <- res{ip: ips[0], err: nil}
		} else {
			ch <- res{ip: "", err: err}
		}
	}()

	go func() {
		ip, err := resolveDoH(host)
		ch <- res{ip: ip, err: err}
	}()

	var lastErr error
	for i := 0; i < 2; i++ {
		r := <-ch
		if r.err == nil && r.ip != "" {
			// Cache result for 5 min
			exp := time.Now().Add(5 * time.Minute)
			dnsCache.Store(host, dnsEntry{ip: r.ip, expiry: exp})
			go func() {
				_, _ = db.Exec("INSERT OR REPLACE INTO dns_records (host, ip, expiry) VALUES (?, ?, ?)", host, r.ip, exp)
			}()
			return r.ip, nil
		}
		lastErr = r.err
	}

	return "", lastErr
}

// DoH resolution using Cloudflare/Google
func resolveDoH(host string) (string, error) {
	urls := []string{
		"https://cloudflare-dns.com/dns-query?name=" + host + "&type=A",
		"https://cloudflare-dns.com/dns-query?name=" + host + "&type=AAAA",
		"https://dns.google/resolve?name=" + host + "&type=A",
		"https://dns.google/resolve?name=" + host + "&type=AAAA",
	}

	client := &http.Client{Timeout: 3 * time.Second}
	for _, url := range urls {
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Accept", "application/dns-json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		var res struct {
			Answer []struct {
				Data string `json:"data"`
				Type int    `json:"type"`
			} `json:"Answer"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&res); err == nil && len(res.Answer) > 0 {
			resp.Body.Close()
			atomic.AddInt64(&dohCalls, 1)
			// Prefer A records (IPv4) for stability, fallback to AAAA (IPv6)
			for _, ans := range res.Answer {
				if ans.Type == 1 { // A record
					return ans.Data, nil
				}
			}
			for _, ans := range res.Answer {
				if ans.Type == 28 { // AAAA record (IPv6)
					return ans.Data, nil
				}
			}
		}
		resp.Body.Close()
	}
	return "", fmt.Errorf("doh: failed for %s", host)
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
var totalBytesUp int64   // bytes sent to targets (client → internet)
var totalBytesDown int64 // bytes received from targets (internet → client)
var dnsHits int64
var dnsMisses int64
var dohCalls int64
var errCount int64
var startTime time.Time
var userTracker sync.Map // map[string]time.Time (IP -> last seen)

// Host traffic stats (host -> last seen + counters)
type hostStat struct {
	mu    sync.Mutex
	count int64
	bytes int64
	last  time.Time
}
var hostStats sync.Map // map[string]*hostStat

func (h *hostStat) addConn(n int64) {
	h.mu.Lock()
	h.count++
	h.bytes += n
	h.last = time.Now()
	h.mu.Unlock()
}

// Rolling traffic history for the sparkline (1 value / sec, 60 slots)
var bwHistory []int64
var bwHistoryMu sync.Mutex

// Active tunnel list for the dashboard
var activeTunnels sync.Map // map[string]time.Time (host -> start time)

var buildTime = "manual_build" // Auto-injected via -ldflags during build

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

// Custom dialer — Native performance with aggressive keep-alive
var customDialer = &net.Dialer{
	Timeout:   10 * time.Second,
	KeepAlive: 30 * time.Second,
	Resolver:  customResolver,
	Control: func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			// Leave SO_RCVBUF/SO_SNDBUF alone to allow Windows Auto-Tuning (God-Mode)
			// Windows is superior at calculating optimal window sizes for fiber.
		})
	},
}

// Custom transport — God-Mode concurrency for heavy video streaming
var proxyTransport = &http.Transport{
	DialContext:           customDialer.DialContext,
	MaxIdleConns:          5000,
	MaxIdleConnsPerHost:   100,
	IdleConnTimeout:       60 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
	ResponseHeaderTimeout: 60 * time.Second,
	DisableCompression:    false,
	ForceAttemptHTTP2:     true,
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite", "proxy_cache.db")
	if err != nil {
		log.Fatal("Failed to open SQLite:", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS domain_rules (
		domain TEXT PRIMARY KEY,
		rule TEXT,
		cisco_detected INTEGER DEFAULT 0,
		last_seen TIMESTAMP
	)`)
	if err != nil {
		log.Fatal("Failed to create domain_rules table:", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS dns_records (
		host TEXT PRIMARY KEY,
		ip TEXT,
		expiry TIMESTAMP
	)`)
	if err != nil {
		log.Fatal("Failed to create dns_records table:", err)
	}

	// Clean up old entries
	_, _ = db.Exec("DELETE FROM domain_rules WHERE last_seen < datetime('now', '-7 days')")
	_, _ = db.Exec("DELETE FROM dns_records WHERE expiry < datetime('now')")
}

func getDomainRule(host string) (string, bool) {
	if v, ok := ruleCache.Load(host); ok {
		e := v.(ruleEntry)
		return e.rule, e.cisco
	}
	// Fallback to DB if cache miss (should be rare)
	var rule string
	var cisco int
	err := db.QueryRow("SELECT rule, cisco_detected FROM domain_rules WHERE domain = ?", host).Scan(&rule, &cisco)
	if err == nil {
		ruleCache.Store(host, ruleEntry{rule: rule, cisco: cisco == 1})
		return rule, cisco == 1
	}
	return "", false
}

func setDomainRule(host string, rule string, cisco bool) {
	ciscoVal := 0
	if cisco {
		ciscoVal = 1
	}
	ruleCache.Store(host, ruleEntry{rule: rule, cisco: cisco})
	// Nitro: Async SQLite write
	go func() {
		_, _ = db.Exec("INSERT OR REPLACE INTO domain_rules (domain, rule, cisco_detected, last_seen) VALUES (?, ?, ?, DATETIME('now'))", host, rule, ciscoVal)
	}()
}

// unwrapCiscoDomain extracts the original domain or IP from Cisco SSE wrapped hostnames
// Case 1: web.cloudmoonapp.com.x.bdd7...sse.cisco-secure.com -> web.cloudmoonapp.com
// Case 2: bc2c576109ac804ca...sse.cisco-secure.com -> 188.44.87.97 (Hex IP)
func unwrapCiscoDomain(host string) string {
	if !strings.Contains(host, ".sse.cisco-secure.com") {
		return host
	}

	// Case 1: Domain with .x. delimiter
	if idx := strings.Index(host, ".x."); idx != -1 {
		return host[:idx]
	}

	// Case 2: Hex-encoded IP
	// Usually the first part of the hostname before the first dot
	firstPart := host
	if idx := strings.Index(host, "."); idx != -1 {
		firstPart = host[:idx]
	}

	// Cisco hex IPs are typically 32-char hashes where the first 8 chars are Hex IP
	if len(firstPart) >= 8 {
		hexPart := firstPart[:8]
		// Check if it's valid hex
		isHex := true
		for _, c := range hexPart {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				isHex = false
				break
			}
		}

		if isHex {
			// Convert 8 hex chars to 4 bytes
			var ipBytes [4]byte
			for i := 0; i < 4; i++ {
				var b byte
				fmt.Sscanf(hexPart[i*2:i*2+2], "%02x", &b)
				ipBytes[i] = b
			}
			ip := net.IPv4(ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3]).String()
			return ip
		}
	}

	return host
}

// isManualProxy checks if a domain should always use proxy logic
func isManualProxy(host string) bool {
	// No manual rules — routing is now 100% detection-based
	return false
}

func main() {
	// Nitro Performance Tuning
	runtime.GOMAXPROCS(runtime.NumCPU())
	// GC tuning via env vars: NET_GOGC (default 200), NET_MEMLIMIT (default 512MB)
	if g := os.Getenv("NET_GOGC"); g != "" {
		if v, err := strconv.Atoi(g); err == nil {
			debug.SetGCPercent(v)
		}
	} else {
		debug.SetGCPercent(200)
	}
	if m := os.Getenv("NET_MEMLIMIT"); m != "" {
		if v, err := strconv.ParseInt(m, 10, 64); err == nil {
			debug.SetMemoryLimit(v)
		}
	} else {
		debug.SetMemoryLimit(512 * 1024 * 1024) // 512MB
	}
	startTime = time.Now()

	enableWindowsANSI()
	initDB()
	defer db.Close()

	// Extreme Performance: Cache local IPs and preload rules
	updateLocalIPs()
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
			updateLocalIPs()
		}
	}()

	rows, err := db.Query("SELECT domain, rule, cisco_detected FROM domain_rules")
	if err == nil {
		for rows.Next() {
			var d, r string
			var c int
			if rows.Scan(&d, &r, &c) == nil {
				ruleCache.Store(d, ruleEntry{rule: r, cisco: c == 1})
			}
		}
		rows.Close()
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	if pu := os.Getenv("PROXY_USERS"); pu != "" {
		for _, up := range strings.Split(pu, ",") {
			if idx := strings.Index(up, ":"); idx > 0 {
				proxyUsers[up[:idx]] = up[idx+1:]
			}
		}
		fmt.Printf("Proxy auth enabled for %d user(s)\n", len(proxyUsers))
	}

	bindAddr := os.Getenv("BIND_ADDR")
	if bindAddr == "" {
		bindAddr = "0.0.0.0"
	}

	proxy := &http.Server{
		Addr:         bindAddr + ":" + port,
		Handler:      http.HandlerFunc(handleRequest),
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  180 * time.Second,
	}

	fmt.Println()
	fmt.Println("=== NetNinja Go Proxy Running on Port " + port + " ===")
	fmt.Println("DNS: Google 8.8.8.8 / Cloudflare 1.1.1.1")
	fmt.Println("Engine: Go (High-Performance Goroutine-based)")
	fmt.Println("==============================================")
	fmt.Println()

	log.Fatal(proxy.ListenAndServe())
}

func isLocalIP(ip string) bool {
	localIPsMu.RLock()
	defer localIPsMu.RUnlock()
	return localIPs[ip]
}

func getClientIP(r *http.Request) string {
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	ip = strings.Trim(ip, "[]")
	if ip == "::1" || ip == "" {
		ip = "127.0.0.1"
	}
	return ip
}

// isVideoDomain returns true for video streaming CDN domains that benefit from shorter DNS TTL
func isVideoDomain(host string) bool {
	h := strings.ToLower(host)
	return strings.Contains(h, "googlevideo.com") ||
		strings.Contains(h, "youtube.com") ||
		strings.Contains(h, "ytimg.com") ||
		strings.Contains(h, "ggpht.com") ||
		strings.Contains(h, "fbcdn.net") ||
		strings.Contains(h, "tiktokcdn") ||
		strings.Contains(h, "cloudfront.net") ||
		strings.Contains(h, "akamai") ||
		strings.Contains(h, "fastly") ||
		strings.Contains(h, "cloudflare") ||
		strings.Contains(h, ".cdn.")
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&totalRequests, 1)

	clientIP := getClientIP(r)
	trackingIP := clientIP
	if isLocalIP(clientIP) {
		trackingIP = "LOCAL-HOST"
	}
	userTracker.Store(trackingIP, time.Now())

	// Shorter DNS TTL for video streaming domains — force refresh for optimal CDN node
	if isVideoDomain(r.URL.Hostname()) {
		dnsCache.Delete(strings.ToLower(r.URL.Hostname()))
	}

	if r.Method == http.MethodConnect {
		if !authRequired(w, r) {
			return
		}
		handleConnect(w, r)
		return
	}

	path := r.URL.Path
	host := r.URL.Host

	// If the request is for this proxy itself (even if it's an absolute URL)
	isForSelf := (host == "" || isSelf(host, r.Host))

	if isForSelf {
		if path == "/proxy.pac" {
			servePAC(w, r)
			return
		} else if path == "/block-check" {
			serveBlockCheck(w, r)
			return
		} else if path == "/ws" {
			serveWS(w, r)
			return
		} else if path == "/welcome" {
			clientIP := getClientIP(r)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ยินดีต้อนรับสู่ NetNinja</title>
<style>
body{background:#0a0a0a;color:#ccc;font:13px/1.6 'Courier New',monospace;margin:0;display:flex;align-items:center;justify-content:center;height:100vh}
.w{max-width:400px;text-align:center;padding:40px;background:#111;border:1px solid #222;border-radius:8px;box-shadow:0 10px 30px rgba(0,0,0,0.5)}
h1{color:#fff;font-size:24px;margin:0 0 10px;font-weight:normal}
h1 span{color:#0a0;margin-right:10px}
p{color:#888;margin-bottom:25px}
.ip{color:#7af;font-weight:bold;margin:10px 0;font-size:16px}
.btn{display:inline-block;padding:12px 24px;background:#060;color:#fff;text-decoration:none;border-radius:4px;font-weight:bold;transition:0.3s;border:1px solid #0a0}
.btn:hover{background:#080;transform:translateY(-2px);box-shadow:0 5px 15px rgba(0,170,0,0.3)}
.footer{margin-top:40px;font-size:10px;color:#333;text-transform:uppercase;letter-spacing:1px}
</style>
</head>
<body>
<div class="w">
    <h1><span>●</span> ยินดีต้อนรับ</h1>
    <p>ระบบ NetNinja Proxy พร้อมใช้งานแล้วสำหรับการเชื่อมต่อของคุณ</p>
    <div style="color:#444;font-size:10px;text-transform:uppercase;letter-spacing:2px;margin-bottom:5px">client_address_detected</div>
    <div class="ip">%s</div>
    <div style="margin-top:35px">
        <a href="/" class="btn">เข้าสู่ Dashboard</a>
    </div>
    <div class="footer">powered_by // netninja_engine</div>
</div>
</body>
</html>`, clientIP)))
			return
		} else if path == "/logs" {
			serveLogs(w, r)
			return
		} else if path == "/status" || path == "/" {
			proxyAddr := os.Getenv("PROXY_ADDR")
			if proxyAddr == "" {
				proxyAddr = r.Host
			}
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			pacURL := fmt.Sprintf("%s://%s/proxy.pac", scheme, r.Host)

			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-cache")
			w.Write([]byte(fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>netninja proxy [build %s]</title>
<style>
body{background:#0a0a0a;color:#ccc;font:13px/1.6 'Courier New',monospace;margin:0;padding:40px 20px}
.w{max-width:550px;margin:0 auto}
h1{color:#fff;font-size:18px;margin:0 0 4px;font-weight:normal;display:flex;align-items:center}
h1 span{color:#0a0;margin-right:10px}
.sub{color:#444;font-size:11px;margin-bottom:30px;letter-spacing:1px}
hr{border:0;border-top:1px solid #222;margin:25px 0}
.row{display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid #111}
.row .k{color:#666;text-transform:lowercase}
.row .v{color:#eee;transition:all 0.3s}
.num{color:#0f0;font-weight:bold}
.pac-box{background:#111;border:1px solid #222;padding:12px 15px;margin:15px 0;border-radius:4px}
.pac-box .k{color:#444;font-size:10px;margin-bottom:8px;text-transform:uppercase}
.pac-url{color:#7af;word-break:break-all;font-size:11px;cursor:pointer}
.flash{color:#fff !important;text-shadow:0 0 8px #0f0}
.tag-list{margin-top:10px;display:flex;flex-wrap:wrap;gap:5px}
.tag{background:#181818;color:#888;padding:2px 8px;font-size:10px;border-radius:3px;border:1px solid #222}
.ip-link{color:#7af;text-decoration:none;border-bottom:1px dotted #333}
.ip-link:hover{color:#fff;border-bottom:1px solid #7af}
.section-title{color:#444;font-size:10px;text-transform:uppercase;letter-spacing:1px;margin:25px 0 10px}
.footer{margin-top:40px;font-size:11px;color:#333}
.footer a{color:#555;text-decoration:none}
.footer a:hover{color:#7af}
</style>
</head>
<body>
<div class="w">
	<h1><span>●</span> netninja proxy</h1>
	<div class="sub">terminal_interface // build: %s</div>

	<div class="section-title">core_metrics</div>
	<div class="row"><span class="k">uptime</span><span class="v" id="uptime">--</span></div>
	<div class="row"><span class="k">active_users</span><span class="v num" id="users" style="color:#7af">0</span></div>
	<div id="ip_list" class="tag-list" style="margin-bottom:10px"></div>
	<div class="row"><span class="k">active_tunnels</span><span class="v num" id="active">0</span></div>
	<div class="row"><span class="k">total_reqs</span><span class="v num" id="total">0</span></div>

	<div class="section-title">live_traffic</div>
	<div class="row"><span class="k">bytes_up</span><span class="v" id="bytes_up">0</span></div>
	<div class="row"><span class="k">bytes_down</span><span class="v" id="bytes_down">0</span></div>
	<div class="row"><span class="k">dns_cache_hits</span><span class="v num" id="dns_hits" style="color:#0f0">0</span></div>
	<div class="row"><span class="k">dns_cache_misses</span><span class="v" id="dns_misses">0</span></div>
	<div class="row"><span class="k">doh_fallbacks</span><span class="v" id="doh_calls">0</span></div>
	<div class="row"><span class="k">errors</span><span class="v" id="err_count" style="color:#f55">0</span></div>
	<div class="spark-wrap">
		<canvas id="bw_spark" width="510" height="52"></canvas>
		<div class="spark-label">throughput_b/sec_history_60s</div>
	</div>

	<div class="section-title">active_tunnels_by_host</div>
	<div class="tag-list" id="tunnels">--</div>

	<div class="section-title">top_hosts_by_conns</div>
	<div class="mini-table" id="top_hosts">
		<div class="mini-row"><span>--</span></div>
	</div>

	<div class="section-title">top_traffic_hosts</div>
	<div class="mini-table" id="recent_traffic">
		<div class="mini-row"><span>--</span></div>
	</div>

	<div class="section-title">memory_runtime</div>
	<div class="row"><span class="k">heap_alloc</span><span class="v" id="mem_heap">--</span></div>
	<div class="row"><span class="k">sys_total</span><span class="v" id="mem_sys">--</span></div>
	<div class="row"><span class="k">goroutines</span><span class="v" id="goroutines">0</span></div>
	<div class="row"><span class="k">runtime_env</span><span class="v" id="go_ver" style="font-size:10px;color:#555">--</span></div>

	<div class="section-title">persistence_stats</div>
	<div class="row"><span class="k">db_rules</span><span class="v" id="db_rules">0</span></div>
	<div class="row"><span class="k">cisco_detections</span><span class="v" id="cisco_hits" style="color:#f55">0</span></div>
	<div class="row"><span class="k">cache_file_size</span><span class="v" id="db_size">--</span></div>

	<div class="pac-box">
		<div class="k">pac_auto_config</div>
		<div class="pac-url" onclick="navigator.clipboard.writeText(this.textContent)">%s</div>
	</div>

	<div class="section-title">recent_intercepts</div>
	<div class="tag-list" id="recent">--</div>

	<div class="footer">
		<a href="/logs">view_full_logs</a> &nbsp;•&nbsp; 
		<a href="/block-check">block_check</a> &nbsp;•&nbsp;
		<span id="ws_status" style="color:#444">connecting_ws...</span>
		<div style="margin-top:15px;color:#222;font-size:10px;text-transform:uppercase;letter-spacing:1px">
			developed_by // Watcharapong Namsaeng
		</div>
	</div>
</div>

<style>
.mini-table{display:flex;flex-direction:column;gap:2px;margin-bottom:10px}
.mini-row{display:flex;justify-content:space-between;padding:3px 0;border-bottom:1px solid #0d0d0d;font-size:11px}
.mini-row .h{color:#7af;word-break:break-all}
.mini-row .c{color:#0f0}
.mini-row .m{color:#888}
.spark-wrap{margin-top:12px}
.spark-label{color:#444;font-size:10px;letter-spacing:1px;margin-top:4px}
#bw_spark{background:#0d0d0d;border:1px solid #1a1a1a;width:100%%;max-width:510px;border-radius:3px}
</style>

<script>
	const updateVal = (id, val) => {
		const el = document.getElementById(id);
		if (el && el.textContent !== String(val)) {
			el.textContent = val;
			el.classList.add('flash');
			setTimeout(() => el.classList.remove('flash'), 500);
		}
	};

	const fmtBytes = (b) => {
		if (!b) return '0 b';
		if (b < 1024) return b + ' b';
		if (b < 1048576) return (b/1024).toFixed(1) + ' kb';
		if (b < 1073741824) return (b/1048576).toFixed(2) + ' mb';
		return (b/1073741824).toFixed(2) + ' gb';
	};

	const drawSpark = (canvas, data) => {
		const ctx = canvas.getContext('2d');
		const w = canvas.width, h = canvas.height;
		ctx.clearRect(0, 0, w, h);
		if (!data || data.length === 0) { ctx.fillStyle='#1a1a1a'; ctx.fillRect(0,0,w,h); return; }
		ctx.lineWidth = 1.5;
		ctx.strokeStyle = '#0f0';
		ctx.beginPath();
		const max = Math.max(...data, 1);
		data.forEach((v, i) => {
			const x = (i / 59) * w;
			const y = h - (v / max) * (h - 4) - 2;
			if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
		});
		ctx.stroke();
	};

	const renderHosts = (el, list, isBytes) => {
		if (!list || list.length === 0) {
			el.innerHTML = '<div class="mini-row"><span class="h" style="color:#444">-- no traffic --</span></div>';
			return;
		}
		el.innerHTML = list.map(h => {
			const val = isBytes ? fmtBytes(h.bytes) : String(h.count);
			const cls = isBytes ? 'm' : 'c';
			return '<div class="mini-row"><span class="h">' + h.host + '</span><span class="' + cls + '">' + val + '</span></div>';
		}).join('');
	};

	const connect = () => {
		const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
		let backoff = 1000;
		const ws = new WebSocket(protocol + '//' + location.host + '/ws');
		ws.onopen = () => {
			backoff = 1000;
			document.getElementById('ws_status').textContent = 'ws_live';
			document.getElementById('ws_status').style.color = '#0f0';
		};
		ws.onclose = () => {
			document.getElementById('ws_status').textContent = 'ws_reconnecting...';
			document.getElementById('ws_status').style.color = '#f55';
			setTimeout(connect, backoff);
			backoff = Math.min(backoff * 2, 10000);
		};
		ws.onerror = () => ws.close();
		ws.onmessage = (e) => {
			let d;
			try { d = JSON.parse(e.data); } catch (_) { return; }
			updateVal('uptime', d.uptime);
			updateVal('users', d.users);
			updateVal('active', d.active_conn);
			updateVal('total', d.total_req);
			updateVal('bytes_up', fmtBytes(d.bytes_up));
			updateVal('bytes_down', fmtBytes(d.bytes_down));
			updateVal('dns_hits', d.dns_hits);
			updateVal('dns_misses', d.dns_misses);
			updateVal('doh_calls', d.doh_calls);
			updateVal('err_count', d.err_count);
			updateVal('mem_heap', d.mem_heap);
			updateVal('mem_sys', d.mem_sys);
			updateVal('goroutines', d.goroutines);
			updateVal('db_rules', d.rules);
			updateVal('cisco_hits', d.cisco);
			updateVal('db_size', d.db_size);
			updateVal('go_ver', d.go_ver + ' (' + d.cpus + ' CPUs)');
			
			drawSpark(document.getElementById('bw_spark'), d.bw_history);

			const tunnelsEl = document.getElementById('tunnels');
			if (d.tunnels && d.tunnels.length > 0) {
				tunnelsEl.innerHTML = d.tunnels.map(t => '<span class="tag ip-link" style="cursor:default">' + t + '</span>').join('');
			} else {
				tunnelsEl.innerHTML = '<span class="tag" style="color:#444">--</span>';
			}

			renderHosts(document.getElementById('top_hosts'), d.top_hosts, false);
			renderHosts(document.getElementById('recent_traffic'), d.recent_traffic, true);

			const ipListEl = document.getElementById('ip_list');
			if (d.user_ips && d.user_ips.length > 0) {
				ipListEl.innerHTML = d.user_ips.map(ip => {
					const display = ip === 'LOCAL-HOST' ? 'Local System' : ip;
					const link = ip === 'LOCAL-HOST' ? '#' : 'https://ipinfo.io/' + ip;
					return '<a href="' + link + '" target="_blank" class="tag ip-link">' + display + '</a>';
				}).join('');
			} else {
				ipListEl.innerHTML = '';
			}

			const recentEl = document.getElementById('recent');
			if (d.recent && d.recent.length > 0) {
				recentEl.innerHTML = d.recent.map(t => '<span class="tag">' + t + '</span>').join('');
			} else {
				recentEl.innerHTML = '<span class="tag" style="color:#444">--</span>';
			}
		};
	};
	connect();
</script>
</body>
</html>`, buildTime, buildTime, pacURL)))
			return
		}
	}

	// Forward other HTTP requests to proxy logic
	if !authRequired(w, r) {
		return
	}
	handleHTTP(w, r)
}

// serveBlockCheck — checks whether a given URL is reachable through the
// proxy (i.e. whether it can bypass a Cisco/ISP content filter). It resolves
// and fetches the origin from the proxy's own IP, which sits outside the filter.
func serveBlockCheck(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	target := r.URL.Query().Get("url")
	if target == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8" name="viewport" content="width=device-width,initial-scale=1">
<title>NetNinja Block Check</title>
<style>
body{background:#0a0a0a;color:#ccc;font:14px/1.6 'Courier New',monospace;margin:0;display:flex;align-items:center;justify-content:center;height:100vh}
.c{max-width:480px;width:90%;text-align:center;padding:40px;background:#111;border:1px solid #222;border-radius:8px}
h1{color:#fff;font-size:22px;margin:0 0 20px;font-weight:normal}
input{width:100%;padding:12px;background:#0d0d0d;border:1px solid #333;border-radius:4px;color:#7af;font:14px 'Courier New',monospace;box-sizing:border-box;margin-bottom:16px}
button{width:100%;padding:12px;background:#060;color:#fff;border:none;border-radius:4px;font:bold 14px 'Courier New',monospace;cursor:pointer}
.footer{margin-top:24px;font-size:10px;color:#333;text-transform:uppercase;letter-spacing:1px}
</style>
</head>
<body>
<div class="c">
<h1>NetNinja Block Check</h1>
<form method="get" action="/block-check">
<input type="text" name="url" placeholder="https://y8.com/" autofocus>
<button type="submit">CHECK</button>
</form>
<p style="color:#555;font-size:11px">ทดสอบว่า URL นี้เปิดผ่าน proxy ได้ (ข้าม Cisco) หรือไม่</p>
<div class="footer">netninja_engine</div>
</div>
</body>
</html>`))
		return
	}

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	type result struct {
		statusCode int
		redirect   string
		err        string
		errKind    string
	}
	resCh := make(chan result, 1)

	timeoutCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	go func() {
		client := &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return errors.New("too many redirects")
				}
				return nil
			},
		}
		resp, err := client.Get(target)
		if err != nil {
			errStr := err.Error()
			kind := "connection"
			if timeoutCtx.Err() != nil {
				kind = "timeout"
			}
			resCh <- result{err: errStr, errKind: kind}
			return
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		resCh <- result{statusCode: resp.StatusCode, redirect: resp.Request.URL.String()}
	}()

	select {
	case res := <-resCh:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if res.err != "" || res.statusCode == 0 {
			color := "#f88"
			verdict := "BLOCKED / UNREACHABLE"
			if res.errKind == "timeout" {
				verdict = "TIMEOUT (probable block)"
			}
			w.Write([]byte(fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Block Check Result</title>
<style>
body{background:#0a0a0a;color:#ccc;font:14px/1.6 'Courier New',monospace;margin:0;display:flex;align-items:center;justify-content:center;height:100vh}
.c{max-width:480px;width:90%%;text-align:center;padding:40px;background:#111;border:1px solid #222;border-radius:8px}
h1{font-size:22px;margin:0 0 20px;font-weight:normal}
.v{font-size:20px;font-weight:bold;padding:16px;border-radius:4px;margin-bottom:16px}
.d{color:#888;font-size:12px;word-break:break-all;margin-bottom:20px}
a{color:#7af}
.back{display:inline-block;margin-top:20px;color:#7af;text-decoration:none}
</style></head><body>
<div class="c">
<h1 style="color:%s">%s</h1>
<div class="v" style="background:#150505;border:1px solid #600">Target not reachable through proxy</div>
<div class="d">URL: %s<br>Error: %s</div>
<a class="back" href="/block-check">&larr; ตรวจอีกครั้ง</a>
</div></body></html>`, color, verdict, html.EscapeString(target), html.EscapeString(res.err))))
			return
		}

		ok := res.statusCode >= 200 && res.statusCode < 400
		center := html.EscapeString(res.redirect)
		if center == "" {
			center = html.EscapeString(target)
		}
		_ = center
		if ok {
			w.Write([]byte(fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Block Check Result</title>
<style>
body{background:#0a0a0a;color:#ccc;font:14px/1.6 'Courier New',monospace;margin:0;display:flex;align-items:center;justify-content:center;height:100vh}
.c{max-width:480px;width:90%%;text-align:center;padding:40px;background:#111;border:1px solid #222;border-radius:8px}
h1{font-size:22px;margin:0 0 20px;font-weight:normal}
.v{font-size:20px;font-weight:bold;padding:16px;border-radius:4px;margin-bottom:16px}
.d{color:#888;font-size:12px;word-break:break-all;margin-bottom:20px}
a{color:#7af}
.back{display:inline-block;margin-top:20px;color:#7af;text-decoration:none}
</style></head><body>
<div class="c">
<h1 style="color:#6f6">NOT BLOCKED</h1>
<div class="v" style="background:#051505;border:1px solid #060">Reachable through proxy — HTTP %d</div>
<div class="d">URL: %s</div>
<a class="back" href="/block-check">&larr; ตรวจอีกครั้ง</a>
</div></body></html>`, res.statusCode, center)))
		} else {
			w.Write([]byte(fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Block Check Result</title>
<style>
body{background:#0a0a0a;color:#ccc;font:14px/1.6 'Courier New',monospace;margin:0;display:flex;align-items:center;justify-content:center;height:100vh}
.c{max-width:480px;width:90%%;text-align:center;padding:40px;background:#111;border:1px solid #222;border-radius:8px}
h1{font-size:22px;margin:0 0 20px;font-weight:normal}
.v{font-size:20px;font-weight:bold;padding:16px;border-radius:4px;margin-bottom:16px}
.d{color:#888;font-size:12px;word-break:break-all;margin-bottom:20px}
a{color:#7af}
.back{display:inline-block;margin-top:20px;color:#7af;text-decoration:none}
</style></head><body>
<div class="c">
<h1 style="color:#fc0">CHECK RESULT</h1>
<div class="v" style="background:#141005;border:1px solid #660">Server responded HTTP %d (site may be up but reachable only via proxy)</div>
<div class="d">URL: %s</div>
<a class="back" href="/block-check">&larr; ตรวจอีกครั้ง</a>
</div></body></html>`, res.statusCode, center)))
		}
		log.Printf("%s[BLOCK-CHECK]%s %s → %d (%s)", colorCyan, colorReset, clientIP, res.statusCode, target)
	case <-timeoutCtx.Done():
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Block Check Result</title>
<style>
body{background:#0a0a0a;color:#ccc;font:14px/1.6 'Courier New',monospace;margin:0;display:flex;align-items:center;justify-content:center;height:100vh}
.c{max-width:480px;width:90%%;text-align:center;padding:40px;background:#111;border:1px solid #222;border-radius:8px}
h1{font-size:22px;margin:0 0 20px;font-weight:normal}
.v{font-size:20px;font-weight:bold;padding:16px;border-radius:4px;margin-bottom:16px}
.d{color:#888;font-size:12px;word-break:break-all;margin-bottom:20px}
a{color:#7af}
</style></head><body>
<div class="c">
<h1 style="color:#f88">TIMEOUT</h1>
<div class="v" style="background:#150505;border:1px solid #600">Check timed out (20s)</div>
<div class="d">URL: %s</div>
</div></body></html>`, html.EscapeString(target))))
	}
}

// servePAC — default PROXY (bypasses Cisco content filter since resolution
// and connection happen from the proxy's IP, outside the filter); DIRECT only
// for LAN/loopback and as a last-resort fallback if the proxy is unreachable.
func servePAC(w http.ResponseWriter, r *http.Request) {
	proxyHost := os.Getenv("PROXY_ADDR")
	if proxyHost == "" {
		proxyHost = r.Host
	}
	if proxyHost == "" {
		proxyHost = "localhost"
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
    if (dnsDomainIs(host, "googlevideo.com") ||
        dnsDomainIs(host, "apple.com") ||
        dnsDomainIs(host, "icloud.com") ||
        dnsDomainIs(host, "apple-cloudkit.com") ||
        dnsDomainIs(host, "mzstatic.com") ||
        dnsDomainIs(host, "itunes.com")) {
        return "DIRECT";
    }
    return "PROXY %s; DIRECT";
}
`, proxyHost)

	w.Write([]byte(pac))

	clientIP := getClientIP(r)
	log.Printf("%s[PAC]%s Served to %s",
		colorCyan, colorReset, clientIP)
}

func serveLogs(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT domain, rule, cisco_detected, last_seen FROM domain_rules ORDER BY last_seen DESC LIMIT 100")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	var output strings.Builder
	output.WriteString("<html><head><style>body{background:#111;color:#ccc;font:12px monospace} table{border-collapse:collapse;width:100%} th,td{border:1px solid #333;padding:8px;text-align:left} th{background:#222} .cisco{background:#822;color:#fff;padding:2px 6px;font-size:10px;border-radius:3px}</style></head><body>")
	output.WriteString("<h1>Routing Cache (SQLite)</h1><table><tr><th>Domain</th><th>Rule</th><th>Cisco?</th><th>Last Seen</th></tr>")

	for rows.Next() {
		var domain, rule, lastSeen string
		var cisco int
		if err := rows.Scan(&domain, &rule, &cisco, &lastSeen); err == nil {
			color := "#ccc"
			if rule == "DIRECT" {
				color = "#f99"
			} else {
				color = "#9f9"
			}
			ciscoTag := ""
			if cisco == 1 {
				ciscoTag = "<span class='cisco'>DETECTED</span>"
			}
			output.WriteString(fmt.Sprintf("<tr><td>%s</td><td style='color:%s'>%s</td><td>%s</td><td>%s</td></tr>", domain, color, rule, ciscoTag, lastSeen))
		}
	}
	output.WriteString("</table><br><a href='/' style='color:#7af'>Back to Status</a></body></html>")

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(output.String()))
}

// handleHTTP forwards standard HTTP requests
func handleHTTP(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	start := time.Now()

	originalHost := r.URL.Host
	unwrappedHost := unwrapCiscoDomain(originalHost)
	isCisco := unwrappedHost != originalHost
	if isCisco {
		log.Printf("%s[CISCO-DETECTOR]%s Detected & Unwrapped: %s%s%s → %s%s%s",
			colorRed, colorReset,
			colorYellow, originalHost, colorReset,
			colorGreen, unwrappedHost, colorReset)
		r.URL.Host = unwrappedHost
	}

	// Update SQLite rule if new or Cisco
	cachedRule, previouslyCisco := getDomainRule(unwrappedHost)
	if cachedRule == "" || isCisco {
		rule := "DIRECT"
		if isCisco || isManualProxy(unwrappedHost) {
			rule = "PROXY"
		}
		setDomainRule(unwrappedHost, rule, isCisco)
	}

	// Console Logging: Show only if Proxy/Cisco
	if isCisco || previouslyCisco || isManualProxy(unwrappedHost) {
		tag := "[PROXY]"
		if isCisco || previouslyCisco {
			tag = "[CISCO-DETECTOR]"
		}
		log.Printf("%s%s%s %s %s ← %s", colorGreen, tag, colorReset, r.Method, unwrappedHost, clientIP)
	}

	// Welcome Redirect: If new IP and GET request, redirect to dashboard
	if !isLocalIP(clientIP) && clientIP != "127.0.0.1" && clientIP != "::1" && r.Method == "GET" {
		if _, loaded := openedForIPs.LoadOrStore(clientIP, true); !loaded {
			proxyAddr := os.Getenv("PROXY_ADDR")
			if proxyAddr == "" {
				proxyAddr = r.Host
			}
			dashURL := fmt.Sprintf("http://%s/welcome", proxyAddr)
			log.Printf("%s[SYSTEM]%s First-time HTTP connection from %s. Redirecting to %s", colorGreen, colorReset, clientIP, dashURL)
			http.Redirect(w, r, dashURL, http.StatusFound)
			return
		}
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
	if err != nil {
		log.Printf("%s[ERR]%s Bad request from %s: %s", colorRed, colorReset, clientIP, err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	copyHeaders(outReq.Header, r.Header)
	outReq.Header.Set("Host", r.URL.Hostname())

	// Implement Transparent IP Forwarding
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		xff = xff + ", " + clientIP
	} else {
		xff = clientIP
	}
	outReq.Header.Set("X-Forwarded-For", xff)
	outReq.Header.Set("X-Real-IP", clientIP)
	removeHopHeaders(outReq.Header)

	resp, err := proxyTransport.RoundTrip(outReq)
	if err != nil {
		// Detect WebSocket upgrade request for manual handling
		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			handleWSUpgrade(w, r, unwrappedHost, clientIP)
			return
		}

		log.Printf("%s[ERR]%s %s → %s: %s", colorRed, colorReset, clientIP, r.URL.Host, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	removeHopHeaders(w.Header())

	w.WriteHeader(resp.StatusCode)

	// Native Zero-Copy: Let Go optimize data transfer
	io.Copy(w, resp.Body)

	// Nitro: Background logging to avoid blocking the request cleanup
	go func() {
		log.Printf("%s[HTTP]%s %s %s → %d %s(%s)%s",
			colorGreen, colorReset,
			r.Method, r.URL.Host,
			resp.StatusCode,
			colorGray, time.Since(start).Round(time.Millisecond), colorReset)
	}()
}

// handleConnect handles HTTPS CONNECT tunneling
func handleConnect(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	host := r.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}

	log.Printf("%s[TLS]%s CONNECT %s ← %s",
		colorCyan, colorReset,
		host, clientIP)

	atomic.AddInt64(&activeConns, 1)
	defer atomic.AddInt64(&activeConns, -1)

	// extract hostname and port for cached DNS
	hostname := host
	port := "443"
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		hostname = host[:idx]
		port = host[idx+1:]
	}

	// Track active tunnel (host-based)
	activeTunnels.Store(hostname, time.Now())

	// Track host stats
	var hs *hostStat
	if s, ok := hostStats.Load(hostname); ok {
		hs = s.(*hostStat)
		hs.addConn(0)
	} else {
		hs = &hostStat{}
		hs.addConn(0)
		hostStats.Store(hostname, hs)
	}

	// Cisco Unwrapping Logic
	unwrapped := unwrapCiscoDomain(hostname)
	isCisco := unwrapped != hostname
	if isCisco {
		hostname = unwrapped
		// Initial rule set if Cisco detected
		setDomainRule(hostname, "PROXY", true)
	}

	// Resolution logic with SQLite Cache
	cachedRule, previouslyCisco := getDomainRule(hostname)

	// Overkill DNS: Resolve EVERY domain via optimized resolver
	// This bypasses slow ISP DNS and finds better GGC nodes for YouTube
	tag := "[DIRECT]"
	if cachedRule == "PROXY" || isCisco || previouslyCisco {
		tag = "[PROXY]"
	} else if strings.Contains(hostname, "googlevideo.com") || strings.Contains(hostname, "youtube.com") {
		tag = "[YOUTUBE-BOOST]"
	}

	log.Printf("%s%s%s %s ← %s", colorGreen, tag, colorReset, hostname, clientIP)

	var dnsErr error
	ip, dnsErr := hyperResolve(r.Context(), hostname)
	if dnsErr != nil {
		log.Printf("%s[WARN]%s DNS failed for %s: %v. Falling back to hostname.", colorYellow, colorReset, hostname, dnsErr)
		ip = hostname
	}

	destConn, err := customDialer.DialContext(r.Context(), "tcp", net.JoinHostPort(ip, port))
	if err != nil {
		atomic.AddInt64(&activeConns, -1)
		atomic.AddInt64(&errCount, 1)
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
		atomic.AddInt64(&errCount, 1)
		destConn.Close()
		http.Error(w, "Hijack failed", http.StatusServiceUnavailable)
		return
	}

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Track active tunnel start time
	activeTunnels.Store(hostname, time.Now())

	// God-Mode: Pure native performance + KeepAlive
	if tc, ok := clientConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}
	if tc, ok := destConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}

	log.Printf("%s[TLS]%s %s ↔ %s %s(tunnel established)%s",
		colorGreen, colorReset,
		clientIP, host,
		colorGray, colorReset)

	errc := make(chan error, 2)

	// Client → dest (upload)
	go func() {
		n, err := io.Copy(destConn, clientConn)
		atomic.AddInt64(&totalBytesUp, n)
		if hs != nil {
			hs.mu.Lock()
			hs.bytes += n
			hs.last = time.Now()
			hs.mu.Unlock()
		}
		destConn.Close()
		errc <- err
	}()
	// dest → client (download)
	go func() {
		n, err := io.Copy(clientConn, destConn)
		atomic.AddInt64(&totalBytesDown, n)
		if hs != nil {
			hs.mu.Lock()
			hs.bytes += n
			hs.last = time.Now()
			hs.mu.Unlock()
		}
		clientConn.Close()
		errc <- err
	}()

	// Record bandwidth history every second (decoupled)
	go func() {
		t := time.NewTicker(1 * time.Second)
		defer t.Stop()
		var lastUp, lastDown int64
		for {
			select {
			case <-t.C:
				cu := atomic.LoadInt64(&totalBytesUp)
				cd := atomic.LoadInt64(&totalBytesDown)
				sample := cu + cd - lastUp - lastDown
				lastUp = cu
				lastDown = cd
				bwHistoryMu.Lock()
				bwHistory = append(bwHistory, sample)
				if len(bwHistory) > 60 {
					bwHistory = bwHistory[len(bwHistory)-60:]
				}
				bwHistoryMu.Unlock()
			case <-errc:
				return
			}
		}
	}()

	<-errc
	activeTunnels.Delete(hostname)
}

func bwSnapshot() []int64 {
	bwHistoryMu.Lock()
	defer bwHistoryMu.Unlock()
	out := make([]int64, len(bwHistory))
	copy(out, bwHistory)
	return out
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
		"Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailer",
		"Transfer-Encoding",
	}

	// For WebSockets, we MUST keep Upgrade and Connection: upgrade
	isWS := strings.EqualFold(h.Get("Upgrade"), "websocket")
	if !isWS {
		hopHeaders = append(hopHeaders, "Connection", "Upgrade")
	}

	for _, hdr := range hopHeaders {
		h.Del(hdr)
	}
}

// isSelf checks if the hostname refers to this proxy server
func isSelf(reqHost, headerHost string) bool {
	if reqHost == "" {
		return true
	}
	hostOnly := reqHost
	if h, _, err := net.SplitHostPort(reqHost); err == nil {
		hostOnly = h
	}
	// Case 1: Matches a local IP (loopback / interface addresses)
	if isLocalIP(hostOnly) {
		return true
	}
	// Case 2: Matches this proxy's own published address (PROXY_ADDR host, BIND_ADDR, localhost)
	if h, _, err := net.SplitHostPort(os.Getenv("PROXY_ADDR")); err == nil && strings.EqualFold(hostOnly, h) {
		return true
	}
	if strings.EqualFold(hostOnly, os.Getenv("BIND_ADDR")) {
		return true
	}
	if strings.EqualFold(hostOnly, "localhost") {
		return true
	}
	return false
}

// handleWSUpgrade handles the WebSocket upgrade manually since RoundTrip doesn't support it
func handleWSUpgrade(w http.ResponseWriter, r *http.Request, host, clientIP string) {
	// 1. Dial the remote server
	port := "80"
	hostname := host
	if h, p, err := net.SplitHostPort(host); err == nil {
		hostname = h
		port = p
	}
	destConn, err := customDialer.DialContext(r.Context(), "tcp", net.JoinHostPort(hostname, port))
	if err != nil {
		log.Printf("%s[ERR]%s WS Dial %s failed: %v", colorRed, colorReset, host, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer destConn.Close()

	// Overkill: Tuning destination socket for WS
	if tc, ok := destConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetReadBuffer(16 * 1024 * 1024)
		tc.SetWriteBuffer(16 * 1024 * 1024)
	}

	// 2. Hijack the client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Hijack failed", http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	// Overkill: Tuning client socket for WS
	if tc, ok := clientConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetReadBuffer(16 * 1024 * 1024)
		tc.SetWriteBuffer(16 * 1024 * 1024)
	}

	// 3. Forward the original GET request with upgrade headers
	// Ensure Host header is correct for the destination
	r.Header.Set("Host", hostname)

	var req strings.Builder
	req.WriteString(fmt.Sprintf("GET %s HTTP/1.1\r\n", r.URL.RequestURI()))
	for k, vv := range r.Header {
		for _, v := range vv {
			req.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
		}
	}
	req.WriteString("\r\n")
	destConn.Write([]byte(req.String()))

	// 4. Pipe binary data (Native Zero-Copy)
	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(destConn, clientConn)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(clientConn, destConn)
		errChan <- err
	}()

	<-errChan
	log.Printf("%s[WS-PROXY]%s Tunnel closed for %s:%s ← %s", colorGray, colorReset, hostname, port, clientIP)
}

func serveWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			var m runtime.MemStats
			runtime.ReadMemStats(&m)

			// Calculate active users and collect their IPs
			userCount := 0
			var activeIPs []string
			now := time.Now()
			userTracker.Range(func(key, value interface{}) bool {
				lastSeen := value.(time.Time)
				if now.Sub(lastSeen) < 60*time.Second {
					userCount++
					activeIPs = append(activeIPs, key.(string))
				} else {
					userTracker.Delete(key)
				}
				return true
			})

			var rules, cisco int
			_ = db.QueryRow("SELECT COUNT(*) FROM domain_rules").Scan(&rules)
			_ = db.QueryRow("SELECT COUNT(*) FROM domain_rules WHERE cisco_detected = 1").Scan(&cisco)

			// Get DB size
			var dbSize string = "--"
			if fi, err := os.Stat("proxy_cache.db"); err == nil {
				dbSize = fmt.Sprintf("%.1f KB", float64(fi.Size())/1024)
				if fi.Size() > 1024*1024 {
					dbSize = fmt.Sprintf("%.2f MB", float64(fi.Size())/1024/1024)
				}
			}

			var recent []string
			rows, err := db.Query("SELECT domain FROM domain_rules WHERE cisco_detected = 1 ORDER BY last_seen DESC LIMIT 5")
			if err == nil {
				for rows.Next() {
					var d string
					if rows.Scan(&d) == nil {
						recent = append(recent, d)
					}
				}
				rows.Close()
			}

			// Top hosts by connection count
			type hostRow struct {
				name  string
				count int64
				bytes int64
			}
			var hosts []hostRow
			hostStats.Range(func(k, v interface{}) bool {
				st := v.(*hostStat)
				st.mu.Lock()
				hosts = append(hosts, hostRow{k.(string), st.count, st.bytes})
				st.mu.Unlock()
				return true
			})
			sort.Slice(hosts, func(i, j int) bool { return hosts[i].count > hosts[j].count })
			if len(hosts) > 12 {
				hosts = hosts[:12]
			}
			topHosts := []map[string]interface{}{}
			for _, h := range hosts {
				topHosts = append(topHosts, map[string]interface{}{
					"host":  h.name,
					"count": h.count,
					"bytes": h.bytes,
				})
			}

			// Active tunnels (host that have open connections right now)
			var tunnels []string
			activeTunnels.Range(func(k, v interface{}) bool {
				tunnels = append(tunnels, k.(string))
				return true
			})
			sort.Strings(tunnels)

			// Bandwidth history snapshot
			bwHistoryMu.Lock()
			bw := make([]int64, len(bwHistory))
			copy(bw, bwHistory)
			bwHistoryMu.Unlock()

			// Recent traffic (last N hosts seen + their bytes)
			var recentTraffic []map[string]interface{}
			var trafficRows []hostRow
			hostStats.Range(func(k, v interface{}) bool {
				st := v.(*hostStat)
				st.mu.Lock()
				trafficRows = append(trafficRows, hostRow{k.(string), st.count, st.bytes})
				st.mu.Unlock()
				return true
			})
			sort.Slice(trafficRows, func(i, j int) bool { return trafficRows[i].bytes > trafficRows[j].bytes })
			if len(trafficRows) > 8 {
				trafficRows = trafficRows[:8]
			}
			for _, t := range trafficRows {
				recentTraffic = append(recentTraffic, map[string]interface{}{
					"host":  t.name,
					"bytes": t.bytes,
				})
			}

			data := map[string]interface{}{
				"uptime":        time.Since(startTime).Round(time.Second).String(),
				"users":         userCount,
				"user_ips":      activeIPs,
				"active_conn":   atomic.LoadInt64(&activeConns),
				"total_req":     atomic.LoadInt64(&totalRequests),
				"bytes_up":      atomic.LoadInt64(&totalBytesUp),
				"bytes_down":    atomic.LoadInt64(&totalBytesDown),
				"dns_hits":      atomic.LoadInt64(&dnsHits),
				"dns_misses":    atomic.LoadInt64(&dnsMisses),
				"doh_calls":     atomic.LoadInt64(&dohCalls),
				"err_count":     atomic.LoadInt64(&errCount),
				"mem_alloc":     fmt.Sprintf("%.2f MB", float64(m.Alloc)/1024/1024),
				"mem_sys":       fmt.Sprintf("%.2f MB", float64(m.Sys)/1024/1024),
				"mem_heap":      fmt.Sprintf("%.2f MB", float64(m.HeapAlloc)/1024/1024),
				"goroutines":    runtime.NumGoroutine(),
				"cpus":          runtime.NumCPU(),
				"go_ver":        runtime.Version(),
				"rules":         rules,
				"cisco":         cisco,
				"db_size":       dbSize,
				"recent":        recent,
				"top_hosts":     topHosts,
				"tunnels":       tunnels,
				"bw_history":    bw,
				"recent_traffic": recentTraffic,
			}

				conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if err := conn.WriteJSON(data); err != nil {
				return
			}
		}
	}
}
