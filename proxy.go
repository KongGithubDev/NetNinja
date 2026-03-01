package main

import (
	"context"
	"encoding/json"
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

	"database/sql"

	"github.com/gorilla/websocket"
	_ "modernc.org/sqlite"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

var db *sql.DB
var openedForIPs sync.Map // map[string]bool

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
			return entry.ip, nil
		}
		dnsCache.Delete(host)
	}

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

// DoH resolution using Cloudflare/Google
func resolveDoH(host string) (string, error) {
	urls := []string{
		"https://cloudflare-dns.com/dns-query?name=" + host + "&type=A",
		"https://dns.google/resolve?name=" + host + "&type=A",
	}

	client := &http.Client{Timeout: 3 * time.Second}
	for _, url := range urls {
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Accept", "application/dns-json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		var res struct {
			Answer []struct {
				Data string `json:"data"`
				Type int    `json:"type"`
			} `json:"Answer"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&res); err == nil && len(res.Answer) > 0 {
			// Find first A record
			for _, ans := range res.Answer {
				if ans.Type == 1 { // A record
					return ans.Data, nil
				}
			}
		}
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
var startTime time.Time
var userTracker sync.Map // map[string]time.Time (IP -> last seen)

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

// Custom dialer — fast timeouts for snappy connections
var customDialer = &net.Dialer{
	Timeout:   5 * time.Second,
	KeepAlive: 30 * time.Second,
	Resolver:  customResolver,
}

// Custom transport — aggressive connection pooling
var proxyTransport = &http.Transport{
	DialContext:           customDialer.DialContext,
	MaxIdleConns:          1000,
	MaxIdleConnsPerHost:   100,
	IdleConnTimeout:       120 * time.Second,
	TLSHandshakeTimeout:   5 * time.Second,
	ExpectContinueTimeout: 500 * time.Millisecond,
	ResponseHeaderTimeout: 30 * time.Second,
	DisableCompression:    false,
	ForceAttemptHTTP2:     true,
	WriteBufferSize:       128 * 1024,
	ReadBufferSize:        128 * 1024,
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

// Domains that go DIRECT (not through proxy) — for GFN streaming etc.
var directDomains = []string{}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&totalRequests, 1)

	clientIP := getClientIP(r)
	trackingIP := clientIP
	if isLocalIP(clientIP) {
		trackingIP = "LOCAL-HOST"
	}
	userTracker.Store(trackingIP, time.Now())

	if r.Method == http.MethodConnect {
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
	<div class="row"><span class="k">active_conns</span><span class="v num" id="active">0</span></div>
	<div class="row"><span class="k">total_reqs</span><span class="v num" id="total">0</span></div>

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
		<span id="ws_status" style="color:#444">connecting_ws...</span>
		<div style="margin-top:15px;color:#222;font-size:10px;text-transform:uppercase;letter-spacing:1px">
			developed_by // Watcharapong Namsaeng
		</div>
	</div>
</div>

<script>
	const updateVal = (id, val) => {
		const el = document.getElementById(id);
		if (el && el.textContent !== String(val)) {
			el.textContent = val;
			el.classList.add('flash');
			setTimeout(() => el.classList.remove('flash'), 500);
		}
	};

	const connect = () => {
		const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
		const ws = new WebSocket(protocol + '//' + location.host + '/ws');
		ws.onopen = () => document.getElementById('ws_status').textContent = 'ws_live';
		ws.onclose = () => {
			document.getElementById('ws_status').textContent = 'ws_reconnecting...';
			setTimeout(connect, 2000);
		};
		ws.onmessage = (e) => {
			const d = JSON.parse(e.data);
			updateVal('uptime', d.uptime);
			updateVal('users', d.users);
			updateVal('active', d.active_conn);
			updateVal('total', d.total_req);
			updateVal('mem_heap', d.mem_heap);
			updateVal('mem_sys', d.mem_sys);
			updateVal('goroutines', d.goroutines);
			updateVal('db_rules', d.rules);
			updateVal('cisco_hits', d.cisco);
			updateVal('db_size', d.db_size);
			updateVal('go_ver', d.go_ver + ' (' + d.cpus + ' CPUs)');
			
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
	handleHTTP(w, r)
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

	if !strings.Contains(host, ":") {
		host += ":443"
	}

	log.Printf("%s[TLS]%s CONNECT %s ← %s",
		colorCyan, colorReset,
		host, clientIP)

	atomic.AddInt64(&activeConns, 1)

	// extract hostname and port for cached DNS
	hostname := host
	port := "443"
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		hostname = host[:idx]
		port = host[idx+1:]
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

	// If it's a new domain, determine rule
	if cachedRule == "" {
		if isCisco || isManualProxy(hostname) {
			cachedRule = "PROXY"
		} else {
			cachedRule = "DIRECT"
		}
		setDomainRule(hostname, cachedRule, isCisco)
	}

	var ip string
	if cachedRule == "DIRECT" {
		// Silent: don't log normal direct connections
		ip = hostname
	} else {
		// High Visibility: Show PROXY or CISCO log
		tag := "[PROXY]"
		if isCisco || previouslyCisco {
			tag = "[CISCO-DETECTOR]"
		}
		log.Printf("%s%s%s %s ← %s", colorGreen, tag, colorReset, hostname, clientIP)

		// PROXY logic: Try resolving via Cache -> Std DNS -> DoH
		var dnsErr error
		ip, dnsErr = cachedResolve(r.Context(), hostname)
		if dnsErr != nil {
			log.Printf("%s[WARN]%s Proxy DNS %s failed: %v. Falling back to DIRECT.", colorYellow, colorReset, hostname, dnsErr)
			ip = hostname
		}
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
	// Case 1: Matches the host header we are listening on
	if reqHost == headerHost {
		return true
	}
	// Case 2: Matches a local IP
	hostOnly := reqHost
	if h, _, err := net.SplitHostPort(reqHost); err == nil {
		hostOnly = h
	}
	if isLocalIP(hostOnly) {
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
	destConn, err := net.DialTimeout("tcp", hostname+":"+port, 5*time.Second)
	if err != nil {
		log.Printf("%s[ERR]%s WS Dial %s failed: %v", colorRed, colorReset, host, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer destConn.Close()

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

	// 4. Pipe binary data
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

	ticker := time.NewTicker(1 * time.Second)
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

			data := map[string]interface{}{
				"uptime":      time.Since(startTime).Round(time.Second).String(),
				"users":       userCount,
				"user_ips":    activeIPs,
				"active_conn": atomic.LoadInt64(&activeConns),
				"total_req":   atomic.LoadInt64(&totalRequests),
				"mem_alloc":   fmt.Sprintf("%.2f MB", float64(m.Alloc)/1024/1024),
				"mem_sys":     fmt.Sprintf("%.2f MB", float64(m.Sys)/1024/1024),
				"mem_heap":    fmt.Sprintf("%.2f MB", float64(m.HeapAlloc)/1024/1024),
				"goroutines":  runtime.NumGoroutine(),
				"cpus":        runtime.NumCPU(),
				"go_ver":      runtime.Version(),
				"rules":       rules,
				"cisco":       cisco,
				"db_size":     dbSize,
				"recent":      recent,
			}

			if err := conn.WriteJSON(data); err != nil {
				return
			}
		}
	}
}
