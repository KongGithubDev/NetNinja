package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
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
	// Treat the proxy's own published hostname (PROXY_ADDR) as local too —
	// otherwise clients that route their dashboard /ws WebSocket through the
	// proxy send absolute-form "ws://proxy.example:443/ws" requests whose host
	// never matches, forcing handleWSUpgrade to dial the proxy itself (self-loop).
	if pa := os.Getenv("PROXY_ADDR"); pa != "" {
		paHost := pa
		if h, _, err := net.SplitHostPort(pa); err == nil {
			paHost = h
		}
		if ip := net.ParseIP(paHost); ip != nil {
			newIPs[ip.String()] = true
		} else if ips, err := net.LookupIP(paHost); err == nil {
			for _, ip := range ips {
				newIPs[ip.String()] = true
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
var adBlocked int64
var startTime time.Time

// Ad-block: banner/tracking domains are refused at the proxy so the
// client falls back gracefully (no banner/ad network round-trips).
//
// The rule set is loaded at boot from ADBLOCK_PATH (local file) or
// ADBLOCK_URL (fetched at boot + refreshed every ADBLOCK_REFRESH_HOURS),
// in adblock (`||domain^`), hosts (`0.0.0.0 domain`), dnsmasq
// (`address=/domain/`) or plain-domain-list formats. When neither is set
// a small built-in list is used as a zero-config fallback.
//
// Matching walks the full hostname and every parent label, so a blocked
// domain covers itself and any subdomain (`||doubleclick.net^` blocks
// `*.doubleclick.net` too). The whole set is swapped atomically on reload.
var (
	adBlockMu      sync.RWMutex
	adBlockDomains map[string]struct{} // blocked domain → struct{}
	adBlockAllow   map[string]struct{} // @@ allowlist domain → struct{}
)

var adBlockSource string
var adBlockUpdated time.Time
var adBlockCount int64

// Built-in fallback list (kept so the proxy still ads-blocks out of the box).
var adBlockFallbackDomains = []string{
	"doubleclick.net", "doubleclick.com",
	"googlesyndication.com", "googleadservices.com",
	"googletagmanager.com", "google-analytics.com", "googletagservices.com",
	"doubleverify.com", "adsafeprotected.com", "moatads.com", "scorecardresearch.com",
	"criteo.com", "criteo.net", "taboola.com", "outbrain.com",
	"adnxs.com", "adsrvr.org", "casalemedia.com", "rubiconproject.com",
	"pubmatic.com", "openx.net", "smartadserver.com", "spotxchange.com",
	"contextweb.com", "emxdgt.com", "tidaltv.com", "teads.tv",
	"amazon-adsystem.com", "quantserve.com", "advertising.com",
	"adcolony.com", "vungle.com", "imrworldwide.com", "thebrighttag.com",
	"adservice.google.com", "adservice.google.co.th",
	"pagead2.googlesyndication.com", "googleads.g.doubleclick.net",
}

func normalizeAdHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimSuffix(h, ".")
	if i := strings.LastIndexByte(h, ':'); i > 0 {
		if _, err := strconv.Atoi(h[i+1:]); err == nil { // trailing :port → strip
			h = h[:i]
		}
		if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") { // [v6]
			h = strings.TrimSuffix(h, "]")
			h = strings.TrimPrefix(h, "[")
		}
	}
	return h
}

func isAdBlockedHost(hostname string) bool {
	adBlockMu.RLock()
	doms, allow := adBlockDomains, adBlockAllow
	adBlockMu.RUnlock()
	if doms == nil {
		return false
	}
	h := normalizeAdHost(hostname)
	// allowlist first: an @@ domain (and its subdomains) is never blocked
	for p := h; p != ""; {
		if _, ok := allow[p]; ok {
			return false
		}
		i := strings.IndexByte(p, '.')
		if i < 0 {
			break
		}
		p = p[i+1:]
	}
	for p := h; p != ""; {
		if _, ok := doms[p]; ok {
			return true
		}
		i := strings.IndexByte(p, '.')
		if i < 0 {
			return false
		}
		p = p[i+1:]
	}
	return false
}

// parseAdLine extracts a domain from one adblock-style entry:
// `||domain^` (+ optional `$modifiers`), `*.domain`, dnsmasq
// `address=/domain/`, or a bare domain.
func parseAdLine(line string) (string, bool) {
	s := line
	if strings.HasPrefix(s, "||") {
		s = strings.TrimPrefix(s, "||")
	}
	if strings.HasPrefix(s, "address=/") {
		s = strings.TrimPrefix(s, "address=/")
		if i := strings.IndexByte(s, '/'); i >= 0 {
			s = s[:i]
		}
	}
	s = strings.TrimPrefix(s, "*.")
	if i := strings.IndexByte(s, '$'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(s, "^")
	s = strings.TrimSpace(s)
	if s == "" || strings.ContainsAny(s, " *#/") {
		return "", false
	}
	s = strings.ToLower(s)
	if !strings.Contains(s, ".") { // single label: too broad for suffix blocking
		return "", false
	}
	return s, true
}

func parseAdBlock(r io.Reader) (doms, allow map[string]struct{}, parsed, skipped int, err error) {
	doms = make(map[string]struct{})
	allow = make(map[string]struct{})
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		if strings.HasPrefix(line, "@@") {
			if d, ok := parseAdLine(strings.TrimPrefix(line, "@@")); ok {
				allow[d] = struct{}{}
				parsed++
			} else {
				skipped++
			}
			continue
		}
		if strings.HasPrefix(line, "0.0.0.0") || strings.HasPrefix(line, "127.0.0.1") ||
			strings.HasPrefix(line, "::1") || strings.HasPrefix(line, ":: ") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				if d, ok := parseAdLine(f[1]); ok {
					doms[d] = struct{}{}
					parsed++
				} else {
					skipped++
				}
			}
			continue
		}
		if d, ok := parseAdLine(line); ok {
			doms[d] = struct{}{}
			parsed++
		} else {
			skipped++
		}
	}
	if err := sc.Err(); err != nil {
		return nil, nil, 0, 0, err
	}
	return doms, allow, parsed, skipped, nil
}

func swapAdBlock(doms, allow map[string]struct{}, src string, n int) {
	adBlockMu.Lock()
	adBlockDomains = doms
	adBlockAllow = allow
	adBlockMu.Unlock()
	adBlockSource = src
	adBlockUpdated = time.Now()
	atomic.StoreInt64(&adBlockCount, int64(n))
}

func loadAdBlockFromReader(r io.Reader, src string) (int, error) {
	doms, allow, parsed, skipped, err := parseAdBlock(r)
	if err != nil {
		return 0, err
	}
	// Always merge the aggressive base ad-network domains into any external
	// list — curated lists like HaGeZi deliberately omit the parent domains
	// (only specific endpoints), so without this `*.doubleclick.net` would
	// slip through.
	for _, d := range adBlockFallbackDomains {
		if _, ok := doms[d]; !ok {
			doms[d] = struct{}{}
			parsed++
		}
	}
	swapAdBlock(doms, allow, src, parsed)
	log.Printf("%s[AD-BLOCK]%s loaded %d domains from %s (skipped %d)", colorGreen, colorReset, parsed, src, skipped)
	return parsed, nil
}

func reloadAdBlock() error {
	if p := os.Getenv("ADBLOCK_PATH"); p != "" {
		if f, err := os.Open(p); err == nil {
			defer f.Close()
			_, err := loadAdBlockFromReader(f, "file:"+p)
			return err
		} else {
			log.Printf("%s[AD-BLOCK]%s cannot read ADBLOCK_PATH=%s: %v — falling back", colorYellow, colorReset, p, err)
		}
	}
	if u := os.Getenv("ADBLOCK_URL"); u != "" {
		client := &http.Client{Timeout: 90 * time.Second}
		resp, err := client.Get(u)
		if err != nil {
			log.Printf("%s[AD-BLOCK]%s fetch %s failed: %v — keeping current list", colorYellow, colorReset, u, err)
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("adblock fetch %s → HTTP %d", u, resp.StatusCode)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		_, err = loadAdBlockFromReader(bytes.NewReader(body), "url:"+u)
		return err
	}
	// built-in fallback (zero-config)
	doms := make(map[string]struct{}, len(adBlockFallbackDomains))
	for _, d := range adBlockFallbackDomains {
		doms[d] = struct{}{}
	}
	swapAdBlock(doms, nil, "builtin", len(doms))
	log.Printf("%s[AD-BLOCK]%s using built-in fallback (%d domains); set ADBLOCK_PATH/ADBLOCK_URL for a fuller list (e.g. HaGeZi)", colorGray, colorReset, len(doms))
	return nil
}

func startAdBlockRefresher() {
	u := os.Getenv("ADBLOCK_URL")
	if u == "" {
		return
	}
	hours := 24
	if s := os.Getenv("ADBLOCK_REFRESH_HOURS"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			hours = v
		}
	}
	go func() {
		for {
			time.Sleep(time.Duration(hours) * time.Hour)
			log.Printf("%s[AD-BLOCK]%s refreshing blocklist from %s ...", colorYellow, colorReset, u)
			if err := reloadAdBlock(); err != nil {
				log.Printf("%s[AD-BLOCK]%s refresh failed: %v", colorRed, colorReset, err)
			}
		}
	}()
}
var userTracker sync.Map // map[string]time.Time (IP -> last seen)

// Per-user usage stats (keyed by proxy auth username)
type userStat struct {
	mu         sync.Mutex
	bytesUp    int64
	bytesDown  int64
	conns      int64
	lastSeen   time.Time
	firstSeen  time.Time
	devices    map[string]bool // distinct device keys (clientIP + UA)
	lastDevice string
}
var userStats sync.Map // map[string]*userStat

func authedUser(r *http.Request) string {
	auth := r.Header.Get("Proxy-Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		return ""
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[0]
}

func trackUserBytes(user string, up, down int64) {
	if user == "" {
		return
	}
	v, _ := userStats.LoadOrStore(user, &userStat{devices: map[string]bool{}})
	st := v.(*userStat)
	st.mu.Lock()
	st.bytesUp += up
	st.bytesDown += down
	now := time.Now()
	st.lastSeen = now
	if st.firstSeen.IsZero() {
		st.firstSeen = now
	}
	st.mu.Unlock()
}

func trackUserConn(user string) {
	if user == "" {
		return
	}
	v, _ := userStats.LoadOrStore(user, &userStat{devices: map[string]bool{}})
	st := v.(*userStat)
	st.mu.Lock()
	st.conns++
	st.mu.Unlock()
}

func trackUserDevice(user, clientIP, ua string) {
	if user == "" {
		return
	}
	v, _ := userStats.LoadOrStore(user, &userStat{devices: map[string]bool{}})
	st := v.(*userStat)
	key := clientIP
	if ua != "" {
		key = clientIP + " | " + ua
	}
	st.mu.Lock()
	st.devices[key] = true
	st.lastDevice = key
	st.lastSeen = time.Now()
	st.mu.Unlock()
}

// Per-user, per-host traffic summary (persisted to SQLite, reloaded on boot)
type userHostStat struct {
	mu        sync.Mutex
	bytesUp   int64
	bytesDown int64
	conns     int64
	firstSeen time.Time
	lastSeen  time.Time
}
var userHosts sync.Map // map[string]*userHostStat  (key = username + "\x00" + host)

// Per-user account settings (persisted in user_settings table)
type userSetting struct {
	quotaBytes     int64 // 0 = unlimited
	suspended      bool
	proxyEnabled   int // -1 inherit global, 0 off (connect direct), 1 on
	adblockEnabled int // -1 inherit global, 0 off, 1 on
	updatedAt      time.Time
}
var userSettings sync.Map // map[string]*userSetting (key = username)

// Global master switches (settings table). 1 = enabled (default).
var globalProxyEnabled int64 = 1
var globalAdblockEnabled int64 = 1

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// proxyEnabledFor: can this user keep using the proxy? Effective = per-user
// override if set, otherwise the global switch. When off, the proxy refuses
// their traffic so the device falls back to a direct connection.
func proxyEnabledFor(user string) bool {
	if v, ok := userSettings.Load(user); ok {
		if st := v.(*userSetting); st.proxyEnabled != -1 {
			return st.proxyEnabled == 1
		}
	}
	return atomic.LoadInt64(&globalProxyEnabled) == 1
}

// adblockEnabledFor: should ad/tracking hosts be refused for this user?
// Effective = per-user override if set, otherwise the global switch.
func adblockEnabledFor(user string) bool {
	if v, ok := userSettings.Load(user); ok {
		if st := v.(*userSetting); st.adblockEnabled != -1 {
			return st.adblockEnabled == 1
		}
	}
	return atomic.LoadInt64(&globalAdblockEnabled) == 1
}

// setAppSetting persists a global switch and applies it immediately.
func setAppSetting(key string, on bool) {
	v := int64(0)
	if on {
		v = 1
	}
	switch key {
	case "proxy_enabled":
		atomic.StoreInt64(&globalProxyEnabled, v)
	case "adblock_enabled":
		atomic.StoreInt64(&globalAdblockEnabled, v)
	}
	_, _ = db.Exec("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, on)
}

// loadAppSettings reads the global switches from the settings table.
func loadAppSettings() {
	rows, err := db.Query("SELECT key, value FROM settings")
	if err != nil {
		log.Printf("%s[SETTINGS]%s failed to read settings: %v", colorRed, colorReset, err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var on bool
		if rows.Scan(&k, &on) == nil {
			setAppSetting(k, on)
		}
	}
}

// saveUserSetting persists a per-user flag set (proxy_enabled / adblock_enabled; -1 = inherit).
func saveUserSetting(user string, proxyOn, adsOn int) {
	old := userSetting{proxyEnabled: -1, adblockEnabled: -1}
	if v, ok := userSettings.Load(user); ok {
		old = *v.(*userSetting)
	}
	ns := userSetting{quotaBytes: old.quotaBytes, suspended: old.suspended,
		proxyEnabled: proxyOn, adblockEnabled: adsOn, updatedAt: time.Now()}
	userSettings.Store(user, &ns)
	_, _ = db.Exec(`INSERT INTO user_settings (username, quota_bytes, suspended, proxy_enabled, adblock_enabled, updated_at) VALUES (?,?,?,?,?,DATETIME('now'))
		ON CONFLICT(username) DO UPDATE SET quota_bytes=excluded.quota_bytes, suspended=excluded.suspended, proxy_enabled=excluded.proxy_enabled, adblock_enabled=excluded.adblock_enabled, updated_at=excluded.updated_at`,
		user, ns.quotaBytes, boolInt(ns.suspended), ns.proxyEnabled, ns.adblockEnabled)
}

// flagLabel renders a human state for the per-user flag buttons.
func flagLabel(v int) string {
	if v == 0 {
		return "off"
	}
	return "on"
}

// Live bytes used per user, seeded from persisted user_hosts and incremented as
// traffic flows. Used for quota enforcement BEFORE the SQLite flush catches up.
var userQuotaUsed sync.Map // map[string]*int64

func quotaUsedOf(user string) int64 {
	if v, ok := userQuotaUsed.Load(user); ok {
		return *v.(*int64)
	}
	return 0
}

func addQuotaUsed(user string, n int64) {
	if n <= 0 {
		return
	}
	v, _ := userQuotaUsed.LoadOrStore(user, new(int64))
	p := v.(*int64)
	atomic.AddInt64(p, n)
}

// Enforced at CONNECT/HTTP: suspended account or quota exceeded?
// Returns false when the user may keep connecting.
func checkUserBlocked(user string) (blocked bool, reason string) {
	if user == "" {
		return false, ""
	}
	if v, ok := userSettings.Load(user); ok {
		st := v.(*userSetting)
		if st.suspended {
			return true, "suspended"
		}
		if st.quotaBytes > 0 && quotaUsedOf(user) > st.quotaBytes {
			return true, "quota"
		}
	}
	return false, ""
}

func touchUserHost(user, host string, up, down int64, conns int64) {
	if user == "" || host == "" {
		return
	}
	key := user + "\x00" + strings.ToLower(host)
	v, _ := userHosts.LoadOrStore(key, &userHostStat{})
	st := v.(*userHostStat)
	now := time.Now()
	st.mu.Lock()
	if st.firstSeen.IsZero() {
		st.firstSeen = now
	}
	st.bytesUp += up
	st.bytesDown += down
	st.conns += conns
	st.lastSeen = now
	st.mu.Unlock()
	addQuotaUsed(user, down)
}

// Connection audit log — batched writes via a background goroutine.
// Entries: (username, client_ip, host, status, bytes_up, bytes_down, duration_ms)
type connLogEntry struct {
	username string
	clientIP string
	host     string
	status   string
	bytesUp  int64
	bytesDown int64
	durMs    int64
}
var connLogCh = make(chan connLogEntry, 4096)
var connLogWriterStarted bool

func startConnLogWriter() {
	if connLogWriterStarted {
		return
	}
	connLogWriterStarted = true
	go func() {
		buf := make([]connLogEntry, 0, 256)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case e, ok := <-connLogCh:
				if !ok {
					flushConnLogs(buf)
					return
				}
				buf = append(buf, e)
				if len(buf) >= 256 {
					flushConnLogs(buf)
					buf = buf[:0]
				}
			case <-ticker.C:
				if len(buf) > 0 {
					flushConnLogs(buf)
					buf = buf[:0]
				}
			}
		}
	}()
}

func flushConnLogs(entries []connLogEntry) {
	if len(entries) == 0 {
		return
	}
	tx, err := db.Begin()
	if err != nil {
		return
	}
	stmt, err := tx.Prepare("INSERT INTO conn_logs (ts, username, client_ip, host, status, bytes_up, bytes_down, duration_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		tx.Rollback()
		return
	}
	now := time.Now().Format("2006-01-02 15:04:05")
	for _, e := range entries {
		_, _ = stmt.Exec(now, e.username, e.clientIP, e.host, e.status, e.bytesUp, e.bytesDown, e.durMs)
	}
	stmt.Close()
	_ = tx.Commit()
}

func pushConnLog(e connLogEntry) {
	select {
	case connLogCh <- e:
	default:
		atomic.AddInt64(&errCount, 1) // table full → count as dropped
	}
}

// Persist the in-memory userHosts totals back to SQLite every 5s so per-user,
// per-host usage (and thus quota accounting) survives restarts.
func startUserHostsFlusher() {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		stmts := make([]string, 0, 32)
		args := make([]interface{}, 0, 128)
		for range ticker.C {
			stmts = stmts[:0]
			args = args[:0]
			userHosts.Range(func(k, v interface{}) bool {
				parts := strings.SplitN(k.(string), "\x00", 2)
				if len(parts) != 2 {
					return true
				}
				st := v.(*userHostStat)
				st.mu.Lock()
				up, down, conns := st.bytesUp, st.bytesDown, st.conns
				f, l := st.firstSeen, st.lastSeen
				st.mu.Unlock()
				fstr, lstr := "", ""
				if !f.IsZero() {
					fstr = f.Format("2006-01-02 15:04:05")
				}
				if !l.IsZero() {
					lstr = l.Format("2006-01-02 15:04:05")
				}
				stmts = append(stmts, "(?, ?, ?, ?, ?, ?, ?)")
				args = append(args, parts[0], parts[1], up, down, conns, fstr, lstr)
				return true
			})
			if len(stmts) == 0 {
				continue
			}
			query := "INSERT INTO user_hosts (username, host, bytes_up, bytes_down, conns, first_seen, last_seen) VALUES " +
				strings.Join(stmts, ", ") +
				" ON CONFLICT(username, host) DO UPDATE SET bytes_up=excluded.bytes_up, bytes_down=excluded.bytes_down, conns=excluded.conns, first_seen=excluded.first_seen, last_seen=excluded.last_seen"
			if _, err := db.Exec(query, args...); err != nil {
				log.Printf("%s[HOSTS]%s failed to flush user_hosts: %v", colorRed, colorReset, err)
			}
		}
	}()
}

// Periodic retention pruning for conn_logs and admin_logs
func startRetentionPruner() {
	go func() {
		days := os.Getenv("LOG_RETENTION_DAYS")
		if days == "" {
			days = "30"
		}
		if _, err := strconv.Atoi(days); err != nil || days == "0" {
			days = "30"
		}
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			var pruned int64
			res, err := db.Exec("DELETE FROM conn_logs WHERE ts < datetime('now', ?)", "-"+days+" days")
			if err == nil {
				if n, er := res.RowsAffected(); er == nil {
					pruned += n
				}
			}
			// Keep admin_logs for 90 days; user_hosts kept forever (rolled into totals)
			res, err = db.Exec("DELETE FROM admin_logs WHERE ts < datetime('now', '-90 days')")
			if err == nil {
				if n, er := res.RowsAffected(); er == nil {
					pruned += n
				}
			}
			if pruned > 0 {
				log.Printf("%s[RETENTION]%s pruned %d log row(s) older than %s days", colorGray, colorReset, pruned, days)
			}
		}
	}()
}

// Periodic heartbeat stats — helps diagnose connectivity issues after the fact
func startHeartbeatStats() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			var tunnels int
			activeTunnels.Range(func(k, v interface{}) bool { tunnels++; return true })
			log.Printf("%s[STATS]%s active_conns=%d tunnels=%d requests=%d dropped=%d ad_blocked=%d blocklist=%d",
				colorGray, colorReset,
				atomic.LoadInt64(&activeConns), tunnels,
				atomic.LoadInt64(&totalRequests), atomic.LoadInt64(&errCount), atomic.LoadInt64(&adBlocked), atomic.LoadInt64(&adBlockCount))
		}
	}()
}

// Record an admin action into admin_logs
func recordAdminLog(adminUser, action, target, detail string) {
	ts := time.Now().Format("2006-01-02 15:04:05")
	if _, err := db.Exec("INSERT INTO admin_logs (ts, admin_user, action, target, detail) VALUES (?, ?, ?, ?, ?)", ts, adminUser, action, target, detail); err != nil {
		log.Printf("%s[ADMIN]%s failed to record audit %s %s: %v", colorRed, colorReset, action, target, err)
	}
}

// Host traffic stats (host -> last seen + counters)
type hostStat struct {
	mu    sync.Mutex
	count int64
	bytes int64
	last  time.Time
}
var hostStats sync.Map // map[string]*hostStat

// activityConn wraps a net.Conn and tracks when bytes last flowed on it, so an
// idle tunnel watchdog can close fully-idle connections with a clean FIN before
// a middlebox (home NAT / Azure SLB) silently drops them.
type activityConn struct {
	net.Conn
	last atomic.Int64 // unix nanos of last read OR write activity
}

func (c *activityConn) mark()      { c.last.Store(time.Now().UnixNano()) }
func (c *activityConn) Read(p []byte) (int, error) {
	if n, err := c.Conn.Read(p); n > 0 {
		c.mark()
		return n, err
	} else {
		return n, err
	}
}
func (c *activityConn) Write(p []byte) (int, error) {
	if n, err := c.Conn.Write(p); n > 0 {
		c.mark()
		return n, err
	} else {
		return n, err
	}
}

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

// startBwSampler appends one aggregate traffic sample per second so the admin
// realtime_bandwidth chart always has the last 60s of data, even with no
// tunnels active (the old per-tunnel sampler left the chart empty between runs).
func startBwSampler() {
	var lastUp, lastDown int64
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for range t.C {
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
	}
}

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

// ---------------------------------------------------------------------------
// Optional second-hop egress: when HOP_DOMAINS lists a host, tunnels to it are
// dialed through a SOCKS5 server (HOP_SOCKS5, e.g. a Thai-VPS or home reverse
// tunnel). DNS is still resolved here (bypasses Cisco Umbrella), only the TCP
// connection leaves from the hop's IP, so Cloudflare zones that block the
// Azure datacenter IP (or geo-lock to Thailand) accept the connection.
var hopDomains map[string]bool
var hopSocks5 string
var hopOnce sync.Once

// Auto-detect: when a host tunnelling directly (from the Azure IP) gets a
// Cloudflare 403/"Just a moment", it is added to the hop list on the fly so
// subsequent connections egress through HOP_SOCKS5. Results persist in SQLite
// (hop_auto) across restarts. Disable with env HOP_AUTODETECT=0.
var hopAutoOn bool
var hopAuto map[string]bool
var hopAutoMu sync.Mutex
var hopAutoTTL time.Duration
var hopProbeMu sync.Mutex
var hopProbeIn map[string]chan bool
var hopProbeRes map[string]hopProbeResult

type hopProbeResult struct {
	t       time.Time
	blocked bool
}

func loadHopConfig() {
	hopOnce.Do(func() {
		if e := os.Getenv("HOP_DOMAINS"); e != "" {
			m := map[string]bool{}
			for _, d := range strings.Split(e, ",") {
				d = strings.ToLower(strings.TrimSpace(d))
				if d != "" {
					m[d] = true
				}
			}
			hopDomains = m
		}
		hopSocks5 = strings.TrimSpace(os.Getenv("HOP_SOCKS5"))
		if len(hopDomains) > 0 {
			names := make([]string, 0, len(hopDomains))
			for d := range hopDomains {
				names = append(names, d)
			}
			sort.Strings(names)
			if hopSocks5 == "" {
				log.Printf("%s[HOP]%s HOP_DOMAINS set but HOP_SOCKS5 empty — hop disabled", colorYellow, colorReset)
			} else {
				log.Printf("%s[HOP]%s domains=[%s] via socks5 %s", colorGreen, colorReset, strings.Join(names, ","), hopSocks5)
			}
		}
		hopAutoOn = os.Getenv("HOP_AUTODETECT") != "0"
		if ttl, err := time.ParseDuration(os.Getenv("HOP_AUTO_TTL")); err == nil {
			hopAutoTTL = ttl
		} else {
			hopAutoTTL = 24 * time.Hour
		}
		hopAuto = map[string]bool{}
		hopProbeIn = map[string]chan bool{}
		hopProbeRes = map[string]hopProbeResult{}
		if hopSocks5 != "" && db != nil {
			rows, err := db.Query("SELECT host, added_at FROM hop_auto")
			if err == nil {
				for rows.Next() {
					var h, added string
					if rows.Scan(&h, &added) == nil {
						if t, terr := time.Parse(time.RFC3339, added); terr == nil && time.Since(t) > hopAutoTTL {
							continue
						}
						hopAuto[h] = true
					}
				}
				rows.Close()
			}
		}
		if hopAutoOn && hopSocks5 != "" {
			log.Printf("%s[HOP][auto]%s enabled — tunnelling any host that Cloudflare 403s from this IP; persisted=%d ttl=%v", colorGreen, colorReset, len(hopAuto), hopAutoTTL)
		}
	})
}

func inHopDomains(host string) bool {
	if hopSocks5 == "" {
		return false
	}
	h := strings.ToLower(host)
	for {
		hopAutoMu.Lock()
		_, inConfig := hopDomains[h]
		_, inAuto := hopAuto[h]
		hopAutoMu.Unlock()
		if inConfig || inAuto {
			return true
		}
		i := strings.IndexByte(h, '.')
		if i == -1 {
			return false
		}
		h = h[i+1:]
	}
}

// autoClassify probes an unknown host once: if Cloudflare 403s it from the
// proxy's own IP it is routed through the hop (and persisted). Results are
// cached 24h so each host is probed at most daily. In-flight probes are shared
// so parallel connection attempts dedupe.
func autoClassify(host string) bool {
	if !hopAutoOn || hopSocks5 == "" {
		return false
	}
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" || net.ParseIP(h) != nil || !strings.Contains(h, ".") {
		return false
	}
	if hopAutoMatch(h) {
		return true
	}
	hopProbeMu.Lock()
	if r, ok := hopProbeRes[h]; ok && time.Since(r.t) < 24*time.Hour {
		hopProbeMu.Unlock()
		return r.blocked
	}
	if ch, dup := hopProbeIn[h]; dup {
		hopProbeMu.Unlock()
		select {
		case <-ch:
			return hopAutoMatch(h)
		case <-time.After(3500 * time.Millisecond):
			return false
		}
	}
	ch := make(chan bool, 1)
	hopProbeIn[h] = ch
	hopProbeMu.Unlock()

	blocked := cfBlockedDirect(h, 3000*time.Millisecond)

	hopProbeMu.Lock()
	hopProbeRes[h] = hopProbeResult{t: time.Now(), blocked: blocked}
	delete(hopProbeIn, h)
	hopProbeMu.Unlock()
	ch <- blocked

	if blocked {
		log.Printf("%s[HOP][auto]%s %s blocked via Azure — added to hop list", colorYellow, colorReset, h)
		hopAutoAdd(h)
	}
	return blocked
}

func hopAutoMatch(h string) bool {
	hopAutoMu.Lock()
	defer hopAutoMu.Unlock()
	for {
		if hopAuto[h] {
			return true
		}
		i := strings.IndexByte(h, '.')
		if i == -1 {
			return false
		}
		h = h[i+1:]
	}
}

func hopAutoAdd(h string) {
	hopAutoMu.Lock()
	if hopAuto == nil {
		hopAuto = map[string]bool{}
	}
	hopAuto[h] = true
	n := len(hopAuto)
	hopAutoMu.Unlock()
	if db != nil {
		_, _ = db.Exec("INSERT OR IGNORE INTO hop_auto(host, added_at) VALUES(?, ?)", h, time.Now().UTC().Format(time.RFC3339))
	}
	log.Printf("%s[HOP][auto]%s now tunnelling %d hosts via %s", colorGreen, colorReset, n, hopSocks5)
}

func hopAutoRemove(h string) {
	hopAutoMu.Lock()
	delete(hopAuto, h)
	n := len(hopAuto)
	hopAutoMu.Unlock()
	if db != nil {
		_, _ = db.Exec("DELETE FROM hop_auto WHERE host = ?", h)
	}
	log.Printf("%s[HOP][auto]%s host %s no longer blocked - removed from tunnel list (%d left)", colorYellow, colorReset, h, n)
}

// startHopAutoSweeper periodically re-probes tunnelled hosts; any host that no
// longer gets a Cloudflare 403 (or no longer resolves) from the direct Azure
// IP is dropped from the tunnel list so it doesn't stay there forever.
func startHopAutoSweeper() {
	if !hopAutoOn || hopSocks5 == "" || hopAutoTTL <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(hopAutoTTL / 2)
		defer ticker.Stop()
		for range ticker.C {
			hosts := []string{}
			hopAutoMu.Lock()
			for h := range hopAuto {
				hosts = append(hosts, h)
			}
			hopAutoMu.Unlock()
			for _, h := range hosts {
				isCfg := false
				hopAutoMu.Lock()
				if hopDomains[h] {
					isCfg = true
				}
				hopAutoMu.Unlock()
				if isCfg {
					continue
				}
				if !cfBlockedDirect(h, 5*time.Second) {
					hopAutoRemove(h)
				}
			}
		}
	}()
}

// cfBlockedDirect dials host directly (proxy's own IP), completes a minimal
// TLS handshake and reads the response status. True = Cloudflare block page
// (403 / "Just a moment").
func cfBlockedDirect(host string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) == 0 {
		d := &net.Dialer{Timeout: 2 * time.Second}
		if c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, "443")); err == nil {
			return probeHTTPStatus(c, host)
		}
		return false
	}
	tried := 0
	for _, a := range addrs {
		if tried >= 3 {
			break
		}
		d := &net.Dialer{Timeout: 2 * time.Second}
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(a.IP.String(), "443"))
		if err != nil {
			continue
		}
		tried++
		if probeHTTPStatus(c, host) {
			return true
		}
	}
	return false
}

func probeHTTPStatus(c net.Conn, host string) bool {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3500 * time.Millisecond))
	tc := tls.Client(c, &tls.Config{ServerName: host, InsecureSkipVerify: true})
	if tc.Handshake() != nil {
		return false
	}
	req := "GET / HTTP/1.1\r\nHost: " + host +
		"\r\nUser-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1" +
		"\r\nAccept: text/html,application/xhtml+xml\r\nAccept-Language: th-TH,th;q=0.9,en;q=0.8\r\nConnection: close\r\n\r\n"
	if _, err := tc.Write([]byte(req)); err != nil {
		return false
	}
	buf := make([]byte, 4096)
	n, err := tc.Read(buf)
	if err != nil && n == 0 {
		return false
	}
	s := string(buf[:n])
	return strings.HasPrefix(s, "HTTP/1.1 403 ") || strings.HasPrefix(s, "HTTP/1.0 403 ") ||
		strings.Contains(s, "Just a moment")
}

// dialHop opens a connection through the SOCKS5 server (no-auth).
func dialHop(ctx context.Context, address string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	c, err := d.DialContext(ctx, "tcp", hopSocks5)
	if err != nil {
		return nil, fmt.Errorf("hop dial %s: %w", hopSocks5, err)
	}
	// Bound the whole SOCKS handshake so a dead/unresponsive hop fails fast
	// and we can fall back to direct instead of hanging the tunnel for ages.
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	fail := func(e error) (net.Conn, error) {
		c.Close()
		return nil, fmt.Errorf("socks5 %s: %w", hopSocks5, e)
	}
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fail(err)
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(c, rep); err != nil {
		return fail(err)
	}
	if rep[0] != 0x05 || rep[1] != 0x00 {
		return fail(fmt.Errorf("handshake rejected (ver=%d method=%d)", rep[0], rep[1]))
	}
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return fail(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fail(err)
	}
	req := []byte{0x05, 0x01, 0x00}
	if ip4 := net.ParseIP(host).To4(); ip4 != nil {
		req = append(req, 0x01)
		req = append(req, ip4...)
	} else if ip16 := net.ParseIP(host).To16(); ip16 != nil {
		req = append(req, 0x04)
		req = append(req, ip16...)
	} else {
		if len(host) > 255 {
			return fail(fmt.Errorf("hostname too long"))
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	req = append(req, byte(port>>8), byte(port&0xff))
	if _, err := c.Write(req); err != nil {
		return fail(err)
	}
	if err := readSocksReply(c); err != nil {
		return fail(err)
	}
	// Handshake done — hand the (now clean) connection back to the tunnel.
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

func readSocksReply(c net.Conn) error {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return err
	}
	if hdr[0] != 0x05 {
		return fmt.Errorf("bad reply version %d", hdr[0])
	}
	if hdr[1] != 0x00 {
		return fmt.Errorf("connect failed status=%d", hdr[1])
	}
	n := 6
	switch hdr[3] {
	case 0x01:
		n = 6
	case 0x04:
		n = 18
	case 0x03:
		var ln [1]byte
		if _, err := io.ReadFull(c, ln[:]); err != nil {
			return err
		}
		n = int(ln[0]) + 2
	default:
		return fmt.Errorf("bad ATYP %d", hdr[3])
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(c, buf)
	return err
}

// hopDial dials address, sending connections for matched hosts out through the
// SOCKS5 hop and everything else via the normal custom dialer. Unknown hosts are
// auto-classified: if Cloudflare 403s them from this IP they get hopped too. If
// the hop is unreachable it degrades to direct instead of failing.
func hopDial(ctx context.Context, network, hostname, address string) (net.Conn, error) {
	useHop := inHopDomains(hostname)
	if !useHop {
		useHop = autoClassify(hostname)
	}
	if useHop {
		c, err := dialHop(ctx, address)
		if err == nil {
			return c, nil
		}
		log.Printf("%s[HOP][warn]%s %s: %v — direct fallback", colorYellow, colorReset, hostname, err)
	}
	return customDialer.DialContext(ctx, network, address)
}
// Custom transport — God-Mode concurrency for heavy video streaming
var proxyTransport = &http.Transport{
	DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		h, _, err := net.SplitHostPort(addr)
		if err != nil {
			h = addr
		}
		return hopDial(ctx, network, h, addr)
	},
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
	// SQLite hardening for production: WAL mode allows concurrent readers while
	// writers wait on busy_timeout instead of failing with "database is locked".
	_, _ = db.Exec("PRAGMA journal_mode=WAL")
	_, _ = db.Exec("PRAGMA busy_timeout=5000")
	_, _ = db.Exec("PRAGMA synchronous=NORMAL")

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

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS hop_auto (
		host TEXT PRIMARY KEY,
		added_at TEXT NOT NULL
	)`)
	if err != nil {
		log.Fatal("Failed to create hop_auto table:", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS proxy_users (
		username TEXT PRIMARY KEY,
		password TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		log.Fatal("Failed to create proxy_users table:", err)
	}

	// Connection audit log (append-only, pruned by LOG_RETENTION_DAYS)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS conn_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ts TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		username TEXT,
		client_ip TEXT,
		host TEXT,
		status TEXT,
		bytes_up INTEGER DEFAULT 0,
		bytes_down INTEGER DEFAULT 0,
		duration_ms INTEGER DEFAULT 0
	)`)
	if err != nil {
		log.Fatal("Failed to create conn_logs table:", err)
	}
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_conn_logs_ts ON conn_logs(ts)")
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_conn_logs_user ON conn_logs(username, ts)")
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_conn_logs_host ON conn_logs(host, ts)")

	// Per-user, per-host traffic summary (persisted, reloaded on boot)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS user_hosts (
		username TEXT NOT NULL,
		host TEXT NOT NULL,
		bytes_up INTEGER DEFAULT 0,
		bytes_down INTEGER DEFAULT 0,
		conns INTEGER DEFAULT 0,
		first_seen TIMESTAMP,
		last_seen TIMESTAMP,
		PRIMARY KEY (username, host)
	)`)
	if err != nil {
		log.Fatal("Failed to create user_hosts table:", err)
	}

	// Admin actions audit — who added/deleted which user, when
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS admin_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ts TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		admin_user TEXT,
		action TEXT,
		target TEXT,
		detail TEXT
	)`)
	if err != nil {
		log.Fatal("Failed to create admin_logs table:", err)
	}
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_admin_logs_ts ON admin_logs(ts)")

	// Per-user account settings (quota + suspension); applies to env and DB users alike
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS user_settings (
		username TEXT PRIMARY KEY,
		quota_bytes INTEGER DEFAULT 0,
		suspended INTEGER DEFAULT 0,
		proxy_enabled INTEGER DEFAULT -1,
		adblock_enabled INTEGER DEFAULT -1,
		updated_at TIMESTAMP
	)`)
	if err != nil {
		log.Fatal("Failed to create user_settings table:", err)
	}
	// Migrate older DBs that lack the flag columns (ignore duplicate-column errors)
	_, _ = db.Exec("ALTER TABLE user_settings ADD COLUMN proxy_enabled INTEGER NOT NULL DEFAULT -1")
	_, _ = db.Exec("ALTER TABLE user_settings ADD COLUMN adblock_enabled INTEGER NOT NULL DEFAULT -1")

	// Global settings key/value (proxy_enabled, adblock_enabled master switches)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value INTEGER NOT NULL DEFAULT 1
	)`)
	if err != nil {
		log.Fatal("Failed to create settings table:", err)
	}

	// Per-user account settings (quota + suspension); applies to env and DB users alike
	rowsS, err := db.Query("SELECT username, quota_bytes, suspended, proxy_enabled, adblock_enabled FROM user_settings")
	if err == nil {
		for rowsS.Next() {
			var u string
			var qb, sus, pe, ad int64
			if rowsS.Scan(&u, &qb, &sus, &pe, &ad) == nil && u != "" {
				userSettings.Store(u, &userSetting{quotaBytes: qb, suspended: sus == 1, proxyEnabled: int(pe), adblockEnabled: int(ad)})
			}
		}
		rowsS.Close()
	}

	// Load persisted users into memory (env PROXY_USERS takes precedence overrides handled in main)
	rowsU, err := db.Query("SELECT username, password FROM proxy_users")
	if err == nil {
		for rowsU.Next() {
			var u, p string
			if rowsU.Scan(&u, &p) == nil && u != "" {
				proxyUsers[u] = p
			}
		}
		rowsU.Close()
	}

	// Reload persisted per-user-host totals into memory on boot
	rowsH, err := db.Query("SELECT username, host, bytes_up, bytes_down, conns, first_seen, last_seen FROM user_hosts")
	if err == nil {
		for rowsH.Next() {
			var u, h, f, l string
			var up, dn, cn int64
			if rowsH.Scan(&u, &h, &up, &dn, &cn, &f, &l) == nil {
				st := &userHostStat{}
				st.bytesUp = up
				st.bytesDown = dn
				st.conns = cn
				if t, err := time.Parse("2006-01-02 15:04:05", f); err == nil {
					st.firstSeen = t
				}
				if t, err := time.Parse("2006-01-02 15:04:05", l); err == nil {
					st.lastSeen = t
				}
				userHosts.Store(u+"\x00"+h, st)
				addQuotaUsed(u, dn)
			}
		}
		rowsH.Close()
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
loadAppSettings()
loadHopConfig()
	startHopAutoSweeper()
	loadAdminCreds()
	startConnLogWriter()
startRetentionPruner()
	startUserHostsFlusher()
	startHeartbeatStats()
	reloadAdBlock()
	startAdBlockRefresher()

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

	portCfg := os.Getenv("PORT")
	if portCfg == "" {
		portCfg = "8080"
	}
	var ports []string
	for _, p := range strings.Split(portCfg, ",") {
		if p = strings.TrimSpace(p); p != "" {
			ports = append(ports, p)
		}
	}
	if len(ports) == 0 {
		ports = []string{"8080"}
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

	go startBwSampler()

	proxy := &http.Server{
		Handler:      http.HandlerFunc(handleRequest),
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  90 * time.Second,
	}

	fmt.Println()
	fmt.Println("=== NetNinja Go Proxy Running on Ports: " + strings.Join(ports, ", ") + " ===")
	fmt.Println("DNS: Google 8.8.8.8 / Cloudflare 1.1.1.1")
	fmt.Println("Engine: Go (High-Performance Goroutine-based)")
	fmt.Println("==============================================")
	fmt.Println()

	var lns []net.Listener
	for _, p := range ports {
		ln, err := net.Listen("tcp", bindAddr+":"+p)
		if err != nil {
			log.Fatal("Failed to listen on "+bindAddr+":"+p+":", err)
		}
		lns = append(lns, ln)
		fmt.Println("LISTEN " + bindAddr + ":" + p)
	}
	fmt.Println()

	for _, ln := range lns {
		ln := ln
		go func() {
			if err := proxy.Serve(keepAliveListener{ln}); err != nil && err != http.ErrServerClosed {
				log.Fatal("proxy.Serve:", err)
			}
		}()
	}
	select {}
}

// keepAliveListener enables TCP keepalive probes on every accepted connection
// (30s period) so home NATs and Azure SLB never silently drop idle proxied
// connections — the #1 cause of "proxy dies until I restart wifi".
type keepAliveListener struct{ net.Listener }

func (k keepAliveListener) Accept() (net.Conn, error) {
	c, err := k.Listener.Accept()
	if err == nil {
		if tc, ok := c.(*net.TCPConn); ok {
			tc.SetNoDelay(true)
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(30 * time.Second)
		}
	}
	return c, err
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
		if u := authedUser(r); u != "" {
			if blocked, reason := checkUserBlocked(u); blocked {
				log.Printf("%s[BLOCKED]%s %s (ip=%s) denied: %s", colorYellow, colorReset, u, clientIP, reason)
				pushConnLog(connLogEntry{username: u, clientIP: clientIP, host: r.URL.Hostname(), status: reason, durMs: 0})
				w.Header().Set("Content-Length", "0")
				w.WriteHeader(403)
				return
			}
			trackUserDevice(u, clientIP, r.Header.Get("User-Agent"))
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
		} else if path == "/admin" || path == "/admin/" {
			serveAdmin(w, r)
			return
		} else if path == "/admin/add" {
			handleAdminAdd(w, r)
			return
		} else if path == "/admin/delete" {
			handleAdminDelete(w, r)
			return
		} else if path == "/admin/user" {
			serveAdminUser(w, r)
			return
		} else if path == "/admin/logs" {
			serveAdminLogs(w, r)
			return
		} else if path == "/admin/audit" {
			serveAdminAudit(w, r)
			return
		} else if path == "/admin/quota" {
			handleAdminQuota(w, r)
			return
		} else if path == "/admin/suspend" {
			handleAdminSuspend(w, r)
			return
		} else if path == "/admin/blocklist" {
			handleAdminBlocklist(w, r)
			return
		} else if path == "/admin/settings" {
			handleAdminSettings(w, r)
			return
		} else if path == "/admin/userflag" {
			handleAdminUserFlag(w, r)
			return
		} else if path == "/settings" {
			serveSettings(w, r)
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
		<a href="/admin">admin</a> &nbsp;•&nbsp;
		<a href="/welcome" id="welcome_link" style="display:none">welcome</a> &nbsp;•&nbsp;
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

	direct := []string{
		"googlevideo.com", "apple.com", "icloud.com",
		"apple-cloudkit.com", "mzstatic.com", "itunes.com",
	}
	if extra := os.Getenv("PAC_DIRECT_DOMAINS"); extra != "" {
		for _, d := range strings.Split(extra, ",") {
			d = strings.TrimSpace(d)
			if strings.Trim(d, `"` + `'`) != "" {
				direct = append(direct, strings.Trim(d, `"` + `'`))
			}
		}
	}
	var directCond []string
	for _, d := range direct {
		directCond = append(directCond, `dnsDomainIs(host, "`+d+`")`)
	}
	directList := strings.Join(directCond, " || ")

	pac := fmt.Sprintf(`function FindProxyForURL(url, host) {
    if (isPlainHostName(host) ||
        shExpMatch(host, "10.*") ||
        shExpMatch(host, "172.16.*") ||
        shExpMatch(host, "192.168.*") ||
        host == "127.0.0.1" ||
        host == "localhost") {
        return "DIRECT";
    }
    if (%s) {
        return "DIRECT";
    }
    return "PROXY %s; DIRECT";
}
`, directList, proxyHost)

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

	// Account policy: proxy disabled? user must connect direct
	if u := authedUser(r); u != "" && !proxyEnabledFor(u) {
		log.Printf("%s[BLOCKED]%s %s (ip=%s) proxy disabled — refused HTTP %s", colorYellow, colorReset, u, clientIP, unwrappedHost)
		pushConnLog(connLogEntry{username: u, clientIP: clientIP, host: unwrappedHost, status: "proxy_off", durMs: 0})
		http.Error(w, "Proxy Disabled for this account (connect directly)", http.StatusForbidden)
		return
	}

	// Ad-block: refuse explicit ad/tracking hosts on plain HTTP too
	if u := authedUser(r); adblockEnabledFor(u) && isAdBlockedHost(unwrappedHost) {
		atomic.AddInt64(&adBlocked, 1)
		log.Printf("%s[AD-BLOCK]%s refused HTTP %s ← %s", colorRed, colorReset, unwrappedHost, clientIP)
		http.Error(w, "Forbidden (Ad-Blocked by NetNinja)", http.StatusForbidden)
		return
	}

	// Account policy: suspended/quota-exceeded users are refused on plain HTTP too
	if u := authedUser(r); u != "" {
		if blocked, reason := checkUserBlocked(u); blocked {
			log.Printf("%s[BLOCKED]%s %s (ip=%s) denied on HTTP: %s", colorYellow, colorReset, u, clientIP, reason)
			pushConnLog(connLogEntry{username: u, clientIP: clientIP, host: unwrappedHost, status: reason, durMs: 0})
			http.Error(w, "Forbidden ("+reason+" by NetNinja)", http.StatusForbidden)
			return
		}
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
	n, _ := io.Copy(w, resp.Body)

	// Audit log for forwarded HTTP request
	if h := unwrappedHost; h != "" {
		hName := h
		if idx := strings.LastIndex(hName, ":"); idx != -1 {
			hName = hName[:idx]
		}
		u := authedUser(r)
		pushConnLog(connLogEntry{username: u, clientIP: clientIP, host: hName, status: "http", bytesDown: n, durMs: time.Since(start).Milliseconds()})
		touchUserHost(u, hName, 0, n, 1)
	}

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
	tunnelStart := time.Now()
	tunnelUser := authedUser(r)

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

	// Account policy: proxy disabled? user must connect direct
	if tunnelUser != "" && !proxyEnabledFor(tunnelUser) {
		atomic.AddInt64(&errCount, 1)
		log.Printf("%s[BLOCKED]%s %s (ip=%s) proxy disabled — refused CONNECT %s", colorYellow, colorReset, tunnelUser, clientIP, host)
		pushConnLog(connLogEntry{username: tunnelUser, clientIP: clientIP, host: hostname, status: "proxy_off", durMs: time.Since(tunnelStart).Milliseconds()})
		http.Error(w, "Proxy Disabled for this account (connect directly)", http.StatusForbidden)
		return
	}

	// Ad-block: refuse tunnels to ad/tracking networks before dialing
	if adblockEnabledFor(tunnelUser) && isAdBlockedHost(hostname) {
		atomic.AddInt64(&adBlocked, 1)
		log.Printf("%s[AD-BLOCK]%s refused CONNECT %s ← %s", colorRed, colorReset, hostname, clientIP)
		pushConnLog(connLogEntry{username: tunnelUser, clientIP: clientIP, host: hostname, status: "ad_block", durMs: time.Since(tunnelStart).Milliseconds()})
		http.Error(w, "Forbidden (Ad-Blocked by NetNinja)", http.StatusForbidden)
		return
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

	destConn, err := hopDial(r.Context(), "tcp", hostname, net.JoinHostPort(ip, port))
	if err != nil {
		atomic.AddInt64(&errCount, 1)
		log.Printf("%s[ERR]%s CONNECT %s failed: %s", colorRed, colorReset, host, err)
		pushConnLog(connLogEntry{username: tunnelUser, clientIP: clientIP, host: hostname, status: "dial_fail", durMs: time.Since(tunnelStart).Milliseconds()})
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		destConn.Close()
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		atomic.AddInt64(&errCount, 1)
		destConn.Close()
		http.Error(w, "Hijack failed", http.StatusServiceUnavailable)
		return
	}

	// IMPORTANT: http.Server applies ReadTimeout/WriteTimeout deadlines to the
	// inbound conn. They survive Hijack() and silently kill healthy idle
	// tunnels at ~60-120s (iOS sees "connection closed unexpectedly" and does
	// not reconnect until wifi toggle). Clear them before speaking on the conn.
	clientConn.SetDeadline(time.Time{})

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

	trackUserConn(tunnelUser)

	clientAct := &activityConn{Conn: clientConn}
	destAct := &activityConn{Conn: destConn}
	tunnelDone := make(chan struct{})

	errc := make(chan error, 2)
	var wg sync.WaitGroup
	var tUp, tDown int64

	// Client → dest (upload)
	wg.Add(1)
	go func() {
		defer wg.Done()
		n, err := io.Copy(destAct, clientAct)
		atomic.AddInt64(&totalBytesUp, n)
		tUp += n
		if hs != nil {
			hs.mu.Lock()
			hs.bytes += n
			hs.last = time.Now()
			hs.mu.Unlock()
		}
		if n > 0 {
			trackUserBytes(tunnelUser, n, 0)
		}
		destAct.Close()
		errc <- err
	}()
	// dest → client (download)
	wg.Add(1)
	go func() {
		defer wg.Done()
		n, err := io.Copy(clientAct, destAct)
		atomic.AddInt64(&totalBytesDown, n)
		tDown += n
		if hs != nil {
			hs.mu.Lock()
			hs.bytes += n
			hs.last = time.Now()
			hs.mu.Unlock()
		}
		if n > 0 {
			trackUserBytes(tunnelUser, 0, n)
		}
		clientAct.Close()
		errc <- err
	}()

	// Bandwidth history is maintained by the global sampler started once at
	// boot (startBwSampler) — NOT per tunnel — so the realtime chart always has
	// the last 60s of aggregate traffic regardless of active tunnels.

	wg.Wait()
	close(tunnelDone)
	activeTunnels.Delete(hostname)

	// Log WHY the tunnel closed — tells us if the server killed it (deadline/
	// read/write error) or a peer vanished (EOF/RST). Crucial for the recurring
	// "connection closed unexpectedly" the client sees after a few minutes.
	var closeReasons []string
	for i := 0; i < 2; i++ {
		if err := <-errc; err != nil && err != io.EOF {
			closeReasons = append(closeReasons, err.Error())
		}
	}
	if len(closeReasons) > 0 {
		log.Printf("%s[CLOSE]%s %s ↔ %s closed after %s up=%d down=%d reason=%s",
			colorYellow, colorReset, clientIP, host,
			time.Since(tunnelStart).Round(time.Millisecond), tUp, tDown,
			strings.Join(closeReasons, " | "))
	} else {
		log.Printf("%s[CLOSE]%s %s ↔ %s closed after %s up=%d down=%d",
			colorYellow, colorReset, clientIP, host,
			time.Since(tunnelStart).Round(time.Millisecond), tUp, tDown)
	}

	// Audit log entry for this completed tunnel
	pushConnLog(connLogEntry{
		username:  tunnelUser,
		clientIP:  clientIP,
		host:      hostname,
		status:    "ok",
		bytesUp:   tUp,
		bytesDown: tDown,
		durMs:     time.Since(tunnelStart).Milliseconds(),
	})
	touchUserHost(tunnelUser, hostname, tUp, tDown, 1)
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
	// Case 1: Matches a local IP (loopback / interface addresses / PROXY_ADDR)
	if isLocalIP(hostOnly) {
		return true
	}
	// Case 1b: Hostname resolves to one of our own IPs (e.g. the proxy's
	// public hostname when accessed absolute-form through itself).
	if ips, err := net.LookupIP(strings.Trim(hostOnly, "[]")); err == nil {
		for _, ip := range ips {
			if isLocalIP(ip.String()) {
				return true
			}
		}
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
	// Refuse to dial the proxy itself (self-loop protection). This happens
	// when a client routes the dashboard /ws WebSocket through the proxy and
	// sends it absolute-form: the request host is this proxy's own hostname,
	// so forwarding it would just loop back into handleWSUpgrade forever.
	if isSelf(hostname, hostname) {
		log.Printf("%s[WS-PROXY]%s Refused self-dial for %s from %s", colorYellow, colorReset, host, clientIP)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	destConn, err := hopDial(r.Context(), "tcp", hostname, net.JoinHostPort(hostname, port))
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

	// Inherited http.Server ReadTimeout/WriteTimeout deadlines survive Hijack()
	// and would kill the WS pipe at ~60-120s. Clear them before forwarding.
	clientConn.SetDeadline(time.Time{})

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

	// Inherited http.Server ReadTimeout/WriteTimeout deadlines survive the
	// gorilla Hijack() and would kill the dashboard WS at ~60-120s. Clear them.
	if tc, ok := conn.UnderlyingConn().(*net.TCPConn); ok {
		tc.SetDeadline(time.Time{})
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}

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

// ---------------------------------------------------------------------------
// Admin interface: manage proxy users + view per-user usage (ADMIN_PASS env)
// ---------------------------------------------------------------------------

var (
	adminUser string
	adminPass string
)

func loadAdminCreds() {
	adminUser = os.Getenv("ADMIN_USER")
	if adminUser == "" {
		adminUser = "admin"
	}
	adminPass = os.Getenv("ADMIN_PASS")
}

func adminAuthRequired(w http.ResponseWriter, r *http.Request) bool {
	if adminPass == "" {
		http.Error(w, "Admin not configured", http.StatusForbidden)
		return false
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		w.Header().Set("WWW-Authenticate", `Basic realm="NetNinja Admin"`)
		http.Error(w, "Admin Authentication Required", http.StatusUnauthorized)
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="NetNinja Admin"`)
		http.Error(w, "Admin Authentication Required", http.StatusUnauthorized)
		return false
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 || parts[0] != adminUser || parts[1] != adminPass {
		w.Header().Set("WWW-Authenticate", `Basic realm="NetNinja Admin"`)
		http.Error(w, "Admin Authentication Required", http.StatusUnauthorized)
		return false
	}
	return true
}

// userSnap is a consistent read of a single user's usage stats
type userSnap struct {
	name        string
	bytesUp     int64
	bytesDown   int64
	conns       int64
	firstSeen   time.Time
	lastSeen    time.Time
	deviceCount int
	devices     []string
	suspended   bool
	quotaBytes  int64
	quotaUsed   int64
}

// snapshotUsers aggregates persisted per-host totals WITH live device info.
// Bytes/conns come from user_hosts (survive restarts); devices come from live stats.
func snapshotUsers() []userSnap {
	agg := map[string]*userSnap{}
	userHosts.Range(func(k, v interface{}) bool {
		key := k.(string)
		parts := strings.SplitN(key, "\x00", 2)
		if len(parts) != 2 {
			return true
		}
		u := parts[0]
		st := v.(*userHostStat)
		if st == nil {
			return true
		}
		st.mu.Lock()
		up, down, conns := st.bytesUp, st.bytesDown, st.conns
		firstSeen, lastSeen := st.firstSeen, st.lastSeen
		st.mu.Unlock()
		s, ok := agg[u]
		if !ok {
			s = &userSnap{name: u}
			agg[u] = s
		}
		s.bytesUp += up
		s.bytesDown += down
		s.conns += conns
		if !firstSeen.IsZero() && (s.firstSeen.IsZero() || firstSeen.Before(s.firstSeen)) {
			s.firstSeen = firstSeen
		}
		if lastSeen.After(s.lastSeen) {
			s.lastSeen = lastSeen
		}
		return true
	})

	// Merge live device info
	userStats.Range(func(k, v interface{}) bool {
		u := k.(string)
		st := v.(*userStat)
		s, ok := agg[u]
		if !ok {
			s = &userSnap{name: u}
			agg[u] = s
		}
		st.mu.Lock()
		for d := range st.devices {
			if len(s.devices) < 8 {
				s.devices = append(s.devices, d)
			}
			s.deviceCount++
		}
		if st.lastSeen.After(s.lastSeen) {
			s.lastSeen = st.lastSeen
		}
		st.mu.Unlock()
		return true
	})

	var out []userSnap
	for _, s := range agg {
		if v, ok := userSettings.Load(s.name); ok {
			st := v.(*userSetting)
			s.suspended = st.suspended
			s.quotaBytes = st.quotaBytes
		}
		s.quotaUsed = quotaUsedOf(s.name)
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].bytesDown+out[i].bytesUp > out[j].bytesDown+out[j].bytesUp
	})
	return out
}

func adminPageTop(title, curPath string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>netninja admin — %s</title>
<script src="https://cdn.tailwindcss.com"></script>
<script>
tailwind.config = {
	theme: {
		extend: {
			colors: {
				ac:     '#ffa500',
				link:   '#7af',
				good:   '#0f0',
				bad:    '#f77',
				panel:  '#111',
				canvas: '#0d0d0d',
				line:   '#222',
				faint:  '#444',
				mut:    '#555',
				soft:   '#888',
				dim:    '#999',
			},
			fontFamily: {
				mono: ['"Courier New"', 'ui-monospace', 'monospace'],
			},
		},
	},
};
</script>
<style type="text/tailwindcss">
@layer components {
	table { @apply w-full border-collapse mb-5; }
	th { @apply text-mut uppercase text-[10px] tracking-wider text-left px-2 py-1.5 border-b border-[#333]; }
	td { @apply px-2 py-2 border-b border-[#151515] align-top; }
	td b { @apply text-[#eee]; }
	td.ok { @apply text-good; }
	td.err { @apply text-bad; }
	td.num { @apply text-link; }
	td.dim { @apply text-mut text-[11px]; }
	td.warn { @apply text-ac; }
	a.u { @apply text-link no-underline font-bold; }
	a.u:hover { @apply text-white underline; }
	.dev { @apply text-soft text-[10px] bg-[#121212] border border-line rounded px-1.5 py-0.5 mr-1 my-0.5 inline-block; }
	.dev.dim { @apply text-mut; }
	.devc { @apply text-good font-bold; }
	.devlist { @apply mt-1; }
	.btn-deL { @apply bg-[#3a0f0f] text-bad border border-[#722] rounded px-2.5 py-1 font-mono text-xs cursor-pointer; }
	.btn-del { @apply bg-[#3a0f0f] text-bad border border-[#722] rounded px-2.5 py-1 font-mono text-xs cursor-pointer hover:bg-[#5a1515]; }
	.btn-sus { @apply bg-[#3a2a00] text-[#ffc966] border border-[#6a4a00] rounded px-2.5 py-1 font-mono text-xs cursor-pointer hover:bg-[#5a3f00] mr-1; }
	.btn-ok { @apply bg-[#0f2f0f] text-good border border-[#274] rounded px-2.5 py-1 font-mono text-xs cursor-pointer hover:bg-[#174017] mr-1; }
	.btn-add { @apply bg-[#5a3a00] text-[#ffc966] border border-[#8a5c00] rounded px-4 py-2.5 font-mono font-bold cursor-pointer mt-3 hover:bg-[#6b4600]; }
	.btn { @apply bg-panel text-[#ccc] border border-[#333] rounded px-3.5 py-1.5 font-mono text-xs cursor-pointer hover:text-white hover:border-ac; }
	.add-card { @apply bg-panel border border-line rounded p-4 mt-2.5; }
	.add-card label { @apply text-mut text-[10px] uppercase tracking-wider block my-2 mb-1; }
	.add-card input[type="text"], .add-card input[type="number"], .add-card select { @apply bg-canvas border border-[#2a2a2a] text-[#eee] px-2.5 py-2 rounded font-mono w-full; }
	.add-card input[type="checkbox"] { @apply accent-ac; }
	.add-card input:focus, .add-card select:focus { @apply outline-none border-ac; }
	.filters input, .filters select { @apply bg-canvas border border-[#2a2a2a] text-[#eee] px-2.5 py-2 rounded font-mono; }
	.filters input:focus, .filters select:focus { @apply outline-none border-ac; }
	.tots { @apply flex gap-3.5 flex-wrap mb-5; }
	.tot { @apply bg-panel border border-line rounded px-3.5 py-2.5 flex-1 min-w-[130px]; }
	.tot .k { @apply text-mut text-[10px] uppercase tracking-wider; }
	.tot .v { @apply text-ac text-base mt-0.5; }
	.tot .v.g { color:#0f0; }
	.tot .v.r { color:#f77; }
	.filters { @apply bg-panel border border-line rounded p-3.5 mb-4; }
	.filters form { @apply flex gap-2.5 flex-wrap items-end; }
	.filters label { @apply text-mut text-[10px] uppercase tracking-wider block mb-1; }
	.pager { @apply flex gap-3 items-center my-3.5; }
	.pager .nav { @apply flex gap-2; }
	.pager a { @apply text-link no-underline; }
	.back { @apply mt-8 inline-block text-link no-underline hover:text-white; }
	.q { color:#ffa500; }
	.msg { @apply bg-[#191919] border border-[#2a3a2a] text-good px-3.5 py-2.5 rounded mb-4; }
	.hbar { @apply flex items-center gap-2 my-1 text-[11px]; }
	.hbar .hl { @apply text-link w-[130px] text-right whitespace-nowrap overflow-hidden text-ellipsis shrink-0; }
	.hbar .htrack { @apply flex-1 bg-[#191919] border border-line h-3 rounded overflow-hidden; }
	.hbar .hfill { @apply h-3 rounded; }
	.hbar .hv { @apply text-[#eee] w-[70px] text-right text-[11px] shrink-0; }
	.legend { @apply mt-2.5; }
	.legend .li { @apply flex items-center gap-2 text-[#bbb] text-[11px] my-1; }
	.legend .dot { @apply w-2.5 h-2.5 rounded inline-block; }
	.charts { @apply grid gap-3.5 mb-5 grid-cols-1; }
	@media (min-width:768px) { .charts { @apply grid-cols-2; } }
	@media (min-width:1180px) { .charts { @apply grid-cols-3; } }
	.chart-card { @apply bg-panel border border-line rounded p-3.5; }
	.chart-card .ck { @apply text-mut text-[10px] uppercase tracking-wider mb-2.5; }
	.navlink { @apply text-dim border border-[#2a2a2a] bg-panel px-3.5 py-1.5 rounded text-xs hover:text-white hover:border-ac; }
	.navlink-cur { @apply text-ac border-ac bg-panel px-3.5 py-1.5 rounded text-xs; }
}
</style>
</head>
<body class="bg-[#0a0a0a] text-[#ccc] font-mono p-5 sm:p-10">
<div class="max-w-[1020px] mx-auto">
	<h1 class="text-white text-lg mb-1 font-normal"><span class="text-ac mr-2.5">●</span> netninja admin</h1>
	<div class="text-faint text-[11px] mb-4 tracking-widest">%s</div>
	<div class="flex gap-1.5 mt-3.5 mb-5 flex-wrap">
		<a href="/admin" %s>users</a>
		<a href="/admin/logs" %s>access_logs</a>
		<a href="/admin/audit" %s>admin_audit</a>
		<a href="/" class="navlink">dashboard</a>
	</div>
`, html.EscapeString(title), html.EscapeString(title),
		navCur(curPath, "/admin", "/admin/user"), navCur(curPath, "/admin/logs"), navCur(curPath, "/admin/audit"))
}

func navCur(curPath string, paths ...string) string {
	for _, p := range paths {
		if curPath == p {
			return `class="navlink-cur"`
		}
	}
	return `class="navlink"`
}

func adminPageEnd(extra string) string {
	return `	<a class="back" href="/admin">&larr; admin</a>
</div>
</body>
</html>` + extra
}

func fmtMB(b int64) string {
	return fmt.Sprintf("%.2f MB", float64(b)/1048576)
}

func fmtSize(b int64) string {
	if b >= 1073741824 {
		return fmt.Sprintf("%.2f GB", float64(b)/1073741824)
	}
	if b >= 1048576 {
		return fmt.Sprintf("%.1f MB", float64(b)/1048576)
	}
	if b >= 1024 {
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	}
	return fmt.Sprintf("%d B", b)
}

func fmtDur(ms int64) string {
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	return fmt.Sprintf("%.1fs", float64(ms)/1000)
}

// hbarRow renders one horizontal-bar row (label / track / value) — reused by the
// admin charts for top hosts and per-user usage.
func hbarRow(label string, val, max int64, color string) string {
	pct := 0
	if max > 0 {
		pct = int(val * 100 / max)
	}
	if pct < 2 && val > 0 {
		pct = 2
	}
	return fmt.Sprintf(`<div class="hbar"><span class="hl" title="%s">%s</span><div class="htrack"><div class="hfill" style="width:%d%%;background:%s"></div></div><span class="hv">%s</span></div>`,
		html.EscapeString(label), html.EscapeString(label), pct, color,
		html.EscapeString(fmtSize(val)))
}

// bwSparkSVG renders the rolling bandwidth history as an SVG area/line chart.
func bwSparkSVG(data []int64, w, h int) string {
	if len(data) == 0 {
		return `<svg viewBox="0 0 ` + fmt.Sprintf("%d %d", w, h) + `" width="100%" height="68" style="background:#0d0d0d"><text x="8" y="30" fill="#555" font-size="11" font-family="Courier New,monospace">-- no data --</text></svg>`
	}
	max := int64(1)
	for _, v := range data {
		if v > max {
			max = v
		}
	}
	pts := ""
	area := ""
	for i, v := range data {
		x := 2 + (float64(w-4) * float64(i) / float64(len(data)-1))
		y := float64(h-2) - (float64(v)/float64(max))*float64(h-6)
		pts += fmt.Sprintf("%.1f,%.1f ", x, y)
		if i == len(data)-1 {
			area += fmt.Sprintf("%.1f,%.1f ", x, float64(h-1))
		}
	}
	area = pts + area
	return `<svg viewBox="0 0 ` + fmt.Sprintf("%d %d", w, h) + `" width="100%" height="68" style="background:#0d0d0d" preserveAspectRatio="none">
<defs><linearGradient id="bwg" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#0f0" stop-opacity="0.35"/><stop offset="100%" stop-color="#0f0" stop-opacity="0.02"/></linearGradient></defs>
<polygon points="` + area + `" fill="url(#bwg)"/>
<polyline points="` + pts + `" fill="none" stroke="#0f0" stroke-width="1.4"/>
</svg>`
}

// adminCharts renders the admin dashboard charts section from live stats:
// bandwidth history, top hosts by bytes, per-user usage, DNS hit/miss/doh, traffic mix.
func adminCharts(snaps []userSnap) string {
	// bandwidth history
	bwHistoryMu.Lock()
	bw := make([]int64, len(bwHistory))
	copy(bw, bwHistory)
	bwHistoryMu.Unlock()

	// top hosts by bytes (biggest first)
	type hrow struct{ host string; bytes int64 }
	var hosts []hrow
	hostStats.Range(func(k, v interface{}) bool {
		st := v.(*hostStat)
		st.mu.Lock()
		hosts = append(hosts, hrow{k.(string), st.bytes})
		st.mu.Unlock()
		return true
	})
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].bytes > hosts[j].bytes })
	if len(hosts) > 8 {
		hosts = hosts[:8]
	}
	hmax := int64(1)
	for _, h := range hosts {
		if h.bytes > hmax {
			hmax = h.bytes
		}
	}
	hostRows := ``
	if len(hosts) == 0 {
		hostRows = `<div class="dim" style="padding:8px 0">-- no traffic --</div>`
	}
	for _, h := range hosts {
		hostRows += hbarRow(h.host, h.bytes, hmax, "#7af")
	}

	// per-user usage
	var us []userSnap
	for _, s := range snaps {
		if s.bytesDown+s.bytesUp > 0 {
			us = append(us, s)
		}
	}
	sort.Slice(us, func(i, j int) bool { return us[i].bytesDown+us[i].bytesUp > us[j].bytesDown+us[j].bytesUp })
	if len(us) > 8 {
		us = us[:8]
	}
	umax := int64(1)
	for _, s := range us {
		if s.bytesDown+s.bytesUp > umax {
			umax = s.bytesDown + s.bytesUp
		}
	}
	userRows := ``
	if len(us) == 0 {
		userRows = `<div class="dim" style="padding:8px 0">-- no usage --</div>`
	}
	for _, s := range us {
		userRows += hbarRow(s.name, s.bytesDown+s.bytesUp, umax, "#0f0")
	}

	// DNS hit / miss / DoH donut + traffic up/down
	dnsH := atomic.LoadInt64(&dnsHits)
	dnsM := atomic.LoadInt64(&dnsMisses)
	dnsD := atomic.LoadInt64(&dohCalls)
	dnsTotal := dnsH + dnsM + dnsD
	dnsLabel := fmt.Sprintf("%d", dnsTotal)
	if dnsTotal == 0 {
		dnsLabel = "--"
		dnsTotal = 1
	}
	const circ = 251.33 // 2*pi*r for r=40
	var donut strings.Builder
	off := float64(0)
	for _, segB := range []struct {
		v     int64
		color string
	}{{dnsH, "#0f0"}, {dnsM, "#ffa500"}, {dnsD, "#7af"}} {
		frac := float64(segB.v) / float64(dnsTotal)
		dash := frac * circ
		donut.WriteString(fmt.Sprintf(`<circle cx="50" cy="50" r="40" fill="none" stroke="%s" stroke-width="16" stroke-dasharray="%.1f %.1f" stroke-dashoffset="%.1f" transform="rotate(-90 50 50)"/>`, segB.color, dash, circ-dash, off))
		off -= dash
	}

	up := atomic.LoadInt64(&totalBytesUp)
	down := atomic.LoadInt64(&totalBytesDown)
	dmix := int64(0)
	if up+down > 0 {
		dmix = int64(float64(down) / float64(up+down) * 100)
	}

	return fmt.Sprintf(`
	<div class="charts">
		<div class="chart-card">
			<div class="ck">realtime_bandwidth (last 60s)</div>
			%s
		</div>
		<div class="chart-card">
			<div class="ck">top_hosts_by_bytes</div>
			%s
		</div>
		<div class="chart-card">
			<div class="ck">per_user_usage (up+down)</div>
			%s
		</div>
		<div class="chart-card">
			<div class="ck">dns_resolution</div>
			<svg viewBox="0 0 100 100" width="120" height="120">%s<text x="50" y="55" text-anchor="middle" fill="#eee" font-size="16" font-family="Courier New,monospace">%s</text><text x="50" y="70" text-anchor="middle" fill="#555" font-size="9" font-family="Courier New,monospace">total</text></svg>
			<div class="legend">
				<div class="li"><span class="dot" style="background:#0f0"></span>cache_hit %s</div>
				<div class="li"><span class="dot" style="background:#ffa500"></span>cache_miss %s</div>
				<div class="li"><span class="dot" style="background:#7af"></span>doh_calls %s</div>
			</div>
		</div>
		<div class="chart-card">
			<div class="ck">traffic_mix (down share of up+down)</div>
			<div class="hbar"><span class="hl">bytes_down</span><div class="htrack"><div class="hfill" style="width:%d%%;background:#7af"></div></div><span class="hv">%d%%</span></div>
			<div class="hbar"><span class="hl">bytes_up</span><div class="htrack"><div class="hfill" style="width:%d%%;background:#888"></div></div><span class="hv">%d%%</span></div>
			<div class="dim" style="margin-top:8px">down %s · up %s</div>
		</div>
	</div>`,
		bwSparkSVG(bw, 600, 70),
		hostRows,
		userRows,
		donut.String(), dnsLabel,
		html.EscapeString(fmtSize(dnsH)), html.EscapeString(fmtSize(dnsM)), html.EscapeString(fmtSize(dnsD)),
		dmix, dmix, 100-dmix, 100-dmix,
		html.EscapeString(fmtSize(down)), html.EscapeString(fmtSize(up)))
}

func serveAdmin(w http.ResponseWriter, r *http.Request) {
	if !adminAuthRequired(w, r) {
		return
	}

	snaps := snapshotUsers()

	known := map[string]bool{}
	for _, s := range snaps {
		known[s.name] = true
	}
	// Add auth users that exist but never connected
	for name := range proxyUsers {
		if !known[name] {
			s := userSnap{name: name}
			if v, ok := userSettings.Load(name); ok {
				st := v.(*userSetting)
				s.suspended = st.suspended
				s.quotaBytes = st.quotaBytes
				s.quotaUsed = quotaUsedOf(name)
			}
			snaps = append(snaps, s)
		}
	}
	sort.Slice(snaps, func(i, j int) bool {
		return snaps[i].bytesDown+snaps[i].bytesUp > snaps[j].bytesDown+snaps[j].bytesUp
	})

	var totalUp, totalDown, totalConns int64
	var totalDev int
	for _, s := range snaps {
		totalUp += s.bytesUp
		totalDown += s.bytesDown
		totalConns += s.conns
		totalDev += s.deviceCount
	}

	// DB log counts
	var logRows int64
	_ = db.QueryRow("SELECT COUNT(*) FROM conn_logs").Scan(&logRows)

	userRows := ""
	for _, s := range snaps {
		devList := ""
		for _, d := range s.devices {
			devList += fmt.Sprintf(`<div class="dev">%s</div>`, html.EscapeString(d))
		}
		if s.deviceCount > len(s.devices) {
			devList += fmt.Sprintf(`<div class="dev dim">… +%d more</div>`, s.deviceCount-len(s.devices))
		}
		first, last := "--", "--"
		if !s.firstSeen.IsZero() {
			first = s.firstSeen.Format("2006-01-02 15:04")
		}
		if !s.lastSeen.IsZero() {
			last = s.lastSeen.Format("2006-01-02 15:04")
		}
		ac := "no"
		acCls := "dim"
		if _, ok := proxyUsers[s.name]; ok {
			ac = "yes"
			acCls = "ok"
		}
		if s.suspended {
			ac = "suspended"
			acCls = "err"
		}
		activeNow := ""
		if time.Since(s.lastSeen) < 90*time.Second {
			activeNow = `&nbsp;<span class="dev" style="color:#0f0;border-color:#040">● live</span>`
		}
		// Quota cell: usage bar + data column
		quotaCell := `<td class="dim">∞</td>`
		if s.quotaBytes > 0 {
			used := s.quotaUsed
			if used > s.quotaBytes {
				used = s.quotaBytes
			}
			pct := int(used * 100 / s.quotaBytes)
			color := "#0f0"
			if pct >= 90 {
				color = "#f77"
			} else if pct >= 60 {
				color = "#ffa500"
			}
			quotaCell = fmt.Sprintf(`<td class="num">%s / %s&nbsp;(%d%%)<div style="background:#151515;border:1px solid #222;border-radius:3px;height:6px;margin-top:4px;width:110px"><div style="background:%s;width:%d%%;height:6px;border-radius:3px"></div></div></td>`,
				fmtSize(used), fmtSize(s.quotaBytes), pct, color, pct)
		}
		suspendBtn := ""
		if s.name != adminUser {
			if s.suspended {
				suspendBtn = fmt.Sprintf(`<form method="post" action="/admin/suspend" style="display:inline"><input type="hidden" name="user" value="%s"><input type="hidden" name="action" value="unsuspend"><button type="submit" class="btn-ok">ปลดระงับ</button></form>`, html.EscapeString(s.name))
			} else {
				suspendBtn = fmt.Sprintf(`<form method="post" action="/admin/suspend" style="display:inline"><input type="hidden" name="user" value="%s"><input type="hidden" name="action" value="suspend"><button type="submit" class="btn-sus" onclick="return confirm('ระงับบัญชี &#39;%s&#39;?')">ระงับ</button></form>`, html.EscapeString(s.name), html.EscapeString(s.name))
			}
		}
		quotaForm := fmt.Sprintf(`<form method="post" action="/admin/quota" style="display:inline"><input type="hidden" name="user" value="%s"><input type="number" step="0.001" min="0" name="gbytes" value="%s" style="width:70px;background:#0d0d0d;border:1px solid #2a2a2a;color:#eee;padding:4px;border-radius:3px;font:inherit"><button type="submit" class="btn">set (GB)</button></form>`, html.EscapeString(s.name), strconv.FormatFloat(float64(s.quotaBytes)/1073741824, 'f', 3, 64))
		pe, ae := -1, -1
		if v, ok := userSettings.Load(s.name); ok {
			pe = v.(*userSetting).proxyEnabled
			ae = v.(*userSetting).adblockEnabled
		}
		proxyBtn := fmt.Sprintf(`<form method="post" action="/admin/userflag" style="display:inline"><input type="hidden" name="user" value="%s"><input type="hidden" name="flag" value="proxy_enabled"><input type="hidden" name="value" value="%d"><button type="submit" class="btn" title="off = ปิด proxy ให้ user นี้ต่อตรงเลย">proxy:%s</button></form>`, html.EscapeString(s.name), nextFlagVal(pe), flagTxt(pe))
		adBtn := fmt.Sprintf(`<form method="post" action="/admin/userflag" style="display:inline"><input type="hidden" name="user" value="%s"><input type="hidden" name="flag" value="adblock_enabled"><input type="hidden" name="value" value="%d"><button type="submit" class="btn" title="off = ปล่อยโฆษณาผ่าน (ไม่บล็อก)">ads:%s</button></form>`, html.EscapeString(s.name), nextFlagVal(ae), flagTxt(ae))
		userRows += fmt.Sprintf(`<tr>
			<td><a class="u" href="/admin/user?name=%s">%s</a>%s</td>
			<td class="%s">%s</td>
			<td class="num">%s</td>
			<td class="num">%s</td>
			<td class="num">%d</td>
			<td class="dim">%s</td>
			<td class="dim">%s</td>
			<td><span class="devc">%d</span><div class="devlist">%s</div></td>
			%s
			<td>%s %s %s %s
				<form method="post" action="/admin/delete" style="display:inline" onsubmit="return confirm('ลบ user &#39;%s&#39;?' )"><input type="hidden" name="user" value="%s"><button type="submit" class="btn-del">ลบ</button></form>
			</td>
		</tr>`,
			url.QueryEscape(s.name), html.EscapeString(s.name), activeNow,
			acCls, ac,
			fmtMB(s.bytesUp), fmtMB(s.bytesDown), s.conns,
			first, last,
			s.deviceCount, devList,
			quotaCell,
			suspendBtn, proxyBtn, adBtn, quotaForm,
			html.EscapeString(s.name), html.EscapeString(s.name))
	}

	msg := r.URL.Query().Get("msg")
	msgHTML := ""
	if msg != "" {
		msgHTML = fmt.Sprintf(`<div class="msg">%s</div>`, html.EscapeString(msg))
	}

	top := adminPageTop("user_management // usage_monitor", r.URL.Path)
	blSrc := adBlockSource
	if blSrc == "" {
		blSrc = "-"
	}
	blUpdated := adBlockUpdated.Format("2006-01-02 15:04")
	if adBlockUpdated.IsZero() {
		blUpdated = "-"
	}
	blCard := fmt.Sprintf(`
	<div class="add-card" style="margin:12px 0">
		<div style="color:#fff;margin-bottom:6px">ad-block blocklist</div>
		<div class="dim" style="margin-bottom:8px">domains: <b>%d</b> &nbsp;·&nbsp; source: %s &nbsp;·&nbsp; loaded: %s &nbsp;·&nbsp; blocked_total: <b>%d</b></div>
		<form method="post" action="/admin/blocklist" style="display:inline"><button type="submit" class="btn">โหลด blocklist ใหม่</button></form>
	</div>
	`, atomic.LoadInt64(&adBlockCount), html.EscapeString(blSrc), html.EscapeString(blUpdated), atomic.LoadInt64(&adBlocked))

	gProxy := atomic.LoadInt64(&globalProxyEnabled) == 1
	gAd := atomic.LoadInt64(&globalAdblockEnabled) == 1
	gblCard := fmt.Sprintf(`
	<div class="add-card" style="margin:12px 0">
		<div style="color:#fff;margin-bottom:6px">global settings (ทุก user)</div>
		<form method="post" action="/admin/settings" style="display:flex;gap:18px;align-items:center;flex-wrap:wrap">
			<label style="color:#bbb;font-size:12px"><input type="checkbox" name="proxy" value="on" %s> ปิด proxy (ให้ทุกคนต่อตรง)</label>
			<label style="color:#bbb;font-size:12px"><input type="checkbox" name="adblock" value="on" %s> ปิด ads block (ปล่อยโฆษณาผ่าน)</label>
			<button type="submit" class="btn">บันทึก global</button>
		</form>
	</div>
	`, checked(!gProxy), checked(!gAd))

	body := fmt.Sprintf(`
	<div class="tots">
		<div class="tot"><div class="k">total_users</div><div class="v">%d</div></div>
		<div class="tot"><div class="k">bytes_up</div><div class="v" style="color:#7af">%s</div></div>
		<div class="tot"><div class="k">bytes_down</div><div class="v">%s</div></div>
		<div class="tot"><div class="k">total_conns</div><div class="v">%d</div></div>
		<div class="tot"><div class="k">total_devices</div><div class="v">%d</div></div>
		<div class="tot"><div class="k">stored_log_rows</div><div class="v g">%d</div></div>
	</div>

	%s
	%s
	%s
	%s

	<table>
	<tr><th>user</th><th>active</th><th>bytes_up</th><th>bytes_down</th><th>conns</th><th>first_seen</th><th>last_seen</th><th>devices</th><th>quota</th><th></th></tr>
	%s
	</table>

	<div class="add-card">
		<div style="color:#fff;margin-bottom:6px">เพิ่มผู้ใช้ใหม่</div>
		<form method="post" action="/admin/add">
			<label>username</label>
			<input type="text" name="user" required autocomplete="off" placeholder="เช่น mama">
			<label>password</label>
			<input type="text" name="pass" required autocomplete="off" placeholder="รหัสผ่าน">
			<label>quota (GB — 0 = ไม่จำกัด)</label>
			<input type="number" step="0.001" min="0" name="gbytes" placeholder="เช่น 2 = 2GB">
			<button type="submit" class="btn-add">เพิ่มผู้ใช้</button>
		</form>
	</div>
`, len(snaps), fmtMB(totalUp), fmtMB(totalDown), totalConns, totalDev, logRows,
		adminCharts(snaps), blCard, gblCard, msgHTML, userRows)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write([]byte(top + body + adminPageEnd("")))
}

// serveAdminUser — drill-down for one user: totals, devices, per-host summary, recent activity
func serveAdminUser(w http.ResponseWriter, r *http.Request) {
	if !adminAuthRequired(w, r) {
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Redirect(w, r, "/admin", http.StatusFound)
		return
	}

	// Aggregate host totals for this user
	type hostRow struct{ Host string; Up, Down, Conns int64; First, Last string }
	var hosts []hostRow
	userHosts.Range(func(k, v interface{}) bool {
		parts := strings.SplitN(k.(string), "\x00", 2)
		if len(parts) != 2 || parts[0] != name {
			return true
		}
		st := v.(*userHostStat)
		if st == nil {
			return true
		}
		st.mu.Lock()
		f, l := "--", "--"
		if !st.firstSeen.IsZero() {
			f = st.firstSeen.Format("2006-01-02 15:04")
		}
		if !st.lastSeen.IsZero() {
			l = st.lastSeen.Format("2006-01-02 15:04")
		}
		up, down, conns := st.bytesUp, st.bytesDown, st.conns
		st.mu.Unlock()
		hosts = append(hosts, hostRow{parts[1], up, down, conns, f, l})
		return true
	})
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Down > hosts[j].Down })

	// Recent activity for this user
	rows, _ := db.Query(`SELECT ts, client_ip, host, status, bytes_up, bytes_down, duration_ms FROM conn_logs WHERE username = ? ORDER BY id DESC LIMIT 100`, name)
	defer rows.Close()
	var acts []string
	for rows.Next() {
		var ts, ip, h, st string
		var up, dn, dur int64
		if rows.Scan(&ts, &ip, &h, &st, &up, &dn, &dur) == nil {
			cls := "ok"
			if st == "dial_fail" || st == "ad_block" || st == "proxy_off" || st == "suspended" || st == "quota" {
				cls = "err"
			}
			acts = append(acts, fmt.Sprintf(`<tr><td class="dim">%s</td><td class="%s">%s</td><td class="num">%s</td><td>%s</td><td class="num">%s</td><td class="num">%s</td><td class="dim">%s</td></tr>`,
				html.EscapeString(ts), cls, html.EscapeString(st), html.EscapeString(ip),
				html.EscapeString(h), fmtMB(up), fmtMB(dn), fmtDur(dur)))
		}
	}
	actBody := strings.Join(acts, "\n")
	if len(acts) == 0 {
		actBody = `<tr><td colspan="7" class="dim">ยังไม่มี activity</td></tr>`
	}

	hostBody := ""
	for _, h := range hosts {
		hostBody += fmt.Sprintf(`<tr><td><b>%s</b></td><td class="num">%s</td><td class="num">%s</td><td class="num">%d</td><td class="dim">%s</td><td class="dim">%s</td></tr>`,
			html.EscapeString(h.Host), fmtMB(h.Up), fmtMB(h.Down), h.Conns, h.First, h.Last)
	}
	if len(hosts) == 0 {
		hostBody = `<tr><td colspan="6" class="dim">ยังไม่มีข้อมูล host</td></tr>`
	}

	var up, down, conns int64
	for _, h := range hosts {
		up += h.Up
		down += h.Down
		conns += h.Conns
	}

	top := adminPageTop("user_detail // " + name, r.URL.Path)
	body := fmt.Sprintf(`
	<div class="tots">
		<div class="tot"><div class="k">user</div><div class="v" style="color:#7af">%s</div></div>
		<div class="tot"><div class="k">bytes_up</div><div class="v" style="color:#7af">%s</div></div>
		<div class="tot"><div class="k">bytes_down</div><div class="v">%s</div></div>
		<div class="tot"><div class="k">conns</div><div class="v">%d</div></div>
		<div class="tot"><div class="k">hosts</div><div class="v">%d</div></div>
	</div>

	<div class="section" style="margin-bottom:20px">
		<div style="color:#555;font-size:10px;text-transform:uppercase;letter-spacing:1px;margin:10px 0">hosts_by_bytes_down</div>
		<table>
		<tr><th>host</th><th>bytes_up</th><th>bytes_down</th><th>conns</th><th>first_seen</th><th>last_seen</th></tr>
		%s
		</table>
	</div>

	<div class="section" style="margin-bottom:20px">
		<div style="color:#555;font-size:10px;text-transform:uppercase;letter-spacing:1px;margin:10px 0">recent_activity (last 100)</div>
		<table>
		<tr><th>ts</th><th>status</th><th>client_ip</th><th>host</th><th>up</th><th>down</th><th>duration</th></tr>
		%s
		</table>
	</div>
`, html.EscapeString(name), fmtMB(up), fmtMB(down), conns, len(hosts), hostBody, actBody)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write([]byte(top + body + adminPageEnd("")))
}

// serveAdminLogs — filterable, paged connection log viewer
func serveAdminLogs(w http.ResponseWriter, r *http.Request) {
	if !adminAuthRequired(w, r) {
		return
	}
	q := r.URL.Query()
	fUser := strings.TrimSpace(q.Get("user"))
	fHost := strings.TrimSpace(q.Get("host"))
	fStatus := strings.TrimSpace(q.Get("status"))
	limit := 200
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	page := 1
	if v := q.Get("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			page = n
		}
	}
	offset := (page - 1) * limit

	where := "WHERE 1=1"
	args := []interface{}{}
	if fUser != "" {
		where += " AND username = ?"
		args = append(args, fUser)
	}
	if fHost != "" {
		where += " AND host LIKE ?"
		args = append(args, "%"+fHost+"%")
	}
	if fStatus != "" {
		where += " AND status = ?"
		args = append(args, fStatus)
	}

	var total int64
	_ = db.QueryRow("SELECT COUNT(*) FROM conn_logs "+where, args...).Scan(&total)

	query := "SELECT ts, username, client_ip, host, status, bytes_up, bytes_down, duration_ms FROM conn_logs " + where +
		" ORDER BY id DESC LIMIT ? OFFSET ?"
	argsQ := append(append([]interface{}{}, args...), limit, offset)

	rows, err := db.Query(query, argsQ...)
	if err != nil {
		http.Error(w, "query error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type rw struct{ Ts, User, IP, Host, Status string; Up, Down, Dur string }
	var list []rw
	for rows.Next() {
		var ts, u, ip, h, st string
		var up, dn, dur int64
		if rows.Scan(&ts, &u, &ip, &h, &st, &up, &dn, &dur) == nil {
			list = append(list, rw{ts, u, ip, h, st, fmtMB(up), fmtMB(dn), fmtDur(dur)})
		}
	}

	// Build user select options
	opts := "<option value=\"\">— ทุกคน —</option>"
	users := make([]string, 0, len(proxyUsers))
	for u := range proxyUsers {
		users = append(users, u)
	}
	sort.Strings(users)
	for _, u := range users {
		sel := ""
		if u == fUser {
			sel = "selected"
		}
		opts += fmt.Sprintf(`<option value="%s" %s>%s</option>`, html.EscapeString(u), sel, html.EscapeString(u))
	}

	bodyRows := ""
	for _, it := range list {
		cls := "ok"
		if it.Status == "dial_fail" || it.Status == "ad_block" {
			cls = "err"
		} else if it.Status == "http" {
			cls = "warn"
		}
		bodyRows += fmt.Sprintf(`<tr><td class="dim">%s</td><td><a class="u" href="/admin/user?name=%s">%s</a></td><td>%s</td><td><b>%s</b></td><td class="%s">%s</td><td class="num">%s</td><td class="num">%s</td><td class="dim">%s</td></tr>`,
			html.EscapeString(it.Ts), url.QueryEscape(it.User), html.EscapeString(it.User),
			it.IP, html.EscapeString(it.Host), cls, html.EscapeString(it.Status),
			it.Up, it.Down, it.Dur)
	}
	if len(list) == 0 {
		bodyRows = `<tr><td colspan="8" class="dim">ไม่มี log ตรงตามเงื่อนไข</td></tr>`
	}

	pages := (int(total) + limit - 1) / limit
	if pages < 1 {
		pages = 1
	}
	if page > pages {
		page = pages
	}
	mkLink := func(p int) string {
		u := "/admin/logs?page=" + strconv.Itoa(p) + "&limit=" + strconv.Itoa(limit)
		if fUser != "" {
			u += "&user=" + url.QueryEscape(fUser)
		}
		if fHost != "" {
			u += "&host=" + url.QueryEscape(fHost)
		}
		if fStatus != "" {
			u += "&status=" + url.QueryEscape(fStatus)
		}
		return u
	}
	pager := fmt.Sprintf(`<div class="pager">
		<span class="dim">%d rows / page %d of %d</span>
		<div class="nav" style="margin:0">%s%s</div>
	</div>`,
		total, page, pages,
		pgLink(page > 1, mkLink(page-1), "prev"),
		pgLink(page < pages, mkLink(page+1), "next"))

	top := adminPageTop("access_logs // audit_trail", r.URL.Path)
	body := fmt.Sprintf(`
	<div class="filters">
		<form method="get" action="/admin/logs">
			<div><label>user</label><select name="user">%s</select></div>
			<div><label>host (contains)</label><input type="text" name="host" value="%s"></div>
			<div><label>status</label>
				<select name="status">
					<option value="">— ทั้งหมด —</option>
					%s
				</select>
			</div>
			<div><label>per_page</label>
				<select name="limit">
					%s
				</select>
			</div>
			<div><button type="submit" class="btn">ค้นหา</button></div>
		</form>
	</div>
	%s
	<table>
	<tr><th>ts</th><th>user</th><th>client_ip</th><th>host</th><th>status</th><th>up</th><th>down</th><th>duration</th></tr>
	%s
	</table>
	%s
`, opts, html.EscapeString(fHost),
		statusOpts(fStatus), limitOpts(limit),
		pager, bodyRows, pager)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write([]byte(top + body + adminPageEnd("")))
}

func pgLink(show bool, href, label string) string {
	if !show {
		return `<a class="dim" style="color:#444;text-decoration:none">` + label + `</a>`
	}
	return fmt.Sprintf(`<a href="%s">%s</a>`, href, label)
}

func statusOpts(cur string) string {
	opts := ""
	for _, s := range []string{"ok", "http", "dial_fail", "ad_block", "proxy_off", "suspended", "quota"} {
		sel := ""
		if s == cur {
			sel = "selected"
		}
		opts += fmt.Sprintf(`<option value="%s" %s>%s</option>`, s, sel, s)
	}
	return opts
}

func limitOpts(cur int) string {
	opts := ""
	for _, n := range []int{50, 100, 200, 500, 1000} {
		sel := ""
		if n == cur {
			sel = "selected"
		}
		opts += fmt.Sprintf(`<option value="%d" %s>%d</option>`, n, sel, n)
	}
	return opts
}

// serveAdminAudit — record of admin actions
func serveAdminAudit(w http.ResponseWriter, r *http.Request) {
	if !adminAuthRequired(w, r) {
		return
	}
	rows, err := db.Query("SELECT ts, admin_user, action, target, detail FROM admin_logs ORDER BY id DESC LIMIT 300")
	if err != nil {
		http.Error(w, "query error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type rowT struct{ Ts, Admin, Action, Target, Detail string }
	var list []rowT
	for rows.Next() {
		var ts, au, ac, tg, det string
		if rows.Scan(&ts, &au, &ac, &tg, &det) == nil {
			list = append(list, rowT{ts, au, ac, tg, det})
		}
	}
	bodyRows := ""
	for _, it := range list {
		acCls := "ok"
		switch it.Action {
		case "delete", "suspend", "quota":
			acCls = "err"
		case "unsuspend":
			acCls = "warn"
		}
		bodyRows += fmt.Sprintf(`<tr><td class="dim">%s</td><td class="num">%s</td><td class="%s">%s</td><td><b>%s</b></td><td class="dim">%s</td></tr>`,
			html.EscapeString(it.Ts), html.EscapeString(it.Admin), acCls, html.EscapeString(it.Action),
			html.EscapeString(it.Target), html.EscapeString(it.Detail))
	}
	if len(list) == 0 {
		bodyRows = `<tr><td colspan="5" class="dim">ยังไม่มีประวัติ admin action</td></tr>`
	}

	top := adminPageTop("admin_audit // trail", r.URL.Path)
	body := fmt.Sprintf(`
	<table>
	<tr><th>ts</th><th>admin</th><th>action</th><th>target</th><th>detail</th></tr>
	%s
	</table>
`, bodyRows)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write([]byte(top + body + adminPageEnd("")))
}

func handleAdminAdd(w http.ResponseWriter, r *http.Request) {
	if !adminAuthRequired(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin", http.StatusFound)
		return
	}
	user := strings.TrimSpace(r.FormValue("user"))
	pass := strings.TrimSpace(r.FormValue("pass"))
	quotaGB, _ := strconv.ParseFloat(strings.TrimSpace(r.FormValue("gbytes")), 64)
	msg := "กรอกข้อมูลไม่ครบ"
	if user != "" && pass != "" && !strings.Contains(user, ":") && !strings.Contains(user, ",") && !strings.Contains(pass, ":") && !strings.Contains(pass, ",") {
		proxyUsers[user] = pass
		if quotaGB > 0 {
			setUserQuota(user, int64(quotaGB*1073741824))
		}
		go func() {
			_, err := db.Exec("INSERT OR REPLACE INTO proxy_users (username, password, created_at) VALUES (?, ?, DATETIME('now'))", user, pass)
			if err != nil {
				log.Printf("%s[ADMIN]%s failed to persist user %s: %v", colorRed, colorReset, user, err)
			}
		}()
		recordAdminLog(adminUser, "add", user, "created user")
		log.Printf("%s[ADMIN]%s added user %q", colorGreen, colorReset, user)
		msg = "เพิ่มผู้ใช้ '" + user + "' เรียบร้อย"
	}
	http.Redirect(w, r, "/admin?msg="+url.QueryEscape(msg), http.StatusFound)
}

func handleAdminDelete(w http.ResponseWriter, r *http.Request) {
	if !adminAuthRequired(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin", http.StatusFound)
		return
	}
	user := strings.TrimSpace(r.FormValue("user"))
	if user == "" {
		http.Redirect(w, r, "/admin?msg="+url.QueryEscape("ไม่พบ user"), http.StatusFound)
		return
	}
	if user == adminUser {
		http.Redirect(w, r, "/admin?msg="+url.QueryEscape("ลบ admin เองไม่ได้"), http.StatusFound)
		return
	}
	delete(proxyUsers, user)
	userStats.Delete(user)
	userSettings.Delete(user)
	userQuotaUsed.Delete(user)
	userHosts.Range(func(k, v interface{}) bool {
		if parts := strings.SplitN(k.(string), "\x00", 2); len(parts) == 2 && parts[0] == user {
			userHosts.Delete(k)
		}
		return true
	})
	go func() {
		_, _ = db.Exec("DELETE FROM proxy_users WHERE username = ?", user)
		_, _ = db.Exec("DELETE FROM user_settings WHERE username = ?", user)
		_, _ = db.Exec("DELETE FROM user_hosts WHERE username = ?", user) // conn_logs kept for audit trail
	}()
	recordAdminLog(adminUser, "delete", user, "removed user account")
	log.Printf("%s[ADMIN]%s deleted user %q", colorYellow, colorReset, user)
	http.Redirect(w, r, "/admin?msg="+url.QueryEscape("ลบ user '"+user+"' แล้ว"), http.StatusFound)
}

// setUserQuota updates the in-memory setting and persists to SQLite
func setUserQuota(user string, qb int64) {
	old := userSetting{proxyEnabled: -1, adblockEnabled: -1}
	if v, ok := userSettings.Load(user); ok {
		old = *v.(*userSetting)
	}
	userSettings.Store(user, &userSetting{quotaBytes: qb, suspended: old.suspended, proxyEnabled: old.proxyEnabled, adblockEnabled: old.adblockEnabled, updatedAt: time.Now()})
	_, _ = db.Exec("INSERT INTO user_settings (username, quota_bytes, suspended, proxy_enabled, adblock_enabled, updated_at) VALUES (?, ?, 0, ?, ?, DATETIME('now')) ON CONFLICT(username) DO UPDATE SET quota_bytes=excluded.quota_bytes, updated_at=excluded.updated_at", user, qb, old.proxyEnabled, old.adblockEnabled)
}

func handleAdminQuota(w http.ResponseWriter, r *http.Request) {
	if !adminAuthRequired(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin", http.StatusFound)
		return
	}
	user := strings.TrimSpace(r.FormValue("user"))
	gb, err := strconv.ParseFloat(strings.TrimSpace(r.FormValue("gbytes")), 64)
	if user == "" || err != nil || gb < 0 {
		http.Redirect(w, r, "/admin?msg="+url.QueryEscape("ค่า quota ไม่ถูกต้อง"), http.StatusFound)
		return
	}
	if gb > 0 {
		setUserQuota(user, int64(gb*1073741824))
		// Lift any quota-induced block automatically once the quota changes
		if v, ok := userSettings.Load(user); ok {
			st := v.(*userSetting)
			if !st.suspended && st.quotaBytes > 0 && quotaUsedOf(user) > st.quotaBytes {
				recordAdminLog(adminUser, "quota", user, "set quota to "+fmtSize(st.quotaBytes)+" (unblocked by quota reset)")
			}
		}
		recordAdminLog(adminUser, "quota", user, "set quota to "+fmtSize(int64(gb*1073741824)))
		log.Printf("%s[ADMIN]%s quota for %q → %s", colorGreen, colorReset, user, fmtSize(int64(gb*1073741824)))
		http.Redirect(w, r, "/admin?msg="+url.QueryEscape("ตั้ง quota ของ '"+user+"' เรียบร้อย ("+fmtSize(int64(gb*1073741824))+")"), http.StatusFound)
	} else {
		setUserQuota(user, 0)
		recordAdminLog(adminUser, "quota", user, "cleared quota (unlimited)")
		log.Printf("%s[ADMIN]%s cleared quota for %q", colorYellow, colorReset, user)
		http.Redirect(w, r, "/admin?msg="+url.QueryEscape("ล้าง quota ของ '"+user+"' แล้ว (ไม่จำกัด)"), http.StatusFound)
	}
}

func handleAdminSuspend(w http.ResponseWriter, r *http.Request) {
	if !adminAuthRequired(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin", http.StatusFound)
		return
	}
	user := strings.TrimSpace(r.FormValue("user"))
	if user == adminUser {
		http.Redirect(w, r, "/admin?msg="+url.QueryEscape("ระงับ admin เองไม่ได้"), http.StatusFound)
		return
	}
	action := r.FormValue("action")
	suspend := action == "suspend"
	old := userSetting{proxyEnabled: -1, adblockEnabled: -1}
	if v, ok := userSettings.Load(user); ok {
		old = *v.(*userSetting)
	}
	userSettings.Store(user, &userSetting{quotaBytes: old.quotaBytes, suspended: suspend, proxyEnabled: old.proxyEnabled, adblockEnabled: old.adblockEnabled, updatedAt: time.Now()})
	sus := 0
	if suspend {
		sus = 1
	}
	_, _ = db.Exec("INSERT INTO user_settings (username, quota_bytes, suspended, proxy_enabled, adblock_enabled, updated_at) VALUES (?, ?, ?, ?, ?, DATETIME('now')) ON CONFLICT(username) DO UPDATE SET suspended=excluded.suspended, updated_at=excluded.updated_at", user, old.quotaBytes, sus, old.proxyEnabled, old.adblockEnabled)
	if suspend {
		recordAdminLog(adminUser, "suspend", user, "account suspended")
		log.Printf("%s[ADMIN]%s suspended user %q", colorYellow, colorReset, user)
		http.Redirect(w, r, "/admin?msg="+url.QueryEscape("ระงับบัญชี '"+user+"' แล้ว"), http.StatusFound)
	} else {
		recordAdminLog(adminUser, "unsuspend", user, "account re-enabled")
		log.Printf("%s[ADMIN]%s unsuspended user %q", colorGreen, colorReset, user)
		http.Redirect(w, r, "/admin?msg="+url.QueryEscape("ปลดระงับ '"+user+"' แล้ว"), http.StatusFound)
	}
}

func handleAdminBlocklist(w http.ResponseWriter, r *http.Request) {
	if !adminAuthRequired(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin", http.StatusFound)
		return
	}
	before := atomic.LoadInt64(&adBlockCount)
	start := time.Now()
	if err := reloadAdBlock(); err != nil {
		recordAdminLog(adminUser, "blocklist", "-", "reload FAILED: "+err.Error())
		log.Printf("%s[ADMIN]%s blocklist reload failed: %v", colorRed, colorReset, err)
		http.Redirect(w, r, "/admin?msg="+url.QueryEscape("โหลด blocklist ไม่สำเร็จ: "+err.Error()), http.StatusFound)
		return
	}
	after := atomic.LoadInt64(&adBlockCount)
	recordAdminLog(adminUser, "blocklist", "-", fmt.Sprintf("reloaded (%d → %d domains, %s)", before, after, time.Since(start).Round(time.Millisecond)))
	log.Printf("%s[ADMIN]%s blocklist reloaded: %d → %d domains", colorGreen, colorReset, before, after)
	http.Redirect(w, r, "/admin?msg="+url.QueryEscape(fmt.Sprintf("โหลด blocklist แล้ว (%d domains)", after)), http.StatusFound)
}

// settingsUser returns the logged-in account for /settings. Accepts the
// proxy-account credentials from either header (browsers send "Authorization",
// proxy clients send "Proxy-Authorization") or the admin account.
func settingsUser(r *http.Request) string {
	check := func(hdr string) string {
		auth := r.Header.Get(hdr)
		if !strings.HasPrefix(auth, "Basic ") {
			return ""
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
		if err != nil {
			return ""
		}
		parts := strings.SplitN(string(raw), ":", 2)
		if len(parts) != 2 {
			return ""
		}
		if p, ok := proxyUsers[parts[0]]; ok && p == parts[1] {
			return parts[0]
		}
		if parts[0] == adminUser && parts[1] == adminPass {
			return parts[0]
		}
		return ""
	}
	if u := check("Authorization"); u != "" {
		return u
	}
	return check("Proxy-Authorization")
}

func validProxyUser(r *http.Request) string {
	auth := r.Header.Get("Proxy-Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
	if err != nil {
		return ""
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return ""
	}
	if p, ok := proxyUsers[parts[0]]; ok && p == parts[1] {
		return parts[0]
	}
	return ""
}

func settingsPage(u string, msg string) string {
	pe, ae := -1, -1
	if v, ok := userSettings.Load(u); ok {
		pe = v.(*userSetting).proxyEnabled
		ae = v.(*userSetting).adblockEnabled
	}
	peEff := proxyEnabledFor(u)
	aeEff := adblockEnabledFor(u)
	peTxt, aeTxt := flagTxt(pe), flagTxt(ae)
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Settings — NetNinja</title>
<style>
body{background:#0a0a0a;color:#ccc;font:13px/1.6 'Courier New',monospace;margin:0;display:flex;align-items:center;justify-content:center;min-height:100vh}
.w{max-width:430px;width:92%%;padding:30px;background:#111;border:1px solid #222;border-radius:8px;box-shadow:0 10px 30px rgba(0,0,0,.5)}
h1{color:#fff;font-size:20px;margin:0 0 4px;font-weight:normal}
h1 span{color:#0a0;margin-right:8px}
.sub{color:#555;font-size:11px;margin-bottom:18px}
.row{background:#151515;border:1px solid #232323;border-radius:6px;padding:14px;margin-bottom:10px}
.row .t{color:#fff;font-size:13px;margin-bottom:2px}
.row .d{color:#666;font-size:11px;margin-bottom:10px}
.tag{display:inline-block;padding:1px 8px;border-radius:3px;font-size:11px;margin-left:6px}
.tag.on{background:#040;color:#0f0;border:1px solid #0a0}
.tag.off{background:#300;color:#f77;border:1px solid #a22}
.tag.inh{background:#222;color:#999;border:1px solid #333}
.row form{display:inline}
button{background:#0d0d0d;border:1px solid #2a2a2a;color:#eee;padding:6px 12px;border-radius:3px;font:inherit;cursor:pointer}
button:hover{border-color:#0a0}
.btn-small{opacity:.6;font-size:11px;padding:5px 8px}
.msg{background:#050;border:1px solid #0a0;color:#9f9;padding:8px 12px;border-radius:4px;margin-bottom:14px}
.glob{background:#101010;border:1px solid #2a2a2a;border-radius:6px;padding:12px 14px;margin-bottom:16px;font-size:12px}
.glob b{color:#fff}
a{color:#7af;text-decoration:none}
</style>
</head>
<body>
<div class="w">
	<h1><span>●</span> settings</h1>
	<div class="sub">user: %s</div>
	%s
	<div class="glob">global · proxy=<b>%s</b> · ads-block=<b>%s</b></div>
	<div class="row">
		<div class="t">Proxy ใช้งานได้ <span class="tag %s">%s</span> → <b>%s</b></div>
		<div class="d">%s</div>
		<form method="post" action="/settings"><input type="hidden" name="user" value="%s"><input type="hidden" name="flag" value="proxy_enabled"><button type="submit">สลับ → %s</button></form>
		<form method="post" action="/settings"><input type="hidden" name="user" value="%s"><input type="hidden" name="flag" value="proxy_enabled"><input type="hidden" name="value" value="-1"><button type="submit" class="btn-small">reset inherit</button></form>
	</div>
	<div class="row">
		<div class="t">Ads block <span class="tag %s">%s</span> → <b>%s</b></div>
		<div class="d">%s</div>
		<form method="post" action="/settings"><input type="hidden" name="user" value="%s"><input type="hidden" name="flag" value="adblock_enabled"><button type="submit">สลับ → %s</button></form>
		<form method="post" action="/settings"><input type="hidden" name="user" value="%s"><input type="hidden" name="flag" value="adblock_enabled"><input type="hidden" name="value" value="-1"><button type="submit" class="btn-small">reset inherit</button></form>
	</div>
	<div style="text-align:center"><a href="/">← dashboard</a></div>
</div>
</body>
</html>`,
		html.EscapeString(u), msg,
		flagTxt(boolInt(atomic.LoadInt64(&globalProxyEnabled) == 1)), flagTxt(boolInt(atomic.LoadInt64(&globalAdblockEnabled) == 1)),
		flagCls(pe), peTxt, flagTxt(boolInt(peEff)), proxyHelp(peEff),
		html.EscapeString(u), toggleLbl(peEff, "proxy"),
		html.EscapeString(u),
		flagCls(ae), aeTxt, flagTxt(boolInt(aeEff)), adHelp(aeEff),
		html.EscapeString(u), toggleLbl(aeEff, "adblock"),
		html.EscapeString(u))
}

// toggleLbl names the action the "สลับ" button will perform.
func toggleLbl(effOn bool, which string) string {
	if which == "proxy" {
		if effOn {
			return "ปิด (ต่อตรง)"
		}
		return "เปิด (ใช้ proxy)"
	}
	if effOn {
		return "ปิด ads block"
	}
	return "เปิด ads block"
}

func flagTxt(v int) string {
	switch v {
	case 0:
		return "off"
	case 1:
		return "on"
	default:
		return "inherit"
	}
}

func checked(on bool) string {
	if on {
		return "checked"
	}
	return ""
}

func flagCls(v int) string {
	if v == 1 {
		return "on"
	}
	if v == 0 {
		return "off"
	}
	return "inh"
}

func nextFlagVal(v int) int {
	if v == 0 {
		return -1
	}
	if v == 1 {
		return 0
	}
	return 1
}

func proxyHelp(effOn bool) string {
	if effOn {
		return "Traffic ผ่าน proxy นี้ตามปกติ"
	}
	return "Proxy ถูกปิด — อุปกรณ์จะต่อตรงไปยังปลายทางเลย"
}

func adHelp(effOn bool) string {
	if effOn {
		return "ปฏิเสธ host โฆษณา/tracking (list ที่โหลดไว้)"
	}
	return "ปล่อยโฆษณาผ่าน ไม่บล็อก"
}

func serveSettings(w http.ResponseWriter, r *http.Request) {
	u := settingsUser(r)
	if u == "" {
		w.Header().Set("Proxy-Authenticate", `Basic realm="NetNinja"`)
		w.Header().Set("WWW-Authenticate", `Basic realm="NetNinja Settings"`)
		http.Error(w, "Authentication Required — use your proxy user/password", http.StatusUnauthorized)
		return
	}
	msg := ""
	if r.Method == http.MethodPost {
		target := strings.TrimSpace(r.FormValue("user"))
		flag := r.FormValue("flag")
		if target != u {
			msg = `<div class="msg" style="background:#300;border-color:#a22;color:#f99">แก้ได้เฉพาะบัญชีตัวเอง</div>`
		} else {
			pe, ae := -1, -1
			if v, ok := userSettings.Load(u); ok {
				pe = v.(*userSetting).proxyEnabled
				ae = v.(*userSetting).adblockEnabled
			}
			// Explicit value given (inherit link) or toggle the effective state?
			if val := strings.TrimSpace(r.FormValue("value")); val != "" {
				if n, err := strconv.Atoi(val); err == nil && n >= -1 && n <= 1 {
					if flag == "proxy_enabled" {
						pe = n
					} else if flag == "adblock_enabled" {
						ae = n
					}
				}
			} else {
				switch flag {
				case "proxy_enabled":
					pe = boolInt(!proxyEnabledFor(u))
				case "adblock_enabled":
					ae = boolInt(!adblockEnabledFor(u))
				}
			}
			saveUserSetting(u, pe, ae)
			recordAdminLog(u, "settings", u, flag+" → "+flagTxt(pe)+"/"+flagTxt(ae))
			msg = `<div class="msg">บันทึกแล้ว</div>`
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write([]byte(settingsPage(u, msg)))
}

func handleAdminSettings(w http.ResponseWriter, r *http.Request) {
	if !adminAuthRequired(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin", http.StatusFound)
		return
	}
	oldP, oldA := atomic.LoadInt64(&globalProxyEnabled), atomic.LoadInt64(&globalAdblockEnabled)
	setAppSetting("proxy_enabled", r.FormValue("proxy") != "on")
	setAppSetting("adblock_enabled", r.FormValue("adblock") != "on")
	newP, newA := atomic.LoadInt64(&globalProxyEnabled), atomic.LoadInt64(&globalAdblockEnabled)
	recordAdminLog(adminUser, "settings", "global", fmt.Sprintf("proxy %d→%d, adblock %d→%d", oldP, newP, oldA, newA))
	log.Printf("%s[ADMIN]%s global settings: proxy=%d adblock=%d", colorGreen, colorReset, newP, newA)
	http.Redirect(w, r, "/admin?msg="+url.QueryEscape(fmt.Sprintf("บันทึก global: proxy=%s adblock=%s", flagTxt(int(newP)), flagTxt(int(newA)))), http.StatusFound)
}

func handleAdminUserFlag(w http.ResponseWriter, r *http.Request) {
	if !adminAuthRequired(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin", http.StatusFound)
		return
	}
	user := strings.TrimSpace(r.FormValue("user"))
	flag := r.FormValue("flag")
	if user == "" {
		http.Redirect(w, r, "/admin?msg="+url.QueryEscape("ไม่พบ user"), http.StatusFound)
		return
	}
	next, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("value")))
	if next < -1 || next > 1 {
		http.Redirect(w, r, "/admin?msg="+url.QueryEscape("ค่าไม่ถูกต้อง"), http.StatusFound)
		return
	}
	pe, ae := -1, -1
	if v, ok := userSettings.Load(user); ok {
		pe = v.(*userSetting).proxyEnabled
		ae = v.(*userSetting).adblockEnabled
	}
	switch flag {
	case "proxy_enabled":
		pe = next
	case "adblock_enabled":
		ae = next
	default:
		http.Redirect(w, r, "/admin?msg="+url.QueryEscape("flag ไม่รู้จัก"), http.StatusFound)
		return
	}
	saveUserSetting(user, pe, ae)
	recordAdminLog(adminUser, "settings", user, fmt.Sprintf("%s=%s", flag, flagTxt(next)))
	log.Printf("%s[ADMIN]%s set %s=%s for %q", colorGreen, colorReset, flag, flagTxt(next), user)
	http.Redirect(w, r, "/admin?msg="+url.QueryEscape(fmt.Sprintf("ตั้งค่า '%s' %s", user, flagTxt(next))), http.StatusFound)
}
