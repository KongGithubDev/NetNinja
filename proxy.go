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
	"os/exec"
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

var proxyAuthEnabled = true

func authRequired(w http.ResponseWriter, r *http.Request) bool {
	if !proxyAuthEnabled || len(proxyUsers) == 0 {
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

	// cache results (30 min)
	exp := time.Now().Add(30 * time.Minute)
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
	var bestIP string
	for i := 0; i < 2; i++ {
		r := <-ch
		if r.err == nil && r.ip != "" {
			if bestIP == "" {
				bestIP = r.ip
			}
		} else if r.err != nil {
			lastErr = r.err
		}
	}
	if bestIP != "" {
		exp := time.Now().Add(30 * time.Minute)
		dnsCache.Store(host, dnsEntry{ip: bestIP, expiry: exp})
		return bestIP, nil
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
	var key string
	if user == clientIP {
		// No-auth mode: user IS the IP, show just the UA
		if ua != "" {
			key = ua
		} else {
			key = clientIP
		}
	} else {
		key = clientIP
		if ua != "" {
			key = clientIP + " | " + ua
		}
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
		// Stagger start to avoid tick alignment with userHostsFlusher
		time.Sleep(3 * time.Second)
		ticker := time.NewTicker(5 * time.Second)
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
		ticker := time.NewTicker(15 * time.Second)
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
func (c *activityConn) Last() time.Time { return time.Unix(0, c.last.Load()) }
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

// windowProbeConn periodically pauses reads to force the client's TCP stack
// to send WINDOW PROBES — real data segments (1-byte retransmissions) with
// normal sequence numbers. Unlike keepalive ACKs (seq=-1) which CGNAT
// ignores, window probes look like genuine data and refresh NAT mappings.
//
// Flow when paused:
//  1. proxy stops reading → TCP receive buffer fills → window → 0
//  2. client TCP stack sees window=0 → starts probe timer (RTO ~200ms)
//  3. probe timer fires → retransmits last byte (1 byte data, normal seq)
//  4. CGNAT sees data segment → keeps mapping alive
type windowProbeConn struct {
	net.Conn
	paused int32 // atomic: 1 = paused
	done   chan struct{}
}

func newWindowProbeConn(conn net.Conn, interval, pauseFor time.Duration) *windowProbeConn {
	wpc := &windowProbeConn{
		Conn: conn,
		done: make(chan struct{}),
	}
	go wpc.loop(interval, pauseFor)
	return wpc
}

func (wpc *windowProbeConn) loop(interval, pauseFor time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-wpc.done:
			return
		case <-ticker.C:
			atomic.StoreInt32(&wpc.paused, 1)
			time.AfterFunc(pauseFor, func() {
				atomic.StoreInt32(&wpc.paused, 0)
			})
		}
	}
}

func (wpc *windowProbeConn) Read(p []byte) (int, error) {
	for atomic.LoadInt32(&wpc.paused) == 1 {
		select {
		case <-wpc.done:
			return 0, io.ErrClosedPipe
		case <-time.After(200 * time.Millisecond):
		}
	}
	return wpc.Conn.Read(p)
}

func (wpc *windowProbeConn) Close() error {
	select {
	case <-wpc.done:
	default:
		close(wpc.done)
	}
	return wpc.Conn.Close()
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

var copyBufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 256*1024)
		return &buf
	},
}

// startMapSweeper periodically prunes stale entries from hostStats and
// userTracker sync.Maps that otherwise grow without bound (memory leak).
// Without this, after hours/days the proxy's heap grows and Range() calls
// in the WS handler become sluggish — contributing to the "dies after N
// minutes" symptom once memory pressure triggers heavy GC.
func startMapSweeper() {
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			cutoff := now.Add(-30 * time.Minute)

			// Prune hostStats: remove hosts not seen in 30 minutes
			hostStats.Range(func(k, v interface{}) bool {
				st := v.(*hostStat)
				st.mu.Lock()
				last := st.last
				st.mu.Unlock()
				if last.Before(cutoff) {
					hostStats.Delete(k)
				}
				return true
			})

			// Prune userTracker: remove IPs not seen in 30 minutes
			userTracker.Range(func(k, v interface{}) bool {
				lastSeen := v.(time.Time)
				if lastSeen.Before(cutoff) {
					userTracker.Delete(k)
				}
				return true
			})

			// Prune dnsCache: remove expired entries to prevent memory leak
			dnsCache.Range(func(k, v interface{}) bool {
				entry := v.(dnsEntry)
				if time.Now().After(entry.expiry) {
					dnsCache.Delete(k)
				}
				return true
			})
		}
	}()
}

var buildTime = "manual_build" // Auto-injected via -ldflags during build

// Custom DNS resolver — uses system resolver (systemd-resolved → Cloudflare DoT)
// Azure blocks outbound UDP 53, so Google/Cloudflare UDP DNS won't work.
// systemd-resolved is configured with Cloudflare DoT (port 853) instead.
var customResolver = &net.Resolver{
	PreferGo: false, // use system resolver (CGO/netgo)
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

// setTCPKeepAliveFD sets TCP keepalive via syscall on a hijacked connection's
// raw fd. Go's net.TCPConn.SetKeepAlive works on normal connections but may not
// persist after HTTP Hijack(). This sets SO_KEEPALIVE, TCP_KEEPIDLE, TCP_KEEPINTVL,
// and TCP_KEEPCNT directly on the socket fd via syscall.
// CRITICAL: SO_KEEPALIVE must be set FIRST, otherwise kernel ignores the other options.
// Uses Go's built-in keepalive on Windows (no TCP_KEEPIDLE syscall constant).
func setTCPKeepAliveFD(conn net.Conn, seconds int) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		setKeepAliveFallback(tc, seconds)
		return
	}
	raw.Control(func(fd uintptr) {
		setSocketKeepAlive(int(fd), seconds)
	})
	// On Windows, setSocketKeepAlive is a no-op; use Go's built-in as well
	setKeepAliveFallback(tc, seconds)
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
	if _, dup := hopProbeIn[h]; dup {
		hopProbeMu.Unlock()
		return false
	}
	ch := make(chan bool, 1)
	hopProbeIn[h] = ch
	hopProbeMu.Unlock()

	go func() {
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
	}()

	return false
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

	dial := func(address string) bool {
		d := &net.Dialer{Timeout: 2 * time.Second}
		c, err := d.DialContext(ctx, "tcp", address)
		if err != nil {
			return false
		}
		defer c.Close()
		return probeHTTPStatus(c, host)
	}

	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) == 0 {
		return dial(net.JoinHostPort(host, "443"))
	}
	tried := 0
	for _, a := range addrs {
		if tried >= 3 {
			break
		}
		if dial(net.JoinHostPort(a.IP.String(), "443")) {
			return true
		}
		tried++
	}
	return false
}

func probeHTTPStatus(c net.Conn, host string) bool {
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

// dialHop opens a connection through the shared HOP_SOCKS5 server (no-auth).
func dialHop(ctx context.Context, address string) (net.Conn, error) {
	return dialSocks5(ctx, hopSocks5, address)
}

// dialSocks5 opens a connection to address through the given SOCKS5 server.
func dialSocks5(ctx context.Context, server string, address string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	c, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, fmt.Errorf("hop dial %s: %w", server, err)
	}
	// Bound the whole SOCKS handshake so a dead/unresponsive hop fails fast
	// and we can fall back to direct instead of hanging the tunnel for ages.
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	fail := func(e error) (net.Conn, error) {
		c.Close()
		return nil, fmt.Errorf("socks5 %s: %w", server, e)
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
//
// Geo domains (GEO_DOMAINS, e.g. ome.tv) always go through the hop: random video
// chat matches peers by the IP it sees, so OmeTV only finds Thai partners when
// the hop itself exits in Thailand.
func hopDial(ctx context.Context, network, hostname, address string) (net.Conn, error) {
	// Geo-sensitive traffic — the listed site itself, and while the client is in
	// a geo session the ad slots and other third parties it loads — leaves from
	// the Thai pool, so the destination sees a Thai visitor.
	if viaThai, why := geoEgressFor(ctx, hostname, address); viaThai {
		if why == "geo" {
			// Mark the whole session Thai, so the ad slots and the other third
			// parties this page loads follow the same egress.
			noteGeoSession(geoKeyFromCtx(ctx))
		}
		c, err := dialGeoThai(ctx, address, hostname+" ("+why+")")
		if err == nil {
			if why == "geo" {
				logGeoOnce(hostname, true)
			} else {
				logGeoEgressOnce(hostname, why)
			}
			return c, nil
		}
		// A country-sensitive site must never silently fall back to this server's
		// country: with GEO_STRICT=1 the dial fails and the client retries instead
		// of matching peers in the wrong country. Ad/asset hosts that merely
		// follow a session may degrade to direct, so the page keeps working when
		// the tunnel is down.
		if why == "geo" && geoPoolStrict && geoPoolOn && geoPoolSize() > 0 {
			return nil, fmt.Errorf("no %s egress for %s: %w", geoExpectCountry(), hostname, err)
		}
		log.Printf("%s[GEO][warn]%s %s: %v — direct fallback (this server's country)", colorYellow, colorReset, hostname, err)
		if why == "geo" {
			logGeoOnce(hostname, false)
		}
		return customDialer.DialContext(ctx, network, address)
	}
	useHop := inHopDomains(hostname)
	if !useHop {
		useHop = autoClassify(hostname)
	}
	if useHop && hopSocks5 != "" {
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
	db.SetMaxOpenConns(1) // Serialize writers to avoid "database is locked"

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
// Case 2: bc2c576109ac804ca...sse.cisco-secure.com -> <resolved-ip> (Hex IP)
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
	initGeoDomains()
	initGeoSession()
	startGeoPool()
	initBandwidthControl()
	initGeoGuard()
	startGeoGuard()
	startGeoDomainRefresher()
	startGeoSessionSweeper()
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

	if v := os.Getenv("PROXY_AUTH_ENABLED"); v == "0" || v == "false" {
		proxyAuthEnabled = false
		fmt.Println("Proxy auth DISABLED (PROXY_AUTH_ENABLED=0)")
		// Clear stale user data — track by IP only
		proxyUsers = map[string]string{}
		userHosts = sync.Map{}
		userSettings = sync.Map{}
		userQuotaUsed = sync.Map{}
	}

	if proxyAuthEnabled {
		if pu := os.Getenv("PROXY_USERS"); pu != "" {
			for _, up := range strings.Split(pu, ",") {
				if idx := strings.Index(up, ":"); idx > 0 {
					proxyUsers[up[:idx]] = up[idx+1:]
				}
			}
			fmt.Printf("Proxy auth enabled for %d user(s)\n", len(proxyUsers))
		}
	} else {
		fmt.Println("Running in no-auth mode — tracking by client IP")
	}

	bindAddr := os.Getenv("BIND_ADDR")
	if bindAddr == "" {
		bindAddr = "0.0.0.0"
	}

	go startBwSampler()
	startMapSweeper()

	proxy := &http.Server{
		Handler:      guardHandler(handleRequest),
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  90 * time.Second,
		// Slowloris guard: a client that opens a socket and dribbles headers
		// must not be able to hold a connection (and a goroutine) forever.
		ReadHeaderTimeout: 20 * time.Second,
		MaxHeaderBytes:    1 << 20,
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
			tc.SetKeepAlivePeriod(10 * time.Second)
		}
	}
	return c, err
}

func isLocalIP(ip string) bool {
	localIPsMu.RLock()
	defer localIPsMu.RUnlock()
	return localIPs[ip]
}

// keepaliveHost is the keepalive hostname that gets its own log line. It is
// configured with KEEPALIVE_HOST instead of being compiled in, so a deployment's
// real domain never ships inside a public repository (empty = no special log).
var (
	keepaliveHostOnce sync.Once
	keepaliveHostVal  string
)

func keepaliveHost() string {
	keepaliveHostOnce.Do(func() {
		keepaliveHostVal = strings.ToLower(strings.TrimSpace(os.Getenv("KEEPALIVE_HOST")))
	})
	return keepaliveHostVal
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

	// Every dial downstream (the SOCKS5 egress choice included) needs to know
	// which client this is, so a geo session can follow the whole session.
	geoKey := "ip:" + trackingIP
	if u := authedUser(r); u != "" {
		geoKey = "u:" + u
	}
	r = r.WithContext(ctxWithGeoKey(r.Context(), geoKey))

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
		} else if !proxyAuthEnabled {
			trackUserDevice(clientIP, clientIP, r.Header.Get("User-Agent"))
		}
		handleConnect(w, r)
		return
	}

	path := r.URL.Path
	host := r.URL.Host

	// If the request is for this proxy itself (even if it's an absolute URL)
	isForSelf := (host == "" || isSelf(host, r.Host))

	if isForSelf {
		if path == "/proxy.pac" || path == "/wpad.dat" {
			servePAC(w, r)
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
		}
		if path == "/geo-check" {
			serveGeoCheck(w, r)
			return
		} else if path == "/geo-bench" {
			serveGeoBench(w, r)
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
	// Extract bare IP for PAC DIRECT match (browser may send host without port)
	proxyIP := proxyHost
	if h, _, err := net.SplitHostPort(proxyHost); err == nil {
		proxyIP = h
	}

	var directCond []string
	for _, d := range pacDirectDomains() {
		directCond = append(directCond, `dnsDomainIs(host, "`+d+`")`)
	}
	directList := strings.Join(directCond, " || ")

	pac := fmt.Sprintf(`function FindProxyForURL(url, host) {
    if (isPlainHostName(host) ||
        shExpMatch(host, "10.*") ||
        shExpMatch(host, "172.16.*") ||
        shExpMatch(host, "192.168.*") ||
        host == "127.0.0.1" ||
        host == "%s" ||
        host == "%s" ||
        host == "localhost") {
        return "DIRECT";
    }
    if (%s) {
        return "DIRECT";
    }
    return "PROXY %s; DIRECT";
}
`, proxyIP, proxyHost, directList, proxyHost)

	// iPadOS fetches this file itself (there is no proxy yet) and is picky about
	// the type: without application/x-ns-proxy-autoconfig Auto mode fails
	// silently, and a cached copy keeps stale rules alive after PROXY_ADDR moves.
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Write([]byte(pac))

	clientIP := getClientIP(r)
	log.Printf("%s[PAC]%s served %s to %s ua=%s",
		colorCyan, colorReset, r.URL.Path, clientIP, r.Header.Get("User-Agent"))
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

	// Debug: log all incoming HTTP requests for tracing (skip noisy static assets)
	if r.URL.Path != "/favicon.ico" && r.URL.Path != "/favicon.svg" {
		log.Printf("%s[HTTP-REQ]%s %s %s ← %s ua=%s",
			colorGreen, colorReset, r.Method, r.URL, clientIP, r.Header.Get("User-Agent"))
	}

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

	// Ad-block: refuse explicit ad/tracking hosts on plain HTTP too, unless the
	// Thai egress is carrying them (see the CONNECT path).
	if u := authedUser(r); adblockEnabledFor(u) && isAdBlockedHost(unwrappedHost) && !geoHandlesAd(r.Context(), unwrappedHost) {
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

	if u := authedUser(r); u != "" {
		trackUserDevice(u, clientIP, r.Header.Get("User-Agent"))
	} else if !proxyAuthEnabled {
		trackUserDevice(clientIP, clientIP, r.Header.Get("User-Agent"))
	}

	// Fix: iOS sometimes sends requests with empty scheme (e.g. "GET / HTTP/1.1")
	// Reconstruct from Host header
	if r.URL.Scheme == "" || r.URL.Host == "" {
		host := r.Host
		if host == "" {
			host = r.Header.Get("Host")
		}
		if host != "" && r.URL.Host == "" {
			r.URL.Host = host
		}
		if r.URL.Scheme == "" {
			r.URL.Scheme = "http"
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

		if !strings.Contains(err.Error(), "context canceled") {
			log.Printf("%s[ERR]%s %s → %s: %s", colorRed, colorReset, clientIP, r.URL.Host, err)
		}
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
		if u == "" {
			u = clientIP
		}
		pushConnLog(connLogEntry{username: u, clientIP: clientIP, host: hName, status: "http", bytesDown: n, durMs: time.Since(start).Milliseconds()})
		touchUserHost(u, hName, 0, n, 1)
	}

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
	tunnelStart := time.Now()
	tunnelUser := authedUser(r)
	trackID := tunnelUser
	if trackID == "" {
		trackID = clientIP
	}

	log.Printf("%s[TLS]%s CONNECT %s ← %s ua=%s",
		colorCyan, colorReset,
		host, clientIP, r.Header.Get("User-Agent"))

	if kh := keepaliveHost(); kh != "" && strings.Contains(strings.ToLower(host), kh) {
		log.Printf("%s[KEEPALIVE]%s %s ← %s",
			colorGreen, colorReset, host, clientIP)
	}

	atomic.AddInt64(&activeConns, 1)
	defer atomic.AddInt64(&activeConns, -1)

	// Per-IP connection cap: one runaway device must not be able to exhaust the
	// proxy's sockets and goroutines.
	releaseSlot := acquireConnSlot(clientIP)
	if releaseSlot == nil {
		atomic.AddInt64(&errCount, 1)
		log.Printf("%s[LIMIT]%s %s hit MAX_CONNS_PER_IP=%d — refusing %s", colorYellow, colorReset, clientIP, maxConnsPerIP(), host)
		pushConnLog(connLogEntry{username: trackID, clientIP: clientIP, host: host, status: "conn_limit", durMs: 0})
		http.Error(w, "Too Many Connections", http.StatusServiceUnavailable)
		return
	}
	defer releaseSlot()

	// extract hostname and port for cached DNS
	hostname := host
	port := "443"
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		hostname = host[:idx]
		port = host[idx+1:]
	}

	// Track the tunnel with a unique key. Keying by hostname alone meant two
	// concurrent tunnels to the same host clobbered each other and the first one
	// to close deleted the entry for both (the dashboard listed dead tunnels).
	tunnelKey := fmt.Sprintf("%s#%d", hostname, atomic.AddInt64(&tunnelSeq, 1))
	activeTunnels.Store(tunnelKey, time.Now())

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
		pushConnLog(connLogEntry{username: trackID, clientIP: clientIP, host: hostname, status: "proxy_off", durMs: time.Since(tunnelStart).Milliseconds()})
		// Same as ad-block: reply 200 + close to avoid iOS bypassing proxy
		hijack, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, _, err := hijack.Hijack()
		if err != nil {
			return
		}
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		conn.Close()
		return
	}

	// Ad-block: refuse tunnels to ad/tracking networks before dialing — unless the
	// Thai egress is carrying them, which is what makes the ad slot local.
	if adblockEnabledFor(tunnelUser) && isAdBlockedHost(hostname) && !geoHandlesAd(r.Context(), hostname) {
		atomic.AddInt64(&adBlocked, 1)
		log.Printf("%s[AD-BLOCK]%s refused CONNECT %s ← %s", colorRed, colorReset, hostname, clientIP)
		pushConnLog(connLogEntry{username: trackID, clientIP: clientIP, host: hostname, status: "ad_block", durMs: time.Since(tunnelStart).Milliseconds()})
		// Reply 200 then close: iOS/macOS treat CONNECT403 as "proxy broken"
		// and permanently bypass the proxy. A 200 + close is treated as a
		// normal connection reset by the remote — the app retries via proxy.
		hijack, ok := w.(http.Hijacker)
		if !ok {
			log.Printf("%s[AD-BLOCK-DBG]%s hijack not supported for %s", colorRed, colorReset, hostname)
			return
		}
		conn, _, err := hijack.Hijack()
		if err != nil {
			log.Printf("%s[AD-BLOCK-DBG]%s hijack failed for %s: %v", colorRed, colorReset, hostname, err)
			return
		}
		conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		log.Printf("%s[AD-BLOCK-DBG]%s sent fake200+close for %s ← %s", colorYellow, colorReset, hostname, clientIP)
		conn.Close()
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
		pushConnLog(connLogEntry{username: trackID, clientIP: clientIP, host: hostname, status: "dial_fail", durMs: time.Since(tunnelStart).Milliseconds()})
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

	// God-Mode: Pure native performance + KeepAlive + large buffers
	if tc, ok := clientConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(10 * time.Second)
		tc.SetReadBuffer(256 * 1024)
		tc.SetWriteBuffer(256 * 1024)
	}
	if tc, ok := destConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(10 * time.Second)
		tc.SetReadBuffer(256 * 1024)
		tc.SetWriteBuffer(256 * 1024)
	}

	// Azure LB idle timeout bypass: set TCP_KEEPIDLE via syscall on hijacked fd
	// Azure Standard LB drops idle connections after 240s. TCP keepalive ACKs
	// are not counted as "data" by Azure's SNAT. We set keepalive to 10s via
	// syscall to ensure the kernel sends probes on the raw socket fd.
	setTCPKeepAliveFD(clientConn, 10)
	setTCPKeepAliveFD(destConn, 10)

	log.Printf("%s[TLS]%s %s ↔ %s %s(tunnel established)%s",
		colorGreen, colorReset,
		clientIP, host,
		colorGray, colorReset)

	trackUserConn(trackID)

	// Window-probe wrapper: periodically pause reads for 5 s every 90 s.
	// During the pause, if the client sends data, TCP buffer fills → window
	// shrinks to 0 → client TCP stack sends WINDOW PROBES (1-byte data
	// segments with normal seq numbers). CGNAT sees real data and keeps the
	// mapping alive.  Unlike keepalive ACKs (seq=-1) which TOT CGNAT
	// ignores, window probes cannot be distinguished from normal data.
	wpConn := newWindowProbeConn(clientConn, 90*time.Second, 5*time.Second)
	clientAct := &activityConn{Conn: wpConn}
	destAct := &activityConn{Conn: destConn}

	// Bandwidth management: meter the client side of the tunnel (Read = upload,
	// Write = download) against the global and per-user buckets.
	upLim, downLim := bwForUser(trackID)
	clientPipe := &limitedConn{
		Conn: clientAct,
		up:   compactLimiters(bwGlobalUp, upLim),
		down: compactLimiters(bwGlobalDown, downLim),
	}

	errc := make(chan error, 2)
	done := make(chan struct{})
	var wg sync.WaitGroup
	var tUp, tDown int64

	// Client → dest (upload)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				atomic.AddInt64(&errCount, 1)
				log.Printf("%s[PANIC]%s tunnel %s ↔ %s: %v", colorRed, colorReset, clientIP, host, r)
				destAct.Close()
				clientAct.Close()
				errc <- fmt.Errorf("panic: %v", r)
			}
		}()
		buf := copyBufPool.Get().(*[]byte)
		defer copyBufPool.Put(buf)
		n, err := io.CopyBuffer(destAct, clientPipe, *buf)
		atomic.AddInt64(&totalBytesUp, n)
		tUp += n
		if hs != nil {
			hs.mu.Lock()
			hs.bytes += n
			hs.last = time.Now()
			hs.mu.Unlock()
		}
		if n > 0 {
			trackUserBytes(trackID, n, 0)
		}
		destAct.Close()
		errc <- err
	}()
	// dest → client (download)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				atomic.AddInt64(&errCount, 1)
				log.Printf("%s[PANIC]%s tunnel %s ↔ %s: %v", colorRed, colorReset, clientIP, host, r)
				destAct.Close()
				clientAct.Close()
				errc <- fmt.Errorf("panic: %v", r)
			}
		}()
		buf := copyBufPool.Get().(*[]byte)
		defer copyBufPool.Put(buf)
		n, err := io.CopyBuffer(clientPipe, destAct, *buf)
		atomic.AddInt64(&totalBytesDown, n)
		tDown += n
		if hs != nil {
			hs.mu.Lock()
			hs.bytes += n
			hs.last = time.Now()
			hs.mu.Unlock()
		}
		if n > 0 {
			trackUserBytes(trackID, 0, n)
		}
		clientAct.Close()
		errc <- err
	}()

	// Graceful FIN close at 3.5 min: Close connections with FIN before CGNAT
	// kills them at ~4-5 min. iOS handles FIN (graceful close) differently
	// from RST (CGNAT reset). FIN = "normal close" → iOS reconnects
	// automatically. RST = "proxy broken" → iOS caches failure.
	go func() {
		const idleTimeout = 210 * time.Second // 3.5 min — before CGNAT ~4-5 min
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				lastClient := clientAct.Last()
				lastDest := destAct.Last()
				last := lastClient
				if destDest := lastDest; destDest.After(last) {
					last = destDest
				}
				if !last.IsZero() && time.Since(last) > idleTimeout {
					log.Printf("%s[REAP]%s %s ↔ %s idle %v > %v, closing with FIN",
						colorYellow, colorReset, clientIP, host,
						time.Since(last).Round(time.Second), idleTimeout)
					// Close client first (sends FIN to iPad) — iOS sees
					// graceful close, not RST. Then close dest.
					clientConn.Close()
					time.Sleep(100 * time.Millisecond)
					destConn.Close()
					return
				}
			}
		}
	}()

	// Bandwidth history is maintained by the global sampler started once at
	// boot (startBwSampler) — NOT per tunnel — so the realtime chart always has
	// the last 60s of aggregate traffic regardless of active tunnels.

	wg.Wait()
	close(done)
	activeTunnels.Delete(tunnelKey)

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
		username:  trackID,
		clientIP:  clientIP,
		host:      hostname,
		status:    "ok",
		bytesUp:   tUp,
		bytesDown: tDown,
		durMs:     time.Since(tunnelStart).Milliseconds(),
	})
	touchUserHost(trackID, hostname, tUp, tDown, 1)
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

	// Tuning destination socket for WS: keepalive to survive CGNAT/NAT
	if tc, ok := destConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(10 * time.Second)
		tc.SetReadBuffer(256 * 1024)
		tc.SetWriteBuffer(256 * 1024)
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

	// Tuning client socket for WS: keepalive to survive CGNAT/NAT
	if tc, ok := clientConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(10 * time.Second)
		tc.SetReadBuffer(256 * 1024)
		tc.SetWriteBuffer(256 * 1024)
	}

	// Azure LB / CGNAT idle timeout bypass: syscall-level keepalive on hijacked fds
	setTCPKeepAliveFD(clientConn, 10)
	setTCPKeepAliveFD(destConn, 10)

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

	// 4. Pipe binary data with activity tracking + idle reap
	clientAct := &activityConn{Conn: clientConn}
	destAct := &activityConn{Conn: destConn}

	wsDone := make(chan struct{})
	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(destAct, clientAct)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(clientAct, destAct)
		errChan <- err
	}()

	// Idle timeout reap: close WS connections idle >4 min (beat CGNAT 5-min)
	go func() {
		const wsIdleTimeout = 4 * time.Minute
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-wsDone:
				return
			case <-ticker.C:
				lastClient := clientAct.Last()
				lastDest := destAct.Last()
				last := lastClient
				if lastDest.After(last) {
					last = lastDest
				}
				if !last.IsZero() && time.Since(last) > wsIdleTimeout {
					log.Printf("%s[WS-REAP]%s %s ↔ %s:%s idle %v > %v, closing",
						colorYellow, colorReset, clientIP, hostname, port,
						time.Since(last).Round(time.Second), wsIdleTimeout)
					clientConn.Close()
					destConn.Close()
					return
				}
			}
		}
	}()

	<-errChan
	close(wsDone)
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
		tc.SetKeepAlivePeriod(10 * time.Second)
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
			seenTunnels := map[string]bool{}
			activeTunnels.Range(func(k, v interface{}) bool {
				h := k.(string)
				if i := strings.IndexByte(h, '#'); i >= 0 {
					h = h[:i]
				}
				seenTunnels[h] = true
				return true
			})
			for h := range seenTunnels {
				tunnels = append(tunnels, h)
			}
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
	extraHeaders := ""
	addCard := ""
	if proxyAuthEnabled {
		extraHeaders = `<th>quota</th><th></th>`
		addCard = `<div class="add-card">
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
	</div>`
	}
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
		if !proxyAuthEnabled {
			quotaCell = ""
		} else if s.quotaBytes > 0 {
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
		quotaForm := ""
		proxyBtn := ""
		adBtn := ""
		deleteBtn := ""
		if proxyAuthEnabled && s.name != adminUser {
			if s.suspended {
				suspendBtn = fmt.Sprintf(`<form method="post" action="/admin/suspend" style="display:inline"><input type="hidden" name="user" value="%s"><input type="hidden" name="action" value="unsuspend"><button type="submit" class="btn-ok">ปลดระงับ</button></form>`, html.EscapeString(s.name))
			} else {
				suspendBtn = fmt.Sprintf(`<form method="post" action="/admin/suspend" style="display:inline"><input type="hidden" name="user" value="%s"><input type="hidden" name="action" value="suspend"><button type="submit" class="btn-sus" onclick="return confirm('ระงับบัญชี &#39;%s&#39;?')">ระงับ</button></form>`, html.EscapeString(s.name), html.EscapeString(s.name))
			}
			quotaForm = fmt.Sprintf(`<form method="post" action="/admin/quota" style="display:inline"><input type="hidden" name="user" value="%s"><input type="number" step="0.001" min="0" name="gbytes" value="%s" style="width:70px;background:#0d0d0d;border:1px solid #2a2a2a;color:#eee;padding:4px;border-radius:3px;font:inherit"><button type="submit" class="btn">set (GB)</button></form>`, html.EscapeString(s.name), strconv.FormatFloat(float64(s.quotaBytes)/1073741824, 'f', 3, 64))
			pe, ae := -1, -1
			if v, ok := userSettings.Load(s.name); ok {
				pe = v.(*userSetting).proxyEnabled
				ae = v.(*userSetting).adblockEnabled
			}
			proxyBtn = fmt.Sprintf(`<form method="post" action="/admin/userflag" style="display:inline"><input type="hidden" name="user" value="%s"><input type="hidden" name="flag" value="proxy_enabled"><input type="hidden" name="value" value="%d"><button type="submit" class="btn" title="off = ปิด proxy ให้ user นี้ต่อตรงเลย">proxy:%s</button></form>`, html.EscapeString(s.name), nextFlagVal(pe), flagTxt(pe))
			adBtn = fmt.Sprintf(`<form method="post" action="/admin/userflag" style="display:inline"><input type="hidden" name="user" value="%s"><input type="hidden" name="flag" value="adblock_enabled"><input type="hidden" name="value" value="%d"><button type="submit" class="btn" title="off = ปล่อยโฆษณาผ่าน (ไม่บล็อก)">ads:%s</button></form>`, html.EscapeString(s.name), nextFlagVal(ae), flagTxt(ae))
			deleteBtn = fmt.Sprintf(`<form method="post" action="/admin/delete" style="display:inline" onsubmit="return confirm('ลบ user &#39;%s&#39;?' )"><input type="hidden" name="user" value="%s"><button type="submit" class="btn-del">ลบ</button></form>`, html.EscapeString(s.name), html.EscapeString(s.name))
		}
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
			<td>%s %s %s %s %s</td>
		</tr>`,
			url.QueryEscape(s.name), html.EscapeString(s.name), activeNow,
			acCls, ac,
			fmtMB(s.bytesUp), fmtMB(s.bytesDown), s.conns,
			first, last,
			s.deviceCount, devList,
			quotaCell,
			suspendBtn, proxyBtn, adBtn, quotaForm, deleteBtn)
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
	<tr><th>user</th><th>active</th><th>bytes_up</th><th>bytes_down</th><th>conns</th><th>first_seen</th><th>last_seen</th><th>devices</th>%s</tr>
	%s
	</table>

	%s
`, len(snaps), fmtMB(totalUp), fmtMB(totalDown), totalConns, totalDev, logRows,
		adminCharts(snaps), blCard, gblCard, msgHTML, extraHeaders, userRows, addCard)

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

// ===========================================================================
// Bandwidth management — token-bucket pacing (global + per user)
//
//   BW_GLOBAL_MBPS=0   aggregate ceiling for the whole proxy (0 = unlimited)
//   BW_USER_MBPS=0     per-user ceiling, keyed by auth user (or client IP in
//                      no-auth mode) (0 = unlimited)
//   BW_BURST_KB=256    burst allowance per bucket
//
// Bytes are metered on the client side of each tunnel: Read == upload
// (client → target), Write == download (target → client). Over-budget traffic
// sleeps just long enough to stay on pace — no drops, no bufferbloat.
// ===========================================================================

const bwChunk = 32 * 1024

type bwLimiter struct {
	mu     sync.Mutex
	rate   float64 // bytes per second, <= 0 = unlimited
	burst  float64
	tokens float64
	last   time.Time
}

func newBwLimiter(bytesPerSec int64, burstBytes int64) *bwLimiter {
	if bytesPerSec <= 0 {
		return nil
	}
	if burstBytes < 16*1024 {
		burstBytes = 16 * 1024
	}
	return &bwLimiter{rate: float64(bytesPerSec), burst: float64(burstBytes), tokens: float64(burstBytes), last: time.Now()}
}

// take reserves n bytes and returns how long the caller must wait to stay on pace.
func (l *bwLimiter) take(n int) time.Duration {
	if l == nil || l.rate <= 0 || n <= 0 {
		return 0
	}
	l.mu.Lock()
	now := time.Now()
	l.tokens += now.Sub(l.last).Seconds() * l.rate
	l.last = now
	if l.tokens > l.burst {
		l.tokens = l.burst
	}
	l.tokens -= float64(n)
	var wait time.Duration
	if l.tokens < 0 {
		wait = time.Duration(-l.tokens / l.rate * float64(time.Second))
		l.tokens = 0
	}
	l.mu.Unlock()
	return wait
}

func compactLimiters(ls ...*bwLimiter) []*bwLimiter {
	out := make([]*bwLimiter, 0, len(ls))
	for _, l := range ls {
		if l != nil {
			out = append(out, l)
		}
	}
	return out
}

func takeAll(ls []*bwLimiter, n int) time.Duration {
	var wait time.Duration
	for _, l := range ls {
		if d := l.take(n); d > wait {
			wait = d
		}
	}
	return wait
}

// limitedConn meters both directions of a tunnel: Read is upload (client →
// target), Write is download (target → client).
type limitedConn struct {
	net.Conn
	up   []*bwLimiter
	down []*bwLimiter
}

func (c *limitedConn) Read(p []byte) (int, error) {
	if len(p) > bwChunk {
		p = p[:bwChunk]
	}
	n, err := c.Conn.Read(p)
	if n > 0 {
		if d := takeAll(c.up, n); d > 0 {
			time.Sleep(d)
		}
	}
	return n, err
}

func (c *limitedConn) Write(p []byte) (int, error) {
	written := 0
	for written < len(p) {
		end := written + bwChunk
		if end > len(p) {
			end = len(p)
		}
		if d := takeAll(c.down, end-written); d > 0 {
			time.Sleep(d)
		}
		n, err := c.Conn.Write(p[written:end])
		written += n
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

var (
	bwGlobalUp     *bwLimiter
	bwGlobalDown   *bwLimiter
	bwUserUp       int64 // bytes/sec per user (0 = off)
	bwUserDown     int64
	bwBurstBytes   int64 = 256 * 1024
	userBwLimiters sync.Map // user -> *userBwLimit
)

type userBwLimit struct {
	up   *bwLimiter
	down *bwLimiter
}

func mbpsToBytes(key string) int64 {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return 0
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f <= 0 {
		return 0
	}
	return int64(f * 1_000_000 / 8)
}

func humanBps(n int64) string {
	if n <= 0 {
		return "unlimited"
	}
	return fmt.Sprintf("%.2f Mbps", float64(n)*8/1_000_000)
}

func initBandwidthControl() {
	if v := strings.TrimSpace(os.Getenv("BW_BURST_KB")); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 16 {
			bwBurstBytes = n * 1024
		}
	}
	global := mbpsToBytes("BW_GLOBAL_MBPS")
	bwUserUp = mbpsToBytes("BW_USER_MBPS")
	bwUserDown = bwUserUp
	bwGlobalUp = newBwLimiter(global, bwBurstBytes)
	bwGlobalDown = newBwLimiter(global, bwBurstBytes)
	if global > 0 || bwUserUp > 0 {
		log.Printf("%s[BW]%s global=%s per-user=%s burst=%dKB",
			colorGreen, colorReset, humanBps(global), humanBps(bwUserUp), bwBurstBytes/1024)
	}
}

// bwForUser lazily creates a user's buckets so a new user always starts with a
// full burst instead of inheriting another account's debt.
func bwForUser(user string) (up, down *bwLimiter) {
	if user == "" || (bwUserUp <= 0 && bwUserDown <= 0) {
		return nil, nil
	}
	v, _ := userBwLimiters.LoadOrStore(user, &userBwLimit{
		up:   newBwLimiter(bwUserUp, bwBurstBytes),
		down: newBwLimiter(bwUserDown, bwBurstBytes),
	})
	b := v.(*userBwLimit)
	return b.up, b.down
}

// ===========================================================================
// Per-client-IP connection cap + panic isolation
//
//   MAX_CONNS_PER_IP=0   concurrent tunnels allowed per client IP (0 = off)
// ===========================================================================

var connsPerIP sync.Map // ip -> *int64
var tunnelSeq int64

func maxConnsPerIP() int64 {
	if v := strings.TrimSpace(os.Getenv("MAX_CONNS_PER_IP")); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

// acquireConnSlot reserves a tunnel slot for ip; it returns a release func, or
// nil when the caller is already at the cap.
func acquireConnSlot(ip string) func() {
	limit := maxConnsPerIP()
	if limit <= 0 || ip == "" {
		return func() {}
	}
	v, _ := connsPerIP.LoadOrStore(ip, new(int64))
	p := v.(*int64)
	if atomic.AddInt64(p, 1) > limit {
		atomic.AddInt64(p, -1)
		return nil
	}
	return func() { atomic.AddInt64(p, -1) }
}

// recoverTo turns a panic into a log line instead of a dead proxy process.
func recoverTo(where string) {
	if r := recover(); r != nil {
		atomic.AddInt64(&errCount, 1)
		log.Printf("%s[PANIC]%s %s: %v\n%s", colorRed, colorReset, where, r, debug.Stack())
	}
}

// guardHandler wraps every request so one malformed request can't take the
// whole proxy down — an unrecovered panic in a handler kills the process.
func guardHandler(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer recoverTo("handler " + r.URL.Path)
		next(w, r)
	}
}

// ===========================================================================
// Geo routing — make geo-sensitive sites see a Thai IP
//
// A forward proxy always shows the destination the *proxy's* IP, so a server in
// Malaysia looks Malaysian to OmeTV and only matches Malaysian peers. Hosts on
// the geo list are dialled through the Thai egress pool instead, so the
// destination sees a Thai address. DNS is still resolved here, so Cisco
// Umbrella on the client never sees the query.
//
// The list is *data*, never code: nothing is compiled in. The proxy merges
// whatever the operator points it at, so adding or dropping a site never needs
// a rebuild and the proxy never guesses which sites are country-sensitive.
//
//   GEO_DOMAINS=...        comma/newline separated domains (env)
//   GEO_DOMAINS_FILE=...   one domain per line, '#' comments (default
//                          /opt/netninja/geo-domains.txt, hot reloaded)
//   GEO_DOMAINS_URL=...    list fetched at boot + refreshed, cached to disk
//   GEO_REFRESH_HOURS=24   refresh interval for the URL
//   GEO_EXPECT_COUNTRY=TH  country a geo egress must exit from
//   GEO_DOMAINS_DISABLE=1  turn geo routing off
// ===========================================================================

// geoDomainSet is an immutable list swapped in atomically. A lookup walks the
// host's own labels (a.b.ome.tv → b.ome.tv → ome.tv) and hits the set, so a
// 100k-entry list costs the same handful of map probes as a 3-entry one.
type geoDomainSet struct {
	list []string
	set  map[string]struct{}
}

var (
	geoDomains      atomic.Pointer[geoDomainSet]
	geoDomainsMu    sync.Mutex // serialises refreshes, guards the fields below
	geoDomainsFile  string
	geoDomainsCache string
	geoDomainsURL   string
	geoDomainsSrc   string
	geoDomainsAt    time.Time
	geoDomainsLast  []string
	geoRefreshEvery = 24 * time.Hour
	geoReloadEvery  = 20 * time.Second
	geoDomainsOff   bool
	geoFileMod      time.Time
)

// normalizeGeoDomain turns whatever shape an operator's list happens to use
// into a bare domain: `||ads.example^`, `*.example.com`, `example.com:8080`
// and `example.com/path` all become `example.com`. Single-label entries are
// rejected — `tv` as a suffix would match half the internet.
func normalizeGeoDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(d, "||")
	d = strings.TrimPrefix(d, "*.")
	d = strings.TrimSuffix(d, "^")
	d = strings.Trim(d, ".")
	if i := strings.IndexAny(d, "/:?@ "); i >= 0 {
		d = d[:i]
	}
	d = strings.Trim(d, ".")
	if d == "" || !strings.Contains(d, ".") {
		return ""
	}
	return d
}

// parseGeoDomainList reads one domain per line and also accepts comma/space
// separated entries, so a hosts-format or adblock-format file works as-is.
func parseGeoDomainList(r io.Reader) []string {
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		for _, part := range strings.FieldsFunc(line, func(c rune) bool {
			return c == ',' || c == ' ' || c == '\t' || c == ';' || c == '|'
		}) {
			if d := normalizeGeoDomain(part); d != "" {
				out = append(out, d)
			}
		}
	}
	return out
}

func buildGeoDomainSet(list []string) *geoDomainSet {
	set := make(map[string]struct{}, len(list))
	uniq := make([]string, 0, len(list))
	for _, d := range list {
		d = normalizeGeoDomain(d)
		if d == "" {
			continue
		}
		if _, ok := set[d]; ok {
			continue
		}
		set[d] = struct{}{}
		uniq = append(uniq, d)
	}
	sort.Strings(uniq)
	return &geoDomainSet{list: uniq, set: set}
}

func geoDomainCount() int {
	if ds := geoDomains.Load(); ds != nil {
		return len(ds.list)
	}
	return 0
}

func geoDomainList() []string {
	if ds := geoDomains.Load(); ds != nil {
		return ds.list
	}
	return nil
}

func loadGeoDomainsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseGeoDomainList(f), nil
}

func loadGeoDomainsURL(u, cachePath string) ([]string, error) {
	client := &http.Client{Timeout: 45 * time.Second}
	resp, err := client.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s → HTTP %d", u, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if cachePath != "" {
		if werr := os.WriteFile(cachePath, body, 0o644); werr != nil {
			log.Printf("%s[GEO]%s cannot cache the list to %s: %v", colorYellow, colorReset, cachePath, werr)
		}
	}
	return parseGeoDomainList(bytes.NewReader(body)), nil
}

// refreshGeoDomains merges every configured source. A source that fails keeps
// its previous contribution, so a network hiccup can never silently switch geo
// routing off in the middle of the day.
func refreshGeoDomains(reason string) {
	geoDomainsMu.Lock()
	defer geoDomainsMu.Unlock()

	var merged, sources []string

	if envList := parseGeoDomainList(strings.NewReader(os.Getenv("GEO_DOMAINS"))); len(envList) > 0 {
		merged = append(merged, envList...)
		sources = append(sources, fmt.Sprintf("env=%d", len(envList)))
	}

	if geoDomainsFile != "" {
		list, err := loadGeoDomainsFile(geoDomainsFile)
		switch {
		case err == nil:
			merged = append(merged, list...)
			sources = append(sources, fmt.Sprintf("file=%d", len(list)))
			if st, serr := os.Stat(geoDomainsFile); serr == nil {
				geoFileMod = st.ModTime()
			}
		case !os.IsNotExist(err):
			log.Printf("%s[GEO]%s cannot read %s: %v", colorYellow, colorReset, geoDomainsFile, err)
		}
	}

	if geoDomainsURL != "" {
		list, err := loadGeoDomainsURL(geoDomainsURL, geoDomainsCache)
		if err != nil {
			log.Printf("%s[GEO]%s list fetch failed (%s): %v — keeping the cached copy", colorYellow, colorReset, reason, err)
			if cached, cerr := loadGeoDomainsFile(geoDomainsCache); cerr == nil {
				list = cached
				sources = append(sources, fmt.Sprintf("cache=%d", len(cached)))
			}
		} else {
			sources = append(sources, fmt.Sprintf("url=%d", len(list)))
		}
		merged = append(merged, list...)
	}

	if len(merged) == 0 && len(geoDomainsLast) > 0 {
		merged = geoDomainsLast
		sources = append(sources, "previous")
	}

	if len(merged) == 0 {
		geoDomains.Store(&geoDomainSet{set: map[string]struct{}{}})
		log.Printf("%s[GEO]%s no domain list configured — geo routing idle (set GEO_DOMAINS, GEO_DOMAINS_FILE or GEO_DOMAINS_URL)", colorYellow, colorReset)
		return
	}

	ds := buildGeoDomainSet(merged)
	geoDomains.Store(ds)
	geoDomainsLast = ds.list
	geoDomainsAt = time.Now()
	geoDomainsSrc = strings.Join(sources, ",")

	if reason == "" {
		log.Printf("%s[GEO]%s %d domain(s) from %s — egress expected in %s",
			colorGreen, colorReset, len(ds.list), geoDomainsSrc, geoExpectCountry())
	} else {
		log.Printf("%s[GEO]%s %d domain(s) from %s (%s) — egress expected in %s",
			colorGreen, colorReset, len(ds.list), geoDomainsSrc, reason, geoExpectCountry())
	}
}

func geoDomainsStatus() string {
	geoDomainsMu.Lock()
	defer geoDomainsMu.Unlock()
	if len(geoDomainsLast) == 0 {
		return "idle (no list configured)"
	}
	return fmt.Sprintf("%d domains from %s, refreshed %s ago (every %v)",
		len(geoDomainsLast), geoDomainsSrc, time.Since(geoDomainsAt).Round(time.Second), geoRefreshEvery)
}

// geoHopSocks5 is an optional dedicated egress for geo domains, so a Thai
// tunnel can exist next to the shared (e.g. Japan) HOP_SOCKS5 without
// disturbing how bilibili and friends are routed.
var geoHopSocks5 string

// geoSocks5 reports the egress geo traffic uses right now: the pool's current
// node while the pool is up, otherwise the single GEO_SOCKS5 override, otherwise
// the shared HOP_SOCKS5 (legacy behaviour).
func geoSocks5() string {
	if a := geoPoolCurrentAddr(); a != "" {
		return a
	}
	if geoHopSocks5 != "" {
		return geoHopSocks5
	}
	return hopSocks5
}

func geoExpectCountry() string {
	if v := strings.TrimSpace(os.Getenv("GEO_EXPECT_COUNTRY")); v != "" {
		return strings.ToUpper(v)
	}
	return "TH"
}

func initGeoDomains() {
	if v := strings.TrimSpace(os.Getenv("GEO_DOMAINS_DISABLE")); v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "off") {
		geoDomainsOff = true
		log.Printf("%s[GEO]%s disabled by GEO_DOMAINS_DISABLE", colorYellow, colorReset)
		return
	}
	geoDomains.Store(&geoDomainSet{set: map[string]struct{}{}})

	geoDomainsFile = strings.TrimSpace(os.Getenv("GEO_DOMAINS_FILE"))
	if geoDomainsFile == "" {
		geoDomainsFile = "/opt/netninja/geo-domains.txt"
	}
	geoDomainsCache = strings.TrimSpace(os.Getenv("GEO_DOMAINS_CACHE"))
	if geoDomainsCache == "" {
		geoDomainsCache = geoDomainsFile + ".cache"
	}
	geoDomainsURL = strings.TrimSpace(os.Getenv("GEO_DOMAINS_URL"))
	if h := strings.TrimSpace(os.Getenv("GEO_REFRESH_HOURS")); h != "" {
		if n, err := strconv.Atoi(h); err == nil && n > 0 {
			geoRefreshEvery = time.Duration(n) * time.Hour
		}
	}
	geoHopSocks5 = strings.TrimSpace(os.Getenv("GEO_SOCKS5"))
	refreshGeoDomains("")
}

// startGeoDomainRefresher keeps a remote list fresh and picks up edits to a
// local list, so the domain set never needs a rebuild or a restart.
func startGeoDomainRefresher() {
	if geoDomainsOff {
		return
	}
	if geoDomainsURL != "" {
		go func() {
			for {
				time.Sleep(geoRefreshEvery)
				refreshGeoDomains("scheduled refresh")
			}
		}()
	}
	if geoDomainsFile != "" {
		go func() {
			for {
				time.Sleep(geoReloadEvery)
				st, err := os.Stat(geoDomainsFile)
				if err != nil {
					continue
				}
				geoDomainsMu.Lock()
				changed := !st.ModTime().Equal(geoFileMod)
				geoDomainsMu.Unlock()
				if changed {
					log.Printf("%s[GEO]%s %s changed on disk — reloading the domain list", colorCyan, colorReset, geoDomainsFile)
					refreshGeoDomains("file changed")
				}
			}
		}()
	}
}

func inGeoDomains(host string) bool {
	if geoDomainsOff {
		return false
	}
	ds := geoDomains.Load()
	if ds == nil || len(ds.set) == 0 {
		return false
	}
	h := normalizeAdHost(host)
	for h != "" {
		if _, ok := ds.set[h]; ok {
			return true
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			return false
		}
		h = h[i+1:]
	}
	return false
}

// ---------------------------------------------------------------------------
// Thai egress pool
//
// Geo-sensitive traffic has to leave from Thailand, but one tunnel dies or gets
// slow without warning — and a VPN client that rotates on failure will happily
// pick a node in another country, which silently changes who the site matches.
// The pool keeps several Thai egresses (one SOCKS5 listener each, provisioned on
// this server) and:
//
//   * probes each node every GEO_POOL_PROBE (TCP connect RTT)
//   * verifies the country each node really exits from, and refuses to use a
//     node that exits elsewhere
//   * sticks to the fastest healthy Thai node, rotating the moment the current
//     one dies or stays slower than GEO_POOL_MAX_RTT
//   * fails over inside a single dial, so a dead node costs one round trip
//   * asks GEO_ROTATE_CMD to rebuild tunnels when no Thai node is healthy
//
//   GEO_SOCKS5_POOL=...       host:port entries, comma separated
//   GEO_SOCKS5=...            single entry (still honoured, joins the pool)
//   GEO_SOCKS5_POOL_FILE=...  one entry per line, hot reloaded
//                             (default /opt/netninja/geo-nodes.txt)
//   GEO_POOL_PROBE=20s        liveness/latency probe interval
//   GEO_POOL_TIMEOUT=1500ms   TCP probe timeout
//   GEO_POOL_MAX_RTT=1500ms   slower than this counts as slow
//   GEO_POOL_SLOW_STRIKES=3   consecutive slow dials before rotating away
//   GEO_POOL_FAIL_STRIKES=2   consecutive failures before marking a node down
//   GEO_POOL_GEOCHECK=5m      how often each node's country is verified
//   GEO_POOL_ATTEMPTS=3       nodes tried inside one dial
//   GEO_POOL_PENALTY=45s      how long a failed node is left out
//   GEO_STRICT=1              fail rather than leak this server's country
// ---------------------------------------------------------------------------

type geoNode struct {
	addr string

	mu        sync.Mutex
	up        bool
	country   string
	countryAt time.Time
	ewma      time.Duration
	fails     int
	slows     int
	lastErr   string
	downUntil time.Time
	probes    int64
}

func newGeoNode(addr string) *geoNode {
	return &geoNode{addr: addr, up: true}
}

// healthyLocked is the one place that decides whether a node may carry geo
// traffic right now: it has to be up, out of its failure penalty, and — once a
// country has been verified — actually exit in the expected country.
func (n *geoNode) healthyLocked(want string) bool {
	if !n.up || time.Now().Before(n.downUntil) {
		return false
	}
	if want != "" && n.country != "" && !strings.EqualFold(n.country, want) {
		return false
	}
	if geoPoolMaxRTT > 0 && n.ewma > geoPoolMaxRTT && n.slows >= geoPoolSlowHits {
		return false
	}
	return true
}

func (n *geoNode) healthy(want string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.healthyLocked(want)
}

func (n *geoNode) score() time.Duration {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.ewma > 0 {
		return n.ewma
	}
	return time.Hour // never dialled yet: usable, but only if nothing better exists
}

func (n *geoNode) snapshot() (up bool, country string, ewma time.Duration, fails, slows int, lerr string, probes int64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.up, n.country, n.ewma, n.fails, n.slows, n.lastErr, n.probes
}

var (
	geoPoolMu         sync.RWMutex
	geoPool           []*geoNode
	geoPoolCur        *geoNode
	geoPoolFile       string
	geoPoolFileMod    time.Time
	geoPoolProbeEvery = 20 * time.Second
	geoPoolTimeout    = 1500 * time.Millisecond
	geoPoolMaxRTT     = 1500 * time.Millisecond
	geoPoolSlowHits   = 3
	geoPoolFailHits   = 2
	geoPoolGeoEvery   = 5 * time.Minute
	geoPoolAttempts   = 3
	geoPoolPenalty    = 45 * time.Second
	geoPoolStrict     = true
	geoPoolOn         bool
	geoPoolRotations  int64
)

func geoPoolSize() int {
	geoPoolMu.RLock()
	defer geoPoolMu.RUnlock()
	return len(geoPool)
}

func geoPoolSnapshot() []*geoNode {
	geoPoolMu.RLock()
	defer geoPoolMu.RUnlock()
	out := make([]*geoNode, len(geoPool))
	copy(out, geoPool)
	return out
}

func geoPoolCurrentAddr() string {
	geoPoolMu.RLock()
	defer geoPoolMu.RUnlock()
	if geoPoolCur != nil {
		return geoPoolCur.addr
	}
	return ""
}

func containsGeoNode(nodes []*geoNode, n *geoNode) bool {
	for _, x := range nodes {
		if x == n {
			return true
		}
	}
	return false
}

// parseGeoNodeAddrs reads the candidate egresses from env and from the pool
// file, so a server script can bring a tunnel up and have it join the pool.
func parseGeoNodeAddrs() []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(strings.Trim(s, "\"'"))
		if s == "" || seen[s] || !strings.Contains(s, ":") {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, s := range strings.Split(os.Getenv("GEO_SOCKS5_POOL"), ",") {
		add(s)
	}
	for _, s := range strings.Split(os.Getenv("GEO_SOCKS5"), ",") {
		add(s)
	}
	if raw, err := os.ReadFile(geoPoolFile); err == nil {
		sc := bufio.NewScanner(bytes.NewReader(raw))
		for sc.Scan() {
			line := sc.Text()
			if i := strings.IndexByte(line, '#'); i >= 0 {
				line = line[:i]
			}
			for _, f := range strings.FieldsFunc(line, func(c rune) bool { return c == ',' || c == ' ' || c == '\t' }) {
				add(f)
			}
		}
		if st, serr := os.Stat(geoPoolFile); serr == nil {
			geoPoolFileMod = st.ModTime()
		}
	}
	return out
}

// syncGeoPool merges the configured endpoints into the live pool, keeping the
// existing node objects (and their health history) for endpoints that stay.
func syncGeoPool(addrs []string, reason string) {
	geoPoolMu.Lock()
	defer geoPoolMu.Unlock()
	have := make(map[string]*geoNode, len(geoPool))
	for _, n := range geoPool {
		have[n.addr] = n
	}
	next := make([]*geoNode, 0, len(addrs))
	for _, a := range addrs {
		if n, ok := have[a]; ok {
			next = append(next, n)
			delete(have, a)
			continue
		}
		next = append(next, newGeoNode(a))
		log.Printf("%s[GEO][pool]%s added node %s (%s)", colorGreen, colorReset, a, reason)
	}
	for a := range have {
		log.Printf("%s[GEO][pool]%s removed node %s (%s)", colorYellow, colorReset, a, reason)
	}
	geoPool = next
	if geoPoolCur != nil && !containsGeoNode(next, geoPoolCur) {
		geoPoolCur = nil
	}
}

// pickGeoNode returns the node to use: the sticky current one while it stays
// healthy, otherwise the fastest healthy Thai node. exclude lets one dial walk
// past the nodes it already failed on.
func pickGeoNode(exclude map[string]bool) *geoNode {
	want := geoExpectCountry()
	geoPoolMu.RLock()
	nodes, cur := geoPool, geoPoolCur
	geoPoolMu.RUnlock()

	if cur != nil && !exclude[cur.addr] && cur.healthy(want) {
		return cur
	}
	var best *geoNode
	var bestScore time.Duration
	for _, n := range nodes {
		if exclude[n.addr] || !n.healthy(want) {
			continue
		}
		if s := n.score(); best == nil || s < bestScore {
			best, bestScore = n, s
		}
	}
	if best != nil {
		setGeoPoolCurrent(best, "fastest healthy Thai node")
	}
	return best
}

func setGeoPoolCurrent(n *geoNode, reason string) {
	geoPoolMu.Lock()
	prev := geoPoolCur
	geoPoolCur = n
	geoPoolMu.Unlock()
	if prev == n || n == nil {
		return
	}
	atomic.AddInt64(&geoPoolRotations, 1)
	up, cc, ewma, _, slows, lerr, _ := n.snapshot()
	from := "-"
	if prev != nil {
		from = prev.addr
	}
	log.Printf("%s[GEO][pool]%s now egressing via %s (was %s) — %s | country=%s rtt=%v up=%v slow=%d %s",
		colorGreen, colorReset, n.addr, from, reason, geoCountryOrDash(cc), ewma.Round(time.Millisecond), up, slows, lerr)
}

func geoCountryOrDash(s string) string {
	if s == "" {
		return "unverified"
	}
	return s
}

// geoPoolDropCurrent steps the sticky pointer off a node so the next dial
// re-elects the fastest healthy Thai node.
func geoPoolDropCurrent(n *geoNode, reason string) {
	geoPoolMu.Lock()
	if geoPoolCur == n {
		geoPoolCur = nil
		log.Printf("%s[GEO][pool]%s leaving %s (%s)", colorYellow, colorReset, n.addr, reason)
	}
	geoPoolMu.Unlock()
}

// geoMarkResult feeds a real dial outcome back into the pool's health state, so
// the rotation decision is driven by the traffic the user actually generated.
func geoMarkResult(n *geoNode, err error, rtt time.Duration) {
	if n == nil {
		return
	}
	now := time.Now()

	n.mu.Lock()
	n.probes++
	if err != nil {
		n.fails++
		n.slows = 0
		n.lastErr = err.Error()
		down := n.up && n.fails >= geoPoolFailHits
		if down {
			n.up = false
			n.downUntil = now.Add(geoPoolPenalty)
		}
		errText := n.lastErr
		n.mu.Unlock()
		if down {
			log.Printf("%s[GEO][pool]%s %s marked down for %v after %d failure(s): %s",
				colorYellow, colorReset, n.addr, geoPoolPenalty, geoPoolFailHits, errText)
			geoPoolDropCurrent(n, "node failed")
		}
		return
	}
	if !n.up {
		log.Printf("%s[GEO][pool]%s %s is answering again", colorGreen, colorReset, n.addr)
	}
	n.up = true
	n.fails = 0
	n.lastErr = ""
	n.downUntil = time.Time{}
	if n.ewma == 0 {
		n.ewma = rtt
	} else {
		n.ewma = (n.ewma*7 + rtt*3) / 10
	}
	if geoPoolMaxRTT > 0 && rtt > geoPoolMaxRTT {
		n.slows++
	} else {
		n.slows = 0
	}
	slows := n.slows
	slowNow := slows >= geoPoolSlowHits
	n.mu.Unlock()

	if slowNow {
		log.Printf("%s[GEO][pool]%s %s stayed slower than %v for %d dial(s) — rotating away",
			colorYellow, colorReset, n.addr, geoPoolMaxRTT, slows)
		geoPoolDropCurrent(n, "node too slow")
	}
}

func geoProbeNode(n *geoNode) {
	d := &net.Dialer{Timeout: geoPoolTimeout}
	start := time.Now()
	c, err := d.Dial("tcp", n.addr)
	rtt := time.Since(start)
	if err == nil {
		c.Close()
	}
	geoMarkResult(n, err, rtt)
}

// geoVerifyNode proves the node's SOCKS5 listener works *and* which country it
// really exits from, which is the one thing a plain TCP probe cannot tell.
func geoVerifyNode(n *geoNode) {
	info, cc := geoLookup(func(ctx context.Context) (net.Conn, error) {
		return dialSocks5(ctx, n.addr, "ip-api.com:80")
	})
	n.mu.Lock()
	n.countryAt = time.Now()
	prev := n.country
	if cc != "" {
		n.country = cc
	}
	n.mu.Unlock()

	if cc == "" {
		log.Printf("%s[GEO][pool][warn]%s %s country check failed: %s", colorYellow, colorReset, n.addr, info)
		geoMarkResult(n, fmt.Errorf("country check: %s", info), 0)
		return
	}
	if prev != cc {
		log.Printf("%s[GEO][pool]%s %s exits %s — %s", colorGreen, colorReset, n.addr, cc, info)
	}
	if !strings.EqualFold(cc, geoExpectCountry()) {
		log.Printf("%s[GEO][pool][warn]%s %s exits %s but %s is required — node left unused",
			colorYellow, colorReset, n.addr, cc, geoExpectCountry())
		geoPoolDropCurrent(n, "wrong country")
	}
}

func geoPoolHousekeeping() {
	want := geoExpectCountry()
	healthy := 0
	for _, n := range geoPoolSnapshot() {
		if n.healthy(want) {
			healthy++
		}
	}
	if healthy > 0 {
		pickGeoNode(nil)
		return
	}
	geoGuardRotate(time.Now(), fmt.Sprintf("no healthy %s egress in the pool (%d node(s) configured)", want, geoPoolSize()))
}

func geoPoolLoop() {
	ticker := time.NewTicker(geoPoolProbeEvery)
	defer ticker.Stop()
	nextCountry := time.Now().Add(20 * time.Second)
	for range ticker.C {
		// Nodes appear and disappear on the server while we run: pick them up.
		if addrs := parseGeoNodeAddrs(); len(addrs) > 0 {
			syncGeoPool(addrs, "poll")
		}
		for _, n := range geoPoolSnapshot() {
			geoProbeNode(n)
		}
		if time.Now().After(nextCountry) {
			for _, n := range geoPoolSnapshot() {
				geoVerifyNode(n)
			}
			nextCountry = time.Now().Add(geoPoolGeoEvery)
		}
		geoPoolHousekeeping()
	}
}

func geoPoolDurationEnv(key string, def time.Duration) time.Duration {
	return geoGuardEnvDur(key, def)
}

func geoPoolIntEnv(key string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key))); err == nil && n > 0 {
		return n
	}
	return def
}

func startGeoPool() {
	geoPoolFile = strings.TrimSpace(os.Getenv("GEO_SOCKS5_POOL_FILE"))
	if geoPoolFile == "" {
		geoPoolFile = "/opt/netninja/geo-nodes.txt"
	}
	geoPoolProbeEvery = geoPoolDurationEnv("GEO_POOL_PROBE", geoPoolProbeEvery)
	geoPoolTimeout = geoPoolDurationEnv("GEO_POOL_TIMEOUT", geoPoolTimeout)
	geoPoolMaxRTT = geoPoolDurationEnv("GEO_POOL_MAX_RTT", geoPoolMaxRTT)
	geoPoolGeoEvery = geoPoolDurationEnv("GEO_POOL_GEOCHECK", geoPoolGeoEvery)
	geoPoolPenalty = geoPoolDurationEnv("GEO_POOL_PENALTY", geoPoolPenalty)
	geoPoolSlowHits = geoPoolIntEnv("GEO_POOL_SLOW_STRIKES", geoPoolSlowHits)
	geoPoolFailHits = geoPoolIntEnv("GEO_POOL_FAIL_STRIKES", geoPoolFailHits)
	geoPoolAttempts = geoPoolIntEnv("GEO_POOL_ATTEMPTS", geoPoolAttempts)
	if v := strings.TrimSpace(os.Getenv("GEO_STRICT")); v != "" {
		geoPoolStrict = !(v == "0" || strings.EqualFold(v, "false") || strings.EqualFold(v, "off"))
	}

	addrs := parseGeoNodeAddrs()
	if len(addrs) == 0 {
		log.Printf("%s[GEO]%s no egress pool configured (GEO_SOCKS5_POOL / GEO_SOCKS5 / %s) — geo traffic falls back to HOP_SOCKS5 when set",
			colorYellow, colorReset, geoPoolFile)
		go logGeoEgressCountry()
		return
	}
	syncGeoPool(addrs, "startup")
	geoPoolOn = true
	log.Printf("%s[GEO][pool]%s %d Thai egress node(s): %s — probe %v, max rtt %v, attempts %d, strict=%v",
		colorGreen, colorReset, len(addrs), strings.Join(addrs, ","), geoPoolProbeEvery, geoPoolMaxRTT, geoPoolAttempts, geoPoolStrict)
	go geoPoolLoop()
	go logGeoEgressCountry()
}

// dialGeoThai dials address through the Thai pool, failing over node by node so
// a node that died a second ago costs this dial one round trip, not a timeout.
func dialGeoThai(ctx context.Context, address, why string) (net.Conn, error) {
	// No pool configured: keep the previous single-egress behaviour.
	if !geoPoolOn {
		server := geoSocks5()
		if server == "" {
			return nil, fmt.Errorf("no geo egress configured for %s", why)
		}
		return dialSocks5(ctx, server, address)
	}
	exclude := make(map[string]bool, geoPoolAttempts)
	var lastErr error
	for i := 0; i < geoPoolAttempts; i++ {
		n := pickGeoNode(exclude)
		if n == nil {
			break
		}
		exclude[n.addr] = true
		start := time.Now()
		c, err := dialSocks5(ctx, n.addr, address)
		rtt := time.Since(start)
		geoMarkResult(n, err, rtt)
		if err == nil {
			if geoPoolMaxRTT > 0 && rtt > geoPoolMaxRTT {
				log.Printf("%s[GEO][pool]%s %s via %s took %v (slow)", colorYellow, colorReset, why, n.addr, rtt.Round(time.Millisecond))
			}
			return c, nil
		}
		lastErr = err
		log.Printf("%s[GEO][pool]%s %s via %s failed (%v) — trying the next Thai node", colorYellow, colorReset, why, n.addr, err)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no healthy %s egress available (%d node(s) configured)", geoExpectCountry(), geoPoolSize())
	}
	return nil, lastErr
}

func geoPoolStatusLines() []string {
	want := geoExpectCountry()
	cur := geoPoolCurrentAddr()
	var out []string
	for _, n := range geoPoolSnapshot() {
		up, cc, ewma, fails, slows, lerr, probes := n.snapshot()
		state := "ok"
		switch {
		case cur == n.addr:
			state = "CURRENT"
		case !n.healthy(want):
			state = "unusable"
		}
		line := fmt.Sprintf("  %-22s %-9s country=%-10s rtt=%-9v fails=%d slow=%d probes=%d",
			n.addr, state, geoCountryOrDash(cc), ewma.Round(time.Millisecond), fails, slows, probes)
		if lerr != "" {
			line += "  last_err=" + lerr
		}
		if !up {
			line += "  (down)"
		}
		out = append(out, line)
	}
	return out
}

var geoLogOnce sync.Map

// ---------------------------------------------------------------------------
// Geo sessions — keep a whole browsing session Thai, not just one domain
//
// A geo-sensitive page pulls in dozens of third-party hosts (ad slots, captcha,
// analytics) that no fixed list can enumerate — and the ad slot is exactly where
// the country shows, because ad networks geo-target by the IP they see. So once
// a client touches a geo domain, that client is marked and, for GEO_SESSION_TTL,
// everything it loads that is not excluded follows the same Thai egress. Which
// hosts are ads comes from the real blocklist the proxy already refreshes
// (ADBLOCK_URL / ADBLOCK_PATH) — never from a hardcoded list.
//
//   GEO_SESSION=all|ads|off   what follows the session (default all)
//   GEO_SESSION_TTL=15m       how long a client stays marked
//   GEO_ADS_EGRESS=0|1        route ad hosts Thai for every client, session or
//                             not (default 0 = only inside a geo session)
//   GEO_SESSION_EXCLUDE=...   extra hosts kept on the direct path (speed)
// ---------------------------------------------------------------------------

type geoCtxKey struct{}

var (
	geoSessionMu   sync.Mutex
	geoSessionMap  = map[string]time.Time{}
	geoSessionTTL  = 15 * time.Minute
	geoSessionMode = "all"
	geoAdsGlobal   bool
	geoSessionExcl []string
	geoSessionLive int64 // atomic: marked sessions right now, for a cheap fast path
)

func initGeoSession() {
	if v := strings.TrimSpace(os.Getenv("GEO_SESSION")); v != "" {
		geoSessionMode = strings.ToLower(v)
	}
	switch geoSessionMode {
	case "off", "ads", "all":
	default:
		log.Printf("%s[GEO]%s GEO_SESSION=%q is not off|ads|all — using all", colorYellow, colorReset, geoSessionMode)
		geoSessionMode = "all"
	}
	geoSessionTTL = geoGuardEnvDur("GEO_SESSION_TTL", geoSessionTTL)
	if v := strings.TrimSpace(os.Getenv("GEO_ADS_EGRESS")); v != "" {
		geoAdsGlobal = v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "on")
	}
	for _, d := range strings.Split(os.Getenv("GEO_SESSION_EXCLUDE"), ",") {
		if d = normalizeGeoDomain(d); d != "" {
			geoSessionExcl = append(geoSessionExcl, d)
		}
	}
	if geoSessionMode == "off" {
		log.Printf("%s[GEO]%s sessions disabled (GEO_SESSION=off) — only the listed domains egress Thai", colorYellow, colorReset)
		return
	}
	log.Printf("%s[GEO]%s geo session mode=%s ttl=%v ads_global=%v exclude=%d host(s) — a client that opens a geo site keeps egressing %s for %v",
		colorGreen, colorReset, geoSessionMode, geoSessionTTL, geoAdsGlobal, len(geoSessionExcl), geoExpectCountry(), geoSessionTTL)
}

func ctxWithGeoKey(ctx context.Context, key string) context.Context {
	if key == "" {
		return ctx
	}
	return context.WithValue(ctx, geoCtxKey{}, key)
}

func geoKeyFromCtx(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if k, ok := ctx.Value(geoCtxKey{}).(string); ok {
		return k
	}
	return ""
}

func noteGeoSession(key string) {
	if key == "" || geoDomainsOff || geoSessionTTL <= 0 || geoSessionMode == "off" {
		return
	}
	geoSessionMu.Lock()
	if _, ok := geoSessionMap[key]; !ok {
		atomic.AddInt64(&geoSessionLive, 1)
	}
	geoSessionMap[key] = time.Now()
	geoSessionMu.Unlock()
}

func geoSessionFresh(key string) bool {
	if key == "" || geoSessionTTL <= 0 || atomic.LoadInt64(&geoSessionLive) == 0 {
		return false
	}
	geoSessionMu.Lock()
	t, ok := geoSessionMap[key]
	geoSessionMu.Unlock()
	return ok && time.Since(t) < geoSessionTTL
}

func startGeoSessionSweeper() {
	go func() {
		for {
			time.Sleep(time.Minute)
			cut := time.Now().Add(-geoSessionTTL)
			geoSessionMu.Lock()
			for k, t := range geoSessionMap {
				if t.Before(cut) {
					delete(geoSessionMap, k)
				}
			}
			atomic.StoreInt64(&geoSessionLive, int64(len(geoSessionMap)))
			geoSessionMu.Unlock()
		}
	}()
}

// geoDirectIP reports whether an already-resolved address is this server
// itself, so keepalive and dashboard traffic is never pushed through the VPN.
func geoDirectIP(ip string) bool {
	ip = strings.Trim(ip, "[]")
	if ip == "" {
		return false
	}
	if isLocalIP(ip) {
		return true
	}
	if pa := strings.TrimSpace(os.Getenv("PROXY_ADDR")); pa != "" {
		h := pa
		if hh, _, err := net.SplitHostPort(pa); err == nil {
			h = hh
		}
		if strings.EqualFold(h, ip) {
			return true
		}
	}
	return false
}

// pacDirectDomains is the single source of truth for "go direct" on both sides:
// the PAC file hands these straight to the client, and the session router keeps
// them direct if they arrive anyway (manual-proxy mode). Built once, because the
// dial path asks on every connection.
func pacDirectDomains() []string {
	pacDirectOnce.Do(func() {
		direct := []string{
			"googlevideo.com", "apple.com", "icloud.com",
			"apple-cloudkit.com", "mzstatic.com", "itunes.com",
			"ookla.com", "speedtest.net", "ooklaserver.net",
		}
		for _, d := range strings.Split(os.Getenv("PAC_DIRECT_DOMAINS"), ",") {
			if d = normalizeGeoDomain(d); d != "" {
				direct = append(direct, d)
			}
		}
		pacDirectList = direct
	})
	return pacDirectList
}

var (
	pacDirectOnce sync.Once
	pacDirectList []string
)

// geoTargetExcluded keeps the hosts whose speed matters more than their country
// on the direct path: this server itself, video/CDN traffic, and the same set the
// PAC file already sends DIRECT.
func geoTargetExcluded(host, address string) bool {
	if ip, _, err := net.SplitHostPort(address); err == nil && geoDirectIP(ip) {
		return true
	}
	h := normalizeAdHost(host)
	if h == "" {
		return false
	}
	if h == "localhost" || strings.HasSuffix(h, ".local") {
		return true
	}
	if isVideoDomain(h) {
		return true
	}
	for _, d := range pacDirectDomains() {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	for _, d := range geoSessionExcl {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

// geoEgressFor decides, for one host, whether it has to leave from Thailand and
// why ("geo", "ad", "session"). It runs on the dial path, so it stays cheap:
// one atomic pointer load, and the ad-list check only for clients that are
// actually inside a geo session.
func geoEgressFor(ctx context.Context, host, address string) (bool, string) {
	if inGeoDomains(host) {
		// Only a self/CDN host on the geo list is sent direct; everything else
		// on the list has to exit Thai.
		if geoTargetExcluded(host, address) {
			return false, ""
		}
		return true, "geo"
	}

	// Fast path for the vast majority of dials: no geo session open and global ad
	// localisation off means nothing else can be routed, so the CDN/blocklist
	// checks are skipped entirely.
	key := geoKeyFromCtx(ctx)
	inSession := geoSessionMode != "off" && geoSessionFresh(key)
	if !geoAdsGlobal && !inSession {
		return false, ""
	}
	if geoTargetExcluded(host, address) {
		return false, ""
	}
	if isAdBlockedHost(host) {
		return true, "ad"
	}
	if inSession && geoSessionMode == "all" {
		return true, "session"
	}
	return false, ""
}

// geoHandlesAd reports whether an ad/tracking host is carried by the Thai egress
// instead of being refused, so the block sites can let it through.
func geoHandlesAd(ctx context.Context, host string) bool {
	via, _ := geoEgressFor(ctx, host, "")
	return via
}

var geoEgressLogged sync.Map

func logGeoEgressOnce(host, why string) {
	key := why + "|" + host
	if _, loaded := geoEgressLogged.LoadOrStore(key, true); loaded {
		return
	}
	switch why {
	case "ad":
		log.Printf("%s[GEO][ads]%s %s leaves via the Thai pool — its ad slot sees a Thai visitor", colorGreen, colorReset, host)
	default:
		log.Printf("%s[GEO][session]%s %s follows the Thai egress while the session is open", colorGreen, colorReset, host)
	}
}

func logGeoOnce(host string, viaHop bool) {
	if _, loaded := geoLogOnce.LoadOrStore(host, true); loaded {
		return
	}
	if viaHop {
		log.Printf("%s[GEO]%s %s egresses through the hop (destination sees the hop's IP)", colorGreen, colorReset, host)
	} else {
		log.Printf("%s[GEO][warn]%s %s has no working hop — destination sees this server's country", colorYellow, colorReset, host)
	}
}

// geoLookupCountry asks ip-api.com (plain HTTP, no key) which country a dialer
// egresses from. This is what proves the hop really is in Thailand.
func geoLookupCountry(dial func(ctx context.Context) (net.Conn, error)) string {
	info, _ := geoLookup(dial)
	return info
}

// geoLookup returns both the human readable egress info and the country code
// ("TH", "JP", …). cc is empty when the lookup failed.
const geoProbeRequest = "GET /json/?fields=query,country,countryCode,city,isp HTTP/1.0\r\nHost: ip-api.com\r\nUser-Agent: netninja-geo\r\nConnection: close\r\n\r\n"

func parseGeoProbe(s string) (info, cc string) {
	if i := strings.Index(s, "\r\n\r\n"); i >= 0 {
		s = s[i+4:]
	} else if i := strings.Index(s, "\n\n"); i >= 0 {
		s = s[i+2:]
	}
	s = strings.TrimSpace(s)
	var out struct {
		Query       string `json:"query"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		City        string `json:"city"`
		ISP         string `json:"isp"`
	}
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return "unparsable: " + s, ""
	}
	return fmt.Sprintf("%s (%s, %s, %s)", out.Query, out.CountryCode, out.City, out.ISP), strings.ToUpper(out.CountryCode)
}

// geoProbe measures one egress end to end: how long the connection took to
// open, how long a complete answer took, and which country it really exits from.
func geoProbe(dial func(ctx context.Context) (net.Conn, error)) (info, cc string, connect, total time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	c, err := dial(ctx)
	if err != nil {
		return "error: " + err.Error(), "", time.Since(start), 0
	}
	defer c.Close()
	connect = time.Since(start)
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := c.Write([]byte(geoProbeRequest)); err != nil {
		return "error: " + err.Error(), "", connect, 0
	}
	body, _ := io.ReadAll(io.LimitReader(c, 8192))
	total = time.Since(start)
	info, cc = parseGeoProbe(string(body))
	return info, cc, connect, total
}

func geoLookup(dial func(ctx context.Context) (net.Conn, error)) (info string, cc string) {
	info, cc, _, _ = geoProbe(dial)
	return info, cc
}

func logGeoEgressCountry() {
	direct := geoLookupCountry(func(ctx context.Context) (net.Conn, error) {
		return customDialer.DialContext(ctx, "tcp", "ip-api.com:80")
	})
	server := geoSocks5()
	via := "(no geo egress configured)"
	if server != "" {
		via = geoLookupCountry(func(ctx context.Context) (net.Conn, error) {
			return dialSocks5(ctx, server, "ip-api.com:80")
		})
	}
	want := geoExpectCountry()
	status := "OK"
	switch {
	case server == "":
		status = "NO EGRESS — set GEO_SOCKS5_POOL (or GEO_SOCKS5)"
	case strings.HasPrefix(via, "error"):
		status = "EGRESS UNREACHABLE — geo dials fail instead of exiting the wrong country"
	case !strings.Contains(via, "("+want+","):
		status = "WRONG COUNTRY — the pool will stop using this node"
	}
	log.Printf("%s[GEO]%s egress check — direct: %s | geo(%s): %s (expect %s → %s)", colorGreen, colorReset, direct, server, via, want, status)
}

var geoBenchMu sync.Mutex

func geoTCPRTT(addr string) time.Duration {
	d := &net.Dialer{Timeout: geoPoolTimeout}
	start := time.Now()
	c, err := d.Dial("tcp", addr)
	if err != nil {
		return 0
	}
	c.Close()
	return time.Since(start)
}

// serveGeoBench measures every path side by side — direct and each pool node —
// so "is the Thai egress slower, and by how much?" is answered with numbers from
// the server instead of a guess. It is read-only: pool health and the current
// node are not touched.
func serveGeoBench(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	if !geoBenchMu.TryLock() {
		fmt.Fprintln(w, "bench already running — try again in a moment")
		return
	}
	defer geoBenchMu.Unlock()

	fmt.Fprintf(w, "netninja geo-bench (build %s)\n", buildTime)
	fmt.Fprintf(w, "expect country: %s   pool: %d node(s)   current: %s\n", geoExpectCountry(), geoPoolSize(), geoPoolCurrentAddr())
	fmt.Fprintf(w, "(connect = time to open the egress connection, total = time to a full answer through it)\n\n")
	fmt.Fprintf(w, "%-26s %-11s %-11s %-11s %s\n", "target", "tcp", "connect", "total", "country")

	row := func(target string, tcp, connect, total time.Duration, cc, note string) {
		dash := func(d time.Duration) string {
			if d <= 0 {
				return "-"
			}
			return d.Round(time.Millisecond).String()
		}
		flag := ""
		if cc != "" && !strings.EqualFold(cc, geoExpectCountry()) {
			flag = "  <-- NOT " + geoExpectCountry()
		}
		fmt.Fprintf(w, "%-26s %-11s %-11s %-11s %s%s%s\n", target, dash(tcp), dash(connect), dash(total), geoCountryOrDash(cc), flag, note)
	}

	_, ccDirect, connectDirect, totalDirect := geoProbe(func(ctx context.Context) (net.Conn, error) {
		return customDialer.DialContext(ctx, "tcp", "ip-api.com:80")
	})
	row("direct (this server)", geoTCPRTT("ip-api.com:80"), connectDirect, totalDirect, ccDirect, "")

	cur := geoPoolCurrentAddr()
	for _, n := range geoPoolSnapshot() {
		_, cc, connect, total := geoProbe(func(ctx context.Context) (net.Conn, error) {
			return dialSocks5(ctx, n.addr, "ip-api.com:80")
		})
		_, _, _, _, slows, lerr, _ := n.snapshot()
		note := ""
		if n.addr == cur {
			note = "  CURRENT"
		}
		if slows > 0 {
			note += fmt.Sprintf("  slow=%d", slows)
		}
		if lerr != "" {
			note += "  last_err=" + lerr
		}
		row(n.addr, geoTCPRTT(n.addr), connect, total, cc, note)
	}

	if hopSocks5 != "" && hopSocks5 != cur {
		_, cc, connect, total := geoProbe(func(ctx context.Context) (net.Conn, error) {
			return dialSocks5(ctx, hopSocks5, "ip-api.com:80")
		})
		row(hopSocks5+" (shared hop)", geoTCPRTT(hopSocks5), connect, total, cc, "")
	}

	fmt.Fprintf(w, "\nอ่านผล: 'total' ที่เกิน direct มาก ๆ = tunnel นั้นช้า (pool จะหมุนออกเองเมื่อช้าเกิน %v ติดกัน %d ครั้ง)\n",
		geoPoolMaxRTT, geoPoolSlowHits)
}

// serveGeoCheck renders the geo routing state plus the real egress IP/country
// for both paths — the quickest way to prove what OmeTV will see.
func serveGeoCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	fmt.Fprintf(w, "netninja geo-check (build %s)\n\n", buildTime)
	fmt.Fprintf(w, "expect country : %s\n", geoExpectCountry())
	fmt.Fprintf(w, "strict         : %v (fail instead of exiting this server's country)\n", geoPoolStrict)
	fmt.Fprintf(w, "domain list    : %s\n", geoDomainsStatus())
	fmt.Fprintf(w, "session mode   : %s (ttl %v, ads egress for every client: %v, %d marked now)\n",
		geoSessionMode, geoSessionTTL, geoAdsGlobal, atomic.LoadInt64(&geoSessionLive))
	fmt.Fprintf(w, "hop socks5     : %q (non-geo hop domains)\n", hopSocks5)
	fmt.Fprintf(w, "hop domains    : %d configured, %d auto-detected\n", len(hopDomains), len(hopAuto))
	fmt.Fprintf(w, "geo domains(%d): %s\n\n", geoDomainCount(), strings.Join(geoDomainList(), ", "))

	if nodes := geoPoolStatusLines(); len(nodes) > 0 {
		fmt.Fprintf(w, "egress pool (%d node(s), current %s):\n%s\n\n", len(nodes), geoPoolCurrentAddr(), strings.Join(nodes, "\n"))
	} else {
		fmt.Fprintf(w, "egress pool    : none configured (set GEO_SOCKS5_POOL)\n\n")
	}

	fmt.Fprintf(w, "direct egress  : %s\n", geoLookupCountry(func(ctx context.Context) (net.Conn, error) {
		return customDialer.DialContext(ctx, "tcp", "ip-api.com:80")
	}))
	if server := geoSocks5(); server == "" {
		fmt.Fprintf(w, "geo egress     : n/a (GEO_SOCKS5_POOL / GEO_SOCKS5 / HOP_SOCKS5 not set)\n")
	} else {
		fmt.Fprintf(w, "geo egress     : %s via %s\n", geoLookupCountry(func(ctx context.Context) (net.Conn, error) {
			return dialSocks5(ctx, server, "ip-api.com:80")
		}), server)
	}
	fmt.Fprintf(w, "\nguard          : %s\n", geoGuardStatus())
	fmt.Fprintf(w, "\nGeo-listed domains — and everything a geo session loads — egress Thai; the rest goes direct.\n")
}

// ===========================================================================
// Geo country guard
//
// A shared hop can silently start exiting in another country (VPNGate rotates
// to whatever node is alive when the Thai one dies). That stays invisible until
// OmeTV starts matching the wrong peers again, so the guard re-checks the hop's
// country every GEO_GUARD_INTERVAL and rotates the egress when it drifts.
//
//   GEO_GUARD=0                turn the guard off (default: on)
//   GEO_ROTATE_CMD=...         rotate command, default:
//                              /bin/bash /opt/vpngate/vpngate-rotate.sh --force
//   GEO_GUARD_INTERVAL=5m      how often the hop's country is checked
//   GEO_GUARD_FIRST_DELAY=45s  wait before the first check (let boot settle)
//   GEO_GUARD_COOLDOWN=3m      minimum gap between rotations
//   GEO_GUARD_MAX_PER_HOUR=6   back off 30m after this many rotations
// ===========================================================================

var (
	geoGuardOn        bool
	geoRotateCmd      []string
	geoGuardInterval  = 5 * time.Minute
	geoGuardFirstWait = 45 * time.Second
	geoGuardCooldown  = 3 * time.Minute
	geoGuardMaxPerHr  = 6

	geoGuardMu        sync.Mutex
	geoGuardBusy      int32
	geoGuardLastCheck time.Time
	geoGuardLastCC    string
	geoGuardBadStreak int
	geoGuardRotations []time.Time
	geoGuardBackoff   time.Time
)

func geoGuardEnvDur(key string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return d
	}
	if n, err := strconv.Atoi(v); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return def
}

func initGeoGuard() {
	if geoDomainsOff || geoDomainCount() == 0 {
		return
	}
	if !geoPoolOn && geoSocks5() == "" {
		log.Printf("%s[GEO][guard]%s no egress configured — guard idle until GEO_SOCKS5_POOL/GEO_SOCKS5 is set", colorYellow, colorReset)
		return
	}
	if v := strings.TrimSpace(os.Getenv("GEO_GUARD")); v == "0" || strings.EqualFold(v, "false") || strings.EqualFold(v, "off") {
		log.Printf("%s[GEO][guard]%s disabled by GEO_GUARD=%s", colorYellow, colorReset, v)
		return
	}
	geoGuardInterval = geoGuardEnvDur("GEO_GUARD_INTERVAL", geoGuardInterval)
	geoGuardFirstWait = geoGuardEnvDur("GEO_GUARD_FIRST_DELAY", geoGuardFirstWait)
	geoGuardCooldown = geoGuardEnvDur("GEO_GUARD_COOLDOWN", geoGuardCooldown)
	if n, err := strconv.Atoi(strings.TrimSpace(os.Getenv("GEO_GUARD_MAX_PER_HOUR"))); err == nil && n > 0 {
		geoGuardMaxPerHr = n
	}

	// The rotate command is optional now: the pool rotates between live Thai
	// nodes by itself, and only needs the server script to *rebuild* tunnels
	// when no Thai node is left at all.
	cmdStr := strings.TrimSpace(os.Getenv("GEO_ROTATE_CMD"))
	if cmdStr == "" && geoPoolOn {
		cmdStr = "/bin/bash /opt/vpngate/vpngate-rotate.sh --force"
	}
	fields := strings.Fields(cmdStr)
	if len(fields) > 0 {
		if _, err := exec.LookPath(fields[0]); err != nil {
			log.Printf("%s[GEO][guard]%s rotate command %q not found — the pool will still rotate between live nodes", colorYellow, colorReset, fields[0])
			fields = nil
		}
	}
	for i, f := range fields {
		if i > 0 && strings.HasPrefix(f, "/") && strings.HasSuffix(f, ".sh") {
			if _, err := os.Stat(f); err != nil {
				log.Printf("%s[GEO][guard]%s rotate script %s not found — tunnel rebuild disabled", colorYellow, colorReset, f)
				fields = nil
				break
			}
		}
	}
	geoRotateCmd = fields
	geoGuardOn = true
	if len(geoRotateCmd) > 0 {
		log.Printf("%s[GEO][guard]%s checking the egress every %v — rebuilds tunnels with %q when no %s node is healthy",
			colorGreen, colorReset, geoGuardInterval, strings.Join(geoRotateCmd, " "), geoExpectCountry())
	} else {
		log.Printf("%s[GEO][guard]%s checking the egress every %v — rotation stays inside the pool",
			colorGreen, colorReset, geoGuardInterval)
	}
}

func startGeoGuard() {
	if !geoGuardOn {
		return
	}
	go func() {
		time.Sleep(geoGuardFirstWait)
		for {
			geoGuardOnce()
			time.Sleep(geoGuardInterval)
		}
	}()
}

func geoGuardStatus() string {
	if !geoGuardOn {
		return "off"
	}
	geoGuardMu.Lock()
	defer geoGuardMu.Unlock()
	state := "enabled"
	if !geoGuardLastCheck.IsZero() {
		state = fmt.Sprintf("last check %s → %s", geoGuardLastCheck.Format("15:04:05"), geoGuardLastCC)
	}
	extra := ""
	if geoGuardBackoff.After(time.Now()) {
		extra = fmt.Sprintf(", backoff until %s", geoGuardBackoff.Format("15:04"))
	}
	return fmt.Sprintf("%s every %v, rotations(1h)=%d%s", state, geoGuardInterval, len(geoGuardRotations), extra)
}

func geoGuardHopCountry() (string, string) {
	return geoLookup(func(ctx context.Context) (net.Conn, error) {
		return dialSocks5(ctx, geoSocks5(), "ip-api.com:80")
	})
}

// geoNodeCountry reads the verified country of a pool node (empty when it has
// not been verified yet).
func geoNodeCountry(addr string) string {
	if addr == "" {
		return ""
	}
	for _, n := range geoPoolSnapshot() {
		if n.addr == addr {
			n.mu.Lock()
			defer n.mu.Unlock()
			return n.country
		}
	}
	return ""
}

func geoGuardOnce() {
	if !geoGuardOn || !atomic.CompareAndSwapInt32(&geoGuardBusy, 0, 1) {
		return
	}
	defer atomic.StoreInt32(&geoGuardBusy, 0)

	want := geoExpectCountry()
	now := time.Now()

	// Pool mode: the pool already rotates between live Thai nodes, so the guard
	// only has to act when *no* node is healthy (and then ask the server to
	// rebuild tunnels).
	if geoPoolOn {
		healthy := 0
		for _, n := range geoPoolSnapshot() {
			if n.healthy(want) {
				healthy++
			}
		}
		cc := geoNodeCountry(geoPoolCurrentAddr())

		geoGuardMu.Lock()
		geoGuardLastCheck = now
		if cc != "" {
			geoGuardLastCC = cc
		}
		geoGuardMu.Unlock()

		if healthy > 0 {
			geoGuardMu.Lock()
			recovered := geoGuardBadStreak > 0
			geoGuardBadStreak = 0
			geoGuardMu.Unlock()
			if recovered {
				log.Printf("%s[GEO][guard]%s %d healthy %s node(s) again — current %s exits %s",
					colorGreen, colorReset, healthy, want, geoPoolCurrentAddr(), geoCountryOrDash(cc))
			}
			return
		}

		geoGuardMu.Lock()
		geoGuardBadStreak++
		streak := geoGuardBadStreak
		geoGuardMu.Unlock()
		log.Printf("%s[GEO][guard]%s no healthy %s node in the pool (%d configured) streak=%d",
			colorYellow, colorReset, want, geoPoolSize(), streak)
		if streak < 2 {
			return
		}
		geoGuardRotate(now, fmt.Sprintf("no healthy %s egress in the pool (%d node(s))", want, geoPoolSize()))
		return
	}

	info, cc := geoGuardHopCountry()
	geoGuardMu.Lock()
	geoGuardLastCheck = now
	geoGuardLastCC = cc
	geoGuardMu.Unlock()

	if cc == want {
		geoGuardMu.Lock()
		recovered := geoGuardBadStreak > 0
		geoGuardBadStreak = 0
		geoGuardMu.Unlock()
		if recovered {
			log.Printf("%s[GEO][guard]%s egress is %s again — %s", colorGreen, colorReset, want, info)
		}
		return
	}

	geoGuardMu.Lock()
	geoGuardBadStreak++
	streak := geoGuardBadStreak
	geoGuardMu.Unlock()

	if cc == "" {
		// Hop unreachable: vpngate-watch already repairs a dead tunnel, so only
		// step in when it stays broken.
		log.Printf("%s[GEO][guard]%s hop not reachable (%s) streak=%d", colorYellow, colorReset, info, streak)
		if streak < 3 {
			return
		}
		geoGuardRotate(now, fmt.Sprintf("hop still unreachable (%s)", info))
		return
	}
	geoGuardRotate(now, fmt.Sprintf("WRONG COUNTRY: hop exits %s but %s is required", info, want))
}

func geoGuardRotate(now time.Time, reason string) {
	geoGuardMu.Lock()
	if now.Before(geoGuardBackoff) {
		until := geoGuardBackoff
		geoGuardMu.Unlock()
		log.Printf("%s[GEO][guard]%s %s — rotation in cooldown until %s", colorYellow, colorReset, reason, until.Format("15:04:05"))
		return
	}
	cut := now.Add(-time.Hour)
	keep := geoGuardRotations[:0]
	for _, t := range geoGuardRotations {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	geoGuardRotations = keep
	if len(geoGuardRotations) >= geoGuardMaxPerHr {
		geoGuardBackoff = now.Add(30 * time.Minute)
		n := len(geoGuardRotations)
		geoGuardMu.Unlock()
		log.Printf("%s[GEO][guard]%s rotated %d time(s) in the last hour already — cooling down 30m (no usable %s node?)",
			colorRed, colorReset, n, geoExpectCountry())
		recordAdminLog("geo-guard", "rotate-cooldown", geoSocks5(), fmt.Sprintf("%d rotations in the last hour", n))
		return
	}
	geoGuardRotations = append(geoGuardRotations, now)
	geoGuardBackoff = now.Add(geoGuardCooldown)
	geoGuardMu.Unlock()

	if len(geoRotateCmd) == 0 {
		log.Printf("%s[GEO][guard]%s %s — no rotate command configured, waiting for the pool to recover", colorYellow, colorReset, reason)
		recordAdminLog("geo-guard", "rotate-skipped", geoSocks5(), reason)
		return
	}

	log.Printf("%s[GEO][guard]%s %s — rotating egress", colorYellow, colorReset, reason)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, geoRotateCmd[0], geoRotateCmd[1:]...)
	cmd.Env = append(os.Environ(), "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	out, err := cmd.CombinedOutput()
	tail := geoLastLines(string(out), 6)
	if err != nil {
		log.Printf("%s[GEO][guard]%s rotate failed: %v\n%s", colorRed, colorReset, err, tail)
		recordAdminLog("geo-guard", "rotate-fail", geoSocks5(), fmt.Sprintf("%v | %s", err, tail))
		return
	}
	log.Printf("%s[GEO][guard]%s rotate finished\n%s", colorGreen, colorReset, tail)
	recordAdminLog("geo-guard", "rotate", geoSocks5(), tail)

	// Give the tunnel a moment, then confirm the country actually changed.
	time.Sleep(10 * time.Second)
	if geoPoolOn {
		for _, n := range geoPoolSnapshot() {
			geoVerifyNode(n)
		}
		if best := pickGeoNode(nil); best != nil {
			geoGuardMu.Lock()
			geoGuardBadStreak = 0
			geoGuardLastCheck = time.Now()
			geoGuardMu.Unlock()
			log.Printf("%s[GEO][guard]%s recovered — egress is now %s", colorGreen, colorReset, best.addr)
			return
		}
		log.Printf("%s[GEO][guard]%s still no healthy %s node after rotating — next attempt after cooldown",
			colorYellow, colorReset, geoExpectCountry())
		return
	}
	info, cc := geoGuardHopCountry()
	if cc == geoExpectCountry() {
		geoGuardMu.Lock()
		geoGuardBadStreak = 0
		geoGuardLastCheck = time.Now()
		geoGuardLastCC = cc
		geoGuardMu.Unlock()
		log.Printf("%s[GEO][guard]%s recovered — egress is now %s", colorGreen, colorReset, info)
		return
	}
	log.Printf("%s[GEO][guard]%s still not %s after rotating (%s) — next attempt after cooldown",
		colorYellow, colorReset, geoExpectCountry(), info)
}

func geoLastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
