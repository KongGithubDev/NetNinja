package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

var (
	portFlag    = flag.String("port", "443", "Listen port")
	uuidFlag    = flag.String("uuid", "b831381d-6324-4d53-ad4f-8cda48b30811", "VLESS UUID")
	pathFlag    = flag.String("path", "/", "WebSocket Path")
	webSNIFlag  = flag.String("web-sni", "", "Proxy these SNIs to real web server (e.g. your-domain.com)")
	webPortFlag = flag.String("web-port", "8443", "Local web server port proxy destination")
	tlsFlag     = flag.Bool("tls", true, "Enable internal TLS termination for VPN")
)

var (
	expectedUUID   []byte
	netActiveConns int64
	netTotalReqs   int64
	netStartTime   time.Time
	netClientsMu   sync.Mutex
	netDashClients = make(map[*websocket.Conn]bool)
)

var netUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func init() {
	flag.Parse()
	// Override with environment variables if present
	if envPort := os.Getenv("NET_PORT"); envPort != "" {
		*portFlag = envPort
	}
	if envUUID := os.Getenv("NET_UUID"); envUUID != "" {
		*uuidFlag = envUUID
	}
	if envPath := os.Getenv("NET_PATH"); envPath != "" {
		*pathFlag = envPath
	}
	if envWebSNI := os.Getenv("NET_WEB_SNI"); envWebSNI != "" {
		*webSNIFlag = envWebSNI
	}
	if envWebPort := os.Getenv("NET_WEB_PORT"); envWebPort != "" {
		*webPortFlag = envWebPort
	}
	if envTLS := os.Getenv("NET_TLS"); envTLS != "" {
		if envTLS == "false" || envTLS == "0" {
			*tlsFlag = false
		} else {
			*tlsFlag = true
		}
	}
	u := strings.ReplaceAll(*uuidFlag, "-", "")
	var err error
	expectedUUID, err = hex.DecodeString(u)
	if err != nil || len(expectedUUID) != 16 {
		log.Fatalf("Invalid UUID format: %v", *uuidFlag)
	}
}

// wsConnAdapter wraps websocket.Conn to act as a standard net.Conn
type wsConnAdapter struct {
	*websocket.Conn
	r io.Reader
}

func (c *wsConnAdapter) Read(b []byte) (int, error) {
	if c.r == nil {
		for {
			msgType, reader, err := c.Conn.NextReader()
			if err != nil {
				return 0, err
			}
			if msgType == websocket.BinaryMessage || msgType == websocket.TextMessage {
				c.r = reader
				break
			}
		}
	}
	n, err := c.r.Read(b)
	if err == io.EOF {
		c.r = nil
		if n > 0 {
			return n, nil
		}
		return c.Read(b) // read from next message
	}
	return n, err
}

func (c *wsConnAdapter) Write(b []byte) (int, error) {
	err := c.Conn.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *wsConnAdapter) LocalAddr() net.Addr  { return c.Conn.LocalAddr() }
func (c *wsConnAdapter) RemoteAddr() net.Addr { return c.Conn.RemoteAddr() }
func (c *wsConnAdapter) SetDeadline(t time.Time) error {
	c.Conn.SetReadDeadline(t)
	return c.Conn.SetWriteDeadline(t)
}
func (c *wsConnAdapter) SetReadDeadline(t time.Time) error  { return c.Conn.SetReadDeadline(t) }
func (c *wsConnAdapter) SetWriteDeadline(t time.Time) error { return c.Conn.SetWriteDeadline(t) }

// handleVLESS handles the VLESS over WebSocket protocol
func handleVLESS(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		// Not a websocket connection, do not upgrade
		return
	}

	atomic.AddInt64(&netTotalReqs, 1)
	conn, err := netUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	atomic.AddInt64(&netActiveConns, 1)
	defer func() {
		atomic.AddInt64(&netActiveConns, -1)
		conn.Close()
	}()

	wsAdapter := &wsConnAdapter{Conn: conn}

	// Set a deadline for the VLESS handshake to prevent half-open connection leaks
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// 1 byte ver
	ver := make([]byte, 1)
	if _, err := io.ReadFull(wsAdapter, ver); err != nil {
		return
	}
	if ver[0] != 0 {
		return // only version 0 is supported
	}

	// 16 bytes UUID
	clientUUID := make([]byte, 16)
	if _, err := io.ReadFull(wsAdapter, clientUUID); err != nil {
		return
	}

	if !bytes.Equal(clientUUID, expectedUUID) {
		log.Printf("[ERR] Unauthorized UUID attempt: %x", clientUUID)
		return
	}

	// 1 byte addon length
	addonLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(wsAdapter, addonLenBuf); err != nil {
		return
	}
	if addonLenBuf[0] > 0 {
		addon := make([]byte, addonLenBuf[0])
		if _, err := io.ReadFull(wsAdapter, addon); err != nil {
			return
		}
	}

	// 1 byte command (1: TCP, 2: UDP)
	cmdBuf := make([]byte, 1)
	if _, err := io.ReadFull(wsAdapter, cmdBuf); err != nil {
		return
	}
	cmd := int(cmdBuf[0])

	// 2 bytes port
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(wsAdapter, portBuf); err != nil {
		return
	}
	targetPort := int(portBuf[0])<<8 | int(portBuf[1])

	// 1 byte address type (1: IPv4, 2: Domain, 3: IPv6)
	atypBuf := make([]byte, 1)
	if _, err := io.ReadFull(wsAdapter, atypBuf); err != nil {
		return
	}
	atyp := int(atypBuf[0])

	var targetHost string
	switch atyp {
	case 1:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(wsAdapter, ip); err != nil {
			return
		}
		targetHost = fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
	case 2:
		domainLenBuf := make([]byte, 1)
		if _, err := io.ReadFull(wsAdapter, domainLenBuf); err != nil {
			return
		}
		domain := make([]byte, int(domainLenBuf[0]))
		if _, err := io.ReadFull(wsAdapter, domain); err != nil {
			return
		}
		targetHost = string(domain)
	case 3:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(wsAdapter, ip); err != nil {
			return
		}
		targetHost = net.IP(ip).String()
	default:
		return
	}

	targetAddr := fmt.Sprintf("%s:%d", targetHost, targetPort)
	log.Printf("[VLESS] Connecting to %s (CMD: %d)", targetAddr, cmd)

	// Send VLESS response
	// Version: 0, Addon length: 0
	wsAdapter.Write([]byte{0, 0})

	// Handshake successful, clear the read deadline for normal tunnel operation
	conn.SetReadDeadline(time.Time{})

	if cmd == 1 {
		// TCP Processing
		dest, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
		if err != nil {
			log.Printf("[ERR] Failed to dial TCP %s: %v", targetAddr, err)
			return
		}
		defer dest.Close()

		errc := make(chan error, 2)
		go func() {
			_, err := io.Copy(dest, wsAdapter)
			if tcpConn, ok := dest.(*net.TCPConn); ok {
				tcpConn.CloseWrite()
			}
			errc <- err
		}()
		go func() {
			_, err := io.Copy(wsAdapter, dest)
			// When the destination closes, force close the websocket to break the other io.Copy
			conn.Close()
			errc <- err
		}()
		<-errc
	} else if cmd == 2 {
		// UDP Processing (DNS, etc.)
		dest, err := net.DialTimeout("udp", targetAddr, 10*time.Second)
		if err != nil {
			log.Printf("[ERR] Failed to dial UDP %s: %v", targetAddr, err)
			return
		}
		defer dest.Close()

		errc := make(chan error, 2)
		go func() {
			buf := make([]byte, 65535)
			for {
				n, err := dest.Read(buf)
				if err != nil {
					errc <- err
					return
				}
				// Write VLESS UDP payload: 2 byte length + payload
				lenBuf := []byte{byte(n >> 8), byte(n & 0xff)}
				wsAdapter.Write(append(lenBuf, buf[:n]...))
			}
		}()

		go func() {
			lb := make([]byte, 2)
			for {
				// Read 2 byte length
				if _, err := io.ReadFull(wsAdapter, lb); err != nil {
					conn.Close()
					errc <- err
					return
				}
				n := int(lb[0])<<8 | int(lb[1])
				pkt := make([]byte, n)
				if _, err := io.ReadFull(wsAdapter, pkt); err != nil {
					conn.Close()
					errc <- err
					return
				}
				dest.Write(pkt)
			}
		}()
		<-errc
	}
}

type MemListener struct {
	conns chan net.Conn
	addr  net.Addr
}

func (m *MemListener) Accept() (net.Conn, error) {
	if c, ok := <-m.conns; ok {
		return c, nil
	}
	return nil, io.EOF
}
func (m *MemListener) Close() error   { close(m.conns); return nil }
func (m *MemListener) Addr() net.Addr { return m.addr }

type peekedConn struct {
	net.Conn
	r io.Reader
}

func (c *peekedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func handleConnection(conn net.Conn, webSNIs map[string]bool, webPort string, tlsConfig *tls.Config, httpMap chan net.Conn) {
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)

	hdr, err := reader.Peek(5)
	if err != nil {
		conn.SetReadDeadline(time.Time{})
		if hdr != nil && len(hdr) > 0 {
			httpMap <- &peekedConn{Conn: conn, r: reader}
		} else {
			conn.Close()
		}
		return
	}

	var proxyToWeb bool
	var sni string
	isTLS := hdr[0] == 0x16

	if isTLS {
		length := int(hdr[3])<<8 | int(hdr[4])
		if length <= 8192 {
			record, err := reader.Peek(5 + length)
			if err == nil {
				sni = readSNI(record)
			}
		}
	}

	conn.SetReadDeadline(time.Time{})

	if sni != "" && webSNIs[sni] {
		proxyToWeb = true
	}

	// Detect if it is a plain HTTP request hitting the HTTPS port
	var isPlainHTTP bool
	if len(hdr) >= 4 {
		methodStr := string(hdr[:4])
		// Matches GET, POST, PUT, HEAD, OPTIONS, DELETE, CONNECT, TRACE
		if methodStr == "GET " || methodStr == "POST" || methodStr == "PUT " ||
			methodStr == "HEAD" || methodStr == "OPTI" || methodStr == "DELE" ||
			methodStr == "CONN" || methodStr == "TRAC" {
			isPlainHTTP = true
		}
	}

	peekConn := &peekedConn{Conn: conn, r: reader}

	if proxyToWeb {
		dest, err := net.DialTimeout("tcp", "127.0.0.1:"+webPort, 5*time.Second)
		if err != nil {
			log.Printf("[SNI] Proxy to %s failed: %v", webPort, err)
			conn.Close()
			return
		}
		go func() {
			io.Copy(dest, peekConn)
			dest.Close()
		}()
		go func() {
			io.Copy(peekConn, dest)
			peekConn.Close()
		}()
		return
	}

	if isPlainHTTP {
		// Pass directly to the internal Go HTTP server without TLS wrapper
		// This ensures requests hitting the direct port via HTTP reach the dashboard cleanly
		httpMap <- peekConn
		return
	} else if isTLS && tlsConfig != nil {
		tlsConn := tls.Server(peekConn, tlsConfig)
		httpMap <- tlsConn
	} else {
		httpMap <- peekConn
	}
}

func readSNI(data []byte) string {
	if len(data) < 44 || data[0] != 0x16 || data[5] != 0x01 {
		return ""
	}
	pos := 43
	if pos >= len(data) {
		return ""
	}
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen
	if pos+1 >= len(data) {
		return ""
	}
	cipherSuitesLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + cipherSuitesLen
	if pos >= len(data) {
		return ""
	}
	compressionMethodsLen := int(data[pos])
	pos += 1 + compressionMethodsLen
	if pos+1 >= len(data) {
		return ""
	}
	extensionsLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2
	end := pos + extensionsLen
	if end > len(data) {
		end = len(data)
	}
	for pos+3 < end {
		extType := int(data[pos])<<8 | int(data[pos+1])
		extLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4
		if extType == 0x0000 {
			if pos+4 < pos+extLen && data[pos+2] == 0x00 {
				nameLen := int(data[pos+3])<<8 | int(data[pos+4])
				if pos+5+nameLen <= pos+extLen {
					return string(data[pos+5 : pos+5+nameLen])
				}
			}
			break
		}
		pos += extLen
	}
	return ""
}

func generateDummyCert() (*tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"NetNinja VPN"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}
	return &cert, nil
}

func broadcastStats() {
	ticker := time.NewTicker(1 * time.Second)
	for range ticker.C {
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)

		upSecs := int(time.Since(netStartTime).Seconds())
		uptime := fmt.Sprintf("%dh %02dm %02ds", upSecs/3600, (upSecs%3600)/60, upSecs%60)

		stat := map[string]interface{}{
			"uptime":      uptime,
			"users":       atomic.LoadInt64(&netActiveConns),
			"active_conn": atomic.LoadInt64(&netActiveConns),
			"total_req":   atomic.LoadInt64(&netTotalReqs),
			"mem_heap":    fmt.Sprintf("%.1f MB", float64(ms.Alloc)/1024/1024),
			"mem_sys":     fmt.Sprintf("%.1f MB", float64(ms.Sys)/1024/1024),
			"goroutines":  runtime.NumGoroutine(),
			"go_ver":      runtime.Version(),
			"cpus":        runtime.NumCPU(),
			"rules":       len(strings.Split(*webSNIFlag, ",")),
		}

		payload, _ := json.Marshal(stat)

		netClientsMu.Lock()
		for c := range netDashClients {
			if err := c.WriteMessage(websocket.TextMessage, payload); err != nil {
				c.Close()
				delete(netDashClients, c)
			}
		}
		netClientsMu.Unlock()
	}
}

func main() {
	netStartTime = time.Now()
	go broadcastStats()

	if *pathFlag != "/" {
		http.HandleFunc(*pathFlag, func(w http.ResponseWriter, r *http.Request) {
			if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
				handleVLESS(w, r)
				return
			}
			// Fallback to Dashboard if accessing VLESS path directly in browser
			serveDashboard(w, r)
		})
	}

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := netUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		netClientsMu.Lock()
		netDashClients[conn] = true
		netClientsMu.Unlock()
	})

	// Default handler serving the Dashboard or VLESS (if path is /)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// If VLESS is configured on the root path
		if r.URL.Path == *pathFlag {
			if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
				handleVLESS(w, r)
				return
			}
		}

		serveDashboard(w, r)
	})

	var tlsConfig *tls.Config
	if *tlsFlag {
		cert, err := generateDummyCert()
		if err != nil {
			log.Fatalf("Failed to generate cert: %v", err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{*cert},
		}
	}

	webSNIs := make(map[string]bool)
	for _, s := range strings.Split(*webSNIFlag, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			webSNIs[s] = true
		}
	}

	listener, err := net.Listen("tcp", "0.0.0.0:"+*portFlag)
	if err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}

	memListener := &MemListener{
		conns: make(chan net.Conn, 1024),
		addr:  listener.Addr(),
	}

	go func() {
		err := http.Serve(memListener, nil)
		if err != nil {
			log.Fatalf("HTTP Serve error: %v", err)
		}
	}()

	log.Printf("========================================")
	log.Printf("       NetNinja VLESS VPN Server        ")
	log.Printf("             SNI Multiplexer            ")
	log.Printf("========================================")
	log.Printf("  Port     : %s", *portFlag)
	log.Printf("  UUID     : %s", *uuidFlag)
	log.Printf("  Path     : %s", *pathFlag)
	log.Printf("  Web SNI  : %s", *webSNIFlag)
	log.Printf("  Web Port : %s", *webPortFlag)
	log.Printf("  TLS      : %v", *tlsFlag)
	log.Printf("========================================")
	log.Printf("Server listening on 0.0.0.0:%s ...", *portFlag)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleConnection(conn, webSNIs, *webPortFlag, tlsConfig, memListener.conns)
	}
}

func serveDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	dashHTML := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>net_server dashboard [v1.1]</title>
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
.section-title{color:#444;font-size:10px;text-transform:uppercase;letter-spacing:1px;margin:25px 0 10px}
.footer{margin-top:40px;font-size:11px;color:#333}
.footer a{color:#555;text-decoration:none}
.footer a:hover{color:#7af}
</style>
</head>
<body>
<div class="w">
	<h1><span>●</span> net_server edge</h1>
	<div class="sub">sni_multiplexer_interface</div>

	<div class="section-title">core_metrics</div>
	<div class="row"><span class="k">uptime</span><span class="v" id="uptime">--</span></div>
	<div class="row"><span class="k">vpn_active_conns</span><span class="v num" id="active">0</span></div>
	<div class="row"><span class="k">total_requests</span><span class="v num" id="total">0</span></div>

	<div class="section-title">memory_runtime</div>
	<div class="row"><span class="k">heap_alloc</span><span class="v" id="mem_heap">--</span></div>
	<div class="row"><span class="k">sys_total</span><span class="v" id="mem_sys">--</span></div>
	<div class="row"><span class="k">goroutines</span><span class="v" id="goroutines">0</span></div>
	<div class="row"><span class="k">runtime_env</span><span class="v" id="go_ver" style="font-size:10px;color:#555">--</span></div>

	<div class="section-title">multiplexer_config</div>
	<div class="row"><span class="k">protected_vless_port</span><span class="v">%s</span></div>
	<div class="row"><span class="k">passthrough_web_port</span><span class="v">%s</span></div>
	<div class="row"><span class="k">routed_sni_domains</span><span class="v" id="rules">0</span></div>

	<div class="footer">
		<span id="ws_status" style="color:#444">connecting_ws...</span>
		<div style="margin-top:15px;color:#222;font-size:10px;text-transform:uppercase;letter-spacing:1px">
			vless_core // sniper_engine
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
			updateVal('active', d.active_conn);
			updateVal('total', d.total_req);
			updateVal('mem_heap', d.mem_heap);
			updateVal('mem_sys', d.mem_sys);
			updateVal('goroutines', d.goroutines);
			updateVal('rules', d.rules);
			updateVal('go_ver', d.go_ver + ' (' + d.cpus + ' CPUs)');
		};
	};
	connect();
</script>
</body>
</html>`, *portFlag, *webPortFlag)
	w.Write([]byte(dashHTML))
}
