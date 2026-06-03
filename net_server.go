package main

import (
	"bufio"
	"bytes"
	"context"
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
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// bufferPool for UDP: 4KB (handles all DNS responses without truncation)
var bufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 4096)
		return &b
	},
}

// copyBufferPool: 512KB for high-throughput streaming
var copyBufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 512*1024)
		return &b
	},
}

var (
	portFlag    = flag.String("port", "443", "Listen port")
	uuidFlag    = flag.String("uuid", "b831381d-6324-4d53-ad4f-8cda48b30811", "VLESS UUID")
	pathFlag    = flag.String("path", "/", "WebSocket Path")
	webSNIFlag  = flag.String("web-sni", "", "Proxy these SNIs to real web server (e.g. your-domain.com)")
	webPortFlag = flag.String("webport", "8443", "Local web server port")
	tlsFlag     = flag.Bool("tls", true, "Enable internal TLS termination")
	certFlag    = flag.String("cert", "", "Path to real SSL certificate (fullchain.pem)")
	keyFlag     = flag.String("key", "", "Path to real SSL private key (privkey.pem)")
	pacFlag     = flag.String("pac", "/proxy.pac", "PAC file path")
	proxyAddr   = flag.String("proxy-addr", "", "Override proxy address in PAC (e.g. your-domain.com)")
	udpPortFlag = flag.String("udp-port", "*auto", "UDP port for QUIC/HTTP3 NAT relay (*auto = same as -port)")
)

var (
	expectedUUID   []byte
	netActiveConns int64
	netTotalReqs   int64
	netBytesUp     int64
	netBytesDown   int64
	netStartTime   time.Time
	netClientsMu   sync.Mutex
	netDashClients = make(map[*websocket.Conn]bool)
)

// Bandwidth history ring buffer (60 samples = 5 min at 5s intervals)
var (
	bwMu   sync.Mutex
	bwIdx  int
	bwHist [60][2]int64
)

// CDN access tracking
var cdnAccess sync.Map

type cdnEntry struct {
	Host  string `json:"host"`
	Count int64  `json:"count"`
}

// Active destinations tracked for dashboard
var activeDests sync.Map

var (
	netDnsCache  sync.Map
	dnsExpiry    = 5 * time.Minute
	videoDNSExtra = 30 * time.Second
)

type netDnsEntry struct {
	ip     string
	expiry time.Time
}

var nitroDialer = &net.Dialer{
	Timeout:   10 * time.Second,
	KeepAlive: 30 * time.Second,
	Resolver: &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return net.DialTimeout("udp", "8.8.8.8:53", 2*time.Second)
		},
	},
}

func nitroDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nitroDialer.DialContext(ctx, network, address)
	}
	if net.ParseIP(host) != nil {
		return nitroDialer.DialContext(ctx, network, address)
	}
	host = netUnwrapCiscoDomain(host)
	effectiveTTL := dnsExpiry
	if isVideoDomain(host) {
		effectiveTTL = videoDNSExtra
	}
	if v, ok := netDnsCache.Load(host); ok {
		entry := v.(netDnsEntry)
		if time.Now().Before(entry.expiry) {
			return nitroDialer.DialContext(ctx, network, net.JoinHostPort(entry.ip, port))
		}
		netDnsCache.Delete(host)
	}
	ips, err := nitroDialer.Resolver.LookupHost(ctx, host)
	if err == nil && len(ips) > 0 {
		netDnsCache.Store(host, netDnsEntry{ip: ips[0], expiry: time.Now().Add(effectiveTTL)})
		return nitroDialer.DialContext(ctx, network, net.JoinHostPort(ips[0], port))
	}
	ipv4, ipv6, _ := netResolveDoHFull(host)
	if ipv4 != "" {
		netDnsCache.Store(host, netDnsEntry{ip: ipv4, expiry: time.Now().Add(effectiveTTL)})
		return nitroDialer.DialContext(ctx, network, net.JoinHostPort(ipv4, port))
	}
	if ipv6 != "" {
		netDnsCache.Store(host, netDnsEntry{ip: ipv6, expiry: time.Now().Add(effectiveTTL)})
		return nitroDialer.DialContext(ctx, network, net.JoinHostPort(ipv6, port))
	}
	return nitroDialer.DialContext(ctx, network, address)
}

func netResolveDoHFull(host string) (string, string, error) {
	urls := []string{
		"https://cloudflare-dns.com/dns-query?name=" + host + "&type=A",
		"https://cloudflare-dns.com/dns-query?name=" + host + "&type=AAAA",
		"https://dns.google/resolve?name=" + host + "&type=A",
		"https://dns.google/resolve?name=" + host + "&type=AAAA",
	}
	client := &http.Client{Timeout: 3 * time.Second}
	var ipv4, ipv6 string
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
			for _, ans := range res.Answer {
				if ans.Type == 1 && ipv4 == "" {
					ipv4 = ans.Data
				} else if ans.Type == 28 && ipv6 == "" {
					ipv6 = ans.Data
				}
			}
			if ipv4 != "" && ipv6 != "" {
				break
			}
			continue
		}
		resp.Body.Close()
	}
	return ipv4, ipv6, nil
}

func netUnwrapCiscoDomain(host string) string {
	if !strings.Contains(host, ".sse.cisco-secure.com") {
		return host
	}
	if idx := strings.Index(host, ".x."); idx != -1 {
		return host[:idx]
	}
	return host
}

type countingWriter struct {
	w     io.Writer
	count *int64
}

func (cw *countingWriter) Write(b []byte) (int, error) {
	n, err := cw.w.Write(b)
	atomic.AddInt64(cw.count, int64(n))
	return n, err
}

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

var nitroTransport = &http.Transport{
	DialContext:           nitroDial,
	MaxIdleConns:          1000,
	MaxIdleConnsPerHost:   100,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

var netUpgrader = websocket.Upgrader{
	CheckOrigin:     func(r *http.Request) bool { return true },
	ReadBufferSize:  64 * 1024,
	WriteBufferSize: 64 * 1024,
}

func init() {
	flag.Parse()
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
	if envCert := os.Getenv("NET_CERT"); envCert != "" {
		*certFlag = envCert
	}
	if envKey := os.Getenv("NET_KEY"); envKey != "" {
		*keyFlag = envKey
	}
	if envProxyAddr := os.Getenv("NET_PROXY_ADDR"); envProxyAddr != "" {
		*proxyAddr = envProxyAddr
	}
	u := strings.ReplaceAll(*uuidFlag, "-", "")
	var err error
	expectedUUID, err = hex.DecodeString(u)
	if err != nil || len(expectedUUID) != 16 {
		log.Fatalf("Invalid UUID format: %v", *uuidFlag)
	}
}

type wsConnAdapter struct {
	*websocket.Conn
	r  io.Reader
	mu sync.Mutex
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
		return c.Read(b)
	}
	return n, err
}

func (c *wsConnAdapter) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
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

func handleVLESS(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
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
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	conn.SetPingHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(120 * time.Second))
		return conn.WriteControl(websocket.PongMessage, []byte{}, time.Now().Add(5*time.Second))
	})
	ver := make([]byte, 1)
	if _, err := io.ReadFull(wsAdapter, ver); err != nil {
		return
	}
	if ver[0] != 0 {
		return
	}
	clientUUID := make([]byte, 16)
	if _, err := io.ReadFull(wsAdapter, clientUUID); err != nil {
		return
	}
	if !bytes.Equal(clientUUID, expectedUUID) {
		log.Printf("[ERR] Unauthorized UUID attempt: %x", clientUUID)
		return
	}
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
	cmdBuf := make([]byte, 1)
	if _, err := io.ReadFull(wsAdapter, cmdBuf); err != nil {
		return
	}
	cmd := int(cmdBuf[0])
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(wsAdapter, portBuf); err != nil {
		return
	}
	targetPort := int(portBuf[0])<<8 | int(portBuf[1])
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

	// Track destination for dashboard
	if cmd == 1 && targetHost != "" {
		if isVideoDomain(targetHost) {
			v, _ := cdnAccess.LoadOrStore(targetHost, new(int64))
			atomic.AddInt64(v.(*int64), 1)
		}
		v, _ := activeDests.LoadOrStore(targetAddr, new(int64))
		atomic.AddInt64(v.(*int64), 1)
		defer func() {
			if v, ok := activeDests.Load(targetAddr); ok {
				atomic.AddInt64(v.(*int64), -1)
			}
		}()
	}

	conn.SetReadDeadline(time.Time{})
	wsAdapter.Write([]byte{0, 0})

	if cmd == 1 {
		dest, err := nitroDial(context.Background(), "tcp", targetAddr)
		if err != nil {
			log.Printf("[ERR] Failed to dial TCP %s: %v", targetAddr, err)
			return
		}
		defer dest.Close()
		if tcpConn, ok := dest.(*net.TCPConn); ok {
			tcpConn.SetNoDelay(true)
			tcpConn.SetKeepAlive(true)
			tcpConn.SetReadBuffer(512 * 1024)
			tcpConn.SetWriteBuffer(512 * 1024)
		}
		destUp := &countingWriter{w: dest, count: &netBytesUp}
		destDown := &countingWriter{w: wsAdapter, count: &netBytesDown}
		errc := make(chan error, 2)
		go func() {
			bufPtr := copyBufferPool.Get().(*[]byte)
			defer copyBufferPool.Put(bufPtr)
			_, err := io.CopyBuffer(destUp, wsAdapter, *bufPtr)
			if tcpConn, ok := dest.(*net.TCPConn); ok {
				tcpConn.CloseWrite()
			}
			errc <- err
		}()
		go func() {
			bufPtr := copyBufferPool.Get().(*[]byte)
			defer copyBufferPool.Put(bufPtr)
			_, err := io.CopyBuffer(destDown, dest, *bufPtr)
			conn.Close()
			errc <- err
		}()
		<-errc
	} else if cmd == 2 {
		dest, err := net.DialTimeout("udp", targetAddr, 10*time.Second)
		if err != nil {
			log.Printf("[ERR] Failed to dial UDP %s: %v", targetAddr, err)
			return
		}
		defer dest.Close()
		errc := make(chan error, 2)
		go func() {
			bufPtr := bufferPool.Get().(*[]byte)
			defer bufferPool.Put(bufPtr)
			buf := *bufPtr
			for {
				n, err := dest.Read(buf)
				if err != nil {
					errc <- err
					return
				}
				atomic.AddInt64(&netBytesDown, int64(n))
				fullMsg := make([]byte, 2+n)
				fullMsg[0] = byte(n >> 8)
				fullMsg[1] = byte(n & 0xff)
				copy(fullMsg[2:], buf[:n])
				wsAdapter.Write(fullMsg)
			}
		}()
		go func() {
			lb := make([]byte, 2)
			for {
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
				atomic.AddInt64(&netBytesUp, int64(n))
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
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetReadBuffer(512 * 1024)
		tcpConn.SetWriteBuffer(512 * 1024)
	}
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
	if sni != "" {
		if webSNIs[sni] {
			proxyToWeb = true
			log.Printf("[SNI] Routing %s to web port %s", sni, webPort)
		} else {
			log.Printf("[SNI] Detected: %s", sni)
		}
	}
	var isPlainHTTP bool
	if len(hdr) >= 4 {
		methodStr := string(hdr[:4])
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
		errc := make(chan error, 2)
		go func() {
			_, err := io.Copy(dest, peekConn)
			dest.Close()
			errc <- err
		}()
		go func() {
			_, err := io.Copy(peekConn, dest)
			peekConn.Close()
			errc <- err
		}()
		<-errc
		return
	}
	if isPlainHTTP {
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

func getTLSConfig() (*tls.Config, error) {
	if *certFlag != "" && *keyFlag != "" {
		cert, err := tls.LoadX509KeyPair(*certFlag, *keyFlag)
		if err == nil {
			log.Printf("[TLS] Using real certificate from: %s", *certFlag)
			return &tls.Config{
				Certificates: []tls.Certificate{cert},
				NextProtos:   []string{"h2", "http/1.1"},
			}, nil
		}
		log.Printf("[ERR] Failed to load real certificate: %v. Falling back to self-signed.", err)
	}
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
	tlsCert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}

func broadcastStats() {
	ticker := time.NewTicker(5 * time.Second)
	for range ticker.C {
		upSecs := int(time.Since(netStartTime).Seconds())
		uptime := fmt.Sprintf("%dh %02dm %02ds", upSecs/3600, (upSecs%3600)/60, upSecs%60)
		up := atomic.LoadInt64(&netBytesUp)
		down := atomic.LoadInt64(&netBytesDown)

		bwMu.Lock()
		bwHist[bwIdx] = [2]int64{up, down}
		bwIdx = (bwIdx + 1) % len(bwHist)
		bwUp := make([]float64, 0, len(bwHist))
		bwDown := make([]float64, 0, len(bwHist))
		for i := 0; i < len(bwHist); i++ {
			idx := (bwIdx + i) % len(bwHist)
			s := bwHist[idx]
			if s[0] == 0 && s[1] == 0 && i > 0 {
				break
			}
			prevIdx := (idx - 1 + len(bwHist)) % len(bwHist)
			prev := bwHist[prevIdx]
			if i == 0 && prev[0] == 0 && prev[1] == 0 {
				bwUp = append(bwUp, 0)
				bwDown = append(bwDown, 0)
				continue
			}
			upD := (s[0] - prev[0]) * 8 / 5
			downD := (s[1] - prev[1]) * 8 / 5
			if upD < 0 {
				upD = 0
			}
			if downD < 0 {
				downD = 0
			}
			bwUp = append(bwUp, float64(upD))
			bwDown = append(bwDown, float64(downD))
		}
		bwMu.Unlock()

		var topCDN []cdnEntry
		cdnAccess.Range(func(key, val interface{}) bool {
			host := key.(string)
			count := atomic.LoadInt64(val.(*int64))
			if count > 0 && isVideoDomain(host) {
				topCDN = append(topCDN, cdnEntry{Host: host, Count: count})
			}
			return true
		})
		for i := 0; i < len(topCDN); i++ {
			for j := i + 1; j < len(topCDN); j++ {
				if topCDN[j].Count > topCDN[i].Count {
					topCDN[i], topCDN[j] = topCDN[j], topCDN[i]
				}
			}
		}
		if len(topCDN) > 10 {
			topCDN = topCDN[:10]
		}

		type destStat struct {
			Dest  string `json:"dest"`
			Count int64  `json:"count"`
		}
		var dests []destStat
		activeDests.Range(func(key, val interface{}) bool {
			c := atomic.LoadInt64(val.(*int64))
			if c > 0 {
				dests = append(dests, destStat{Dest: key.(string), Count: c})
			}
			return true
		})
		for i := 0; i < len(dests); i++ {
			for j := i + 1; j < len(dests); j++ {
				if dests[j].Count > dests[i].Count {
					dests[i], dests[j] = dests[j], dests[i]
				}
			}
		}
		if len(dests) > 10 {
			dests = dests[:10]
		}

		stat := map[string]interface{}{
			"uptime":      uptime,
			"users":       atomic.LoadInt64(&netActiveConns),
			"active_conn": atomic.LoadInt64(&netActiveConns),
			"total_req":   atomic.LoadInt64(&netTotalReqs),
			"bytes_up":    up,
			"bytes_down":  down,
			"bw_up":       bwUp,
			"bw_down":     bwDown,
			"cdn":         topCDN,
			"dests":       dests,
			"mem_heap":    "Nitro-X",
			"mem_sys":     "Nitro-X",
			"goroutines":  runtime.NumGoroutine(),
			"go_ver":      runtime.Version(),
			"cpus":        runtime.NumCPU(),
			"udp_relays":  len(udpRelayEntries),
		}

		payload, _ := json.Marshal(stat)
		var clients []*websocket.Conn
		netClientsMu.Lock()
		for c := range netDashClients {
			clients = append(clients, c)
		}
		netClientsMu.Unlock()

		for _, c := range clients {
			go func(conn *websocket.Conn) {
				conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
				if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
					conn.Close()
					netClientsMu.Lock()
					delete(netDashClients, conn)
					netClientsMu.Unlock()
				}
			}(c)
		}
	}
}

func main() {
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
	netStartTime = time.Now()
	go broadcastStats()

	if *pathFlag != "/" {
		http.HandleFunc(*pathFlag, func(w http.ResponseWriter, r *http.Request) {
			if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
				handleVLESS(w, r)
				return
			}
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

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Host != "" {
			handleProxy(w, r)
			return
		}
		if r.URL.Path == *pacFlag {
			servePAC(w, r)
			return
		}
		if r.URL.Path == *pathFlag {
			if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
				handleVLESS(w, r)
				return
			}
		}
		serveDashboard(w, r)
	})

	if *pacFlag != "/" {
		http.HandleFunc(*pacFlag, servePAC)
	}
	http.HandleFunc("/proxy", handleProxy)

	var tlsConfig *tls.Config
	if *tlsFlag {
		var err error
		tlsConfig, err = getTLSConfig()
		if err != nil {
			log.Fatalf("Failed to get TLS config: %v", err)
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

	udpAddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:"+getUDPPort())
	if err == nil {
		udpListener, err := net.ListenUDP("udp", udpAddr)
		if err == nil {
			go startUDPRelay(udpListener)
		} else {
			log.Printf("[WARN] Failed to start UDP relay on :%s: %v (QUIC/HTTP3 relay disabled)", getUDPPort(), err)
		}
	}

	log.Printf("========================================")
	log.Printf("       NetNinja VLESS VPN Server        ")
	log.Printf("             SNI Multiplexer            ")
	log.Printf("             [NITRO-ULTRA]             ")
	log.Printf("========================================")
	log.Printf("  Port     : %s", *portFlag)
	log.Printf("  UUID     : %s", *uuidFlag)
	log.Printf("  Path     : %s", *pathFlag)
	log.Printf("  Web SNI  : %s", *webSNIFlag)
	log.Printf("  Web Port : %s", *webPortFlag)
	log.Printf("  TLS      : %v", *tlsFlag)
	log.Printf("  UDP Relay: %s (QUIC/HTTP3)", getUDPPort())
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

// ── UDP NAT Relay for QUIC/HTTP3 ──────────────────────────────────────────

type udpRelayEntry struct {
	clientAddr *net.UDPAddr
	remoteConn *net.UDPConn
	lastUse    time.Time
}

var (
	udpRelayMu      sync.Mutex
	udpRelayEntries = make(map[string]*udpRelayEntry)
	udpRelayBufPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 65535)
			return &b
		},
	}
)

func getUDPPort() string {
	if *udpPortFlag == "*auto" {
		return *portFlag
	}
	return *udpPortFlag
}

func startUDPRelay(listener *net.UDPConn) {
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		for range ticker.C {
			udpRelayMu.Lock()
			now := time.Now()
			for key, entry := range udpRelayEntries {
				if now.After(entry.lastUse.Add(5 * time.Minute)) {
					entry.remoteConn.Close()
					delete(udpRelayEntries, key)
				}
			}
			udpRelayMu.Unlock()
		}
	}()
	log.Printf("[UDP] QUIC/HTTP3 NAT relay listening on 0.0.0.0:%s", getUDPPort())
	for {
		bufPtr := udpRelayBufPool.Get().(*[]byte)
		buf := *bufPtr
		n, clientAddr, err := listener.ReadFromUDP(buf)
		if err != nil {
			udpRelayBufPool.Put(bufPtr)
			continue
		}
		packet := buf[:n]
		clientKey := clientAddr.String()

		udpRelayMu.Lock()
		entry, exists := udpRelayEntries[clientKey]
		udpRelayMu.Unlock()

		if exists {
			entry.lastUse = time.Now()
			entry.remoteConn.Write(packet)
			udpRelayBufPool.Put(bufPtr)
			continue
		}

		if n < 4 {
			udpRelayBufPool.Put(bufPtr)
			continue
		}

		destPort := int(packet[0])<<8 | int(packet[1])
		atyp := int(packet[2])
		var destHost string
		var offset int

		switch atyp {
		case 1:
			if n < 7 {
				udpRelayBufPool.Put(bufPtr)
				continue
			}
			destHost = net.IP(packet[3:7]).String()
			offset = 7
		case 2:
			if n < 4 {
				udpRelayBufPool.Put(bufPtr)
				continue
			}
			dlen := int(packet[3])
			if n < 4+dlen {
				udpRelayBufPool.Put(bufPtr)
				continue
			}
			destHost = string(packet[4 : 4+dlen])
			offset = 4 + dlen
		case 3:
			if n < 19 {
				udpRelayBufPool.Put(bufPtr)
				continue
			}
			destHost = net.IP(packet[3:19]).String()
			offset = 19
		default:
			udpRelayBufPool.Put(bufPtr)
			continue
		}

		destAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(destHost, fmt.Sprintf("%d", destPort)))
		if err != nil {
			udpRelayBufPool.Put(bufPtr)
			continue
		}

		remoteConn, err := net.DialUDP("udp", nil, destAddr)
		if err != nil {
			udpRelayBufPool.Put(bufPtr)
			continue
		}
		_ = remoteConn.SetReadBuffer(512 * 1024)
		_ = remoteConn.SetWriteBuffer(256 * 1024)

		entry = &udpRelayEntry{
			clientAddr: clientAddr,
			remoteConn: remoteConn,
			lastUse:    time.Now(),
		}

		var isWinner bool
		udpRelayMu.Lock()
		if _, existing := udpRelayEntries[clientKey]; !existing {
			udpRelayEntries[clientKey] = entry
			isWinner = true
		}
		udpRelayMu.Unlock()

		if !isWinner {
			remoteConn.Close()
			udpRelayBufPool.Put(bufPtr)
			continue
		}

		payload := packet[offset:]
		remoteConn.Write(payload)
		udpRelayBufPool.Put(bufPtr)

		go func(e *udpRelayEntry, key string) {
			defer func() {
				e.remoteConn.Close()
				udpRelayMu.Lock()
				delete(udpRelayEntries, key)
				udpRelayMu.Unlock()
			}()
			rbufPtr := udpRelayBufPool.Get().(*[]byte)
			defer udpRelayBufPool.Put(rbufPtr)
			rbuf := *rbufPtr
			for {
				e.remoteConn.SetReadDeadline(time.Now().Add(90 * time.Second))
				n, err := e.remoteConn.Read(rbuf)
				if err != nil {
					return
				}
				if _, err := listener.WriteToUDP(rbuf[:n], e.clientAddr); err != nil {
					return
				}
				e.lastUse = time.Now()
			}
		}(entry, clientKey)
	}
}

func servePAC(w http.ResponseWriter, r *http.Request) {
	host := *proxyAddr
	if host == "" {
		host = r.Host
	}
	if host == "" {
		host = "localhost"
	}
	if !strings.Contains(host, ":") {
		if *portFlag != "443" && *portFlag != "80" {
			host = net.JoinHostPort(host, *portFlag)
		} else if *portFlag == "443" {
			host = net.JoinHostPort(host, "443")
		}
	}
	proxyType := "PROXY"
	if *portFlag == "443" {
		proxyType = "HTTPS"
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
    return "%s %s; DIRECT";
}
`, proxyType, host)
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.Write([]byte(pac))
}

func handleProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		handleConnect(w, r)
		return
	}
	if !r.URL.IsAbs() {
		http.Error(w, "Proxy request required", http.StatusBadRequest)
		return
	}
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for k, vv := range r.Header {
		for _, v := range vv {
			outReq.Header.Add(k, v)
		}
	}
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	outReq.Header.Set("X-Forwarded-For", clientIP)
	resp, err := nitroTransport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func handleConnect(w http.ResponseWriter, r *http.Request) {
	dest, err := nitroDial(r.Context(), "tcp", r.Host)
	if err != nil {
		log.Printf("[ERR] Failed to proxy CONNECT %s: %v", r.Host, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer dest.Close()
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	client, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer client.Close()
	client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if tc, ok := dest.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}
	if tc, ok := client.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
	}
	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(dest, client)
		dest.Close()
		errc <- err
	}()
	go func() {
		_, err := io.Copy(client, dest)
		client.Close()
		errc <- err
	}()
	<-errc
}

func serveDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect || r.URL.IsAbs() {
		handleProxy(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write([]byte(fmt.Sprintf(dashHTML, *pacFlag)))
}

const dashHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>net_server · control_center [v2.0]</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0f;color:#c8d6e5;font:14px/1.5 'SF Mono','Cascadia Code','JetBrains Mono','Courier New',monospace;padding:30px 20px}
.w{max-width:800px;margin:0 auto}
h1{color:#e8e8f0;font-size:20px;font-weight:500;display:flex;align-items:center;gap:10px;margin-bottom:2px}
h1 .dot{width:10px;height:10px;border-radius:50%;background:#0f0;display:inline-block;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1;box-shadow:0 0 6px #0f0}50%{opacity:.6;box-shadow:0 0 2px #0f0}}
.sub{color:#5a6a7a;font-size:11px;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:28px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin:18px 0}
.card{background:#111118;border:1px solid #1a1a28;border-radius:8px;padding:16px}
.card.full{grid-column:1/-1}
.card-title{color:#5a6a7a;font-size:9px;text-transform:uppercase;letter-spacing:2px;margin-bottom:12px}
.row{display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid #14141e}
.row:last-child{border:none}
.row .k{color:#5a7a9a}
.row .v{color:#e0e8f0;font-weight:500}
.num{color:#00e676}
.num-warn{color:#ffab00}
.chart-wrap{position:relative;height:120px;margin:10px 0 0}
#bwChart{width:100%;height:120px;display:block;border-radius:4px}
.dest-list{display:flex;flex-wrap:wrap;gap:6px;margin-top:6px}
.dest-tag{background:#0d0d18;border:1px solid #1a1a2e;border-radius:4px;padding:4px 10px;font-size:11px;color:#7a9ab0;transition:.2s}
.dest-tag:hover{border-color:#2a4a6e;color:#c8e0f0}
.dest-tag .count{color:#00e676;margin-left:5px}
.cdn-tag{background:#0d0d18;border:1px solid #1a2a1e;border-radius:4px;padding:3px 8px;font-size:10px;color:#6aaa7a}
.cdn-tag .count{color:#4aee7a;margin-left:4px}
.pac-box{background:#0d0d18;border:1px solid #1a1a2e;border-radius:6px;padding:12px 14px;margin:12px 0}
.pac-box .label{color:#4a5a6a;font-size:9px;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:6px}
.pac-url{color:#4a9aee;word-break:break-all;font-size:12px;cursor:pointer;transition:.2s}
.pac-url:hover{color:#7abaff}
.pac-url::before{content:'📋 ';color:#5a6a7a}
.bw-legend{display:flex;gap:18px;margin:6px 0 0;font-size:10px;color:#5a6a7a}
.bw-legend span{display:flex;align-items:center;gap:5px}
.bw-legend .dl::before{content:'';display:inline-block;width:10px;height:3px;background:#4a9aee;border-radius:2px}
.bw-legend .ul::before{content:'';display:inline-block;width:10px;height:3px;background:#ee9a4a;border-radius:2px}
.sni-list{display:flex;flex-wrap:wrap;gap:4px}
.sni-tag{background:#0d0d18;border:1px solid #1a1a2e;padding:2px 8px;font-size:10px;border-radius:3px;color:#5a7a9a}
.footer{margin-top:30px;font-size:10px;color:#2a3a4a;text-align:center;letter-spacing:1px;text-transform:uppercase}
.footer .ws{color:#4a6a8a;margin-bottom:6px}
@media(max-width:600px){.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="w">
	<h1><span class="dot"></span> net_server · control_center</h1>
	<div class="sub">sni_multiplexer · v2.0</div>

	<div class="grid">
		<div class="card">
			<div class="card-title">core_traffic</div>
			<div class="row"><span class="k">active_vpn_conns</span><span class="v num" id="active">0</span></div>
			<div class="row"><span class="k">total_requests</span><span class="v num" id="total">0</span></div>
			<div class="row"><span class="k">throughput_up</span><span class="v" id="bw_up_val">— bps</span></div>
			<div class="row"><span class="k">throughput_down</span><span class="v" id="bw_down_val">— bps</span></div>
			<div class="row"><span class="k">data_transferred</span><span class="v" id="data_total">0 B</span></div>
		</div>

		<div class="card">
			<div class="card-title">system</div>
			<div class="row"><span class="k">uptime</span><span class="v" id="uptime">—</span></div>
			<div class="row"><span class="k">goroutines</span><span class="v num" id="goroutines">0</span></div>
			<div class="row"><span class="k">runtime</span><span class="v" id="go_ver" style="font-size:11px;color:#5a7a9a">—</span></div>
			<div class="row"><span class="k">udp_relays</span><span class="v num" id="udp_relays">0</span></div>
		</div>

		<div class="card full">
			<div class="card-title">real-time_bandwidth (last 5 min)</div>
			<div class="chart-wrap"><canvas id="bwChart"></canvas></div>
			<div class="bw-legend"><span class="dl">download</span><span class="ul">upload</span></div>
		</div>

		<div class="card full">
			<div class="card-title">active_destinations</div>
			<div class="dest-list" id="destList"><span style="color:#3a4a5a;font-size:11px">awaiting data...</span></div>
		</div>

		<div class="card full">
			<div class="card-title">cdn_nodes_detected</div>
			<div class="dest-list" id="cdnList"><span style="color:#3a4a5a;font-size:11px">awaiting data...</span></div>
		</div>
	</div>

	<div class="pac-box">
		<div class="label">pac_auto_config</div>
		<div class="pac-url" id="pac-link" onclick="navigator.clipboard.writeText(this.textContent);this.textContent='✓ copied!';(()=>setTimeout(()=>{const u=location.protocol+'//'+location.host+'%s';document.getElementById('pac-link').textContent=u},1500))()">—</div>
	</div>

	<div class="footer">
		<div class="ws" id="ws_status">connecting_ws...</div>
		vless_core // sni_mux // nitro-engine
	</div>
</div>

<script>
const canvas=document.getElementById('bwChart'),ctx=canvas.getContext('2d');
function resizeCanvas(){const r=canvas.parentElement.getBoundingClientRect();canvas.width=r.width*devicePixelRatio;canvas.height=120*devicePixelRatio;ctx.scale(devicePixelRatio,devicePixelRatio)}
resizeCanvas();window.addEventListener('resize',resizeCanvas);

function fmtBW(bps){if(bps>=1e9)return (bps/1e9).toFixed(1)+' Gbps';if(bps>=1e6)return (bps/1e6).toFixed(1)+' Mbps';if(bps>=1e3)return (bps/1e3).toFixed(0)+' Kbps';return bps.toFixed(0)+' bps'}
function fmtBytes(b){if(b>=1e12)return (b/1e12).toFixed(2)+' TB';if(b>=1e9)return (b/1e9).toFixed(1)+' GB';if(b>=1e6)return (b/1e6).toFixed(1)+' MB';if(b>=1e3)return (b/1e3).toFixed(0)+' KB';return b+' B'}

function drawChart(up,down){
	const w=canvas.width/devicePixelRatio,h=120;ctx.clearRect(0,0,w,h);
	const maxVal=Math.max(1,...up,...down)*1.15;
	const stepY=h/maxVal,stepX=w/(Math.max(up.length,down.length,2)-1);
	
	function drawLine(data,color,fill){
		if(data.length<2)return;
		ctx.beginPath();ctx.strokeStyle=color;ctx.lineWidth=2;ctx.lineJoin='round';
		data.forEach((v,i)=>{const x=i*stepX,y=h-v*stepY;i===0?ctx.moveTo(x,y):ctx.lineTo(x,y)});
		ctx.stroke();
		if(fill){ctx.lineTo((data.length-1)*stepX,h);ctx.lineTo(0,h);ctx.closePath();ctx.fillStyle=color+'15';ctx.fill()}
	}
	drawLine(down,'#4a9aee',true);
	drawLine(up,'#ee9a4a',true);
	ctx.fillStyle='#2a3a4a';ctx.font='9px monospace';ctx.fillText('5 min',w-38,14);ctx.fillText('now',w-38,h-6);
}

const u=document.getElementById('bw_up_val'),d=document.getElementById('bw_down_val'),dt=document.getElementById('data_total');
let bwUpHist=[],bwDownHist=[];

const upd=(id,v)=>{const e=document.getElementById(id);if(e&&e.textContent!==String(v)){e.textContent=v;e.style.transition='color .1s';e.style.color='#fff';setTimeout(()=>e.style.color='',300)}};

const connect=()=>{
	const ws=new WebSocket((location.protocol==='https:'?'wss:':'ws:')+'//'+location.host+'/ws');
	ws.onopen=()=>{document.getElementById('ws_status').textContent='ws_live ✓';document.getElementById('ws_status').style.color='#0a0'};
	ws.onclose=()=>{document.getElementById('ws_status').textContent='ws_reconnecting...';document.getElementById('ws_status').style.color='#a55';setTimeout(connect,2000)};
	ws.onmessage=e=>{
		const d=JSON.parse(e.data);
		upd('uptime',d.uptime);upd('active',d.active_conn);upd('total',d.total_req);
		upd('goroutines',d.goroutines);upd('go_ver',d.go_ver+' ('+d.cpus+' CPUs)');upd('udp_relays',d.udp_relays||0);
		
		if(d.bw_up&&d.bw_up.length>1){bwUpHist=d.bw_up;bwDownHist=d.bw_down;drawChart(d.bw_up,d.bw_down)}
		const lastUp=bwUpHist.length?bwUpHist[bwUpHist.length-1]:0,lastDown=bwDownHist.length?bwDownHist[bwDownHist.length-1]:0;
		u.textContent=fmtBW(lastUp);d.textContent=fmtBW(lastDown);
		dt.textContent=fmtBytes((d.bytes_up||0)+(d.bytes_down||0));

		if(d.dests&&d.dests.length){const el=document.getElementById('destList');el.innerHTML=d.dests.slice(0,10).map(x=>'<span class="dest-tag">'+x.dest+' <span class="count">'+x.count+'</span></span>').join('')}
		if(d.cdn&&d.cdn.length){const el=document.getElementById('cdnList');el.innerHTML=d.cdn.slice(0,10).map(x=>'<span class="cdn-tag">'+x.host+' <span class="count">'+x.count+'</span></span>').join('')}
	};
};
connect();
const pacUrl=location.protocol+'//'+location.host+'%s';document.getElementById('pac-link').textContent=pacUrl;
</script>
</body>
</html>`
