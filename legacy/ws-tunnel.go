package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

var (
	wsPort    = flag.String("port", "443", "Listen port")
	wsPath    = flag.String("path", "/", "WebSocket path")
	wsEmbed   = flag.Bool("embed", false, "Embed SSH server instead of proxying to external")
	wsSSHAddr = flag.String("ssh-addr", "127.0.0.1:22", "Local SSH server address (proxy mode)")
	wsUser    = flag.String("user", "vpn", "SSH username (embedded mode)")
	wsPass    = flag.String("pass", "vpn", "SSH password (embedded mode)")
	wsHostKey = flag.String("host-key", "", "SSH host key file (PEM, embedded mode)")
	wsFwdAddr = flag.String("fwd-addr", "", "Forward decoded WS data to this TCP addr")

	certFile = flag.String("cert", "fullchain.pem", "TLS certificate file")
	keyFile  = flag.String("key", "privkey.pem", "TLS private key file")
	webSNI   = flag.String("web-sni", "", "Proxy these SNIs to real web server (e.g. your-domain.com)")
	webPort  = flag.String("web-port", "8443", "Backend web server port")
)

func init() {
	flag.Parse()
	if v := os.Getenv("WS_PORT"); v != "" { *wsPort = v }
	if v := os.Getenv("WS_SSH_ADDR"); v != "" { *wsSSHAddr = v }
	if v := os.Getenv("WS_PATH"); v != "" { *wsPath = v }
	if v := os.Getenv("WS_EMBED"); v == "true" || v == "1" { *wsEmbed = true }
	if v := os.Getenv("WS_HOST_KEY"); v != "" { *wsHostKey = v }
	if v := os.Getenv("WS_USER"); v != "" { *wsUser = v }
	if v := os.Getenv("WS_PASS"); v != "" { *wsPass = v }
	if v := os.Getenv("WS_FWD_ADDR"); v != "" { *wsFwdAddr = v }
	if v := os.Getenv("NET_WEB_SNI"); v != "" { *webSNI = v }
	if v := os.Getenv("NET_WEB_PORT"); v != "" { *webPort = v }
}

// ── WebSocket → TCP Adapter ──────────────────────────────────────────────────

type wsAdapter struct {
	*websocket.Conn
	r  io.Reader
	mu sync.Mutex
}

func (c *wsAdapter) Read(b []byte) (int, error) {
	for {
		msgType, reader, err := c.Conn.NextReader()
		if err != nil { return 0, err }
		if msgType == websocket.BinaryMessage || msgType == websocket.TextMessage {
			n, err := reader.Read(b)
			if err == io.EOF {
				if n > 0 { return n, nil }
				continue
			}
			return n, err
		}
	}
}

func (c *wsAdapter) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.Conn.WriteMessage(websocket.BinaryMessage, b); err != nil { return 0, err }
	return len(b), nil
}

func (c *wsAdapter) SetDeadline(t time.Time) error       { return c.Conn.SetReadDeadline(t) }
func (c *wsAdapter) SetReadDeadline(t time.Time) error    { return c.Conn.SetReadDeadline(t) }
func (c *wsAdapter) SetWriteDeadline(t time.Time) error   { return nil }

// ── Peeked Connection ────────────────────────────────────────────────────────

type peekedConn struct {
	net.Conn
	r *bufio.Reader
}
func (c *peekedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// ── SSH Server ───────────────────────────────────────────────────────────────

func handleSSHChannel(conn *ssh.ServerConn, newChan ssh.NewChannel) {
	switch newChan.ChannelType() {
	case "session":
		ch, reqs, err := newChan.Accept()
		if err != nil { return }
		go func() {
			for req := range reqs {
				if req.Type == "shell" || req.Type == "exec" || req.Type == "subsystem" {
					req.Reply(true, nil)
				} else { req.Reply(false, nil) }
			}
		}()
		go io.Copy(io.Discard, ch)

	case "direct-tcpip":
		type t struct { DestAddr string; DestPort uint32; SrcAddr string; SrcPort uint32 }
		var d t
		if err := ssh.Unmarshal(newChan.ExtraData(), &d); err != nil {
			newChan.Reject(ssh.Prohibited, fmt.Sprintf("bad data: %v", err)); return
		}
		dest := net.JoinHostPort(d.DestAddr, fmt.Sprintf("%d", d.DestPort))
		log.Printf("[TCP] Forward: %s -> %s", conn.RemoteAddr(), dest)
		remote, err := net.DialTimeout("tcp", dest, 15*time.Second)
		if err != nil {
			log.Printf("[TCP] Dial %s failed: %v", dest, err)
			newChan.Reject(ssh.Prohibited, fmt.Sprintf("dial failed: %v", err)); return
		}
		ch, _, err := newChan.Accept()
		if err != nil { remote.Close(); return }
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); io.Copy(ch, remote) }()
		go func() { defer wg.Done(); io.Copy(remote, ch) }()
		wg.Wait()

	default:
		newChan.Reject(ssh.UnknownChannelType, "unsupported channel type")
	}
}

var (
	embedSSHOnce   sync.Once
	embedSSHConfig *ssh.ServerConfig
)

func getEmbedSSHConfig() *ssh.ServerConfig {
	embedSSHOnce.Do(func() {
		config := &ssh.ServerConfig{
			PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
				if c.User() == *wsUser && string(pass) == *wsPass { return nil, nil }
				return nil, fmt.Errorf("auth failed")
			},
		}
		if *wsHostKey != "" {
			if data, err := os.ReadFile(*wsHostKey); err == nil {
				if key, err := ssh.ParsePrivateKey(data); err == nil {
					config.AddHostKey(key); embedSSHConfig = config; return
				} else { log.Printf("[SSH] Failed to parse host key: %v", err) }
			} else { log.Printf("[SSH] Failed to read host key file: %v", err) }
		}
		log.Printf("[SSH] Generating ephemeral ed25519 host key...")
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil { log.Fatalf("[SSH] Failed to generate host key: %v", err) }
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil { log.Fatalf("[SSH] Failed to create signer: %v", err) }
		config.AddHostKey(signer)
		embedSSHConfig = config
	})
	return embedSSHConfig
}

// ── WebSocket Handler ────────────────────────────────────────────────────────

var wsUpgrader = websocket.Upgrader{
	CheckOrigin:    func(r *http.Request) bool { return true },
	ReadBufferSize:  64 * 1024,
	WriteBufferSize: 64 * 1024,
}

func handleWSTunnel(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		return
	}
	if r.Header.Get("Sec-WebSocket-Key") == "" {
		k := make([]byte, 16)
		rand.Read(k)
		r.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString(k))
	}
	if r.Header.Get("Sec-WebSocket-Version") == "" {
		r.Header.Set("Sec-WebSocket-Version", "13")
	}
	// gorilla/websocket requires GET method; swap temporarily
	origMethod := r.Method; r.Method = "GET"
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	r.Method = origMethod
	if err != nil { log.Printf("[WS] Upgrade failed: %v", err); return }

	log.Printf("[WS] New connection from %s", conn.RemoteAddr())
	if *wsFwdAddr != "" {
		forwardWS(conn, *wsFwdAddr)
	} else if *wsEmbed {
		embedSSH(conn, getEmbedSSHConfig())
	} else {
		proxyRawSSH(conn)
	}
}

func forwardWS(ws *websocket.Conn, addr string) {
	defer ws.Close()
	dest, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil { log.Printf("[FWD] Connect %s failed: %v", addr, err); return }
	defer dest.Close()
	log.Printf("[FWD] Connected to %s", addr)
	adapter := &wsAdapter{Conn: ws}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(dest, adapter); dest.Close() }()
	go func() { defer wg.Done(); io.Copy(adapter, dest) }()
	wg.Wait()
	log.Printf("[FWD] Done")
}

func embedSSH(ws *websocket.Conn, config *ssh.ServerConfig) {
	defer ws.Close()
	adapter := &wsAdapter{Conn: ws}
	conn2, chans, reqs, err := ssh.NewServerConn(adapter, config)
	if err != nil { log.Printf("[SSH] Handshake failed: %v", err); return }
	defer conn2.Close()
	go ssh.DiscardRequests(reqs)
	for newChan := range chans { go handleSSHChannel(conn2, newChan) }
}

func proxyRawSSH(ws *websocket.Conn) {
	defer ws.Close()
	adapter := &wsAdapter{Conn: ws}
	dest, err := net.DialTimeout("tcp", *wsSSHAddr, 10*time.Second)
	if err != nil { log.Printf("[PROXY] SSH proxy failed: %v", err); return }
	defer dest.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(dest, adapter); dest.Close() }()
	go func() { defer wg.Done(); io.Copy(adapter, dest) }()
	wg.Wait()
}

// ── HTTP Server Frontend ─────────────────────────────────────────────────────

func startHTTPServer(conns chan net.Conn) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != *wsPath { w.Write([]byte("NetNinja WS-Tunnel Server\n")); return }
		handleWSTunnel(w, r)
	})
	httpServer := &http.Server{Handler: nil}
	httpServer.Serve(&memListener{conns: conns})
}

type memListener struct { conns chan net.Conn }
func (m *memListener) Accept() (net.Conn, error) { return <-m.conns, nil }
func (m *memListener) Close() error { return nil }
func (m *memListener) Addr() net.Addr { return nil }

// ── SNI Reader ───────────────────────────────────────────────────────────────

func readSNI(data []byte) string {
	if len(data) < 44 || data[0] != 0x16 || data[5] != 0x01 { return "" }
	pos := 43
	if pos >= len(data) { return "" }
	sessionIDLen := int(data[pos]); pos += 1 + sessionIDLen
	if pos+1 >= len(data) { return "" }
	cipherSuitesLen := int(data[pos])<<8 | int(data[pos+1]); pos += 2 + cipherSuitesLen
	if pos >= len(data) { return "" }
	compressionMethodsLen := int(data[pos]); pos += 1 + compressionMethodsLen
	if pos+1 >= len(data) { return "" }
	extensionsLen := int(data[pos])<<8 | int(data[pos+1]); pos += 2
	end := pos + extensionsLen
	if end > len(data) { end = len(data) }
	for pos+3 < end {
		extType := int(data[pos])<<8 | int(data[pos+1])
		extLen := int(data[pos+2])<<8 | int(data[pos+3]); pos += 4
		if extType == 0x0000 {
			if pos+4 < pos+extLen && data[pos+2] == 0x00 {
				nameLen := int(data[pos+3])<<8 | int(data[pos+4])
				if pos+5+nameLen <= pos+extLen { return string(data[pos+5 : pos+5+nameLen]) }
			}
			break
		}
		pos += extLen
	}
	return ""
}

// ── Connection Handler ───────────────────────────────────────────────────────

func handleConnection(conn net.Conn, webSNIs map[string]bool, tlsCfg *tls.Config, httpConns chan net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true); tcpConn.SetKeepAlive(true)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)
	hdr, err := reader.Peek(5)
	if err != nil {
		conn.SetReadDeadline(time.Time{})
		if hdr != nil && len(hdr) > 0 {
			httpConns <- &peekedConn{Conn: conn, r: reader}
		} else {
			conn.Close()
		}
		return
	}
	var proxyToWeb bool; var sni string
	isTLS := hdr[0] == 0x16
	if isTLS {
		length := int(hdr[3])<<8 | int(hdr[4])
		if length <= 8192 {
			if record, err := reader.Peek(5 + length); err == nil { sni = readSNI(record) }
		}
	}
	conn.SetReadDeadline(time.Time{})
	if sni != "" {
		if webSNIs[sni] {
			proxyToWeb = true
			log.Printf("[SNI] Routing %s to web port %s", sni, *webPort)
		} else {
			log.Printf("[SNI] Detected: %s", sni)
		}
	}
	isPlainHTTP := false
	if len(hdr) >= 4 {
		m := string(hdr[:4])
		if m == "GET " || m == "POST" || m == "PUT " || m == "HEAD" || m == "OPTI" || m == "DELE" || m == "CONN" || m == "TRAC" || m == "PATC" { isPlainHTTP = true }
	}
	isSSH := len(hdr) >= 4 && string(hdr[:4]) == "SSH-"
	peekConn := &peekedConn{Conn: conn, r: reader}
	if proxyToWeb {
		dest, err := net.DialTimeout("tcp", "127.0.0.1:"+*webPort, 5*time.Second)
		if err != nil { log.Printf("[SNI] Proxy to %s failed: %v", *webPort, err); conn.Close(); return }
		var wg sync.WaitGroup; wg.Add(2)
		go func() { defer wg.Done(); io.Copy(dest, peekConn); dest.Close() }()
		go func() { defer wg.Done(); io.Copy(peekConn, dest); peekConn.Close() }()
		wg.Wait(); return
	}
	if isSSH {
		log.Printf("[SSH] Direct SSH from %s", conn.RemoteAddr())
		if *wsEmbed { handleRawSSH(peekConn) } else { proxyRawToExternalSSH(peekConn) }
		return
	}
	// ── fwd-addr mode: detect Upgrade & forward raw ──
	if *wsFwdAddr != "" && tlsCfg != nil {
		if isTLS {
			// Terminate TLS, check decrypted data for Upgrade
			tlsConn := tls.Server(peekConn, tlsCfg)
			tlsConn.SetReadDeadline(time.Now().Add(3 * time.Second))
			br := bufio.NewReader(tlsConn)
			peek, err := br.Peek(128)
			tlsConn.SetReadDeadline(time.Time{})
			if err == nil && strings.Contains(string(peek), "Upgrade:") {
				dest, err := net.DialTimeout("tcp", *wsFwdAddr, 10*time.Second)
				if err == nil {
					log.Printf("[FWD] %s -> %s (raw TLS→%s)", conn.RemoteAddr(), *wsFwdAddr, *wsFwdAddr)
					pc := &peekedConn{Conn: tlsConn, r: br}
					var wg sync.WaitGroup; wg.Add(2)
					go func() { defer wg.Done(); io.Copy(dest, pc); dest.Close() }()
					go func() { defer wg.Done(); io.Copy(pc, dest); pc.Close() }()
					wg.Wait()
				}
				return
			}
			// Non-Upgrade TLS (PING) → HTTP server
			httpConns <- tlsConn
			return
		}
	}
	if isPlainHTTP { httpConns <- peekConn
	} else if isTLS && tlsCfg != nil { httpConns <- tls.Server(peekConn, tlsCfg)
	} else { httpConns <- peekConn }
}

func handleRawSSH(conn net.Conn) {
	defer conn.Close()
	config := getEmbedSSHConfig()
	conn2, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil { log.Printf("[SSH] Direct handshake failed: %v", err); return }
	defer conn2.Close()
	go ssh.DiscardRequests(reqs)
	for newChan := range chans { go handleSSHChannel(conn2, newChan) }
}

func proxyRawToExternalSSH(conn net.Conn) {
	defer conn.Close()
	dest, err := net.DialTimeout("tcp", *wsSSHAddr, 10*time.Second)
	if err != nil { log.Printf("[PROXY] SSH proxy failed: %v", err); return }
	defer dest.Close()
	var wg sync.WaitGroup; wg.Add(2)
	go func() { defer wg.Done(); io.Copy(dest, conn) }()
	go func() { defer wg.Done(); io.Copy(conn, dest) }()
	wg.Wait()
}

// ── Main ─────────────────────────────────────────────────────────────────────

func main() {
	log.Printf("  NetNinja WS-Tunnel  port=%s embed=%v fwd=%s", *wsPort, *wsEmbed, *wsFwdAddr)
	webSNIs := make(map[string]bool)
	for _, s := range strings.Split(*webSNI, ",") {
		s = strings.TrimSpace(s)
		if s != "" { webSNIs[s] = true }
	}
	var tlsCfg *tls.Config
	if data, err := os.ReadFile(*certFile); err == nil {
		if keyData, err := os.ReadFile(*keyFile); err == nil {
			if cert, err := tls.X509KeyPair(data, keyData); err == nil {
				tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}}
				log.Printf("[TLS] Loaded certificate: %s", *certFile)
			} else { log.Printf("[TLS] Parse cert failed: %v", err) }
		} else { log.Printf("[TLS] Read key failed: %v", err) }
	} else { log.Printf("[TLS] No cert: %v", err) }

	httpConns := make(chan net.Conn, 1024)
	go startHTTPServer(httpConns)
	listener, err := net.Listen("tcp", "0.0.0.0:"+*wsPort)
	if err != nil { log.Fatalf("Server failed: %v", err) }
	log.Printf("Listening on 0.0.0.0:%s ...", *wsPort)
	for {
		conn, err := listener.Accept()
		if err != nil { continue }
		go handleConnection(conn, webSNIs, tlsCfg, httpConns)
	}
}
