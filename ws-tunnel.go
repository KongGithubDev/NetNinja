package main

import (
	"crypto/ed25519"
	"crypto/rand"
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
	wsPort    = flag.String("port", "143", "Listen port")
	wsSSHAddr = flag.String("ssh-addr", "127.0.0.1:22", "Local SSH server address (proxy mode)")
	wsPath    = flag.String("path", "/", "WebSocket path")
	wsEmbed   = flag.Bool("embed", false, "Embed SSH server instead of proxying to external")
	wsHostKey = flag.String("host-key", "", "SSH host key file (PEM, embedded mode)")
	wsUser    = flag.String("user", "vpn", "SSH username (embedded mode)")
	wsPass    = flag.String("pass", "vpn", "SSH password (embedded mode)")
)

var wsUpgrader = websocket.Upgrader{
	CheckOrigin:     func(r *http.Request) bool { return true },
	ReadBufferSize:  64 * 1024,
	WriteBufferSize: 64 * 1024,
}

func init() {
	flag.Parse()
	if v := os.Getenv("WS_PORT"); v != "" {
		*wsPort = v
	}
	if v := os.Getenv("WS_SSH_ADDR"); v != "" {
		*wsSSHAddr = v
	}
	if v := os.Getenv("WS_PATH"); v != "" {
		*wsPath = v
	}
	if v := os.Getenv("WS_EMBED"); v == "true" || v == "1" {
		*wsEmbed = true
	}
	if v := os.Getenv("WS_HOST_KEY"); v != "" {
		*wsHostKey = v
	}
	if v := os.Getenv("WS_USER"); v != "" {
		*wsUser = v
	}
	if v := os.Getenv("WS_PASS"); v != "" {
		*wsPass = v
	}
}

type wsSSHAdapter struct {
	*websocket.Conn
	r  io.Reader
	mu sync.Mutex
}

func (c *wsSSHAdapter) Read(b []byte) (int, error) {
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

func (c *wsSSHAdapter) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.Conn.WriteMessage(websocket.BinaryMessage, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *wsSSHAdapter) SetDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *wsSSHAdapter) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *wsSSHAdapter) SetWriteDeadline(t time.Time) error {
	return nil
}

func embedSSHSession(ws *websocket.Conn, config *ssh.ServerConfig) {
	defer ws.Close()
	adapter := &wsSSHAdapter{Conn: ws}
	conn, chans, reqs, err := ssh.NewServerConn(adapter, config)
	if err != nil {
		log.Printf("[SSH] Handshake failed: %v", err)
		return
	}
	defer conn.Close()

	go ssh.DiscardRequests(reqs)
	for newChan := range chans {
		go handleSSHChannel(conn, newChan)
	}
}

func handleSSHChannel(conn *ssh.ServerConn, newChan ssh.NewChannel) {
	switch newChan.ChannelType() {
	case "session":
		ch, reqs, err := newChan.Accept()
		if err != nil {
			return
		}
		go ssh.DiscardRequests(reqs)
		go io.Copy(io.Discard, ch)
		ch.Close()

	case "direct-tcpip":
		type directTCPIP struct {
			DestAddr string
			DestPort uint32
			SrcAddr  string
			SrcPort  uint32
		}
		var d directTCPIP
		if err := ssh.Unmarshal(newChan.ExtraData(), &d); err != nil {
			newChan.Reject(ssh.Prohibited, fmt.Sprintf("bad data: %v", err))
			return
		}
		dest := net.JoinHostPort(d.DestAddr, fmt.Sprintf("%d", d.DestPort))
		log.Printf("[TCP] Forward: %s -> %s", conn.RemoteAddr(), dest)

		remote, err := net.DialTimeout("tcp", dest, 15*time.Second)
		if err != nil {
			newChan.Reject(ssh.Prohibited, fmt.Sprintf("dial failed: %v", err))
			return
		}

		ch, _, err := newChan.Accept()
		if err != nil {
			remote.Close()
			return
		}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			io.Copy(ch, remote)
			remote.Close()
		}()
		go func() {
			defer wg.Done()
			io.Copy(remote, ch)
			ch.Close()
		}()
		wg.Wait()

	default:
		newChan.Reject(ssh.UnknownChannelType, "unsupported channel type")
	}
}

func proxyToExternalSSH(ws *websocket.Conn) {
	defer ws.Close()
	adapter := &wsSSHAdapter{Conn: ws}
	dest, err := net.DialTimeout("tcp", *wsSSHAddr, 10*time.Second)
	if err != nil {
		log.Printf("[PROXY] Failed to connect to SSH %s: %v", *wsSSHAddr, err)
		return
	}
	defer dest.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(dest, adapter)
		dest.Close()
	}()
	go func() {
		defer wg.Done()
		io.Copy(adapter, dest)
		ws.Close()
	}()
	wg.Wait()
}

func handleWSTunnel(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "WebSocket upgrade required", http.StatusBadRequest)
		return
	}
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[WS] Upgrade failed: %v", err)
		return
	}
	log.Printf("[WS] New connection from %s", conn.RemoteAddr())
	if *wsEmbed {
		embedSSHSession(conn, getEmbedSSHConfig())
	} else {
		proxyToExternalSSH(conn)
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
				if c.User() == *wsUser && string(pass) == *wsPass {
					return nil, nil
				}
				return nil, fmt.Errorf("auth failed")
			},
		}
		if *wsHostKey != "" {
			data, err := os.ReadFile(*wsHostKey)
			if err == nil {
				key, err := ssh.ParsePrivateKey(data)
				if err == nil {
					config.AddHostKey(key)
					embedSSHConfig = config
					return
				}
				log.Printf("[SSH] Failed to parse host key: %v", err)
			} else {
				log.Printf("[SSH] Failed to read host key file: %v", err)
			}
		}
		log.Printf("[SSH] Generating ephemeral ed25519 host key...")
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatalf("[SSH] Failed to generate host key: %v", err)
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			log.Fatalf("[SSH] Failed to create signer: %v", err)
		}
		config.AddHostKey(signer)
		embedSSHConfig = config
	})
	return embedSSHConfig
}

func main() {
	log.Printf("========================================")
	log.Printf("   NetNinja WS-Tunnel Server")
	log.Printf("   SSH over WebSocket Bridge")
	log.Printf("========================================")
	log.Printf("  Port     : %s", *wsPort)
	log.Printf("  Path     : %s", *wsPath)
	if *wsEmbed {
		log.Printf("  Mode     : EMBEDDED SSH (user=%s)", *wsUser)
	} else {
		log.Printf("  Mode     : PROXY -> %s", *wsSSHAddr)
	}
	log.Printf("========================================")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != *wsPath {
			w.Write([]byte("NetNinja WS-Tunnel Server\n"))
			return
		}
		handleWSTunnel(w, r)
	})

	listener, err := net.Listen("tcp", "0.0.0.0:"+*wsPort)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	log.Printf("Listening on 0.0.0.0:%s ...", *wsPort)
	if err := http.Serve(listener, nil); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
