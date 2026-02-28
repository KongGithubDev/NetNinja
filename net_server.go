package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

var (
	portFlag = flag.String("port", "443", "Listen port")
	uuidFlag = flag.String("uuid", "b831381d-6324-4d53-ad4f-8cda48b30811", "VLESS UUID")
	pathFlag = flag.String("path", "/", "WebSocket Path")
)

var expectedUUID []byte

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func init() {
	flag.Parse()
	// Override with environment variables if present
	if envPort := os.Getenv("PORT"); envPort != "" {
		*portFlag = envPort
	} else if envPort := os.Getenv("NET_PORT"); envPort != "" {
		*portFlag = envPort
	}
	if envUUID := os.Getenv("NET_UUID"); envUUID != "" {
		*uuidFlag = envUUID
	}
	if envPath := os.Getenv("NET_PATH"); envPath != "" {
		*pathFlag = envPath
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
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	wsAdapter := &wsConnAdapter{Conn: conn}

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
			errc <- err
		}()
		go func() {
			_, err := io.Copy(wsAdapter, dest)
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
					errc <- err
					return
				}
				n := int(lb[0])<<8 | int(lb[1])
				pkt := make([]byte, n)
				if _, err := io.ReadFull(wsAdapter, pkt); err != nil {
					errc <- err
					return
				}
				dest.Write(pkt)
			}
		}()
		<-errc
	}
}

func main() {
	// Single handler to avoid route collision panics (e.g., when NET_PATH=/ and default is /)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
			return
		}

		if r.URL.Path == *pathFlag {
			handleVLESS(w, r)
			return
		}

		// Mask the server to scanners
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not Found"))
	})

	log.Printf("========================================")
	log.Printf("       NetNinja VLESS VPN Server        ")
	log.Printf("========================================")
	log.Printf("  Port : %s", *portFlag)
	log.Printf("  UUID : %s", *uuidFlag)
	log.Printf("  Path : %s", *pathFlag)
	log.Printf("========================================")
	log.Printf("Server listening on 0.0.0.0:%s ...", *portFlag)

	err := http.ListenAndServe("0.0.0.0:"+*portFlag, nil)
	if err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
