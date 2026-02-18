package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// ANSI colors
const (
	dnsColorReset  = "\033[0m"
	dnsColorGreen  = "\033[32m"
	dnsColorYellow = "\033[33m"
	dnsColorCyan   = "\033[36m"
	dnsColorRed    = "\033[31m"
	dnsColorGray   = "\033[90m"
)

// DNS over HTTPS endpoints (use HTTPS port 443, can't be intercepted!)
var dohServers = []string{
	"https://dns.google/dns-query",
	"https://cloudflare-dns.com/dns-query",
}

// Reusable HTTP client for DoH
var dohClient = &http.Client{
	Timeout: 5 * time.Second,
}

func main() {
	port := os.Getenv("DNS_PORT")
	if port == "" {
		port = "53"
	}

	addr := "0.0.0.0:" + port
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Fatalf("Failed to start DNS on %s: %v (Run as Administrator!)\n", addr, err)
		return
	}
	defer conn.Close()

	fmt.Println()
	fmt.Println("=== NetNinja DNS-over-HTTPS Forwarder on Port " + port + " ===")
	fmt.Println("Method: DNS over HTTPS (bypasses DNS hijacking)")
	fmt.Println("Upstream: Google DoH + Cloudflare DoH")
	fmt.Println("Port 53 interception: DEFEATED (queries go via HTTPS:443)")
	fmt.Println()
	fmt.Println("Setup on iPad/Device:")
	fmt.Println("  Settings > Wi-Fi > (i) > Configure DNS > Manual")

	nets, _ := net.Interfaces()
	for _, iface := range nets {
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
				fmt.Printf("  Add DNS Server: %s\n", ipnet.IP.String())
			}
		}
	}
	fmt.Println()
	fmt.Println("==============================================")
	fmt.Println()

	buf := make([]byte, 4096)
	for {
		n, clientAddr, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])
		go handleDNSQuery(conn, clientAddr, packet)
	}
}

// handleDNSQuery forwards DNS query via HTTPS (DoH) — bypasses port 53 interception
func handleDNSQuery(conn net.PacketConn, clientAddr net.Addr, query []byte) {
	domain := parseDomainName(query)
	clientIP := clientAddr.String()
	if idx := strings.LastIndex(clientIP, ":"); idx > 0 {
		clientIP = clientIP[:idx]
	}

	start := time.Now()

	// Try each DoH server
	for _, server := range dohServers {
		resp, err := dohClient.Post(
			server,
			"application/dns-message",
			bytes.NewReader(query),
		)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if err != nil || resp.StatusCode != 200 {
			continue
		}

		// Send DNS response back to client
		conn.WriteTo(body, clientAddr)

		elapsed := time.Since(start).Round(time.Millisecond)
		serverName := "Google"
		if strings.Contains(server, "cloudflare") {
			serverName = "Cloudflare"
		}

		log.Printf("%s[DoH]%s %s%s%s via %s%s%s %s← %s%s %s(%s)%s",
			dnsColorGreen, dnsColorReset,
			dnsColorYellow, domain, dnsColorReset,
			dnsColorCyan, serverName, dnsColorReset,
			dnsColorGray, clientIP, dnsColorReset,
			dnsColorGray, elapsed, dnsColorReset)
		return
	}

	log.Printf("%s[ERR]%s Failed to resolve %s for %s (all DoH servers failed)",
		dnsColorRed, dnsColorReset, domain, clientIP)
}

// parseDomainName extracts domain name from DNS query packet
func parseDomainName(packet []byte) string {
	if len(packet) < 13 {
		return "?"
	}

	pos := 12
	var parts []string

	for pos < len(packet) {
		length := int(packet[pos])
		if length == 0 {
			break
		}
		pos++
		if pos+length > len(packet) {
			break
		}
		parts = append(parts, string(packet[pos:pos+length]))
		pos += length
	}

	if len(parts) == 0 {
		return "?"
	}
	return strings.Join(parts, ".")
}
