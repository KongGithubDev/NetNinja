package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	proxyAddr := "85.211.183.237:5988"
	target := "httpbin.org:443"

	fmt.Println("=== CGNAT Keepalive Test ===")
	fmt.Println("Proxy:", proxyAddr)
	fmt.Println("Target:", target)
	fmt.Println("Test: Open tunnel, idle 7 min, then try to use it")
	fmt.Println("If keepalive works → can still use tunnel after 7 min")
	fmt.Println("If keepalive fails → CGNAT kills at ~4-5 min")
	fmt.Println()

	conn, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		fmt.Println("FAIL:", err)
		os.Exit(1)
	}
	fmt.Println("[1] Connected to proxy")

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	reader := bufio.NewReader(conn)
	line, _ := reader.ReadString('\n')
	fmt.Printf("   Proxy: %s", line)
	for {
		l, _ := reader.ReadString('\n')
		if l == "\r\n" || l == "\n" {
			break
		}
	}

	fmt.Println("[2] Tunnel established. Idling for 7 minutes...")
	start := time.Now()
	for {
		time.Sleep(30 * time.Second)
		elapsed := time.Since(start).Round(time.Second)
		fmt.Printf("   ... %v\n", elapsed)
		if time.Since(start) >= 7*time.Minute {
			break
		}
	}

	fmt.Println("[3] Trying to use tunnel after 7 min idle...")
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte("GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n"))
	if err != nil {
		fmt.Printf("   FAIL: %v\n", err)
		fmt.Println("   CGNAT killed it → keepalive DOES NOT work")
		conn.Close()
		return
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Printf("   FAIL: %v\n", err)
		fmt.Println("   CGNAT killed it → keepalive DOES NOT work")
	} else {
		resp := string(buf[:n])
		if len(resp) > 80 {
			resp = resp[:80] + "..."
		}
		fmt.Printf("   OK: %s\n", resp)
		fmt.Println("   CGNAT did NOT kill it → keepalive WORKS!")
	}

	conn.Close()
	fmt.Println("\nTest complete.")
}
