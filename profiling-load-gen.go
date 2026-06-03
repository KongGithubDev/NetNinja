// +build ignore

package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

func main() {
	dir, _ := os.Getwd()
	serverExe := filepath.Join(dir, "net_server.exe")
	profileFile := filepath.Join(dir, "default.pgo")
	serverPort := "8444"
	profileSeconds := 30

	fmt.Fprintf(os.Stderr, "[PGO] Starting net_server on port %s...\n", serverPort)

	// Step 1: Start net_server
	serverCmd := exec.Command(serverExe, "-port", serverPort, "-tls", "false")
	serverCmd.Stdout = os.Stderr
	serverCmd.Stderr = os.Stderr
	if err := serverCmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "[PGO] Failed to start server: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "[PGO] Server PID: %d\n", serverCmd.Process.Pid)

	// Ensure server is killed on exit
	defer func() {
		serverCmd.Process.Kill()
		serverCmd.Wait()
	}()

	// Wait for server to start
	time.Sleep(3 * time.Second)

	// Verify server
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + serverPort + "/")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[PGO] Server not responding: %v\n", err)
		os.Exit(1)
	}
	resp.Body.Close()
	fmt.Fprintf(os.Stderr, "[PGO] Server running.\n")

	// Step 2: Generate workload in background
	fmt.Fprintf(os.Stderr, "[PGO] Generating workload...\n")
	var loadWg sync.WaitGroup

	// Proxy client setup
	proxyURL, _ := url.Parse("http://127.0.0.1:" + serverPort + "/")
	proxyClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 10 * time.Second,
	}

	directClient := &http.Client{Timeout: 5 * time.Second}

	targets := []string{
		"http://www.google.com/",
		"http://www.youtube.com/",
		"http://googlevideo.com/",
		"http://www.facebook.com/",
		"http://www.tiktok.com/",
		"http://netflix.com/",
	}

	// Phase 1: Direct dashboard requests
	for i := 0; i < 20; i++ {
		loadWg.Add(1)
		go func() {
			defer loadWg.Done()
			r, e := directClient.Get("http://127.0.0.1:" + serverPort + "/")
			if e == nil { io.Copy(io.Discard, r.Body); r.Body.Close() }
		}()
	}

	// Phase 2: Proxy HTTP requests
	for i := 0; i < 30; i++ {
		for _, t := range targets {
			loadWg.Add(1)
			go func(target string) {
				defer loadWg.Done()
				req, _ := http.NewRequest("GET", target, nil)
				r, e := proxyClient.Do(req)
				if e == nil { io.Copy(io.Discard, r.Body); r.Body.Close() }
			}(t)
			time.Sleep(50 * time.Millisecond)
		}
	}

	// Phase 3: CONNECT tunnels
	for i := 0; i < 20; i++ {
		loadWg.Add(1)
		go func() {
			defer loadWg.Done()
			conn, e := tls.Dial("tcp", "127.0.0.1:"+serverPort, &tls.Config{InsecureSkipVerify: true})
			if e == nil {
				conn.Write([]byte("CONNECT www.youtube.com:443 HTTP/1.1\r\nHost: www.youtube.com:443\r\n\r\n"))
				buf := make([]byte, 1024)
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				conn.Read(buf)
				conn.Close()
			}
		}()
		time.Sleep(100 * time.Millisecond)
	}

	// Phase 4: PAC file request
	for i := 0; i < 10; i++ {
		loadWg.Add(1)
		go func() {
			defer loadWg.Done()
			r, e := directClient.Get("http://127.0.0.1:" + serverPort + "/proxy.pac")
			if e == nil { io.Copy(io.Discard, r.Body); r.Body.Close() }
		}()
	}

	fmt.Fprintf(os.Stderr, "[PGO] Workload running. Collecting profile (%ds)...\n", profileSeconds)

	// Step 3: Collect CPU profile
	profileClient := &http.Client{Timeout: time.Duration(profileSeconds+15) * time.Second}
	resp2, err := profileClient.Get("http://127.0.0.1:" + serverPort + "/debug/pprof/profile?seconds=" + fmt.Sprintf("%d", profileSeconds))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[PGO] Profile collection failed: %v\n", err)
		os.Exit(1)
	}
	defer resp2.Body.Close()

	outFile, err := os.Create(profileFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[PGO] Cannot create profile file: %v\n", err)
		os.Exit(1)
	}
	defer outFile.Close()

	written, _ := io.Copy(outFile, resp2.Body)
	fmt.Fprintf(os.Stderr, "[PGO] Profile collected: %d bytes\n", written)

	// Wait for all load to finish
	loadWg.Wait()
	fmt.Fprintf(os.Stderr, "[PGO] Workload complete.\n")

	// Step 4: Done
	fi, _ := os.Stat(profileFile)
	sizeKB := float64(fi.Size()) / 1024
	fmt.Fprintf(os.Stderr, "[PGO] Profile saved: default.pgo (%.1f KB)\n", sizeKB)
	fmt.Fprintf(os.Stderr, "[PGO] Ready. Rebuild with: go build -pgo=%s -o net_server.exe net_server.go\n", profileFile)
}
