package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	proxy := "85.211.183.237:443"
	if len(os.Args) > 1 {
		proxy = os.Args[1]
	}
	n := 20
	if len(os.Args) > 2 {
		fmt.Sscanf(os.Args[2], "%d", &n)
	}

	targets := []string{
		"httpbin.org:80", "www.google.com:443", "clients4.google.com:443",
		"www.youtube.com:443", "www.facebook.com:443",
	}

	fmt.Printf("Proxy: %s | Workers: %d | Targets: %d\n\n", proxy, n, len(targets))

	var wg sync.WaitGroup
	var total int64
	var bytes int64
	var errs int64
	stop := time.After(30 * time.Second)
	ticker := time.NewTicker(2 * time.Second)
	done := make(chan struct{})
	prevTotal := int64(0)
	prevBytes := int64(0)

	go func() {
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				t := atomic.LoadInt64(&total)
				b := atomic.LoadInt64(&bytes)
				e := atomic.LoadInt64(&errs)
				fmt.Printf("  [%s] requests=%d (%.0f/s) throughput=%.2fMB/s errors=%d\n",
					time.Now().Format("15:04:05"), t, float64(t-prevTotal)/2, float64(b-prevBytes)/2/1024/1024, e)
				prevTotal = t
				prevBytes = b
			}
		}
	}()

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				tgt := targets[id%len(targets)]
				testConnection(proxy, tgt, &total, &bytes, &errs)
			}
		}(i)
	}

	wg.Wait()
	close(done)

	fmt.Printf("\n=== Final: %d requests, %.2f MB, %d errors ===\n",
		atomic.LoadInt64(&total), float64(atomic.LoadInt64(&bytes))/1024/1024, atomic.LoadInt64(&errs))
}

func testConnection(proxy, target string, total, bytes, errs *int64) {
	conn, err := net.DialTimeout("tcp", proxy, 5*time.Second)
	if err != nil {
		atomic.AddInt64(errs, 1)
		time.Sleep(100 * time.Millisecond)
		return
	}

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// CONNECT
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	reader := bufio.NewReader(conn)
	line, _ := reader.ReadString('\n')
	if line == "" {
		conn.Close()
		atomic.AddInt64(errs, 1)
		return
	}

	// Drain headers
	for {
		l, _ := reader.ReadString('\n')
		if l == "\r\n" || l == "\n" || l == "" {
			break
		}
	}

	// Send HTTP request
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	n, _ := io.Copy(io.Discard, conn)
	conn.Close()

	atomic.AddInt64(total, 1)
	atomic.AddInt64(bytes, n)
}
