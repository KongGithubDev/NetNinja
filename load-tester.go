// +build ignore

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"math/rand"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type Result struct {
	Name        string
	Requests    int64
	Duration    time.Duration
	Bytes       int64
	Errors      int64
	LatenciesUs []int64 // microseconds
}

func (r *Result) RPS() float64 {
	if r.Duration == 0 {
		return 0
	}
	return float64(r.Requests) / r.Duration.Seconds()
}

func (r *Result) MBps() float64 {
	if r.Duration == 0 {
		return 0
	}
	return float64(r.Bytes) / r.Duration.Seconds() / 1024 / 1024
}

func (r *Result) LatencyP(p float64) time.Duration {
	if len(r.LatenciesUs) == 0 {
		return 0
	}
	idx := int(float64(len(r.LatenciesUs)-1) * p / 100)
	if idx < 0 {
		idx = 0
	}
	return time.Duration(r.LatenciesUs[idx]) * time.Microsecond
}

func (r *Result) Print() {
	fmt.Printf("  %-30s\n", r.Name)
	fmt.Printf("    Requests:      %10d\n", r.Requests)
	fmt.Printf("    Duration:      %10s\n", r.Duration.Round(time.Millisecond))
	fmt.Printf("    Throughput:    %10.1f req/s\n", r.RPS())
	fmt.Printf("    Bandwidth:     %10.2f MB/s\n", r.MBps())
	fmt.Printf("    Transferred:   %10s\n", formatBytes(r.Bytes))
	fmt.Printf("    Errors:        %10d", r.Errors)
	if r.Errors > 0 {
		fmt.Printf(" (%.1f%%)", float64(r.Errors)/float64(r.Requests)*100)
	}
	fmt.Println()
	if len(r.LatenciesUs) > 0 {
		fmt.Printf("    Latency P50:    %10s\n", r.LatencyP(50))
		fmt.Printf("    Latency P90:    %10s\n", r.LatencyP(90))
		fmt.Printf("    Latency P99:    %10s\n", r.LatencyP(99))
		fmt.Printf("    Latency Max:    %10s\n", time.Duration(r.LatenciesUs[len(r.LatenciesUs)-1])*time.Microsecond)
	}
	fmt.Println()
}

type BenchmarkConfig struct {
	ProxyAddr       string
	DirectAddr      string
	Concurrency     int
	Duration        time.Duration
	TargetURL       string
	Connections     int
}

var (
	flagProxyAddr  = flag.String("proxy", "127.0.0.1:8444", "Proxy server address")
	flagDirectAddr = flag.String("direct", "127.0.0.1:8444", "Direct server address (dashboard)")
	flagDuration   = flag.Int("duration", 10, "Test duration in seconds")
)

func main() {
	flag.Parse()

	cfg := BenchmarkConfig{
		ProxyAddr:       *flagProxyAddr,
		DirectAddr:      *flagDirectAddr,
		Duration:        time.Duration(*flagDuration) * time.Second,
		TargetURL:       "http://www.google.com/",
	}

	fmt.Println("========================================================================")
	fmt.Println("  NetNinja Load Test Suite")
	fmt.Println("  Target proxy:", cfg.ProxyAddr)
	fmt.Println("  Duration:    ", cfg.Duration)
	fmt.Println("========================================================================")
	fmt.Println()

	var results []*Result

	// Test 1: Dashboard direct HTTP
	results = append(results, benchmarkDashboard(cfg))

	// Test 2: HTTP proxy throughput (small requests)
	results = append(results, benchmarkHTTPProxy(cfg, 1))

	// Test 3: HTTP proxy throughput (medium concurrency)
	results = append(results, benchmarkHTTPProxy(cfg, 10))

	// Test 4: HTTP proxy throughput (high concurrency)
	results = append(results, benchmarkHTTPProxy(cfg, 50))

	// Test 5: CONNECT tunnel throughput
	results = append(results, benchmarkCONNECT(cfg, 5))

	// Test 6: CONNECT tunnel (high concurrency)
	results = append(results, benchmarkCONNECT(cfg, 25))

	// Test 7: Large file transfer through proxy
	results = append(results, benchmarkLargeTransfer(cfg))

	// Test 8: PAC file response time
	results = append(results, benchmarkPAC(cfg))

	// Summary
	fmt.Println("========================================================================")
	fmt.Println("  RESULTS SUMMARY")
	fmt.Println("========================================================================")
	fmt.Println()

	for _, r := range results {
		r.Print()
	}

	// Overall assessment
	fmt.Println("========================================================================")
	fmt.Println("  ASSESSMENT")
	fmt.Println("========================================================================")
	fmt.Println()

	for _, r := range results {
		assessment := "GOOD"
		if r.Errors > 0 {
			ratio := float64(r.Errors) / float64(r.Requests)
			if ratio > 0.05 {
				assessment = "POOR"
			} else if ratio > 0.01 {
				assessment = "FAIR"
			}
		}
		fmt.Printf("  %-35s %s  (%.1f req/s, %.2f MB/s)\n", r.Name, assessment, r.RPS(), r.MBps())
	}
}

// ── Proxy Client Setup ──────────────────────────────────────────────────

func newProxyClient(proxyAddr string) *http.Client {
	proxyURL, _ := url.Parse("http://" + proxyAddr + "/")
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			MaxIdleConns:        200,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     30 * time.Second,
			DisableCompression:  true,
		},
		Timeout: 30 * time.Second,
	}
}

func newDirectClient(directAddr string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 10 * time.Second,
	}
}

// ── Benchmarks ──────────────────────────────────────────────────────────

func benchmarkDashboard(cfg BenchmarkConfig) *Result {
	r := &Result{Name: "Dashboard HTTP Direct"}
	client := newDirectClient(cfg.DirectAddr)
	start := time.Now()

	for time.Since(start) < cfg.Duration {
		t0 := time.Now()
		resp, err := client.Get("http://" + cfg.DirectAddr + "/")
		latencyUs := time.Since(t0).Microseconds()
		r.Requests++
		r.LatenciesUs = append(r.LatenciesUs, latencyUs)
		if err != nil {
			r.Errors++
			continue
		}
		n, _ := io.Copy(io.Discard, resp.Body)
		r.Bytes += n
		resp.Body.Close()
	}

	r.Duration = time.Since(start)
	sort.Slice(r.LatenciesUs, func(i, j int) bool { return r.LatenciesUs[i] < r.LatenciesUs[j] })
	return r
}

func benchmarkHTTPProxy(cfg BenchmarkConfig, concurrency int) *Result {
	r := &Result{
		Name: fmt.Sprintf("HTTP Proxy (concurrency=%d)", concurrency),
	}
	client := newProxyClient(cfg.ProxyAddr)
	var wg sync.WaitGroup
	start := time.Now()
	var reqCount, errCount, byteCount int64
	var latMu sync.Mutex
	var latencies []int64
	const maxSamples = 100000

	for c := 0; c < concurrency; c++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if time.Since(start) >= cfg.Duration {
					return
				}
				t0 := time.Now()
				req, _ := http.NewRequest("GET", cfg.TargetURL, nil)
				resp, err := client.Do(req)
				lat := time.Since(t0).Microseconds()
				atomic.AddInt64(&reqCount, 1)
				if err != nil {
					atomic.AddInt64(&errCount, 1)
					continue
				}
				n, _ := io.Copy(io.Discard, resp.Body)
				atomic.AddInt64(&byteCount, n)
				resp.Body.Close()

				latMu.Lock()
				if len(latencies) < maxSamples {
					latencies = append(latencies, lat)
				} else if rand.Intn(len(latencies)) == 0 {
					latencies[rand.Intn(len(latencies))] = lat
				}
				latMu.Unlock()
			}
		}()
	}
	wg.Wait()

	r.Requests = atomic.LoadInt64(&reqCount)
	r.Errors = atomic.LoadInt64(&errCount)
	r.Bytes = atomic.LoadInt64(&byteCount)
	r.Duration = time.Since(start)
	r.LatenciesUs = latencies
	sort.Slice(r.LatenciesUs, func(i, j int) bool { return r.LatenciesUs[i] < r.LatenciesUs[j] })
	return r
}

func benchmarkCONNECT(cfg BenchmarkConfig, concurrency int) *Result {
	r := &Result{
		Name: fmt.Sprintf("CONNECT Tunnel (concurrency=%d)", concurrency),
	}
	var wg sync.WaitGroup
	start := time.Now()
	var reqCount, errCount int64
	var latMu sync.Mutex
	var latencies []int64

	for c := 0; c < concurrency; c++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if time.Since(start) >= cfg.Duration {
					return
				}
				t0 := time.Now()
				conn, err := net.DialTimeout("tcp", cfg.ProxyAddr, 5*time.Second)
				lat := time.Since(t0).Microseconds()
				atomic.AddInt64(&reqCount, 1)
				if err != nil {
					atomic.AddInt64(&errCount, 1)
					continue
				}
				_, err = conn.Write([]byte("CONNECT www.google.com:443 HTTP/1.1\r\nHost: www.google.com:443\r\n\r\n"))
				if err != nil {
					atomic.AddInt64(&errCount, 1)
					conn.Close()
					continue
				}
				resp := make([]byte, 256)
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, _ := conn.Read(resp)
				conn.Close()
				if n > 0 && string(resp[:12]) == "HTTP/1.1 200" {
					// success
				} else {
					atomic.AddInt64(&errCount, 1)
				}

				latMu.Lock()
				latencies = append(latencies, lat)
				latMu.Unlock()
			}
		}()
	}
	wg.Wait()

	r.Requests = atomic.LoadInt64(&reqCount)
	r.Errors = atomic.LoadInt64(&errCount)
	r.Duration = time.Since(start)
	r.LatenciesUs = latencies
	sort.Slice(r.LatenciesUs, func(i, j int) bool { return r.LatenciesUs[i] < r.LatenciesUs[j] })
	return r
}

func benchmarkLargeTransfer(cfg BenchmarkConfig) *Result {
	r := &Result{Name: "Large Transfer (HTTP proxy)"}
	client := newProxyClient(cfg.ProxyAddr)
	targetURL := "http://speedtest.tele2.net/10MB.zip"
	start := time.Now()

	resp, err := client.Get(targetURL)
	if err != nil {
		r.Errors = 1
		r.Requests = 1
		r.Duration = time.Since(start)
		return r
	}
	defer resp.Body.Close()

	n, _ := io.Copy(io.Discard, resp.Body)
	r.Bytes = n
	r.Requests = 1
	r.Duration = time.Since(start)
	return r
}

func benchmarkPAC(cfg BenchmarkConfig) *Result {
	r := &Result{Name: "PAC File Response"}
	client := newDirectClient(cfg.DirectAddr)
	start := time.Now()

	for time.Since(start) < cfg.Duration {
		t0 := time.Now()
		resp, err := client.Get("http://" + cfg.DirectAddr + "/proxy.pac")
		latencyUs := time.Since(t0).Microseconds()
		r.Requests++
		r.LatenciesUs = append(r.LatenciesUs, latencyUs)
		if err != nil {
			r.Errors++
			continue
		}
		n, _ := io.Copy(io.Discard, resp.Body)
		r.Bytes += n
		resp.Body.Close()
	}

	r.Duration = time.Since(start)
	sort.Slice(r.LatenciesUs, func(i, j int) bool { return r.LatenciesUs[i] < r.LatenciesUs[j] })
	return r
}

// ── Helpers ─────────────────────────────────────────────────────────────

func formatBytes(b int64) string {
	if b >= 1<<30 {
		return fmt.Sprintf("%.2f GB", float64(b)/(1<<30))
	}
	if b >= 1<<20 {
		return fmt.Sprintf("%.2f MB", float64(b)/(1<<20))
	}
	if b >= 1<<10 {
		return fmt.Sprintf("%.2f KB", float64(b)/(1<<10))
	}
	return fmt.Sprintf("%d B", b)
}
