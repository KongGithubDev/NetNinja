# NetNinja Load Test Benchmarks

## Running the Tests

```powershell
# Run all benchmarks with 10s per test
.\run-loadtest.ps1

# Run with custom duration (30s per test for more stable results)
.\run-loadtest.ps1 -Duration 30

# Run on a different port
.\run-loadtest.ps1 -Port 8444

# Skip build and leave server running after test
.\run-loadtest.ps1 -NoBuild -NoCleanup
```

## What Each Test Measures

### 1. Dashboard HTTP Direct

Measures raw HTTP throughput of the built-in dashboard server (no proxy layer).

- **What it tests:** ServeMux routing, HTML template rendering, connection handling
- **Expected:** 5000-15000 req/s (local)
- **Bottleneck if low:** HTTP handler, template rendering

### 2. HTTP Proxy (concurrency=1)

Measures single-stream HTTP forward proxy throughput.

- **What it tests:** HTTP request parsing, header forwarding, DNS resolution, TCP dial, response relay
- **Expected:** 50-200 req/s per connection (depends on target server latency)
- **Bottleneck if low:** DNS resolution, upstream latency, TCP handshake overhead

### 3. HTTP Proxy (concurrency=10)

Measures moderate concurrency HTTP proxy throughput.

- **What it tests:** Connection pooling, goroutine scheduling, concurrent DNS resolution
- **Expected:** 200-1000 req/s (10x concurrent connections)
- **Bottleneck if low:** `MaxIdleConnsPerHost` limit (currently 100), goroutine overhead

### 4. HTTP Proxy (concurrency=50)

Measures high-concurrency HTTP proxy throughput (stress test).

- **What it tests:** Scalability under load, GC pressure, socket exhaustion
- **Expected:** 500-3000 req/s
- **Bottleneck if low:** Windows port exhaustion, GC spikes, `MaxIdleConns` limit (currently 1000)

### 5. CONNECT Tunnel (concurrency=5)

Measures HTTPS CONNECT tunnel throughput.

- **What it tests:** SNI detection, TCP relay, `io.Copy` zero-copy performance
- **Expected:** 100-500 tunnels/s
- **Bottleneck if low:** `handleConnection` SNI parsing, TCP dial latency

### 6. CONNECT Tunnel (concurrency=25)

Measures high-concurrency HTTPS CONNECT tunnel throughput.

- **What it tests:** Concurrent `handleVLESS` or `handleConnect` goroutines
- **Expected:** 200-1500 tunnels/s
- **Bottleneck if low:** Goroutine scheduling, memory allocation per connection

### 7. Large Transfer

Measures bulk data transfer bandwidth through the proxy.

- **What it tests:** `io.CopyBuffer` with 512KB buffer, TCP socket throughput, no GC interference
- **Expected:** 50-500 MB/s (local loopback)
- **Bottleneck if low:** TCP buffer sizes, Windows TCP auto-tuning, CPU

### 8. PAC File Response

Measures PAC auto-config file serving throughput.

- **What it tests:** `servePAC` function, string formatting, response headers
- **Expected:** 5000-20000 req/s
- **Bottleneck if low:** fmt.Sprintf performance

---

## Interpreting Results

### Performance Tiers

| Tier | HTTP Proxy (req/s) | CONNECT (tunnels/s) | Large Transfer (MB/s) | Assessment |
|------|-------------------|---------------------|-----------------------|------------|
| Excellent | >3000 | >1000 | >300 | Ready for production |
| Good | 1000-3000 | 500-1000 | 100-300 | Acceptable |
| Fair | 300-1000 | 100-500 | 20-100 | Needs optimization |
| Poor | <300 | <100 | <20 | Critical issues |

### Error Rate Guidelines

- **< 0.1%:** Excellent - no issues
- **0.1-1%:** Acceptable - minor timeout under load
- **1-5%:** Fair - investigate DNS or connection timeouts
- **> 5%:** Poor - critical issue, check server logs

### Expected Baseline (Windows VPS, local loopback)

| Test | Expected Range | Notes |
|------|---------------|-------|
| Dashboard | 5000-15000 req/s | CPU-bound, Go HTTP server |
| HTTP Proxy (1 conn) | 50-200 req/s | Limited by upstream latency |
| HTTP Proxy (10 conn) | 200-1000 req/s | Scales with concurrency |
| HTTP Proxy (50 conn) | 500-3000 req/s | Limited by Windows TCP stack |
| CONNECT (5) | 100-500 tunnels/s | TCP handshake overhead |
| CONNECT (25) | 200-1500 tunnels/s | Scales with goroutines |
| Large Transfer | 50-500 MB/s | Loopback bandwidth |
| PAC | 5000-20000 req/s | Lightweight handler |

### Remote VPS (via internet)

| Test | Expected Range | Notes |
|------|---------------|-------|
| HTTP Proxy | 10-100 req/s | Limited by network latency |
| CONNECT | 20-200 tunnels/s | Limited by RTT |
| Large Transfer | 5-50 MB/s | Limited by VPS bandwidth |

---

## Optimization Guide

### If Dashboard is slow (<1000 req/s)

- Check for expensive operations in `serveDashboard`
- Template rendering uses `fmt.Sprintf` with a large HTML constant - consider pre-rendering

### If HTTP Proxy is slow (<100 req/s)

1. Check DNS resolution time (increase DNS cache TTL)
2. Verify `MaxIdleConnsPerHost` is not too low (currently 100)
3. Increase `MaxIdleConns` (currently 1000)
4. Check for resource leaks (file descriptors, goroutines)

### If CONNECT tunnels are slow (<100 tunnels/s)

1. Check `handleConnection` SNI parsing overhead
2. Verify TCP `SetNoDelay` and `KeepAlive` settings
3. Check for `errc` channel blocking issues

### If Large Transfer is slow (<20 MB/s)

1. Increase `copyBufferPool` buffer size (currently 512KB)
2. Enable Windows TCP auto-tuning (`autotuninglevel=normal`)
3. Check CPU usage - Go runtime scheduling overhead
4. Increase TCP socket buffers (`SetReadBuffer`/`SetWriteBuffer`)

---

## Advanced: Manual Test Commands

```powershell
# Test basic connectivity
curl -k -s -o NUL -w "%%{http_code}" https://localhost:8444/

# Measure single request latency
Measure-Command { curl -k -s -o NUL https://localhost:8444/ }

# Check open connections
netstat -an | findstr ":8444"

# Monitor server resource usage
while ($true) {
    Clear-Host
    Get-Process net_server -ErrorAction SilentlyContinue |
        Select-Object CPU, WorkingSet, Handles, Threads
    Start-Sleep -Seconds 2
}

# Test with goroutine count
while ($true) {
    $resp = Invoke-WebRequest -Uri "http://127.0.0.1:8444/" -UseBasicParsing
    $content = $resp.Content
    if ($content -match 'goroutines">(\d+)') {
        Write-Host "Goroutines: $($Matches[1])"
    }
    Start-Sleep -Seconds 2
}
```

## Historical Comparison

Record baseline results before and after changes to measure improvement:

```powershell
# Before optimization
.\run-loadtest.ps1 -Duration 10 -ReportFile baseline-before.txt

# After optimization
.\run-loadtest.ps1 -Duration 10 -ReportFile baseline-after.txt

# Compare
Compare-Object (Get-Content baseline-before.txt) (Get-Content baseline-after.txt)
```
