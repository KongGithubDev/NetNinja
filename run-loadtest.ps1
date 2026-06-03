param(
    [int]$Port = 8444,
    [int]$Duration = 10,
    [switch]$NoBuild,
    [switch]$NoCleanup,
    [string]$ReportFile = ""
)

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$StartTime = Get-Date

if ($ReportFile -eq "") {
    $timestamp = $StartTime.ToString("yyyyMMdd-HHmmss")
    $ReportFile = Join-Path $ProjectRoot "loadtest-report-$timestamp.txt"
}

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  NetNinja Load Test Suite"
Write-Host "  Started: $($StartTime.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Host "  Port:    $Port"
Write-Host "  Duration per test: $Duration seconds"
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Build load-tester
if (-not $NoBuild) {
    Write-Host "[SETUP] Building load-tester..." -ForegroundColor Yellow
    $env:CGO_ENABLED = "0"
    go build -o load-tester.exe load-tester.go 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[SETUP] Build failed!" -ForegroundColor Red
        exit 1
    }
    Write-Host "[SETUP] Load-tester built." -ForegroundColor Green

    # Also build net_server if not present
    if (-not (Test-Path (Join-Path $ProjectRoot "net_server.exe"))) {
        Write-Host "[SETUP] Building net_server..." -ForegroundColor Yellow
        $pgoFlag = ""
        if (Test-Path (Join-Path $ProjectRoot "default.pgo")) {
            $pgoFlag = "-pgo=default.pgo"
            Write-Host "[SETUP] PGO enabled" -ForegroundColor Cyan
        }
        go build $pgoFlag -o net_server.exe net_server.go 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[SETUP] net_server build failed!" -ForegroundColor Red
            exit 1
        }
        Write-Host "[SETUP] net_server built." -ForegroundColor Green
    }
} else {
    Write-Host "[SETUP] Skipping build (-NoBuild)" -ForegroundColor Yellow
}

# Step 2: Start net_server
Write-Host "[SETUP] Starting net_server on port $Port..." -ForegroundColor Yellow
$serverLog = Join-Path $ProjectRoot "loadtest-server.log"

# Use Start-Process with separate stdout/stderr files to avoid PowerShell stream conflict
$stdoutLog = Join-Path $ProjectRoot "loadtest-server-stdout.log"
$stderrLog = Join-Path $ProjectRoot "loadtest-server-stderr.log"
$serverProc = Start-Process -FilePath (Join-Path $ProjectRoot "net_server.exe") `
    -ArgumentList "-port $Port -tls false" `
    -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput $stdoutLog `
    -RedirectStandardError $stderrLog

Write-Host "[SETUP] Server PID: $($serverProc.Id)" -ForegroundColor Gray
Start-Sleep -Seconds 3

# Verify server is running by checking PID
$serverRunning = Get-Process -Id $serverProc.Id -ErrorAction SilentlyContinue
if (-not $serverRunning) {
    Write-Host "[SETUP] Server process exited prematurely" -ForegroundColor Red
    if (Test-Path $stderrLog) { Get-Content $stderrLog -Tail 10 }
    exit 1
}

# Check if port is listening
try {
    $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/" -TimeoutSec 5 -UseBasicParsing
    if ($resp.StatusCode -ne 200) { throw "Status: $($resp.StatusCode)" }
    Write-Host "[SETUP] Server is running (HTTP $($resp.StatusCode))." -ForegroundColor Green
} catch {
    Write-Host "[SETUP] Server PID $($serverProc.Id) exists but not responding on port $Port" -ForegroundColor Yellow
    Write-Host "[SETUP] Waiting 5 more seconds..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    try {
        $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/" -TimeoutSec 5 -UseBasicParsing
        Write-Host "[SETUP] Server is now responding (HTTP $($resp.StatusCode))." -ForegroundColor Green
    } catch {
        Write-Host "[SETUP] Server failed to start: $_" -ForegroundColor Red
        if (Test-Path $stderrLog) { Get-Content $stderrLog -Tail 10 }
        Stop-Process -Id $serverProc.Id -Force -ErrorAction SilentlyContinue
        exit 1
    }
}

# Step 3: Run benchmarks
$testResults = @()

function Run-Test {
    param(
        [string]$Name,
        [string]$ExtraArgs
    )
    Write-Host "[TEST] $Name..." -ForegroundColor Yellow
    $output = & (Join-Path $ProjectRoot "load-tester.exe") `
        -proxy "127.0.0.1:$Port" `
        -direct "127.0.0.1:$Port" `
        -duration $Duration `
        $ExtraArgs 2>&1
    $testResults += @{
        Name = $Name
        Output = ($output | Out-String)
    }
    Write-Host "[TEST] $Name complete." -ForegroundColor Green
    $output | Select-Object -Last 1 | Write-Host
}

# Wait for server to be warm
Start-Sleep -Seconds 1

Run-Test "Benchmark Suite" ""

# Step 4: Collect server stats during test
Write-Host "[STATS] Collecting server statistics..." -ForegroundColor Yellow
$before = Get-Date
$dashboardResp = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/" -UseBasicParsing
$after = Get-Date
Write-Host "[STATS] Dashboard responded in $(($after - $before).TotalMilliseconds.ToString('F0')) ms" -ForegroundColor Gray

# Step 5: Stop server
Write-Host "[CLEANUP] Stopping server..." -ForegroundColor Yellow
if (-not $NoCleanup) {
    Stop-Process -Id $serverProc.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Write-Host "[CLEANUP] Server stopped." -ForegroundColor Green
} else {
    Write-Host "[CLEANUP] Server left running (-NoCleanup)" -ForegroundColor Yellow
}

# Step 6: Generate report
$EndTime = Get-Date
$TotalDuration = ($EndTime - $StartTime).TotalSeconds

$report = @"
================================================================================
  NetNinja Load Test Report
  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
  Duration per test: ${Duration}s
  Total time: $($TotalDuration.ToString('F1'))s
================================================================================

$(($testResults | ForEach-Object { "--- $($_.Name) ---`n$($_.Output)`n" }) -join "`n")

================================================================================
  System Information
================================================================================

  Go version: $(go version 2>$null)
  OS: $((Get-WmiObject Win32_OperatingSystem).Caption)
  CPU: $((Get-WmiObject Win32_Processor).Name | Select-Object -First 1)
  Cores: $((Get-WmiObject Win32_ComputerSystem).NumberOfLogicalProcessors)
  Memory: $([math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory/1GB, 1)) GB
  PGO: $((Test-Path (Join-Path $ProjectRoot "default.pgo")).ToString())

"@

# Write report
$report | Out-File -FilePath $ReportFile -Encoding UTF8
Write-Host "[REPORT] Report saved: $ReportFile" -ForegroundColor Green

# Display summary
Write-Host "`n========================================================================" -ForegroundColor Cyan
Write-Host "  LOAD TEST COMPLETE" -ForegroundColor Cyan
Write-Host "  Report: $ReportFile" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan

# Show test results inline
Write-Host "`nQuick summary:" -ForegroundColor Cyan
foreach ($test in $testResults) {
    $lines = $test.Output -split "`n"
    $assessmentLine = $lines | Where-Object { $_ -match "^  \w" } | Select-Object -First 1
    $rpsLine = $lines | Where-Object { $_ -match "req/s" } | Select-Object -First 1
    $bwLine = $lines | Where-Object { $_ -match "MB/s" } | Select-Object -First 1
    $errLine = $lines | Where-Object { $_ -match "Errors" } | Select-Object -First 1
    Write-Host "  $($test.Name)" -ForegroundColor White
    if ($rpsLine) { Write-Host "    $rpsLine" -ForegroundColor Gray }
    if ($bwLine) { Write-Host "    $bwLine" -ForegroundColor Gray }
    if ($errLine) { Write-Host "    $errLine" -ForegroundColor Gray }
}
