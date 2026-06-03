# collect-pgo.ps1
# Profile-Guided Optimization collection for net_server

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ServerPort = 8444
$ProfileDuration = 30
$PgoFile = Join-Path $ProjectRoot "default.pgo"
$LoadGen = Join-Path $ProjectRoot "profiling-load-gen.go"
$ServerLog = Join-Path $ProjectRoot "net_server_pgo.log"

Write-Host "[PGO] Profile-Guided Optimization collection" -ForegroundColor Cyan

# Step 1: Build net_server (no PGO yet)
Write-Host "[PGO] Building net_server..." -ForegroundColor Yellow
$env:CGO_ENABLED = "0"
$env:GOGC = "off"
go build -o net_server.exe net_server.go 2>&1
if ($LASTEXITCODE -ne 0) { Write-Host "[PGO] Build failed!" -ForegroundColor Red; exit 1 }
Write-Host "[PGO] net_server built." -ForegroundColor Green

# Step 2: Build load generator
Write-Host "[PGO] Building load generator..." -ForegroundColor Yellow
go build -o profiling-load-gen.exe profiling-load-gen.go 2>&1
if ($LASTEXITCODE -ne 0) { Write-Host "[PGO] Load gen build failed!" -ForegroundColor Red; exit 1 }
Write-Host "[PGO] Load generator built." -ForegroundColor Green

# Step 3: Start net_server in background
Write-Host "[PGO] Starting net_server on port $ServerPort (no TLS)..." -ForegroundColor Yellow
$serverProc = Start-Process -FilePath (Join-Path $ProjectRoot "net_server.exe") `
    -ArgumentList "-port $ServerPort -tls false" `
    -PassThru `
    -NoNewWindow `
    -RedirectStandardOutput $ServerLog `
    -RedirectStandardError $ServerLog

Write-Host "[PGO] Server PID: $($serverProc.Id)" -ForegroundColor Green
Start-Sleep -Seconds 3

# Step 4: Verify server is running
try {
    $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$ServerPort/" -TimeoutSec 5 -UseBasicParsing
    Write-Host "[PGO] Server running. Status: $($resp.StatusCode)" -ForegroundColor Green
} catch {
    Write-Host "[PGO] Server failed to start!" -ForegroundColor Red
    Get-Content $ServerLog -Tail 10
    Stop-Process -Id $serverProc.Id -Force -ErrorAction SilentlyContinue
    exit 1
}

# Step 5: Start load generator in background
Write-Host "[PGO] Starting workload generation..." -ForegroundColor Yellow
$loadProc = Start-Process -FilePath (Join-Path $ProjectRoot "profiling-load-gen.exe") -PassThru -NoNewWindow

# Wait for load to ramp up
Start-Sleep -Seconds 2

# Step 6: Collect CPU profile
Write-Host "[PGO] Collecting CPU profile ($ProfileDuration seconds)..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri "http://127.0.0.1:$ServerPort/debug/pprof/profile?seconds=$ProfileDuration" `
        -OutFile $PgoFile `
        -TimeoutSec ($ProfileDuration + 15) `
        -UseBasicParsing
    Write-Host "[PGO] Profile collected successfully." -ForegroundColor Green
} catch {
    Write-Host "[PGO] Profile collection failed: $_" -ForegroundColor Red
}

# Step 7: Wait for load generator
Write-Host "[PGO] Waiting for load generator..." -ForegroundColor Gray
try { Wait-Process -Id $loadProc.Id -Timeout 120 -ErrorAction SilentlyContinue } catch {}
Stop-Process -Id $loadProc.Id -Force -ErrorAction SilentlyContinue

# Step 8: Stop server
Write-Host "[PGO] Stopping server..." -ForegroundColor Yellow
Stop-Process -Id $serverProc.Id -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# Step 9: Verify profile
if (Test-Path $PgoFile) {
    $info = Get-Item $PgoFile
    $sizeKB = [math]::Round($info.Length / 1024, 1)
    Write-Host "[PGO] Profile saved: default.pgo ($sizeKB KB)" -ForegroundColor Green
    
    # Show top functions from profile
    Write-Host "[PGO] Top functions in profile:" -ForegroundColor Cyan
    go tool pprof -top -nodecount=10 -compact $PgoFile 2>&1 | Select-Object -Skip 1 | ForEach-Object { Write-Host "    $_" }
} else {
    Write-Host "[PGO] ERROR: Profile file not created!" -ForegroundColor Red
    exit 1
}

Write-Host "[PGO] Complete. Now rebuild with PGO:" -ForegroundColor Cyan
Write-Host "  go build -pgo=$PgoFile -o net_server.exe net_server.go" -ForegroundColor Green
