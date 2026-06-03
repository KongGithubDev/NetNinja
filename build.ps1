param(
    [switch]$NoPGO
)

$now = [DateTime]::Now.ToString("yyyy-MM-dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
$ldflags = "-X 'main.buildTime=$now' -s -w"

# Build net_server (with PGO if default.pgo exists)
$pgoFlag = ""
if (-not $NoPGO -and (Test-Path "default.pgo")) {
    $pgoFlag = "-pgo=default.pgo"
    Write-Host "[PGO] Profile-Guided Optimization enabled" -ForegroundColor Cyan
}

Write-Host "[BUILD] Building net_server.exe..." -ForegroundColor Yellow
go build $pgoFlag -ldflags $ldflags -o net_server.exe net_server.go
if ($LASTEXITCODE -eq 0) {
    Write-Host "[BUILD] net_server.exe built successfully" -ForegroundColor Green
} else {
    Write-Host "[BUILD] net_server.exe build FAILED" -ForegroundColor Red
    exit 1
}

Write-Host "[BUILD] Building proxy.exe..." -ForegroundColor Yellow
go build -ldflags $ldflags -o proxy.exe proxy.go
if ($LASTEXITCODE -eq 0) {
    Write-Host "[BUILD] proxy.exe built successfully" -ForegroundColor Green
} else {
    Write-Host "[BUILD] proxy.exe build FAILED" -ForegroundColor Red
    exit 1
}

Write-Host "`n[SUCCESS] NetNinja Build Finished at $now" -ForegroundColor Green
Write-Host "[INFO] Output: net_server.exe, proxy.exe" -ForegroundColor Gray
if ($pgoFlag -ne "") {
    Write-Host "[INFO] PGO: Enabled (default.pgo)" -ForegroundColor Gray
}
