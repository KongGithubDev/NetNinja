$now = [DateTime]::Now.ToString("yyyy-MM-dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
$ldflags = "-X 'main.buildTime=$now' -s -w"
go build -ldflags $ldflags -o proxy.exe proxy.go
if ($?) {
    Write-Host "`n[SUCCESS] NetNinja Build Finished at $now" -ForegroundColor Green
    Write-Host "[INFO] Output: proxy.exe" -ForegroundColor Gray
}
else {
    Write-Host "`n[ERROR] Build Failed!" -ForegroundColor Red
}
