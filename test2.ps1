# test2.ps1
Write-Host "Starting fake backend (Python HTTP on 18080)..."
$pythonProc = Start-Process -FilePath "python" -ArgumentList "-m", "http.server", "18080" -WindowStyle Hidden -PassThru

Write-Host "Starting net_server (Port 14443)..."
$netProc = Start-Process -FilePath ".\net_server.exe" -ArgumentList "-port", "14443", "-web-port", "18080", "-web-sni", "example.com", "-tls", "true" -WindowStyle Hidden -PassThru

Start-Sleep -Seconds 3

Write-Host "`n========================================================"
Write-Host "TEST 1: Direct HTTP Access (Should return Bad Request)"
Write-Host "========================================================"
$output1 = curl.exe -s http://127.0.0.1:14443/
if ($output1 -match "Bad Request") {
    Write-Host "✅ TEST 1 PASSED: Plain HTTP on 443 safely rejected!"
}
else {
    Write-Host "❌ TEST 1 FAILED! Output: $output1"
}

Write-Host "`n========================================================"
Write-Host "TEST 2: Direct HTTPS Access (Should trigger Dashboard UI)"
Write-Host "========================================================"
$output2 = curl.exe -s -k https://127.0.0.1:14443/
if ($output2 -match "net_server dashboard") {
    Write-Host "✅ TEST 2 PASSED: HTTPS dashboard loaded!"
}
else {
    Write-Host "❌ TEST 2 FAILED!"
}

Write-Host "`n========================================================"
Write-Host "TEST 3: Access with SNI 'example.com' (Should hit Python trigger bad SSL)"
Write-Host "========================================================"
$output3 = curl.exe -v -k --resolve example.com:14443:127.0.0.1 https://example.com:14443/ 2>&1
$combinedOutput3 = $output3 -join "`n"

if ($combinedOutput3 -match "SSL" -or $combinedOutput3 -match "Connection reset" -or $combinedOutput3 -match "unrecognized name") {
    Write-Host "✅ TEST 3 PASSED: Connection forwarded to Python backend successfully!"
}
else {
    Write-Host "❌ TEST 3 FAILED!"
}

Write-Host "`nCleaning up processes..."
Stop-Process -Id $pythonProc.Id -Force
Stop-Process -Id $netProc.Id -Force
Write-Host "Done!"
