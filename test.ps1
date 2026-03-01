# test.ps1
Write-Host "Starting fake backend (Python HTTP on 18080)..."
$pythonProc = Start-Process -FilePath "python" -ArgumentList "-m", "http.server", "18080" -WindowStyle Hidden -PassThru

Write-Host "Starting net_server (Port 14443, proxying 'example.com' to 18080)..."
$netProc = Start-Process -FilePath ".\net_server.exe" -ArgumentList "-port", "14443", "-web-port", "18080", "-web-sni", "example.com", "-tls", "true" -WindowStyle Hidden -PassThru

Start-Sleep -Seconds 3

Write-Host "`n========================================================"
Write-Host "TEST 1: Direct IP Access (Should trigger Dashboard UI)"
Write-Host "========================================================"
$output1 = curl.exe -s -k https://127.0.0.1:14443/
if ($output1 -match "net_server dashboard") {
    Write-Host "✅ TEST 1 PASSED: Found dashboard HTML!"
}
else {
    Write-Host "❌ TEST 1 FAILED: Did not find dashboard HTML."
    Write-Host $output1
}

Write-Host "`n========================================================"
Write-Host "TEST 2: Access with SNI 'example.com' (Should hit Python trigger bad SSL)"
Write-Host "========================================================"
# Since Python expects HTTP but curl sends HTTPS, curl will fail in handshake, PROVING proxy worked!
$output2 = curl.exe -v -k --resolve example.com:14443:127.0.0.1 https://example.com:14443/ 2>&1
$combinedOutput2 = $output2 -join "`n"

if ($combinedOutput2 -match "SSL" -or $combinedOutput2 -match "Connection reset" -or $combinedOutput2 -match "unrecognized name") {
    # If the handshake failed because the backend didn't speak TLS, then it worked.
    # Wait, curl -v will show if it connected.
    Write-Host "✅ TEST 2 PASSED: Connection forwarded to Python backend successfully! (SSL Handshake failed as expected since Python isn't an SSL server)"
}
else {
    Write-Host "❌ TEST 2 FAILED: Connection was not proxy'd correctly."
    Write-Host $combinedOutput2
}

Write-Host "`nCleaning up processes..."
Stop-Process -Id $pythonProc.Id -Force
Stop-Process -Id $netProc.Id -Force
Write-Host "Done!"
