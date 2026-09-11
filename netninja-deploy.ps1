# netninja-deploy.ps1 — deploy the new NetNinja proxy binary to the proxy VM.
#
# The public host address deliberately does NOT live in this file: the
# repository is public, so the target and the key stay on your machine. Point it
# at the server with either
#
#   * environment variables  NETNINJA_SERVER / NETNINJA_USER, or
#   * a local netninja.local.ps1 next to this script (git-ignored), e.g.
#         $env:NETNINJA_SERVER = '<server-ip-or-host>'
#         $env:NETNINJA_USER   = '<ssh-user>'
#
# Run it yourself (it needs the remote root credential, which stays on this
# machine — it is read as a SecureString and piped straight into ssh):
#
#   powershell -ExecutionPolicy Bypass -File .\netninja-deploy.ps1 -ThaiEgress
#   powershell -ExecutionPolicy Bypass -File .\netninja-deploy.ps1 -ThaiPool
#
# What it does:
#   1. scp the freshly built binary (dist\proxy_linux by default) to /tmp on the VM
#   2. run /tmp/netninja-deploy.sh there with root privileges
#      (backup → install → restart → optional Thai egress rotate → verify)
#   2b. when netninja-th-pool.sh sits next to this script it is uploaded too, and
#      -ThaiPool installs/enables the systemd service that supervises the tunnels
#   3. print /geo-check so you can confirm geo traffic exits from Thailand
param(
    [string]$Server = $env:NETNINJA_SERVER,
    [string]$User   = $env:NETNINJA_USER,
    [string]$Key    = "$PSScriptRoot\azure-sg.key",
    [string]$Binary = "$PSScriptRoot\dist\proxy_linux",
    [string]$ThaiNodes = '',
    [switch]$ThaiEgress,
    [switch]$ThaiPool,
    [switch]$SkipUpload
)

$ErrorActionPreference = 'Stop'

# Local, uncommitted settings win over the environment.
$localSettings = Join-Path $PSScriptRoot 'netninja.local.ps1'
if (Test-Path $localSettings) { . $localSettings }
if (-not $Server) { $Server = $env:NETNINJA_SERVER }
if (-not $User)   { $User   = $env:NETNINJA_USER }
if (-not $Server -or -not $User) {
    throw @"
Target host not configured. Set it outside the repository:
  `$env:NETNINJA_SERVER = '<server-ip-or-host>'
  `$env:NETNINJA_USER   = '<ssh-user>'
...or create netninja.local.ps1 next to this script (already git-ignored) with those two lines.
"@
}

if (-not (Test-Path $Key))    { throw "SSH key not found: $Key" }
if (-not $SkipUpload -and -not (Test-Path $Binary)) { throw "Binary not found: $Binary (build it first, or use -SkipUpload)" }

$target  = "$User@$Server"
$sshOpts = @('-i', $Key, '-o', 'StrictHostKeyChecking=accept-new', '-o', 'ConnectTimeout=15')

if (-not $SkipUpload) {
    Write-Host "== uploading binary ($Binary) ==" -ForegroundColor Cyan
    scp @sshOpts -- $Binary "${target}:/tmp/proxy_linux_new"
    if ($LASTEXITCODE -ne 0) { throw "scp failed" }
}

# The Thai egress pool and the geo domain list are data files on the server.
# Upload the local copies when they exist (geo-nodes.txt = one host:port per
# line, optional; geo-domains.txt = the domain list, replaced if present).
$poolFile = "$PSScriptRoot\geo-nodes.txt"
if (Test-Path $poolFile) {
    Write-Host "== uploading Thai egress pool file ($poolFile) ==" -ForegroundColor Cyan
    scp @sshOpts -- $poolFile "${target}:/tmp/geo-nodes.txt"
    if ($LASTEXITCODE -ne 0) { throw "scp of geo-nodes.txt failed" }
}
$domainsFile = "$PSScriptRoot\geo-domains.txt"
if (Test-Path $domainsFile) {
    Write-Host "== uploading geo domain list ($domainsFile) ==" -ForegroundColor Cyan
    scp @sshOpts -- $domainsFile "${target}:/tmp/geo-domains.txt"
    if ($LASTEXITCODE -ne 0) { throw "scp of geo-domains.txt failed" }
}

# The pool supervisor (optional): it keeps the tunnels listed in the pool file
# alive by itself. Its real config (/etc/netninja/th-pool.conf) stays on the
# server — only the script and the example config are uploaded here.
$supervisor = "$PSScriptRoot\netninja-th-pool.sh"
if (Test-Path $supervisor) {
    Write-Host "== uploading Thai pool supervisor ($supervisor) ==" -ForegroundColor Cyan
    scp @sshOpts -- $supervisor "${target}:/tmp/netninja-th-pool.sh"
    if ($LASTEXITCODE -ne 0) { throw "scp of netninja-th-pool.sh failed" }
    $supervisorConf = "$PSScriptRoot\netninja-th-pool.conf.example"
    if (Test-Path $supervisorConf) {
        scp @sshOpts -- $supervisorConf "${target}:/tmp/netninja-th-pool.conf.example"
        if ($LASTEXITCODE -ne 0) { throw "scp of netninja-th-pool.conf.example failed" }
    }
}

$remoteCmd = 'bash /tmp/netninja-deploy.sh'
if ($ThaiEgress) { $remoteCmd += ' --th-egress' }
if ($ThaiNodes)  { $remoteCmd += " --th-nodes '$ThaiNodes'" }
if ($ThaiPool)   { $remoteCmd += ' --th-pool' }

Write-Host "== remote root password for $target (only used for this command) ==" -ForegroundColor Yellow
$secure = Read-Host -AsSecureString -Prompt "password"
$bstr   = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)

    # sudo -S reads the password from the first line of stdin; the deploy script
    # itself never reads stdin, so the rest of the pipe is free.
    $plain + "`n" | ssh @sshOpts -T $target "sudo -S $remoteCmd"
    if ($LASTEXITCODE -ne 0) { throw "remote deploy failed (see output above — the script rolls the binary back automatically)" }
}
finally {
    if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    $plain = $null
}

Write-Host ""
Write-Host "== geo-check (ยืนยันว่า ometv จะเห็นประเทศไหน) ==" -ForegroundColor Cyan
ssh @sshOpts $target "curl -s --max-time 40 http://127.0.0.1:5988/geo-check"

Write-Host ""
Write-Host "เสร็จแล้ว — จากเครื่องนี้เปิด http://${Server}:5988/geo-check ได้เลย" -ForegroundColor Green
Write-Host "(host นี้ไม่ได้ถูกเก็บในไฟล์นี้ — มาจาก env หรือ netninja.local.ps1 เท่านั้น)" -ForegroundColor DarkGray
