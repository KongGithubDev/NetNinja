# netninja-deploy.ps1 - deploy the new NetNinja proxy binary to the proxy VM.
#
# KEEP THIS FILE ASCII-ONLY. Windows PowerShell 5.1 reads a BOM-less .ps1 with
# the system ANSI codepage, not UTF-8: the three UTF-8 bytes of a dash or of a
# Thai character decode into curly quotes, PowerShell treats a curly quote as a
# string delimiter, and the file stops parsing before a single line runs (seen
# as "Unexpected token ... Missing closing '}'" on a line far below the cause).
# Plain ASCII is byte-identical in every codepage, so it cannot break this way.
#
# The public host address deliberately does NOT live in this file: the
# repository is public, so the target and the key stay on your machine. Point it
# at the server with either
#
#   * environment variables  NETNINJA_SERVER / NETNINJA_USER, or
#   * a local netninja.local.ps1 in the repository root (git-ignored), e.g.
#         $env:NETNINJA_SERVER = '<server-ip-or-host>'
#         $env:NETNINJA_USER   = '<ssh-user>'
#
# Run it yourself (it needs the remote password, which stays on this machine -
# it is read as a SecureString and piped straight into ssh):
#
#   powershell -ExecutionPolicy Bypass -File .\scripts\netninja-deploy.ps1 -ThaiEgress
#   powershell -ExecutionPolicy Bypass -File .\scripts\netninja-deploy.ps1 -ThaiPool
#
# What it does:
#   1. scp the freshly built binaries (dist\proxy_linux and, when present,
#      dist\keepalive_linux - see `make`) to /tmp on the VM, so one run updates
#      the proxy *and* the keepalive page (proxy-only deploys are how the two
#      drift apart; -NoKeepalive is the explicit opt-out)
#   2. run /tmp/netninja-deploy.sh there with root privileges
#      (geo data first -> backup -> install -> restart each service -> optional
#      Thai egress rotate -> verify, each binary rolled back on its own on failure)
#   2b. it also uploads scripts/netninja-th-pool.sh (plus
#      examples/netninja-th-pool.conf.example), and -ThaiPool installs and
#      enables the systemd service that supervises the tunnels (writing a
#      discovery config when /etc/netninja/th-pool.conf does not exist yet)
#   2c. and scripts/netninja-pool-health.sh, the timer that alerts when the Thai
#      pool drops below MIN_NODES verified nodes
#   3. print /geo-check so you can confirm geo traffic exits from Thailand
#
# Secrets and per-deployment data (azure-sg.key, netninja.local.ps1,
# geo-nodes.txt, geo-domains.txt) live untracked in the repository root. The geo
# domain list is also tracked (data\geo-domains.txt), so the shipped list is
# uploaded when the root copy is absent.
param(
    [string]$Server = $env:NETNINJA_SERVER,
    [string]$User   = $env:NETNINJA_USER,
    [string]$Key    = '',
    [string]$Binary = '',
    [string]$KeepaliveBinary = '',
    [string]$ThaiNodes = '',
    [string]$GeoDomainsUrl = '',
    [switch]$ThaiEgress,
    [switch]$ThaiPool,
    [switch]$NoKeepalive,
    [switch]$SkipUpload
)

$ErrorActionPreference = 'Stop'

# This script lives in scripts/; everything it uploads lives in the repository
# root, next to the Makefile.
$Repo = Split-Path -Parent $PSScriptRoot
if (-not $Key)    { $Key    = Join-Path $Repo 'azure-sg.key' }
if (-not $Binary) { $Binary = Join-Path $Repo 'dist\proxy_linux' }
if (-not $KeepaliveBinary) { $KeepaliveBinary = Join-Path $Repo 'dist\keepalive_linux' }

# Local, uncommitted settings win over the environment.
$localSettings = Join-Path $Repo 'netninja.local.ps1'
if (Test-Path $localSettings) { . $localSettings }
if (-not $Server) { $Server = $env:NETNINJA_SERVER }
if (-not $User)   { $User   = $env:NETNINJA_USER }
if (-not $Server -or -not $User) {
    throw @"
Target host not configured. Set it outside the repository:
  `$env:NETNINJA_SERVER = '<server-ip-or-host>'
  `$env:NETNINJA_USER   = '<ssh-user>'
...or create netninja.local.ps1 in the repository root (already git-ignored) with those two lines.
"@
}

if (-not (Test-Path $Key))    { throw "SSH key not found: $Key" }
if (-not $SkipUpload -and -not (Test-Path $Binary)) { throw "Binary not found: $Binary (build it first, or use -SkipUpload)" }
if (-not $SkipUpload -and -not $NoKeepalive -and -not (Test-Path $KeepaliveBinary)) {
    Write-Host "keepalive binary not found ($KeepaliveBinary) - proxy only; build it with `make`, or pass -NoKeepalive to silence this" -ForegroundColor Yellow
    $NoKeepalive = $true
}

$target  = "$User@$Server"
$sshOpts = @('-i', $Key, '-o', 'StrictHostKeyChecking=accept-new', '-o', 'ConnectTimeout=15')

if (-not $SkipUpload) {
    Write-Host "== uploading binary ($Binary) ==" -ForegroundColor Cyan
    scp @sshOpts -- $Binary "${target}:/tmp/proxy_linux_new"
    if ($LASTEXITCODE -ne 0) { throw "scp failed" }

    if (-not $NoKeepalive) {
        Write-Host "== uploading keepalive binary ($KeepaliveBinary) ==" -ForegroundColor Cyan
        scp @sshOpts -- $KeepaliveBinary "${target}:/tmp/keepalive_server_new"
        if ($LASTEXITCODE -ne 0) { throw "scp of the keepalive binary failed" }
    }
}

# The Thai egress pool and the geo domain list are data files on the server.
# Upload the local copies when they exist (geo-nodes.txt = one host:port per
# line, optional; geo-domains.txt = the domain list, replaced if present).
# The list this deployment ships is tracked as data\geo-domains.txt; an
# untracked geo-domains.txt in the repository root overrides it. Checking both
# is what keeps a local edit (data\...) from silently never reaching the proxy:
# with only the root copy looked at, the server would keep an old list forever.
$poolFile = Join-Path $Repo 'geo-nodes.txt'
if (Test-Path $poolFile) {
    Write-Host "== uploading Thai egress pool file ($poolFile) ==" -ForegroundColor Cyan
    scp @sshOpts -- $poolFile "${target}:/tmp/geo-nodes.txt"
    if ($LASTEXITCODE -ne 0) { throw "scp of geo-nodes.txt failed" }
}
$domainsFile = @(
    (Join-Path $Repo 'geo-domains.txt'),
    (Join-Path $Repo 'data\geo-domains.txt')
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $domainsFile) {
    Write-Host "no geo-domains.txt (root) or data\geo-domains.txt - the server keeps the list it already has" -ForegroundColor Yellow
} else {
    Write-Host "== uploading geo domain list ($domainsFile) ==" -ForegroundColor Cyan
    scp @sshOpts -- $domainsFile "${target}:/tmp/geo-domains.txt"
    if ($LASTEXITCODE -ne 0) { throw "scp of geo-domains.txt failed" }
}

# The pool supervisor (optional): it keeps the tunnels listed in the pool file
# alive by itself. Its real config (/etc/netninja/th-pool.conf) stays on the
# server - only the script and the example config are uploaded here.
$supervisor = Join-Path $Repo 'scripts\netninja-th-pool.sh'
if (Test-Path $supervisor) {
    Write-Host "== uploading Thai pool supervisor ($supervisor) ==" -ForegroundColor Cyan
    scp @sshOpts -- $supervisor "${target}:/tmp/netninja-th-pool.sh"
    if ($LASTEXITCODE -ne 0) { throw "scp of netninja-th-pool.sh failed" }
    $supervisorConf = Join-Path $Repo 'examples\netninja-th-pool.conf.example'
    if (Test-Path $supervisorConf) {
        scp @sshOpts -- $supervisorConf "${target}:/tmp/netninja-th-pool.conf.example"
        if ($LASTEXITCODE -ne 0) { throw "scp of netninja-th-pool.conf.example failed" }
    }
}

# The pool health check (optional): alerts when the Thai egress pool loses its
# spare, instead of leaving that to be noticed on the dashboard later.
$health = Join-Path $Repo 'scripts\netninja-pool-health.sh'
if (Test-Path $health) {
    Write-Host "== uploading Thai pool health check ($health) ==" -ForegroundColor Cyan
    scp @sshOpts -- $health "${target}:/tmp/netninja-pool-health.sh"
    if ($LASTEXITCODE -ne 0) { throw "scp of netninja-pool-health.sh failed" }
    $healthConf = Join-Path $Repo 'examples\netninja-pool-health.conf.example'
    if (Test-Path $healthConf) {
        scp @sshOpts -- $healthConf "${target}:/tmp/netninja-pool-health.conf.example"
        if ($LASTEXITCODE -ne 0) { throw "scp of netninja-pool-health.conf.example failed" }
    }
}

$remoteCmd = 'bash /tmp/netninja-deploy.sh'
if ($ThaiEgress)    { $remoteCmd += ' --th-egress' }
if ($ThaiNodes)     { $remoteCmd += " --th-nodes '$ThaiNodes'" }
if ($ThaiPool)      { $remoteCmd += ' --th-pool' }
if ($GeoDomainsUrl) { $remoteCmd += " --geo-url '$GeoDomainsUrl'" }
if ($NoKeepalive)   { $remoteCmd += ' --no-keepalive' }

Write-Host "== the password here is the ssh user's, NOT root's: sudo asks for" -ForegroundColor Yellow
Write-Host "   $target's own password, and it is used for this one command only ==" -ForegroundColor Yellow
$secure = Read-Host -AsSecureString -Prompt "password"
$bstr   = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)

    # sudo -S reads the password from the first line of stdin; the deploy script
    # itself never reads stdin, so the rest of the pipe is free.
    $plain + "`n" | ssh @sshOpts -T $target "sudo -S $remoteCmd"
    if ($LASTEXITCODE -ne 0) { throw "remote deploy failed (see output above - the script rolls the binary back automatically)" }
}
finally {
    if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    $plain = $null
}

Write-Host ""
Write-Host "== geo-check (confirm ometv sees a Thai address) ==" -ForegroundColor Cyan
ssh @sshOpts $target "curl -s --max-time 40 http://127.0.0.1:5988/geo-check"

Write-Host ""
Write-Host "done - open http://${Server}:5988/geo-check from this machine" -ForegroundColor Green
Write-Host "(the host itself is never stored in this file - it comes from the env or netninja.local.ps1)" -ForegroundColor DarkGray
