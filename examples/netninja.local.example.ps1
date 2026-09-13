# Template for the local deploy settings - copy it, never edit this one.
# Keep it ASCII-only: Windows PowerShell 5.1 reads a BOM-less .ps1 with the
# system ANSI codepage, and non-ASCII bytes can stop the file from parsing.
#
#   Copy-Item netninja.local.example.ps1 netninja.local.ps1
#   notepad netninja.local.ps1
#
# netninja.local.ps1 is git-ignored, so the real server address stays on your
# machine and never lands in this public repository (or its history).
# netninja-deploy.ps1 loads it automatically; NETNINJA_SERVER / NETNINJA_USER
# environment variables work the same way if you prefer.
#
# Moving to another machine? Bring these git-ignored files along with it:
#   netninja.local.ps1, azure-sg.key, geo-nodes.txt, geo-domains.txt,
#   TROUBLESHOOTING.md   (see README, section "Moving to another machine")

$env:NETNINJA_SERVER = '<server-ip-or-host>'
$env:NETNINJA_USER   = '<ssh-user>'
