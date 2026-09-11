# Template for the local deploy settings — copy it, never edit this one.
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
#   TROUBLESHOOTING.md   (see README → "Moving to another machine")

$env:NETNINJA_SERVER = '<server-ip-or-host>'
$env:NETNINJA_USER   = '<ssh-user>'
