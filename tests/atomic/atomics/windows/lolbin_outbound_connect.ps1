# Atomic test - rule 717396f6-aff0-49b0-b8f3-53568e276d5c
#   "Outbound Connection from Script or LOLBin Host"  (network_connection)
#
# Has cscript.exe open a connection to a public address. The script it runs is
# a one-line .vbs that POSTs nothing; XMLHTTP issues a single GET to the public
# resolver endpoint 1.1.1.1 and the result is ignored. The rule fires on the
# kernel connection attempt, so the outcome of the request does not matter.
$ErrorActionPreference = 'SilentlyContinue'
$dir = Join-Path $env:TEMP 'rustinel-lolbin-net-atomic'
$vbs = Join-Path $dir 'probe.vbs'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
Set-Content -LiteralPath $vbs -Value @'
On Error Resume Next
Set h = CreateObject("MSXML2.ServerXMLHTTP.6.0")
h.setTimeouts 3000, 3000, 3000, 3000
h.open "GET", "http://1.1.1.1/", False
h.send
'@
& cscript.exe //nologo //T:15 $vbs | Out-Null
Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
exit 0
