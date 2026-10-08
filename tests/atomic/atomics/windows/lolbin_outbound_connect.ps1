# Atomic test - rule 717396f6-aff0-49b0-b8f3-53568e276d5c
#   "Outbound Connection from Script or LOLBin Host"  (network_connection)
#
# Has certutil.exe open a connection to a public address: a single URL-cache
# fetch of 1.1.1.1 into a temp file that is removed afterwards. The rule fires
# on the connection attempt, so the outcome of the request does not matter.
# Loopback cannot be used because the rule filters non-public destinations.
$ErrorActionPreference = 'SilentlyContinue'
$out = Join-Path $env:TEMP 'rustinel_atomic_lolbin_net.tmp'
foreach ($url in 'http://1.1.1.1/rustinel-atomic', 'https://8.8.8.8/rustinel-atomic') {
    $p = Start-Process -FilePath certutil.exe `
      -ArgumentList '-urlcache', '-f', $url, $out `
      -WindowStyle Hidden -PassThru
    if (-not $p.WaitForExit(20000)) { $p.Kill(); "certutil $url timed out" }
    else { "certutil $url exit $($p.ExitCode)" }
}
# Recorded in the report when the test fails: does the runner reach the target?
"reachability: " + (Test-NetConnection -ComputerName 1.1.1.1 -Port 443 -WarningAction SilentlyContinue).TcpTestSucceeded
Remove-Item $out -Force -ErrorAction SilentlyContinue
exit 0
