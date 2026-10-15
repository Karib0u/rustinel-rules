# Negative fixture for rule 127db158-346f-4244-b2ad-1522e7c3c2a1
# Deletes a .pf file outside C:\Windows\Prefetch and a non-.pf file inside it.
# The rule must not alert on either.
$ErrorActionPreference = 'SilentlyContinue'
$tmp = Join-Path $env:TEMP 'rustinel_negative_prefetch'
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$a = Join-Path $tmp 'RUSTINELNEGATIVE.EXE-00000000.pf'
Set-Content -Path $a -Value 'x'
$b = Join-Path (Join-Path $env:SystemRoot 'Prefetch') 'rustinel_negative.txt'
Set-Content -Path $b -Value 'x'
Start-Sleep -Seconds 1
Remove-Item -Path $a, $b -Force
Remove-Item -Path $tmp -Recurse -Force
Start-Sleep -Seconds 1
exit 0
