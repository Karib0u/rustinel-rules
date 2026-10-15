# Atomic test - rule 127db158-346f-4244-b2ad-1522e7c3c2a1
#   "Prefetch or Event Log File Deleted"  (file_delete)
#
# Creates a dummy .pf file in C:\Windows\Prefetch and deletes it from PowerShell.
# The name is not a real executable's, so no genuine Prefetch history is touched.
$ErrorActionPreference = 'SilentlyContinue'
$dir = Join-Path $env:SystemRoot 'Prefetch'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
$f = Join-Path $dir 'RUSTINELATOMIC.EXE-00000000.pf'
Set-Content -Path $f -Value 'rustinel atomic'
Start-Sleep -Seconds 1
Remove-Item -Path $f -Force
Start-Sleep -Seconds 1
exit 0
