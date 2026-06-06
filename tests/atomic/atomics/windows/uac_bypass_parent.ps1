# Atomic test - rule f2b8c4d1-6e90-4a27-9d3b-5a1c2e7f8b21
#   "UAC Bypass via Auto-Elevating LOLBin"  (process_creation)
#
# Copies cmd.exe to fodhelper.exe and has that parent spawn cmd.exe. This tests
# the parent-child shape without registry hijack or elevation.
$ErrorActionPreference = 'SilentlyContinue'
$dir = Join-Path $env:TEMP 'rustinel-uac-atomic'
$parent = Join-Path $dir 'fodhelper.exe'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
Copy-Item "$env:SystemRoot\System32\cmd.exe" $parent -Force
& $parent /c "$env:SystemRoot\System32\cmd.exe /c exit 0" | Out-Null
Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
exit 0
