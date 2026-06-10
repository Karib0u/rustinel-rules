# Atomic test - rule c4a7f2e9-5d3b-4810-a6c1-9e0f3b7d2a03
#   "Office Application Spawning a Command Shell"  (process_creation)
#
# Copies cmd.exe to winword.exe, then has that parent spawn cmd.exe.
$ErrorActionPreference = 'SilentlyContinue'
$dir = Join-Path $env:TEMP 'rustinel-office-atomic'
$parent = Join-Path $dir 'winword.exe'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
Copy-Item "$env:SystemRoot\System32\cmd.exe" $parent -Force
& $parent /c "$env:SystemRoot\System32\cmd.exe /c exit 0" | Out-Null
Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
exit 0
