# Atomic test - rule 1e9b4d68-2c7a-4f93-8b15-6d0a2e4c1b04
#   "Volume Shadow Copy Deletion"  (process_creation)
#
# Copies cmd.exe to vssadmin.exe and emits the command-line shape without
# deleting any real shadow copies.
$ErrorActionPreference = 'SilentlyContinue'
$dir = Join-Path $env:TEMP 'rustinel-shadow-atomic'
$bin = Join-Path $dir 'vssadmin.exe'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
Copy-Item "$env:SystemRoot\System32\cmd.exe" $bin -Force
& $bin /c echo delete shadows | Out-Null
Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
exit 0
