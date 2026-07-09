# Atomic test - rule e86de5fe-3908-4a95-b4e8-930a93bf4555
#   "Boot Recovery Tampering via bcdedit or wbadmin"  (process_creation)
#
# Copies cmd.exe to bcdedit.exe and emits the recovery-disable command-line
# shape without changing any real boot configuration.
$ErrorActionPreference = 'SilentlyContinue'
$dir = Join-Path $env:TEMP 'rustinel-bcdedit-atomic'
$bin = Join-Path $dir 'bcdedit.exe'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
Copy-Item "$env:SystemRoot\System32\cmd.exe" $bin -Force
& $bin /c echo recoveryenabled no | Out-Null
Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
exit 0
