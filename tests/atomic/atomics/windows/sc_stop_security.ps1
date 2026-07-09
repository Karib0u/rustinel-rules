# Atomic test - rule 43c59081-d5ec-4153-9e26-04e66e07461a
#   "Security Service Stop or Disable via sc or net"  (process_creation)
#
# Copies cmd.exe to sc.exe and emits a "stop <security service>" command-line
# shape without touching any real service.
$ErrorActionPreference = 'SilentlyContinue'
$dir = Join-Path $env:TEMP 'rustinel-scstop-atomic'
$bin = Join-Path $dir 'sc.exe'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
Copy-Item "$env:SystemRoot\System32\cmd.exe" $bin -Force
& $bin /c echo stop Sysmon | Out-Null
Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
exit 0
