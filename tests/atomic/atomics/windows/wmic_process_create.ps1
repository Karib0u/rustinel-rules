# Atomic test - rule 2a3c3182-80b8-42d4-bd39-83c55582ef70
#   "WMI Process Execution via WMIC"  (process_creation)
#
# Copies cmd.exe to wmic.exe and emits the WMIC process creation command-line
# shape. This avoids depending on WMIC being installed on the runner image.
$ErrorActionPreference = 'SilentlyContinue'
$dir = Join-Path $env:TEMP 'rustinel-wmic-atomic'
$bin = Join-Path $dir 'wmic.exe'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
Copy-Item "$env:SystemRoot\System32\cmd.exe" $bin -Force
& $bin /c echo process call create | Out-Null
Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
exit 0
