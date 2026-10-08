# Atomic test - rule 5ffa485e-7667-4ecc-a17c-fc5f9068c0d4
#   "Renamed System Binary Execution"  (process_creation)
#
# Copies powershell.exe to a temp file with another name and runs it. The copy
# keeps its PowerShell.EXE version resource (OriginalFileName), which no longer
# matches the image name.
$ErrorActionPreference = 'SilentlyContinue'
$dir = Join-Path $env:TEMP 'rustinel_atomic_renamed'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
$copy = Join-Path $dir 'rustinel_atomic_renamed.exe'
Copy-Item "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" $copy -Force
& $copy -NoProfile -Command 'Start-Sleep -Seconds 2'
Remove-Item -Path $dir -Recurse -Force
exit 0
