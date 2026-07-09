# Atomic test - rule d97177dd-c74f-465e-96c1-194cc1dd681d
#   "BITS Job Download via bitsadmin"  (process_creation)
#
# Copies cmd.exe to bitsadmin.exe and emits a /transfer ... http command-line
# shape without creating any real BITS job.
$ErrorActionPreference = 'SilentlyContinue'
$dir = Join-Path $env:TEMP 'rustinel-bitsadmin-atomic'
$bin = Join-Path $dir 'bitsadmin.exe'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
Copy-Item "$env:SystemRoot\System32\cmd.exe" $bin -Force
& $bin /c echo /transfer atomicjob http://127.0.0.1/x C:\x | Out-Null
Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
exit 0
