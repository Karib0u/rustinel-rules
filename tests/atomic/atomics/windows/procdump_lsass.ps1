# Atomic test - rule 04d66f93-97ae-4674-96a8-1bb524a1da60
#   "LSASS Memory Dump via Procdump"  (process_creation)
#
# Copies cmd.exe to procdump.exe and emits the procdump-against-lsass
# command-line shape without dumping any process memory.
$ErrorActionPreference = 'SilentlyContinue'
$dir = Join-Path $env:TEMP 'rustinel-procdump-atomic'
$bin = Join-Path $dir 'procdump.exe'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
Copy-Item "$env:SystemRoot\System32\cmd.exe" $bin -Force
& $bin /c echo -ma lsass lsass.dmp | Out-Null
Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
exit 0
