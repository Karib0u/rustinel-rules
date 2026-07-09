# Atomic test - rule 596b49d3-561e-49d7-9538-f3115c1c8cfd
#   "USN Journal Deletion via fsutil"  (process_creation)
#
# Copies cmd.exe to fsutil.exe and emits the usn deletejournal command-line
# shape without touching any real change journal.
$ErrorActionPreference = 'SilentlyContinue'
$dir = Join-Path $env:TEMP 'rustinel-fsutil-atomic'
$bin = Join-Path $dir 'fsutil.exe'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
Copy-Item "$env:SystemRoot\System32\cmd.exe" $bin -Force
& $bin /c echo usn deletejournal /D C: | Out-Null
Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
exit 0
