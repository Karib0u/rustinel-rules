# Atomic test - rule 157ffa4c-89d0-4b92-9119-66ca256eea60
#   "Web Server or SQL Server Spawning a Command Shell"  (process_creation)
#
# Copies cmd.exe to w3wp.exe and has that copy spawn cmd.exe, which gives the
# w3wp.exe parent / cmd.exe child shape without installing IIS.
$ErrorActionPreference = 'SilentlyContinue'
$dir = Join-Path $env:TEMP 'rustinel-w3wp-atomic'
$bin = Join-Path $dir 'w3wp.exe'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
Copy-Item "$env:SystemRoot\System32\cmd.exe" $bin -Force
& $bin /c "$env:SystemRoot\System32\cmd.exe /c echo rustinel-atomic" | Out-Null
Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
exit 0
