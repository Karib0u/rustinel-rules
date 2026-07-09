# Atomic test - rule 6c46cc68-2e66-4834-b058-0a2cfd115409
#   "Netsh Port-Proxy Tunnel Configuration"  (process_creation)
#
# Copies cmd.exe to netsh.exe and emits the interface portproxy add command-line
# shape without configuring any real port forwarding.
$ErrorActionPreference = 'SilentlyContinue'
$dir = Join-Path $env:TEMP 'rustinel-netsh-atomic'
$bin = Join-Path $dir 'netsh.exe'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
Copy-Item "$env:SystemRoot\System32\cmd.exe" $bin -Force
& $bin /c echo interface portproxy add v4tov4 | Out-Null
Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
exit 0
