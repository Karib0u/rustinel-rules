# Atomic test - rule ddada813-a945-40a5-af78-3131b2e93fe9
#   "Windows Firewall Disabled from the Command Line"  (process_creation)
#
# Copies cmd.exe to netsh.exe and emits the firewall-disable command line
# without touching the real firewall.
$ErrorActionPreference = 'SilentlyContinue'
$dir = Join-Path $env:TEMP 'rustinel-netsh-atomic'
$bin = Join-Path $dir 'netsh.exe'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
Copy-Item "$env:SystemRoot\System32\cmd.exe" $bin -Force
& $bin /c echo advfirewall set allprofiles state off | Out-Null
Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
exit 0
