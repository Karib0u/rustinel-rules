# Atomic test - rule 86c19f1a-add5-4553-9c24-f76e7fe3da9d
#   "Unmanaged PowerShell via Automation DLL in Foreign Host"  (image_load)
#
# Copies powershell.exe to a name outside the rule's host allowlist and runs a
# no-op command, so System.Management.Automation.dll loads into a process that
# is not a known PowerShell host. The copy resolves the assembly from the GAC.
$ErrorActionPreference = 'SilentlyContinue'
$dir = Join-Path $env:TEMP 'rustinel-automation-atomic'
$bin = Join-Path $dir 'rustinel_runspace_host.exe'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
Copy-Item "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" $bin -Force
& $bin -NoProfile -NonInteractive -Command 'Start-Sleep -Seconds 2' | Out-Null
Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
exit 0
