# Atomic test - rule 92557796-ce11-410a-b976-dd63dd189b82
#   "Known Offensive PowerShell Cmdlet Invoked"  (ps_module 4103)
#
# Module Logging is off by default: the script enables it for all modules, then
# runs a harmless function named Invoke-Mimikatz in a new powershell.exe (the
# policy is read at engine start). The function only echoes; no tooling is
# involved. The policy is removed afterwards.
$ErrorActionPreference = 'SilentlyContinue'
$key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
$existed = Test-Path $key

New-Item -Path "$key\ModuleNames" -Force | Out-Null
New-ItemProperty -Path $key -Name EnableModuleLogging -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path "$key\ModuleNames" -Name '*' -Value '*' -PropertyType String -Force | Out-Null

& powershell.exe -NoProfile -Command "function Invoke-Mimikatz { param([string]`$Command) Write-Output 'rustinel atomic' }; Invoke-Mimikatz -Command 'noop'" | Out-Null
Start-Sleep -Seconds 2

if (-not $existed) { Remove-Item -Path $key -Recurse -Force }
exit 0
