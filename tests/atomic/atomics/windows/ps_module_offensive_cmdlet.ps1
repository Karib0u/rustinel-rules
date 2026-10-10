# Atomic test - rule 92557796-ce11-410a-b976-dd63dd189b82
#   "Known Offensive PowerShell Cmdlet Invoked"  (ps_module 4103)
#
# Module Logging is off by default: the script enables it for all modules, then
# runs a harmless function named Invoke-Mimikatz in a new powershell.exe (the
# policy is read at engine start). The function lives in a throwaway module:
# 4103 only records commands that belong to a logged module, so a function
# defined in the session (as an earlier version of this test did) never
# produced the CommandInvocation record the rule anchors on. The function only
# echoes; no tooling is involved. The policy and the module are removed afterwards.
$ErrorActionPreference = 'SilentlyContinue'
$key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
$existed = Test-Path $key
$dir = Join-Path $env:TEMP 'RustinelAtomicOffensive'

New-Item -Path "$key\ModuleNames" -Force | Out-Null
New-ItemProperty -Path $key -Name EnableModuleLogging -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path "$key\ModuleNames" -Name '*' -Value '*' -PropertyType String -Force | Out-Null

New-Item -ItemType Directory -Path $dir -Force | Out-Null
$psm1 = Join-Path $dir 'RustinelAtomicOffensive.psm1'
Set-Content -Path $psm1 -Value @'
function Invoke-Mimikatz { param([string]$Command) Write-Output 'rustinel atomic' }
Export-ModuleMember -Function Invoke-Mimikatz
'@

& powershell.exe -NoProfile -Command "Import-Module '$psm1' -Force; Invoke-Mimikatz -Command 'noop'" | Out-Null
Start-Sleep -Seconds 2

Remove-Item -Path $dir -Recurse -Force
if (-not $existed) { Remove-Item -Path $key -Recurse -Force }
exit 0
