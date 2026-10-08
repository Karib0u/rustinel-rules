# Atomic test - rule 3781aa92-44a2-4a03-a2d0-c8fb08e1110e
#   "Microsoft Defender Weakened via PowerShell Cmdlet"  (ps_module 4103)
#   and rule efac4650-a3aa-4dd9-9f6f-679bfcf14c16
#   "Microsoft Defender Exclusion Added"  (windefend 5007)
#
# Module Logging (4103) is off by default, so the script enables it for all
# modules, runs Add-MpPreference in a *new* powershell.exe (the policy is read at
# engine start), then removes the exclusion and restores the policy. The exclusion
# is a never-used folder name. Tamper Protection can block the change on some
# images; the manifest marks this test allow_failure until a run proves it.
$ErrorActionPreference = 'SilentlyContinue'
$key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
$existed = Test-Path $key
$path = 'C:\RustinelAtomicExclusion'

New-Item -Path "$key\ModuleNames" -Force | Out-Null
New-ItemProperty -Path $key -Name EnableModuleLogging -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path "$key\ModuleNames" -Name '*' -Value '*' -PropertyType String -Force | Out-Null

& powershell.exe -NoProfile -Command "Add-MpPreference -ExclusionPath '$path'; Start-Sleep -Seconds 2; Remove-MpPreference -ExclusionPath '$path'" | Out-Null
Start-Sleep -Seconds 2

if (-not $existed) { Remove-Item -Path $key -Recurse -Force }
exit 0
