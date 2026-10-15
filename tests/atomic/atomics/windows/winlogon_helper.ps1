# Atomic test - rule 52b94494-756b-40d7-af01-8d0c7d54a6cc
#   "Winlogon Helper DLL or Shell Modification"  (registry_set)
#
# Sets a non-default Shell value under an HKCU-only Winlogon key (the live HKLM
# value is never touched), then removes the key.
$ErrorActionPreference = 'SilentlyContinue'
$key = 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
New-Item -Path $key -Force | Out-Null
New-ItemProperty -Path $key -Name 'Shell' -Value 'explorer.exe,rustinel_atomic.exe' -PropertyType String -Force | Out-Null
Start-Sleep -Seconds 1
Remove-Item $key -Recurse -Force -ErrorAction SilentlyContinue
exit 0
