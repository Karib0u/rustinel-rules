# Atomic test - rule 52b94494-756b-40d7-af01-8d0c7d54a6cc
#   "Winlogon Helper DLL or Shell Modification"  (registry_event)
#
# Creates a Winlogon key whose path ends in the watched Shell value name, under
# HKCU only, then removes it. Registry telemetry exposes the key path but not the
# value name.
$ErrorActionPreference = 'SilentlyContinue'
$base = 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
$key = "$base\Shell"
New-Item -Path $key -Force | Out-Null
New-ItemProperty -Path $key -Name 'AtomicValue' -Value 'explorer.exe' -PropertyType String -Force | Out-Null
Start-Sleep -Seconds 1
Remove-Item $base -Recurse -Force -ErrorAction SilentlyContinue
exit 0
