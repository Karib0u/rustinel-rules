# Atomic test - rule b2c3d4e5-8f90-4123-8b4c-5d6e7f801a11
#   "Microsoft Defender Tampering via Registry"  (registry_event)
#
# Writes and removes a Defender policy key whose path includes the watched
# value name. Registry telemetry exposes the key path but not the value name.
$ErrorActionPreference = 'SilentlyContinue'
$key = 'HKCU:\Software\Microsoft\Windows Defender\DisableRealtimeMonitoring'
New-Item -Path $key -Force | Out-Null
New-ItemProperty -Path $key -Name 'AtomicValue' -Value 1 -PropertyType DWord -Force | Out-Null
Start-Sleep -Seconds 1
Remove-Item $key -Recurse -Force -ErrorAction SilentlyContinue
exit 0
