# Atomic test - rule b2c3d4e5-8f90-4123-8b4c-5d6e7f801a11
#   "Microsoft Defender Tampering via Registry"  (registry_set)
#
# Sets DisableRealtimeMonitoring = 1 under an HKCU-only Defender-shaped key (the
# live HKLM policy is never touched), then removes the key tree.
$ErrorActionPreference = 'SilentlyContinue'
$base = 'HKCU:\Software\RustinelAtomic'
$key = "$base\Windows Defender\Real-Time Protection"
New-Item -Path $key -Force | Out-Null
New-ItemProperty -Path $key -Name 'DisableRealtimeMonitoring' -Value 1 -PropertyType DWord -Force | Out-Null
Start-Sleep -Seconds 1
Remove-Item $base -Recurse -Force -ErrorAction SilentlyContinue
exit 0
