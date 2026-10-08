# Negative fixture for rule b2c3d4e5-8f90-4123-8b4c-5d6e7f801a11
# Sets DisableRealtimeMonitoring = 0 (protection enabled) under the same
# HKCU-only key. The rule must not alert on it.
$ErrorActionPreference = 'SilentlyContinue'
$base = 'HKCU:\Software\RustinelAtomic'
$key = "$base\Windows Defender\Real-Time Protection"
New-Item -Path $key -Force | Out-Null
New-ItemProperty -Path $key -Name 'DisableRealtimeMonitoring' -Value 0 -PropertyType DWord -Force | Out-Null
Start-Sleep -Seconds 1
Remove-Item $base -Recurse -Force -ErrorAction SilentlyContinue
exit 0
