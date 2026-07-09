# Atomic test - rule cda4a133-fe67-4aa6-815d-f8c69ff16828
#   "IFEO Debugger or SilentProcessExit Hijack"  (registry_event)
#
# Creates an Image File Execution Options key whose path ends in the watched
# Debugger value name, under HKCU only, then removes it. Registry telemetry
# exposes the key path but not the value name.
$ErrorActionPreference = 'SilentlyContinue'
$base = 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\rustinel_atomic.exe'
$key = "$base\Debugger"
New-Item -Path $key -Force | Out-Null
New-ItemProperty -Path $key -Name 'AtomicValue' -Value 'x' -PropertyType String -Force | Out-Null
Start-Sleep -Seconds 1
Remove-Item $base -Recurse -Force -ErrorAction SilentlyContinue
exit 0
