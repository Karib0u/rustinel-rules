# Atomic test - rule cda4a133-fe67-4aa6-815d-f8c69ff16828
#   "IFEO Debugger or SilentProcessExit Hijack"  (registry_set), GlobalFlag branch
#
# Sets GlobalFlag = 0x200 (FLG_MONITOR_SILENT_PROCESS_EXIT) on an IFEO entry for
# a nonexistent image, under HKCU only, then removes the entry.
$ErrorActionPreference = 'SilentlyContinue'
$key = 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\rustinel_atomic.exe'
New-Item -Path $key -Force | Out-Null
New-ItemProperty -Path $key -Name 'GlobalFlag' -Value 512 -PropertyType DWord -Force | Out-Null
Start-Sleep -Seconds 1
Remove-Item $key -Recurse -Force -ErrorAction SilentlyContinue
exit 0
