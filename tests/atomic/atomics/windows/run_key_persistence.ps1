# Atomic test - rule a1b2c3d4-7e8f-4012-9a3b-4c5d6e7f0a10
#   "Registry Run Key Persistence"  (registry_event)
#
# Creates then deletes an autorun value under HKCU ...\CurrentVersion\Run, the
# key path the rule watches. HKCU only, value points at notepad.exe, removed
# immediately. Nothing is actually scheduled to run.
$ErrorActionPreference = 'SilentlyContinue'
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
New-ItemProperty -Path $key -Name 'RustinelAtomicTest' -Value 'notepad.exe' -PropertyType String -Force | Out-Null
Start-Sleep -Seconds 1
Remove-ItemProperty -Path $key -Name 'RustinelAtomicTest' -ErrorAction SilentlyContinue
exit 0
