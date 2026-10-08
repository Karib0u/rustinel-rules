# Atomic test - rule d0e8f644-2661-4f99-b1b2-69eb70abe050
#   "Mass File Rename to Ransomware-Style Extension"  (file_rename, event_count)
#
# One PowerShell process creates 60 files and renames each to
# .rustinel-locked, crossing the correlation threshold (50 in a minute).
$ErrorActionPreference = 'SilentlyContinue'
$dir = Join-Path $env:TEMP 'rustinel_atomic_mass_rename'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
1..60 | ForEach-Object { Set-Content -Path (Join-Path $dir "doc$_.txt") -Value 'x' }
Get-ChildItem -Path $dir -Filter '*.txt' | ForEach-Object {
    Rename-Item -Path $_.FullName -NewName ($_.Name + '.rustinel-locked')
}
Start-Sleep -Seconds 2
Remove-Item -Path $dir -Recurse -Force
exit 0
