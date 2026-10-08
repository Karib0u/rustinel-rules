# Negative fixture for rule d0e8f644-2661-4f99-b1b2-69eb70abe050
# Renames 60 files to an ordinary .bak extension from one process. The
# correlation must not alert.
$ErrorActionPreference = 'SilentlyContinue'
$dir = Join-Path $env:TEMP 'rustinel_negative_mass_rename'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
1..60 | ForEach-Object { Set-Content -Path (Join-Path $dir "doc$_.txt") -Value 'x' }
Get-ChildItem -Path $dir -Filter '*.txt' | ForEach-Object {
    Rename-Item -Path $_.FullName -NewName ($_.Name + '.bak')
}
Start-Sleep -Seconds 2
Remove-Item -Path $dir -Recurse -Force
exit 0
