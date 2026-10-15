# Negative fixture for rule a1b2c3d4-7e8f-4012-9a3b-4c5d6e7f0a10
# Writes a value under a sibling key whose name merely starts with "Run"
# (...\CurrentVersion\RunRustinelNegative). The rule matches the Run key paths
# with a trailing separator, so this must not alert.
$ErrorActionPreference = 'SilentlyContinue'
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunRustinelNegative'
New-Item -Path $key -Force | Out-Null
New-ItemProperty -LiteralPath $key -Name 'Value' -Value 'notepad.exe' -PropertyType String -Force | Out-Null
Start-Sleep -Seconds 1
Remove-Item $key -Recurse -Force -ErrorAction SilentlyContinue
exit 0
