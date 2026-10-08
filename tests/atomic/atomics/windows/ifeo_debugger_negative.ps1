# Negative fixture for rule cda4a133-fe67-4aa6-815d-f8c69ff16828
# Writes an unwatched value (RustinelNegative) and a GlobalFlag that is not
# 0x200 under an HKCU-only IFEO entry. The rule must not alert on either.
$ErrorActionPreference = 'SilentlyContinue'
$key = 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\rustinel_negative.exe'
New-Item -Path $key -Force | Out-Null
New-ItemProperty -Path $key -Name 'RustinelNegative' -Value 'x' -PropertyType String -Force | Out-Null
New-ItemProperty -Path $key -Name 'GlobalFlag' -Value 2 -PropertyType DWord -Force | Out-Null
Start-Sleep -Seconds 1
Remove-Item $key -Recurse -Force -ErrorAction SilentlyContinue
exit 0
