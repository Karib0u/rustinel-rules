# Atomic test - rule ad5acb04-ea4e-4d6d-9719-85042d2963b5
#   "File Timestamp Changed by Script Host"  (file_change)
#
# Back-dates the creation time of a temporary .exe from PowerShell.
$ErrorActionPreference = 'SilentlyContinue'
$f = Join-Path $env:TEMP 'rustinel_atomic_timestomp.exe'
Set-Content -Path $f -Value 'rustinel atomic'
Start-Sleep -Seconds 1
(Get-Item $f).CreationTime = [datetime]'2019-03-14 09:26:53'
Start-Sleep -Seconds 1
Remove-Item -Path $f -Force
exit 0
