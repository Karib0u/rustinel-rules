# Negative fixture for rule ad5acb04-ea4e-4d6d-9719-85042d2963b5
# Changes the creation time of a .txt file. The rule only watches executable and
# script targets, so it must not alert.
$ErrorActionPreference = 'SilentlyContinue'
$f = Join-Path $env:TEMP 'rustinel_negative_timestomp.txt'
Set-Content -Path $f -Value 'x'
Start-Sleep -Seconds 1
(Get-Item $f).CreationTime = [datetime]'2019-03-14 09:26:53'
Start-Sleep -Seconds 1
Remove-Item -Path $f -Force
exit 0
