# Negative fixture for rule 5ffa485e-7667-4ecc-a17c-fc5f9068c0d4
# Runs a copy of powershell.exe that keeps its original name from a temp
# directory. OriginalFileName matches the image name, so the rule must not alert.
$ErrorActionPreference = 'SilentlyContinue'
$dir = Join-Path $env:TEMP 'rustinel_negative_renamed'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
$copy = Join-Path $dir 'powershell.exe'
Copy-Item "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" $copy -Force
& $copy -NoProfile -Command 'Start-Sleep -Seconds 2'
Remove-Item -Path $dir -Recurse -Force
exit 0
