# Atomic test - rule 68863af9-9225-4d43-8708-0fb73581d4c6
#   "Rclone Used to Copy Data to a Remote Storage"  (process_creation)
#
# Copies cmd.exe to rclone.exe and emits a copy command line with the
# transfer options; nothing is transferred.
$ErrorActionPreference = 'SilentlyContinue'
$dir = Join-Path $env:TEMP 'rustinel-rclone-atomic'
$bin = Join-Path $dir 'rclone.exe'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
Copy-Item "$env:SystemRoot\System32\cmd.exe" $bin -Force
& $bin /c echo copy C:\data remote:bucket --transfers 16 --auto-confirm | Out-Null
Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
exit 0
