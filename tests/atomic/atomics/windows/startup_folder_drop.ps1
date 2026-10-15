# Atomic test - rule 59bbd501-1c61-45c9-940d-9465cabd36c4
#   "File Dropped in Startup Folder"  (file_event)
#
# Writes an inert .txt file into the current user's Startup folder and removes
# it. Nothing in the folder is executed at logon while the file exists.
$ErrorActionPreference = 'Stop'
$dir = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'
$file = Join-Path $dir 'rustinel_atomic_startup.txt'
try {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    Set-Content -LiteralPath $file -Value 'rustinel atomic test'
    Start-Sleep -Seconds 2
} finally {
    Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
}
exit 0
