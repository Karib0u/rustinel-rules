$ErrorActionPreference = 'Stop'
$dir = Join-Path $env:TEMP "rustinel-history-$([Guid]::NewGuid().ToString('N'))"

try {
    New-Item -ItemType Directory -Path $dir | Out-Null
    # Only delete the dummy file in this run's private temp directory.
    $history = Join-Path $dir 'ConsoleHost_history.txt'
    Set-Content -LiteralPath $history -Value 'rustinel atomic'
    Start-Sleep -Seconds 1
    Remove-Item -LiteralPath $history
    Start-Sleep -Seconds 1
} finally {
    if (Test-Path -LiteralPath $dir) {
        Remove-Item -LiteralPath $dir -Recurse -Force
    }
}
