# Writes inert text in a temporary directory that Office does not use.
$ErrorActionPreference = 'Stop'
$root = Join-Path $env:TEMP "rustinel-office-atomic-$([Guid]::NewGuid())"
$xlstart = Join-Path $root 'XLSTART'
$file = Join-Path $xlstart 'rustinel_atomic_office.xlam'

try {
    New-Item -ItemType Directory -Path $xlstart -Force | Out-Null
    Set-Content -LiteralPath $file -Value 'Rustinel atomic fixture'
} finally {
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}
