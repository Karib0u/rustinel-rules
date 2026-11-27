# Atomic test - rule 27ef6465-457b-4442-a6cc-3af7b595d1df (file_event).
# Writes plain text to a mock document root under a unique temporary directory.
$ErrorActionPreference = 'Stop'
$dir = Join-Path $env:TEMP "rustinel-web-root-$([Guid]::NewGuid().ToString('N'))"
$webRoot = Join-Path $dir 'inetpub\wwwroot'
try {
    New-Item -ItemType Directory -Path $webRoot -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $webRoot 'rustinel-probe.aspx') -Value 'rustinel atomic test'
    Start-Sleep -Seconds 2
} finally {
    Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
}
