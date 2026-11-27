# Atomic test - rule 439b4c58-8ead-4719-8a84-dca5d7e4f612 (process_creation).
# Decodes a comment into a temporary file and verifies the text.
$ErrorActionPreference = 'Stop'
$dir = Join-Path $env:TEMP "rustinel-certutil-$([Guid]::NewGuid().ToString('N'))"
$inputFile = Join-Path $dir 'input.b64'
$outputFile = Join-Path $dir 'output.ps1'
$text = '# rustinel atomic test'
try {
    New-Item -ItemType Directory -Path $dir | Out-Null
    Set-Content -LiteralPath $inputFile -Encoding Ascii -Value ([Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($text)))
    & "$env:SystemRoot\System32\certutil.exe" -decode $inputFile $outputFile | Out-Null
    if ($LASTEXITCODE -ne 0 -or (Get-Content -LiteralPath $outputFile -Raw) -ne $text) {
        throw 'certutil did not decode the test fixture'
    }
} finally {
    Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
}
