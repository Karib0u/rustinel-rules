# Atomic test - rule yara-fixture-memory-marker  (yara process_memory)
#
# A long-lived PowerShell process builds the marker from fragments at runtime and
# holds it, so the bytes exist only in its heap: not in the image, the script
# file, or the command line. Only a process-memory scan can see them (the rule
# matches the UTF-16 form a .NET string uses). The harness enables
# scanner.yara_memory_enabled for the whole run; the engine waits
# yara_memory_delay_ms after process start before reading, so stay alive past it.
$ErrorActionPreference = 'Stop'
$dir = Join-Path $env:TEMP 'rustinel-memory-atomic'
$child = Join-Path $dir 'hold.ps1'
try {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    Set-Content -Path $child -Encoding ASCII -Value @'
$parts = @('RUSTINEL', 'MEMORY', 'FIXTURE', 'b83e41c7')
$marker = $parts -join '-'
$held = @($marker, $marker.ToCharArray(), [Text.Encoding]::ASCII.GetBytes($marker))
Start-Sleep -Seconds 8
$held.Count | Out-Null
'@
    & powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $child | Out-Null
} finally {
    Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
}
exit 0
