# Atomic test - rule yara-fixture-memory-marker  (yara process_memory)
#
# A long-lived cmd.exe builds the marker from fragments at runtime, so the bytes
# exist only in its memory (its environment block, UTF-16): not in the image or
# the command line. Only a process-memory scan can see them. cmd runs from a temp
# copy because the engine does not scan trusted system paths such as System32.
# The harness enables scanner.yara_memory_enabled for the whole run; the engine
# waits yara_memory_delay_ms after process start before reading, so cmd must
# outlive it.
$ErrorActionPreference = 'Stop'
$dir = Join-Path $env:TEMP 'rustinel-memory-atomic'
$bin = Join-Path $dir 'rustinel_memory_fixture.exe'
try {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    Copy-Item "$env:SystemRoot\System32\cmd.exe" $bin -Force
    & $bin /v:on /c 'set a=RUSTINEL&set b=MEMORY&set c=FIXTURE&set d=b83e41c7&set m=!a!-!b!-!c!-!d!&ping -n 12 127.0.0.1 >nul' | Out-Null
} finally {
    Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
}
exit 0
