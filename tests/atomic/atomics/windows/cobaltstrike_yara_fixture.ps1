# Atomic test - rule yara-win-cobaltstrike-beacon
#   "Cobalt Strike beacon artifacts in Windows PE images"  (yara file_scan)
#
# Copies cmd.exe, appends marker strings the production signature keys on as a
# PE overlay, executes the copy, then removes it. The strings are plain text and
# the overlay does not affect execution; no implant code is involved.
$ErrorActionPreference = 'Stop'
$dir = Join-Path $env:TEMP 'rustinel-yara-cobaltstrike-atomic'
$bin = Join-Path $dir 'rustinel_cobaltstrike_fixture.exe'
try {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    Copy-Item "$env:SystemRoot\System32\cmd.exe" $bin -Force
    [IO.File]::AppendAllText($bin, "beacon.dll`nbeacon.x64.dll`n")
    & $bin /c exit 0 | Out-Null
    # ETW delivery and the YARA worker are asynchronous. Keep the file
    # available after process exit so this tests detection, not a deletion race.
    Start-Sleep -Seconds 5
} finally {
    Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
}
exit 0
