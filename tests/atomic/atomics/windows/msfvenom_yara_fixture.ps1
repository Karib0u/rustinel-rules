# Atomic test - rule yara-win-msfvenom-stager
#   "Metasploit / Meterpreter Windows stager markers"  (yara file_scan)
#
# Copies cmd.exe, appends Meterpreter stage marker strings as a PE overlay,
# executes the copy, then removes it. The overlay does not affect execution.
$ErrorActionPreference = 'Stop'
$dir = Join-Path $env:TEMP 'rustinel-msfvenom-atomic'
$bin = Join-Path $dir 'rustinel_msfvenom_fixture.exe'
try {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    Copy-Item "$env:SystemRoot\System32\cmd.exe" $bin -Force
    [IO.File]::AppendAllText($bin, "metsrv.dll`nReflectiveLoader`nmeterpreter`ncore_channel_open`nstdapi_sys_config`n")
    & $bin /c exit 0 | Out-Null
    # ETW delivery and the YARA worker are asynchronous. Keep the file
    # available after process exit so this tests detection, not a deletion race.
    Start-Sleep -Seconds 5
} finally {
    Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
}
exit 0
