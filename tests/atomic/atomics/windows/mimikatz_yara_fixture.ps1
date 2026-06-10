# Atomic test - rule yara-win-mimikatz-strings
#   "Mimikatz credential-dumping strings"  (yara file_scan)
#
# Copies cmd.exe, appends Mimikatz marker strings as a PE overlay, executes the
# copy, then removes it. The overlay does not affect execution.
$ErrorActionPreference = 'SilentlyContinue'
$dir = Join-Path $env:TEMP 'rustinel-yara-atomic'
$bin = Join-Path $dir 'rustinel_mimikatz_fixture.exe'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
Copy-Item "$env:SystemRoot\System32\cmd.exe" $bin -Force
[IO.File]::AppendAllText($bin, "sekurlsa::logonpasswords`nsekurlsa::minidump`ngentilkiwi`nmimikatz`n")
& $bin /c exit 0 | Out-Null
Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
exit 0
