# Atomic test - rule yara-win-xmrig-coinminer
#   "XMRig / coinminer strings in Windows PE binaries"  (yara file_scan)
#
# Copies cmd.exe, appends XMRig marker strings as a PE overlay, executes the
# copy, then removes it. The overlay does not affect execution.
$ErrorActionPreference = 'SilentlyContinue'
$dir = Join-Path $env:TEMP 'rustinel-xmrig-atomic'
$bin = Join-Path $dir 'rustinel_xmrig_fixture.exe'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
Copy-Item "$env:SystemRoot\System32\cmd.exe" $bin -Force
[IO.File]::AppendAllText($bin, "xmrig`nstratum+tcp://`ndonate-level`nrandomx`nmonero`n")
& $bin /c exit 0 | Out-Null
Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
exit 0
