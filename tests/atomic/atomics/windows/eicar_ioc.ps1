# Atomic test - IOC set ioc-eicar-test  (hash IOC / file scan)
#
# Writes the standardized, harmless EICAR test file and reads it so the engine
# hashes it and matches the bundled EICAR IOC hashes. The signature is assembled
# from fragments at runtime so this script is never the full EICAR string on
# disk. The CI workflow adds a Defender exclusion for the workspace so real-time
# protection does not quarantine the file before the engine sees it.
#
# Marked allow_failure in the manifest: detection depends on file-scan timing
# and on Defender staying out of the way.
$ErrorActionPreference = 'SilentlyContinue'
$p1 = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICA'
$p2 = 'R-STANDARD-ANTIVIRUS-'
$p3 = 'TEST-FILE!$H+H*'
$f = Join-Path $PWD 'rustinel_atomic_eicar.tmp'
[IO.File]::WriteAllText($f, $p1 + $p2 + $p3)
foreach ($i in 1..3) { Get-Content $f | Out-Null; Start-Sleep -Seconds 1 }
Remove-Item $f -Force -ErrorAction SilentlyContinue
exit 0
