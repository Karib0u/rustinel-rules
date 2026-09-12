# Atomic test - IOC set ioc-canary-exec  (hash IOC / file_scan)
#
# Rustinel computes hash IOCs from the resolved image path of a *process start*,
# so the only honest end-to-end test of that path is to launch a file whose bytes
# are fixed in advance. This writes the deterministic canary - a 1 KB import-less
# PE that returns immediately - and runs it. Its SHA-256 is the indicator in
# preview\ioc\common\ioc_canary_exec.yml.
#
# Regenerate both the blob below and the recorded hash with:
#   uv run python tests/atomic/canary/make_canary.py
#
# This replaces the EICAR test, which could never pass: a dropped file that is
# never executed is never hashed, and EICAR is a 16-bit DOS .COM that cannot
# become a process image on 64-bit Windows.
#
# Written under the workspace, which the CI job excludes from Defender, so
# real-time protection does not quarantine an unsigned tiny PE before the engine
# sees it.
$ErrorActionPreference = 'Stop'
$b64 =
    'TVoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAQAAAAFBFAABkhgEAAAAAAAAAAAAAAAAA8AAiAAsCDgAAAgAA' +
    'AAAAAAAAAAAAEAAAABAAAAAAAEABAAAAABAAAAACAAAGAAAAAAAAAAYAAAAAAAAA' +
    'ACAAAAACAAAAAAAAAwAAAQAAEAAAAAAAABAAAAAAAAAAABAAAAAAAAAQAAAAAAAA' +
    'AAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC50ZXh0AAAA' +
    'AAIAAAAQAAAAAgAAAAIAAAAAAAAAAAAAAAAAACAAAGAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAxwMMAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
    'AAAAAAAAAAAAAAAAAAAAAA=='

$dir = Join-Path $PWD 'rustinel-atomic-canary'
$bin = Join-Path $dir 'canary-exec.exe'
try {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    [IO.File]::WriteAllBytes($bin, [Convert]::FromBase64String($b64))
    & $bin | Out-Null
    # The hash worker runs off the process-start event; keep the file in place
    # for a moment so this tests detection rather than a deletion race.
    Start-Sleep -Seconds 5
} finally {
    Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
}
exit 0
