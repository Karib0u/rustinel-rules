# Atomic test - Sigma correlation (event_count) fixture
#   "Fixture - Correlation Event Count" over "Fixture - Correlation Base Marker"
#
# Starts the same marker process twice. The base rule matches each start by its
# command line; the correlation fires once it has seen two within its window.
$ErrorActionPreference = 'Stop'
foreach ($i in 1..2) {
    & "$env:SystemRoot\System32\cmd.exe" /c 'ping -n 2 127.0.0.1 >nul & rem rustinel-corr-fixture-7f3a' | Out-Null
}
exit 0
