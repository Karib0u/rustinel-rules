# Atomic test - rule ecf18769-8140-452c-b00e-b9debc35375e (process_creation).
# Passes a reserved pool URL to a fixture with no mining or network code.
. "$PSScriptRoot\command_line_fixture.ps1"
Invoke-AtomicCommandLines @{
    'miner-fixture.exe' = '-o stratum+tcp://pool.invalid:3333'
}
