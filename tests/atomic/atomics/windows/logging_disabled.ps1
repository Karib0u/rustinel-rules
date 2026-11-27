# Atomic test - rule d27324cd-1546-46de-b237-1cc7195e7210 (process_creation).
# Passes arguments to a fixture that leaves channels and trace sessions alone.
. "$PSScriptRoot\command_line_fixture.ps1"
Invoke-AtomicCommandLines ([ordered]@{
    'wevtutil.exe' = 'sl "RustinelAtomic/Operational" /e:false'
    'logman.exe' = 'stop RustinelAtomic -ets'
})
