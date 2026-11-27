# Atomic test - rule a30c71e5-f274-46d8-838a-1c0f2b569368 (process_creation).
# Uses a fixture named after a system process.
. "$PSScriptRoot\command_line_fixture.ps1"
Invoke-AtomicCommandLines @{
    'svchost.exe' = 'RustinelAtomic'
}
