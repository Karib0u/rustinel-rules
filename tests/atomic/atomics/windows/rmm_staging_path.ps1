# Runs an inert process named AnyDesk.exe from the user's local temp directory.
. (Join-Path $PSScriptRoot 'command_line_fixture.ps1')
Invoke-AtomicCommandLines -Root (Join-Path $env:LOCALAPPDATA 'Temp') -Commands @{
    'AnyDesk.exe' = '--atomic-fixture'
}
