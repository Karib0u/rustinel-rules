$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'command_line_fixture.ps1')

# The fixture named cmd.exe sleeps. It never opens the pipe or runs a command.
Invoke-AtomicCommandLines -Commands @{
    'cmd.exe' = '/c echo rustinel-replay > \\.\pipe\rustinel-atomic-unused'
}
