# Atomic test - rule 77d79285-57e8-459d-9b8d-2a2627010d1e (process_creation).
# Both images are fixture copies. The command and URL are inert arguments.
. "$PSScriptRoot\command_line_fixture.ps1"
Invoke-AtomicCommandLines @{ 'cmd.exe' = '/c echo https://example.invalid/rustinel-atomic' } -ParentName 'explorer.exe'
