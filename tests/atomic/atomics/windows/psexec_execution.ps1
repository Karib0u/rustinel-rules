# Atomic test - rule c28cddd0-5518-4a27-b412-dcf69191825d (process_creation).
# The fixture ignores both flags and starts no service or remote process.
. "$PSScriptRoot\command_line_fixture.ps1"
Invoke-AtomicCommandLines @{ 'rustinel-atomic-worker.exe' = '-accepteula -i' }
