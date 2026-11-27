# Atomic test - rule f6599547-6e3e-4c33-be91-245433216c75 (process_creation).
# Runs an inert command-line fixture with the Cloudflare client name and verb.
. "$PSScriptRoot\command_line_fixture.ps1"
Invoke-AtomicCommandLines @{
    'cloudflared.exe' = 'tunnel run rustinel-atomic-fixture'
}
