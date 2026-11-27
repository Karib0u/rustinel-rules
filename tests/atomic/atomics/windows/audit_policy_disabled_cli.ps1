# Atomic test - rule c7eccf1c-329e-423d-8ba0-cdf572b52023 (process_creation).
# Passes auditpol switches to a fixture that leaves the audit policy alone.
. "$PSScriptRoot\command_line_fixture.ps1"
Invoke-AtomicCommandLines @{
    'auditpol.exe' = '/set /subcategory:"Process Creation" /success:disable'
}
