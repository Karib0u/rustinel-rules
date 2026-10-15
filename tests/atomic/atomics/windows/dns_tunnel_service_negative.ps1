# Negative fixture for rule c2f19723-1801-48d4-a45f-c47f2f9d41b5
# Resolves a name that merely resembles a tunnel domain. The rule must not alert.
$ErrorActionPreference = 'SilentlyContinue'
Resolve-DnsName -Name 'rustinel-negative.mytrycloudflare.com' -Type A -DnsOnly | Out-Null
Start-Sleep -Seconds 1
exit 0
