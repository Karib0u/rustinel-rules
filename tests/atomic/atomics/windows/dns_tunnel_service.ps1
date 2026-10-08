# Atomic test - rule c2f19723-1801-48d4-a45f-c47f2f9d41b5
#   "DNS Query to Tunnel Service"  (dns_query)
#
# Resolves a random name under trycloudflare.com. The name does not exist, so
# nothing is reached; the lookup alone is the telemetry.
$ErrorActionPreference = 'SilentlyContinue'
$name = 'rustinel-atomic-' + (Get-Random -Maximum 99999) + '.trycloudflare.com'
Resolve-DnsName -Name $name -Type A -DnsOnly | Out-Null
nslookup.exe $name 1.1.1.1 | Out-Null
Start-Sleep -Seconds 1
exit 0
