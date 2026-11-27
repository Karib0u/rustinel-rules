# Run a DNS-only lookup. No connection is made to the service.
$ErrorActionPreference = 'SilentlyContinue'
Resolve-DnsName -Name api.telegram.org -Type A -DnsOnly -Server 1.1.1.1 | Out-Null
Start-Sleep -Seconds 1
exit 0
