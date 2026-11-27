# Query a reserved name with a valid, 50-byte first label.
$ErrorActionPreference = 'SilentlyContinue'
$name = (Get-Random -Maximum 99999).ToString('D50') + '.rustinel-shape.invalid'
Resolve-DnsName -Name $name -Type A -DnsOnly -Server 1.1.1.1 | Out-Null
nslookup.exe $name 1.1.1.1 | Out-Null
Start-Sleep -Seconds 1
exit 0
