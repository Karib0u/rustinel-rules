# Atomic test - IOC set ioc-canary-exec  (IP and domain IOCs / process command line)
#
# Rustinel matches IP and domain indicators against the hosts found in a process
# command line, so no network traffic is needed: a short-lived cmd.exe that
# carries a TEST-NET-3 address and a reserved .invalid name as URLs is enough.
# URL form matters - a bare host name is not read as a domain, a URL host is.
#
# The two values must keep matching the ips and domains indicators in
# preview/ioc/common/ioc_canary_exec.yml.
$ErrorActionPreference = 'Stop'
# rem makes cmd treat the URLs as a comment; nothing is contacted.
& "$env:SystemRoot\System32\cmd.exe" /c 'rem http://203.0.113.61/ http://canary-exec.rustinel-test.invalid/ & ping -n 3 127.0.0.1 >nul' | Out-Null
exit 0
