#!/usr/bin/env bash
# Atomic test - IOC set ioc-canary-exec  (IP and domain IOCs / process command line)
#
# Rustinel matches IP and domain indicators against the hosts found in a process
# command line, so no network traffic is needed: a short-lived shell that carries
# a TEST-NET-3 address and a reserved .invalid name as URL operands is enough.
# URL form matters - a bare host name is not read as a domain, a URL host is.
#
# The two values must keep matching the ips and domains indicators in
# preview/ioc/common/ioc_canary_exec.yml.
set -u
# The tokens after -c's script are positional arguments; sh never runs them.
sh -c 'sleep 2' rustinel-ioc-fixture 'http://203.0.113.61/' 'http://canary-exec.rustinel-test.invalid/' >/dev/null 2>&1
exit 0
