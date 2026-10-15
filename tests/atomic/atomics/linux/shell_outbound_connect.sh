#!/usr/bin/env bash
# Atomic test - rule d0c6216e-881c-408f-8e72-0a466522306b
#   "Outbound Network Connection from Shell Binary"  (network_connection)
#
# Has a shell open a TCP connection to a public address through /dev/tcp and
# send nothing. 1.1.1.1:443 is a public resolver endpoint; the connection is
# closed immediately. Loopback and private ranges cannot be used: the sensor
# drops loopback and the rule filters non-public destinations.
set -u
timeout 10 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443; sleep 2; exec 3>&-' >/dev/null 2>&1 || true
exit 0
