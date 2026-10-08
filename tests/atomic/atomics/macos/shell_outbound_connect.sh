#!/usr/bin/env bash
# Atomic test - rule e6aa2995-f56a-454a-af2c-14db0ec296ee
#   "Outbound Network Connection from Shell Binary (macOS)"  (network_connection)
#
# Apple's stock /bin/bash is built without /dev/tcp, so this copies bash to a
# temporary directory, re-signs the copy ad hoc so it can execute, and has it
# open a TCP connection to the public resolver 1.1.1.1:443 through /dev/tcp.
# Nothing is sent. Loopback cannot be used: it would not be a public address.
set -u
DIR=/tmp/rustinel_atomic_shell_net
mkdir -p "$DIR" 2>/dev/null || true
cp /bin/bash "$DIR/bash" 2>/dev/null || true
chmod 0755 "$DIR/bash" 2>/dev/null || true
codesign -f -s - "$DIR/bash" >/dev/null 2>&1 || true
"$DIR/bash" -c 'exec 3<>/dev/tcp/1.1.1.1/443; sleep 3; exec 3>&-' >/dev/null 2>&1 &
pid=$!
sleep 5
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
rm -rf "$DIR" 2>/dev/null || true
exit 0
