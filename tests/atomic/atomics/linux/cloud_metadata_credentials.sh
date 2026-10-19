#!/usr/bin/env bash
# Atomic test - rule 94f6d29a-b19b-4bb2-9283-f3d6f9976811
#   "Cloud Instance Metadata Credential Request from the Command Line"  (process_creation)
#
# Copies /bin/sh to a file named curl and passes the metadata credential URL as
# an argument; no request is made.
# The shell copy lives under /opt (not world-writable) so the broad
# execution-from-temp rule does not shadow this one. Nothing connects.
set -u
DIR=/opt/rustinel_atomic_curl.d
BIN="$DIR/curl"
mkdir -p "$DIR" 2>/dev/null || true
cp /bin/sh "$BIN" 2>/dev/null || cp /usr/bin/sh "$BIN" 2>/dev/null || true
chmod 0755 "$BIN" 2>/dev/null || true
timeout 3 "$BIN" -c 'sleep 1; :' http://169.254.169.254/latest/meta-data/iam/security-credentials/ >/dev/null 2>&1 || true
rm -rf "$DIR" 2>/dev/null || true
exit 0
