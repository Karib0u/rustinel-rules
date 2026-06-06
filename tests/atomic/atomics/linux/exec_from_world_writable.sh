#!/usr/bin/env bash
# Atomic test - rule 60718293-a4b5-46c7-8fd8-5b6c7d8e9fa6
#   "Execution from World-Writable / Temporary Directory"  (process_creation)
#
# Copies /bin/true to /tmp and executes the copy.
set -u
BIN=/tmp/rustinel_atomic_exec
cp /bin/true "$BIN" 2>/dev/null || cp /usr/bin/true "$BIN" 2>/dev/null || true
chmod 0755 "$BIN" 2>/dev/null || true
"$BIN" >/dev/null 2>&1 || true
rm -f "$BIN" 2>/dev/null || true
exit 0
