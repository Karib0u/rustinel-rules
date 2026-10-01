#!/usr/bin/env bash
# Atomic test — rule 5c3e4051-6d7f-4082-8c92-3d4e5f601203
#   "Gatekeeper or Quarantine Protection Disabled"  (process_creation)
#
# Exercises the clear-all branch: stamps com.apple.quarantine onto a throwaway
# temp file, then removes every attribute with `xattr -c`, the form fake
# installers tell victims to paste into Terminal. Only our own temp file is
# touched; no system state changes.
set -u
F="/tmp/rustinel_atomic_quarantine_clear"
: > "$F"
xattr -w com.apple.quarantine "0083;00000000;Rustinel;" "$F" >/dev/null 2>&1 || true
xattr -c "$F" >/dev/null 2>&1 || true
rm -f "$F" 2>/dev/null || true
exit 0
