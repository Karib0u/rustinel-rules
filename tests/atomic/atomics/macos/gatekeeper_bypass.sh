#!/usr/bin/env bash
# Atomic test — rule 5c3e4051-6d7f-4082-8c92-3d4e5f601203
#   "Gatekeeper or Quarantine Protection Disabled"  (process_creation)
#
# Exercises the safe xattr branch of the rule rather than `spctl
# --master-disable` (which would actually weaken Gatekeeper system-wide). It
# stamps the com.apple.quarantine attribute onto a throwaway temp file and then
# deletes it with `xattr -d com.apple.quarantine` — the exact image+argv the
# rule keys on. Only our own temp file is touched; no system state changes.
set -u
F="/tmp/rustinel_atomic_quarantine"
: > "$F"
xattr -w com.apple.quarantine "0083;00000000;Rustinel;" "$F" >/dev/null 2>&1 || true
xattr -d com.apple.quarantine "$F" >/dev/null 2>&1 || true
rm -f "$F" 2>/dev/null || true
exit 0
