#!/usr/bin/env bash
# Atomic test - rule 0a1b2c3d-4e5f-4061-8a72-9b0c1d2e3f40
#   "Dynamic Linker Hijacking via ld.so.preload"  (file_event)
#
# Creates /etc/ld.so.preload briefly, then restores any previous content.
set -u
TARGET=/etc/ld.so.preload
BACKUP=/tmp/rustinel_atomic_ldso_preload.backup
if [ -e "$TARGET" ]; then
  cp "$TARGET" "$BACKUP" 2>/dev/null || true
fi
printf '%s\n' '/tmp/rustinel_atomic_missing.so' > "$TARGET" 2>/dev/null || true
sleep 1
if [ -e "$BACKUP" ]; then
  cp "$BACKUP" "$TARGET" 2>/dev/null || true
  rm -f "$BACKUP" 2>/dev/null || true
else
  rm -f "$TARGET" 2>/dev/null || true
fi
exit 0
