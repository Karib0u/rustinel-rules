#!/usr/bin/env bash
# Atomic test - rule 2c3d4e5f-6071-4283-8c94-1d2e3f4a5b62
#   "Sudoers Configuration Tampering"  (file_event)
#
# Drops a harmless sudoers include file, then removes it.
set -u
FILE=/etc/sudoers.d/rustinel_atomic
printf '%s\n' '# rustinel atomic sudoers file' > "$FILE" 2>/dev/null || true
chmod 0440 "$FILE" 2>/dev/null || true
sleep 1
rm -f "$FILE" 2>/dev/null || true
exit 0
