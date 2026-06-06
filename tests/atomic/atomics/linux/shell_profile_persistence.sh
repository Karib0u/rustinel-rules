#!/usr/bin/env bash
# Atomic test - rule 5f607182-93a4-45b6-9fc7-4a5b6c7d8e95
#   "Shell Profile / RC File Persistence"  (file_event)
#
# Writes a harmless profile.d drop-in, then removes it.
set -u
FILE=/etc/profile.d/rustinel_atomic.sh
printf '%s\n' '# rustinel atomic profile file' > "$FILE" 2>/dev/null || true
sleep 1
rm -f "$FILE" 2>/dev/null || true
exit 0
