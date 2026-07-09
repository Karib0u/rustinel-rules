#!/usr/bin/env bash
# Atomic test - rule 1bb5e9e4-f17e-476e-8e77-aaa1858f12f7
#   "udev Rules Persistence"  (file_event)
#
# Drops a harmless udev rules file under /etc/udev/rules.d, then removes it.
set -u
FILE=/etc/udev/rules.d/rustinel_atomic.rules
printf '%s\n' '# rustinel atomic udev rule' > "$FILE" 2>/dev/null || true
sleep 1
rm -f "$FILE" 2>/dev/null || true
exit 0
