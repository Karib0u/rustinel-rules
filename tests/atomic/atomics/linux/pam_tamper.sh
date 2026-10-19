#!/usr/bin/env bash
# Atomic test - rule 2ef433bf-d843-424c-8223-c31efb639535
#   "PAM Configuration or Module Tampering"  (file_event)
#
# Drops a harmless, unreferenced file under /etc/pam.d, then removes it. PAM
# ignores files no service includes, so no authentication path changes.
set -u
FILE=/etc/pam.d/rustinel_atomic
printf '%s\n' '# rustinel atomic pam file' > "$FILE" 2>/dev/null || true
sleep 1
rm -f "$FILE" 2>/dev/null || true
exit 0
