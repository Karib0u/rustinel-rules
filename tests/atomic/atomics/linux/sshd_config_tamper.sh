#!/usr/bin/env bash
# Atomic test - rule 9ac8732e-1818-4cda-89ac-01ca08a7b836
#   "SSH Daemon Configuration Tampering"  (file_event)
#
# Uses the sshd_config.d drop-in path so the primary sshd_config is untouched.
set -u
DIR=/etc/ssh/sshd_config.d
FILE="$DIR/rustinel_atomic.conf"
mkdir -p "$DIR" 2>/dev/null || true
printf '%s\n' '# rustinel atomic sshd drop-in' > "$FILE" 2>/dev/null || true
sleep 1
rm -f "$FILE" 2>/dev/null || true
exit 0
