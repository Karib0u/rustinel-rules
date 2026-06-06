#!/usr/bin/env bash
# Atomic test - rule 3d4e5f60-7182-4394-9da5-2e3f4a5b6c73
#   "Systemd Unit Persistence"  (file_event)
#
# Creates a service unit file without enabling or starting it.
set -u
FILE=/etc/systemd/system/rustinel-atomic.service
cat > "$FILE" 2>/dev/null <<'UNIT' || true
[Unit]
Description=Rustinel atomic service fixture

[Service]
Type=oneshot
ExecStart=/bin/true
UNIT
sleep 1
rm -f "$FILE" 2>/dev/null || true
exit 0
