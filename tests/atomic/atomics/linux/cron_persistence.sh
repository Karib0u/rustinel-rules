#!/usr/bin/env bash
# Atomic test — rule 4e5f6071-8293-44a5-8eb6-3f4a5b6c7d84
#   "Cron Job Persistence"  (file_event)
#
# Drops a cron file into /etc/cron.d/ — a classic scheduled-task persistence
# spot the rule watches. The job body is a harmless `true`. Requires root
# (the runner is privileged for eBPF anyway). Cleans up after itself.
set -u
CRON=/etc/cron.d/rustinel_atomic_test
printf '%s\n' '* * * * * root true' > "$CRON" 2>/dev/null || true
sleep 1
rm -f "$CRON" 2>/dev/null || true
exit 0
