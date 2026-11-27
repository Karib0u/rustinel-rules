#!/usr/bin/env bash
# crontab rejects a file that does not exist before changing the table.
set -eu
workdir=$(mktemp -d /private/tmp/rustinel-atomic-cron.XXXXXXXX)
trap 'rmdir "$workdir"' EXIT
/usr/bin/crontab "$workdir/missing.crontab" </dev/null >/dev/null 2>&1 || true
