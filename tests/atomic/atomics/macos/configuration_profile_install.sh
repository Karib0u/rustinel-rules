#!/usr/bin/env bash
# A missing profile exercises the installation arguments without a profile or GUI.
set -eu
workdir=$(mktemp -d /private/tmp/rustinel-atomic-profile.XXXXXXXX)
trap 'rmdir "$workdir"' EXIT
/usr/bin/profiles install -path "$workdir/missing.mobileconfig" </dev/null >/dev/null 2>&1 || true
