#!/usr/bin/env bash
# Atomic test — rule 1a728495-a123-44c6-8ad6-718293a4b527
#   "Unsigned or Ad-Hoc Signed Binary Executed from a Staging Directory"  (process_creation)
#
# Copies /usr/bin/true into /tmp, re-signs the copy ad hoc (`codesign -f -s -`,
# which gives it a new code directory hash and no Team ID, so it is no longer an
# Apple platform binary) and executes it. This is the ad-hoc-signed payload
# shape the rule keys on. macOS resolves /tmp to /private/tmp; the rule matches
# both forms.
set -u
DST="/tmp/rustinel_atomic_exec"
cp /usr/bin/true "$DST" 2>/dev/null || cp /bin/echo "$DST" 2>/dev/null || true
chmod 0755 "$DST" 2>/dev/null || true
codesign -f -s - "$DST" >/dev/null 2>&1 || true
"$DST" >/dev/null 2>&1 || true
rm -f "$DST" 2>/dev/null || true
exit 0
