#!/usr/bin/env bash
# Atomic test — rule 1a728495-a123-44c6-8ad6-718293a4b527
#   "Execution from World-Writable or Temporary Directory"  (process_creation)
#
# Copies /usr/bin/true into /tmp and executes the copy. The copy is byte-for-byte
# identical, so its code signature stays valid and it runs. macOS resolves /tmp
# to /private/tmp; the rule matches both forms. The Image path is what fires.
set -u
DST="/tmp/rustinel_atomic_exec"
cp /usr/bin/true "$DST" 2>/dev/null || cp /bin/echo "$DST" 2>/dev/null || true
chmod 0755 "$DST" 2>/dev/null || true
"$DST" >/dev/null 2>&1 || true
rm -f "$DST" 2>/dev/null || true
exit 0
