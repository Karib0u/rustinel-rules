#!/usr/bin/env bash
# Atomic test — rule 2f617384-9012-43b5-9fc5-60718293a416
#   "Local Admin Account Created via Directory Services"  (process_creation)
#
# Invokes `dscl` with `-create /Users/...` — the image+argv the rule keys on.
# The target is the read-only /Search aggregation node, so the create can never
# succeed and no account is written, even when the harness runs us as root. A
# guard delete against the local node is a belt-and-suspenders no-op cleanup.
set -u
dscl /Search -create /Users/_rustinel_atomic RealName "Rustinel Atomic" >/dev/null 2>&1 || true
dscl . -delete /Users/_rustinel_atomic >/dev/null 2>&1 || true
exit 0
