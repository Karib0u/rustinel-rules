#!/usr/bin/env bash
# Atomic test — rule 97b0f988-7268-4854-9251-4da5a8397da9
#   "Account Added to the macOS Admin Group"  (process_creation)
#
# Invokes `dscl -append /Groups/admin GroupMembership` against the read-only
# /Search aggregation node, so the change can never succeed and the admin group
# is never modified, even when the harness runs as root.
set -u
dscl /Search -append /Groups/admin GroupMembership _rustinel_atomic >/dev/null 2>&1 || true
exit 0
