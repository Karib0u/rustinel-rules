#!/usr/bin/env bash
# Atomic test — rule 55eaad6e-88a1-4eae-8014-24d96a68f965
#   "Local Account Hidden from the Login Window"  (process_creation)
#
# Invokes `dscl -create /Users/... IsHidden 1` against the read-only /Search
# aggregation node, so no account record is written even when the harness runs
# as root. A guard delete against the local node is a no-op cleanup.
set -u
dscl /Search -create /Users/_rustinel_atomic IsHidden 1 >/dev/null 2>&1 || true
dscl . -delete /Users/_rustinel_atomic >/dev/null 2>&1 || true
exit 0
