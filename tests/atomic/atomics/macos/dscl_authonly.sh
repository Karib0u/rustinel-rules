#!/usr/bin/env bash
# Atomic test - rule 7cdd4118-b1f9-4396-a9fd-728b9d453803
#   "Password Validation via dscl -authonly"  (process_creation)
#
# Asks dscl to authenticate a local account that does not exist with a dummy
# password. The call fails immediately, validates no real credential and shows
# no prompt; the -authonly argument in the process telemetry trips the rule.
set -u
/usr/bin/dscl . -authonly rustinel_atomic_nouser not-a-password >/dev/null 2>&1 || true
exit 0
