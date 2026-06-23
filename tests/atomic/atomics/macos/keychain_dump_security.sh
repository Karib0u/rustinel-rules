#!/usr/bin/env bash
# Atomic test — rule 7a1c2e3f-4b5d-4e6f-8a90-1b2c3d4e5f01
#   "Keychain Credential Dump via security"  (process_creation)
#
# Invokes the macOS `security` tool with `dump-keychain`, the exact token the
# rule keys on. It targets a non-existent keychain path, so `security` errors
# out immediately — no real keychain is read, nothing is dumped and no access
# prompt appears. The process-creation telemetry (argv) is what trips the rule.
set -u
security dump-keychain "/tmp/rustinel_atomic_nonexistent.keychain" >/dev/null 2>&1 || true
exit 0
