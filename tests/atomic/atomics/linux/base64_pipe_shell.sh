#!/usr/bin/env bash
# Atomic test - rule d24c4943-3e22-481f-99ee-ca631b8a77af
#   "Base64-Decode Piped to Shell"  (process_creation)
#
# Shell command line that base64-decodes a benign payload ("id") and pipes it
# into bash. The trailing sleep keeps the outer shell alive long enough for
# /proc command-line enrichment; the command line is what the rule detects.
set -u
timeout 5 bash -c 'echo aWQK | base64 -d | bash; sleep 1' >/dev/null 2>&1 || true
exit 0
