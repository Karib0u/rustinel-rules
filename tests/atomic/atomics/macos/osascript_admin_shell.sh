#!/usr/bin/env bash
# Atomic test — rule d3aaca03-eeea-4d6b-80a8-8e45c38b4fdd
#   "osascript Privileged Shell Command with Staging Indicators"  (process_creation)
#
# Runs osascript with a `do shell script ... with administrator privileges`
# command that mentions curl. The trailing token makes the script a syntax
# error, so AppleScript refuses to compile it and no authorization prompt is
# ever shown and nothing executes; the argv is what the rule matches.
# A background guard kills it after a few seconds as a backstop.
set -u
osascript -e 'do shell script "curl --max-time 1 http://127.0.0.1:9/ -o /tmp/rustinel_atomic_stage" with administrator privileges rustinel_atomic_invalid' >/dev/null 2>&1 &
pid=$!
sleep 3
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
exit 0
