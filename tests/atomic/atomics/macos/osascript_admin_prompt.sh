#!/usr/bin/env bash
# Atomic test — rule 6b2d3f40-5c6e-4f71-9b81-2c3d4e5f6012
#   "osascript Credential Prompt or Suspicious Admin Shell"  (process_creation)
#
# Runs osascript with a hidden-answer "display dialog" — the infostealer
# password-phish pattern the rule keys on (selection_phish: 'display dialog' +
# 'hidden answer'). `giving up after 1` makes any real dialog self-dismiss after
# a second; on a headless/locked-down session osascript just errors out. Either
# way nothing is typed and the process argv is what trips the rule. A background
# guard kills it after a few seconds as a backstop.
set -u
osascript -e 'display dialog "Rustinel atomic test" default answer "" with hidden answer giving up after 1' >/dev/null 2>&1 &
pid=$!
sleep 3
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
exit 0
