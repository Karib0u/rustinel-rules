#!/usr/bin/env bash
# Negative for rule 578195d3-de1a-4c46-84c8-b246a060474c
#   "launchctl Load from User-Writable Path"
#
# `launchctl unload` of a plist in /tmp is cleanup, not activation. The path
# carries `_neg` so an alert on this event can be told from the positive's.
set -u
DIR=/tmp/rustinel_atomic_launch_neg
mkdir -p "$DIR" 2>/dev/null || true
launchctl unload "$DIR/com.rustinel.atomic.plist" >/dev/null 2>&1 || true
rm -rf "$DIR" 2>/dev/null || true
exit 0
