#!/usr/bin/env bash
# Atomic test - rule b01a8433-8768-4825-8d7e-665e132f17b6
#   "Shell Profile Modified by a Shell or Scripting Process"  (file_event)
#
# Appends a comment line to ~/.zprofile from this shell, then restores the
# original file (or removes it if it did not exist). Only a comment is added.
set -u
F="$HOME/.zprofile"
BACKUP=""
if [ -f "$F" ]; then BACKUP="$(mktemp)"; cp "$F" "$BACKUP"; fi
echo "# rustinel atomic" >> "$F" 2>/dev/null || true
sleep 1
if [ -n "$BACKUP" ]; then cp "$BACKUP" "$F" 2>/dev/null; rm -f "$BACKUP"; else rm -f "$F"; fi
exit 0
