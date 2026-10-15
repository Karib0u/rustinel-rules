#!/usr/bin/env bash
# Atomic test — rule 8da551dd-08cf-4b73-b3cc-a18708f548b4
#   "Launch Agent or Daemon Plist Written by a Shell or Scripting Process"  (file_event)
#
# A `sh -c` process writes a .plist into the user's ~/Library/LaunchAgents —
# the path plus writer the rule keys on. It is never loaded, so no persistence
# is installed, and the file is removed afterwards.
set -u
DIR="$HOME/Library/LaunchAgents"
mkdir -p "$DIR" 2>/dev/null || true
F="$DIR/com.rustinel.atomic.scripted.plist"
/bin/sh -c 'printf "%s\n" "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict><key>Label</key><string>com.rustinel.atomic.scripted</string><key>ProgramArguments</key><array><string>/usr/bin/true</string></array><key>RunAtLoad</key><false/></dict></plist>" > "$1"' sh "$F" 2>/dev/null || true
sleep 1
rm -f "$F" 2>/dev/null || true
exit 0
