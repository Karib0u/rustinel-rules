#!/usr/bin/env bash
# Atomic test — rule 4d4f5162-7e80-4193-9da3-4e5f60712304
#   "Launch Agent or Daemon Plist Written"  (file_event)
#
# Writes a .plist into the user's ~/Library/LaunchAgents directory — the path
# the rule keys on (contains '/Library/LaunchAgents/', endswith '.plist'). The
# file_event telemetry is what fires. It is never `launchctl load`-ed, so no
# persistence is actually installed, and the file is removed afterwards.
#
# The plist is written by `dd`, not by the shell: a shell writer also matches the
# stronger scripted-writer rule, and the engine reports one alert per event, so
# the generic rule would never be the one that fires.
set -u
DIR="$HOME/Library/LaunchAgents"
mkdir -p "$DIR" 2>/dev/null || true
F="$DIR/com.rustinel.atomic.plist"
dd of="$F" 2>/dev/null <<'PLIST' || true
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.rustinel.atomic</string>
  <key>ProgramArguments</key><array><string>/usr/bin/true</string></array>
  <key>RunAtLoad</key><false/>
</dict>
</plist>
PLIST
sleep 1
rm -f "$F" 2>/dev/null || true
exit 0
