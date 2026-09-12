#!/usr/bin/env bash
# Atomic test — rule 578195d3-de1a-4c46-84c8-b246a060474c
#   "launchctl Load from User-Writable Path"  (process_creation)
#
# Runs `launchctl load` against a plist in /tmp, then unloads it. The plist has
# RunAtLoad false and would run /usr/bin/true, so nothing executes even if the
# load succeeds, and the unload plus cleanup leave no persistence behind. The
# rule matches the launchctl command line, so this fires whether or not launchctl
# accepts the job in a headless CI session.
set -u
DIR=/tmp/rustinel_atomic_launch
F="$DIR/com.rustinel.atomic.plist"
mkdir -p "$DIR" 2>/dev/null || true
cat > "$F" <<'PLIST' 2>/dev/null || true
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
launchctl load "$F" >/dev/null 2>&1 || true
sleep 1
launchctl unload "$F" >/dev/null 2>&1 || true
rm -rf "$DIR" 2>/dev/null || true
exit 0
