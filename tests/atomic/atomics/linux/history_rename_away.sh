#!/usr/bin/env bash
# Atomic test - rule 55e6e499-c8d5-4d12-8e03-dd56f113d2a0
#   "Shell History File Renamed Away"  (file_rename, SourceFilename)
#
# Moves a history file out of place. The rule keys on SourceFilename — the
# pre-rename name — so it sees this and not the temp-file-renamed-onto-history
# save that zsh performs on every normal shell exit.
set -u
DIR=/tmp/rustinel_atomic_home
F="$DIR/.bash_history"
mkdir -p "$DIR" 2>/dev/null || true
printf '%s\n' 'id' 'uname -a' > "$F" 2>/dev/null || true
sleep 1
mv -f "$F" "$DIR/history.bak" 2>/dev/null || true
sleep 1
rm -rf "$DIR" 2>/dev/null || true
exit 0
