#!/usr/bin/env bash
# Atomic test — rule 457c6ee7-e5d8-4f06-b25e-a7a3d40e354d
#   "Shell History File Renamed Away (macOS)"  (file_rename, SourceFilename)
#
# Moves a history file out of place. The rule keys on SourceFilename — the
# pre-rename name — so it sees this and not the HIST_SAVE_BY_COPY rename zsh
# performs onto .zsh_history on every normal shell exit.
set -u
DIR=/tmp/rustinel_atomic_home
F="$DIR/.zsh_history"
mkdir -p "$DIR" 2>/dev/null || true
printf '%s\n' 'id' 'uname -a' > "$F" 2>/dev/null || true
sleep 1
mv -f "$F" "$DIR/history.bak" 2>/dev/null || true
sleep 1
rm -rf "$DIR" 2>/dev/null || true
exit 0
