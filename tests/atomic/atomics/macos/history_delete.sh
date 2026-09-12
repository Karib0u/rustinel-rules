#!/usr/bin/env bash
# Atomic test — rule ffd3b3b3-9fd4-4fd2-9988-fe837e062181
#   "Shell History File Deleted (macOS)"  (file_delete)
#
# Creates a zsh history file inside a disposable HOME and deletes it. The delete
# is the event under test: the previous shape of this rule watched file_event,
# which Endpoint Security raises on the close of every written file, so it fired
# on every normal shell exit and never on a deletion.
set -u
DIR=/tmp/rustinel_atomic_home
F="$DIR/.zsh_history"
mkdir -p "$DIR" 2>/dev/null || true
printf '%s\n' 'id' 'uname -a' 'security dump-keychain' > "$F" 2>/dev/null || true
sleep 1
rm -f "$F" 2>/dev/null || true
sleep 1
rm -rf "$DIR" 2>/dev/null || true
exit 0
