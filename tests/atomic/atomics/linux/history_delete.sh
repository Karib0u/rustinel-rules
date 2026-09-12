#!/usr/bin/env bash
# Atomic test - rule 6df6fcdc-e5e5-413b-aabe-ec3d51d6bfeb
#   "Shell History File Deleted"  (file_delete)
#
# Creates a shell history file inside a disposable HOME and deletes it. The
# delete is the event under test: the previous shape of this rule watched
# file_event, which never carries a deletion, so it could only ever fire on the
# appends a normal shell makes when it saves history on exit.
set -u
DIR=/tmp/rustinel_atomic_home
F="$DIR/.bash_history"
mkdir -p "$DIR" 2>/dev/null || true
printf '%s\n' 'id' 'uname -a' 'cat /etc/passwd' > "$F" 2>/dev/null || true
sleep 1
rm -f "$F" 2>/dev/null || true
sleep 1
rm -rf "$DIR" 2>/dev/null || true
exit 0
