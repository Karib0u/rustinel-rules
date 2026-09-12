#!/usr/bin/env bash
# Atomic test — rule 40b5bf5b-055e-4db2-90df-bd2968ddad9f
#   "Shell History Destroyed in Place (macOS)"  (process_creation)
#
# Empties a history file without deleting or renaming it, which is the only
# variant of history tampering that leaves nothing but a command line behind.
# macOS ships no truncate(1), so this exercises the /dev/null branches: a shell
# redirect over the file, and symlinking the history file at /dev/null so
# nothing is ever written again.
set -u
DIR=/tmp/rustinel_atomic_home
F="$DIR/.zsh_history"
mkdir -p "$DIR" 2>/dev/null || true
printf '%s\n' 'id' 'uname -a' > "$F" 2>/dev/null || true
bash -c "cat /dev/null > $DIR/.zsh_history" 2>/dev/null || true
sleep 1
rm -f "$F" 2>/dev/null || true
ln -sf /dev/null "$DIR/.zsh_history" 2>/dev/null || true
sleep 1
rm -rf "$DIR" 2>/dev/null || true
exit 0
