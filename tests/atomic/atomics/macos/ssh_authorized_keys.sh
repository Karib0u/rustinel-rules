#!/usr/bin/env bash
# Atomic test — rule c92540cf-466d-4959-ab25-1c456bedf9d5
#   "SSH authorized_keys Created or Replaced (macOS)"  (file_event)
#
# Writes an authorized_keys file under a disposable directory. The key is not
# valid for any account and the file is never installed under a real home.
set -u
DIR=/tmp/rustinel_atomic_home/.ssh
FILE="$DIR/authorized_keys"
mkdir -p "$DIR" 2>/dev/null || true
printf '%s\n' 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIRustinelAtomicKeyOnly test@example' > "$FILE" 2>/dev/null || true
sleep 1
rm -rf /tmp/rustinel_atomic_home 2>/dev/null || true
exit 0
