#!/usr/bin/env bash
# Atomic test - rule 1b2c3d4e-5f60-4172-9b83-0c1d2e3f4a51
#   "SSH authorized_keys Created or Replaced"  (file_event)
#
# Writes an authorized_keys file under a disposable directory.
set -u
DIR=/tmp/rustinel_atomic_home/.ssh
FILE="$DIR/authorized_keys"
mkdir -p "$DIR" 2>/dev/null || true
printf '%s\n' 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIRustinelAtomicKeyOnly test@example' > "$FILE" 2>/dev/null || true
sleep 1
rm -rf /tmp/rustinel_atomic_home 2>/dev/null || true
exit 0
