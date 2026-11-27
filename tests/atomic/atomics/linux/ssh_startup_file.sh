#!/usr/bin/env bash
# Exercise a user .ssh/rc write under a disposable stand-in for a home directory.
set -eu
DIR=$(mktemp -d /tmp/rustinel_atomic_ssh_rc.XXXXXX)
trap 'rm -f -- "$DIR/.ssh/rc"; rmdir -- "$DIR/.ssh" "$DIR"' EXIT
mkdir -- "$DIR/.ssh"
printf '%s\n' ':' >"$DIR/.ssh/rc"
sleep 1
