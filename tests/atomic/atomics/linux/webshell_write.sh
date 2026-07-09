#!/usr/bin/env bash
# Atomic test - rule e96a9b85-26f6-4251-a26b-361d4b6761ef
#   "Webshell Written by Web-Server Process"  (file_event)
#
# Copies /bin/sh to a file named nginx and has it write a .php file, emitting a
# "web-server process creates a server-side script" file-create event. The
# copied shell then sleeps briefly so its process is attributed. Harmless
# content, cleaned up after.
set -u
WEB=/tmp/nginx
SHELL_PHP=/tmp/rustinel_atomic_shell.php
cp /bin/sh "$WEB" 2>/dev/null || cp /usr/bin/sh "$WEB" 2>/dev/null || true
chmod 0755 "$WEB" 2>/dev/null || true
timeout 3 "$WEB" -c "echo '<?php // rustinel atomic ?>' > $SHELL_PHP; sleep 1" >/dev/null 2>&1 || true
rm -f "$WEB" "$SHELL_PHP" 2>/dev/null || true
exit 0
