#!/usr/bin/env bash
# Atomic test - rule 8fd4d1d9-38cf-4704-8009-00e41a009c98
#   "Linux Web Server Spawning Interactive Shell"  (process_creation)
#
# Runs a copied shell named php-fpm8.2 (the versioned name Debian and Ubuntu
# install) that spawns /bin/sh as a child.
set -u
PARENT=/tmp/php-fpm8.2
cp /bin/sh "$PARENT" 2>/dev/null || true
chmod 0755 "$PARENT" 2>/dev/null || true
timeout 5 "$PARENT" -c '/bin/sh -c true' >/dev/null 2>&1 || true
rm -f "$PARENT" 2>/dev/null || true
exit 0
