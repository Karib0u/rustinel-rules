#!/usr/bin/env bash
# Atomic test - rule a360dda4-e2ba-42e1-8fda-4a787afebf2d
#   "Root Certificate Added to the Trust Store via security"  (process_creation)
#
# Calls `security add-trusted-cert` with a certificate and keychain that do not
# exist, so it fails immediately and changes no trust setting.
set -u
/usr/bin/security add-trusted-cert -d -r trustRoot -k /tmp/rustinel_atomic_nonexistent.keychain /tmp/rustinel_atomic_nonexistent.pem >/dev/null 2>&1 || true
exit 0
