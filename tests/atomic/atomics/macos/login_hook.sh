#!/usr/bin/env bash
# Atomic test - rule ba4c78ad-7cd1-4fce-b409-57af0f79c814
#   "Login Hook or Login Item Added from the Command Line"  (process_creation)
#
# Runs `defaults write` on a plist file in a temp directory whose name carries
# the com.apple.loginwindow domain and a LoginHook key. The real login window
# preferences are never touched; the command line is what trips the rule.
set -u
DIR=/tmp/rustinel_atomic_loginhook
mkdir -p "$DIR" 2>/dev/null || true
/usr/bin/defaults write "$DIR/com.apple.loginwindow" LoginHook /usr/bin/true >/dev/null 2>&1 || true
rm -rf "$DIR" 2>/dev/null || true
exit 0
