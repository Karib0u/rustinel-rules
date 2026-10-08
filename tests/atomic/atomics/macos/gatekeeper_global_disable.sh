#!/usr/bin/env bash
# Atomic test — rule 5c3e4051-6d7f-4082-8c92-3d4e5f601203
#   "Gatekeeper Globally Disabled via spctl"  (process_creation)
#
# Runs `spctl --master-disable`. The rule matches the command line, so the
# command only has to be launched, not to succeed. When the harness runs as
# root it is dropped to `nobody` first, which has no authority to change the
# Gatekeeper policy, so the system setting is never touched. A guard re-enables
# assessment in case the change did go through.
set -u
if [ "$(id -u)" = "0" ]; then
  sudo -u nobody /usr/sbin/spctl --master-disable >/dev/null 2>&1 || true
else
  /usr/sbin/spctl --master-disable >/dev/null 2>&1 || true
fi
if /usr/sbin/spctl --status 2>/dev/null | grep -q disabled; then
  /usr/sbin/spctl --master-enable >/dev/null 2>&1 || sudo /usr/sbin/spctl --master-enable >/dev/null 2>&1 || true
fi
exit 0
