#!/usr/bin/env bash
# Atomic test - rule abc435d7-cb05-4288-8e87-f549e189bbb0
#   "Authorization Plugin Written to SecurityAgentPlugins"  (file_event)
#
# Writes an empty, harmless file into /Library/Security/SecurityAgentPlugins/
# and removes it. The directory is only read for *.bundle plugins that the
# authorization database references, so a stray file loads nothing. Written by
# dd under sudo so the writer is a plain tool, not a system installer.
set -u
DIR=/Library/Security/SecurityAgentPlugins
F="$DIR/rustinel_atomic.txt"
sudo -n mkdir -p "$DIR" >/dev/null 2>&1 || true
echo "rustinel atomic" | sudo -n dd of="$F" >/dev/null 2>&1 || true
sleep 1
sudo -n rm -f "$F" >/dev/null 2>&1 || true
exit 0
