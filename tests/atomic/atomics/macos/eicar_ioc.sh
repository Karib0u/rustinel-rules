#!/usr/bin/env bash
# Atomic test — IOC set ioc-eicar-test  (hash IOC / file scan)
#
# Writes the standardized, harmless EICAR test file and then reads it so the
# engine hashes it and matches the bundled EICAR IOC hashes. The signature is
# assembled from fragments at runtime so this script file itself is never the
# full EICAR string on disk (keeps your own AV from quarantining the repo).
#
# Marked allow_failure in the manifest: detection depends on the engine hashing
# files on create/access, which is the least deterministic path to time in CI.
set -u
P1='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICA'
P2='R-STANDARD-ANTIVIRUS-'
P3='TEST-FILE!$H+H*'
F="$(pwd)/rustinel_atomic_eicar.tmp"
printf '%s%s%s' "$P1" "$P2" "$P3" > "$F"
# Touch/read the file a few times to generate file-scan telemetry.
for _ in 1 2 3; do cat "$F" >/dev/null 2>&1 || true; sleep 1; done
rm -f "$F" 2>/dev/null || true
exit 0
