# Atomic test - rule 6f0d2a91-3b7c-4e58-9a16-8c4e1d7b2a09
#   "Local Account Created or Added to Administrators"  (process_creation)
#
# Creates and deletes a local test user on the disposable runner.
$ErrorActionPreference = 'SilentlyContinue'
$user = 'rustinel_atomic_user'
& net.exe user $user 'P@ssw0rd-Atomic-123!' /add | Out-Null
Start-Sleep -Seconds 1
& net.exe user $user /delete | Out-Null
exit 0
