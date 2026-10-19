"""Check that trusted-writer exclusions cannot be claimed by a lookalike path.

An exclusion that matches a basename or a path substring is satisfied by any
binary an attacker names `dpkg`, drops under `.../jamf/`, or copies to
`powershell.exe`. Each case replays one event against its own rule with the
real engine: the genuine trusted writer must stay silent, and the lookalike at
an untrusted path must alert.
"""

import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import advanced_negatives as base  # noqa: E402

import lib  # noqa: E402

PM = "/usr/bin/"
PS_DLL = r"C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Management.Automation\System.Management.Automation.ni.dll"  # noqa: E501
STARTUP = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\vendor.lnk"
JAMF = "/usr/local/jamf/bin/jamf"
BREW = "/opt/homebrew/Library/Homebrew/vendor/portable-ruby/3.4.5/bin/ruby"
CRON = "/etc/crontab"

# (rule file, event fields, whether it must alert)
CASES = []


def add(rule, field_sets):
    for fields, alerts in field_sets:
        CASES.append((rule, fields, alerts))


def linux_writer(rule, path):
    add(
        rule,
        [
            ({"Image": PM + "dpkg", "TargetFilename": path}, False),
            (
                {"Image": "/usr/sbin/pam-auth-update", "TargetFilename": path},
                not rule.endswith("pam_tamper.yml"),
            ),
            ({"Image": "/tmp/dpkg", "TargetFilename": path}, True),
            ({"Image": "/home/eve/rpm", "TargetFilename": path}, True),
            ({"Image": "/dev/shm/apt-get", "TargetFilename": path}, True),
        ],
    )


for name, path in [
    ("file_event_lnx_ssh_authorized_keys.yml", "/root/.ssh/authorized_keys"),
    ("file_event_lnx_sudoers_tamper.yml", "/etc/sudoers.d/90-x"),
    ("file_event_lnx_sshd_config_tamper.yml", "/etc/ssh/sshd_config"),
    ("file_event_lnx_udev_persistence.yml", "/etc/udev/rules.d/90-x.rules"),
    ("file_event_lnx_pam_tamper.yml", "/etc/pam.d/sshd"),
]:
    linux_writer(name, path)
for name, target in [
    ("file_event_lnx_cron_persistence.yml", "/var/lib/docker/overlay2/x/etc/crontab"),
    (
        "file_event_lnx_systemd_persistence.yml",
        "/var/lib/docker/overlay2/x/etc/systemd/system/a.service",
    ),
    ("file_event_lnx_shell_profile_persistence.yml", "/var/lib/docker/overlay2/x/root/.bashrc"),
]:
    add(
        name,
        [
            ({"Image": "/usr/bin/dockerd", "TargetFilename": target}, False),
            ({"Image": "/tmp/dockerd", "TargetFilename": target}, True),
        ],
    )

MAC_HOME = "/Users/alice/"
for name, target in [
    ("file_event_macos_ssh_authorized_keys.yml", MAC_HOME + ".ssh/authorized_keys"),
    ("file_event_macos_launch_persistence.yml", MAC_HOME + "Library/LaunchAgents/com.x.plist"),
    (
        "file_event_macos_authorization_plugin.yml",
        "/Library/Security/SecurityAgentPlugins/x.bundle/y",
    ),
]:
    add(
        name,
        [
            ({"Image": JAMF, "TargetFilename": target}, False),
            ({"Image": "/tmp/jamf", "TargetFilename": target}, True),
            ({"Image": MAC_HOME + "Downloads/jamf/payload", "TargetFilename": target}, True),
        ],
    )
# Homebrew's Ruby is trusted on the rules that name it.
for name, target in [
    ("file_event_macos_ssh_authorized_keys.yml", MAC_HOME + ".ssh/authorized_keys"),
    ("file_event_macos_launch_persistence.yml", MAC_HOME + "Library/LaunchAgents/com.x.plist"),
]:
    add(
        name,
        [
            ({"Image": BREW, "TargetFilename": target}, False),
            ({"Image": "/tmp/Library/Homebrew/ruby", "TargetFilename": target}, True),
        ],
    )
add(
    "file_event_macos_shell_profile_scripted.yml",
    [
        ({"Image": "/usr/local/jamf/bin/bash", "TargetFilename": MAC_HOME + ".zshrc"}, False),
        ({"Image": BREW, "TargetFilename": MAC_HOME + ".zshrc"}, False),
        ({"Image": "/tmp/jamf/bash", "TargetFilename": MAC_HOME + ".zshrc"}, True),
        ({"Image": "/tmp/Library/Homebrew/bash", "TargetFilename": MAC_HOME + ".zshrc"}, True),
    ],
)
add(
    "proc_creation_macos_quarantine_attribute_removed.yml",
    [
        (
            {
                "Image": "/usr/bin/xattr",
                "CommandLine": "xattr -cr /Applications/App.app",
                "ParentImage": "/usr/local/jamf/bin/jamf",
            },
            False,
        ),
        (
            {
                "Image": "/usr/bin/xattr",
                "CommandLine": "xattr -cr /Applications/App.app",
                "ParentImage": "/tmp/jamf",
            },
            True,
        ),
        (
            {
                "Image": "/usr/bin/xattr",
                "CommandLine": "xattr -cr /Applications/App.app",
                "ParentImage": "/tmp/Kandji",
            },
            True,
        ),
    ],
)
add(
    "image_load_win_susp_automation_dll.yml",
    [
        (
            {
                "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "ImageLoaded": PS_DLL,
            },
            False,
        ),
        ({"Image": r"C:\Users\eve\AppData\Local\Temp\powershell.exe", "ImageLoaded": PS_DLL}, True),
        ({"Image": r"C:\Users\Public\wsmprovhost.exe", "ImageLoaded": PS_DLL}, True),
    ],
)
add(
    "file_event_win_startup_folder_drop.yml",
    [
        ({"Image": r"C:\Windows\System32\msiexec.exe", "TargetFilename": STARTUP}, False),
        ({"Image": r"C:\Users\eve\Downloads\msiexec.exe", "TargetFilename": STARTUP}, True),
    ],
)
RCLONE = r"C:\Tools\rclone.exe"
add(
    "proc_creation_win_susp_rclone_exfil.yml",
    [
        ({"Image": RCLONE, "CommandLine": r"rclone.exe copy C:\data remote:bucket"}, True),
        (
            {"Image": RCLONE, "CommandLine": r"rclone.exe copy C:\data mega:backup --transfers 16"},
            True,
        ),
        (
            {"Image": RCLONE, "CommandLine": r"rclone.exe sync C:\data :s3,provider=AWS:bucket"},
            True,
        ),
        (
            {"Image": RCLONE, "CommandLine": r"rclone.exe copy C:\data D:\x --config C:\r.conf"},
            True,
        ),
        ({"Image": RCLONE, "CommandLine": r"rclone.exe move C:\a b --auto-confirm"}, True),
        ({"Image": RCLONE, "CommandLine": r"rclone.exe copy C:\a D:\b --transfers 8"}, False),
        ({"Image": RCLONE, "CommandLine": r"rclone.exe sync C:\a \\nas\share\b"}, False),
        ({"Image": RCLONE, "CommandLine": "rclone.exe listremotes"}, False),
    ],
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    args = parser.parse_args()
    engine = args.engine.resolve()
    artifacts = {a.path.name: a for a in lib.load_all_artifacts() if a.path.suffix == ".yml"}
    grouped = {}
    for rule, fields, alerts in CASES:
        grouped.setdefault(rule, []).append((fields, alerts))
    failures = []
    for rule, cases in grouped.items():
        artifact = artifacts[rule]
        events = base.build_events(artifact, [{"fields": fields} for fields, _ in cases])
        title = artifact.meta["title"]
        fired = {
            int(a["process.pid"])
            for a in base.replay(engine, artifact, events)
            if a["rule.name"] == title
        }
        for index, (fields, alerts) in enumerate(cases, 1):
            if (index in fired) != alerts:
                want = "alert" if alerts else "stay silent"
                failures.append(f"{rule}: expected to {want}: {fields}")
    if failures:
        raise RuntimeError("\n".join(failures))
    print(f"Passed {len(CASES)} lookalike-exclusion cases across {len(grouped)} rules.")


if __name__ == "__main__":
    main()
