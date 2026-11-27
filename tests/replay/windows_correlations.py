"""Replay Windows correlation positives and near misses with the real engine."""

import argparse
from datetime import UTC, datetime, timedelta
from pathlib import Path

from advanced_negatives import build_events, lib, replay

START = datetime(2026, 11, 27, 8, tzinfo=UTC)
DOMAIN = "S-1-5-21-1004336348-1177238915-682003330"
ACCOUNT = f"{DOMAIN}-1005"
CREATED = {"EventID": "4720", "TargetSid": ACCOUNT, "SubjectLogonId": "0x100"}
ADDED = {
    "EventID": "4732",
    "TargetSid": "S-1-5-32-544",
    "MemberSid": ACCOUNT,
    "SubjectLogonId": "0x100",
}

PARENT = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
SYSTEM32 = "C:\\Windows\\System32\\"
SHADOW = {
    "Image": SYSTEM32 + "vssadmin.exe",
    "CommandLine": "vssadmin.exe delete shadows",
    "ParentImage": PARENT,
}
BOOT = {
    "Image": SYSTEM32 + "bcdedit.exe",
    "CommandLine": "bcdedit.exe /set recoveryenabled off",
    "ParentImage": PARENT,
}
SERVICE = {
    "Image": SYSTEM32 + "sc.exe",
    "CommandLine": "sc.exe stop Sysmon",
    "ParentImage": PARENT,
}


def without(fields, field):
    return {k: v for k, v in fields.items() if k != field}


# (case, events at successive seconds unless timed explicitly, correlation alert count)
ACCOUNT_CASES = [
    ("local member added", [CREATED, ADDED], 1),
    (
        "global member added",
        [CREATED, ADDED | {"EventID": "4728", "TargetSid": f"{DOMAIN}-512"}],
        1,
    ),
    (
        "universal member added",
        [CREATED, ADDED | {"EventID": "4756", "TargetSid": f"{DOMAIN}-519"}],
        1,
    ),
    ("unrelated member added", [CREATED, ADDED | {"MemberSid": f"{DOMAIN}-1006"}], 0),
    ("another logon session", [CREATED, ADDED | {"SubjectLogonId": "0x101"}], 0),
    ("membership before creation", [ADDED, CREATED], 0),
    ("created account SID missing", [without(CREATED, "TargetSid"), ADDED], 0),
    ("added member SID missing", [CREATED, without(ADDED, "MemberSid")], 0),
    ("both account SIDs missing", [without(CREATED, "TargetSid"), without(ADDED, "MemberSid")], 0),
    ("membership after window", [CREATED, (601, ADDED)], 0),
]

RECOVERY_CASES = [
    ("all three signals in any order", [SERVICE, SHADOW, (599, BOOT)], 1),
    ("only two distinct signals", [SHADOW, BOOT, SHADOW], 0),
    ("different parent image", [SHADOW, BOOT, SERVICE | {"ParentImage": SYSTEM32 + "cmd.exe"}], 0),
    ("parent images missing", [without(f, "ParentImage") for f in [SHADOW, BOOT, SERVICE]], 0),
    ("last signal after window", [SHADOW, BOOT, (601, SERVICE)], 0),
]


def check_cases(engine, artifact, cases):
    title = artifact.meta["title"]
    for name, samples, expected in cases:
        timed = [
            sample if isinstance(sample, tuple) else (i, sample) for i, sample in enumerate(samples)
        ]
        events = build_events(artifact, [{"fields": fields} for _, fields in timed])
        for event, (seconds, _) in zip(events, timed, strict=True):
            event["event_time"] = (START + timedelta(seconds=seconds)).isoformat()
        alerts = replay(engine, artifact, events)
        fired = sum(alert["rule.name"] == title for alert in alerts)
        if fired != expected:
            raise RuntimeError(f"{title}, {name}: expected {expected} alerts, got {fired}")
    print(f"Passed {len(cases)} replay cases for {title}.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    engine = parser.parse_args().engine.resolve()
    rules = {artifact.path.stem: artifact for artifact in lib.load_all_artifacts()}
    check_cases(engine, rules["security_win_account_created_and_privileged"], ACCOUNT_CASES)
    check_cases(engine, rules["proc_creation_win_ransomware_recovery_inhibition"], RECOVERY_CASES)


if __name__ == "__main__":
    main()
