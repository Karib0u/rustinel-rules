"""Replay Windows AD, lockout and password-spray fixtures with the pinned engine."""

import argparse
from pathlib import Path

from advanced_negatives import lib
from windows_correlations import check_cases, without

DCSYNC = {
    "EventID": "4662",
    "Properties": "%%7688 {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}",
    "SubjectUserName": "directory_operator",
}
KERBEROAST = {
    "EventID": "4769",
    "TicketEncryptionType": "0x17",
    "Status": "0x0",
    "ServiceName": "svc_reports",
}
ASREP = {"EventID": "4768", "PreAuthType": "0", "Status": "0x0", "TargetUserName": "alice"}
SHADOW = {
    "EventID": "5136",
    "AttributeLDAPDisplayName": "msDS-KeyCredentialLink",
    "SubjectUserName": "directory_operator",
}
LOCKOUT = {"EventID": "4740", "TargetUserName": "alice"}
FAILED = {"EventID": "4625", "IpAddress": "192.0.2.10", "TargetUserName": "alice"}

# Advanced rule negatives are also read from rustinel.negatives by both checks.
SECURITY_CASES = {
    "security_win_dcsync_replication": [
        (DCSYNC, True),
        (DCSYNC | {"Properties": "%%7688\n{1131F6AD-9C07-11D1-F79F-00C04FC2DCD2}"}, True),
        (DCSYNC | {"Properties": "%%7688 {89e95b76-444d-4c62-991a-0facbeda640c}"}, True),
        (DCSYNC | {"SubjectUserName": "other_MSOL_123456"}, True),
        (DCSYNC | {"EventID": "4663"}, False),
    ],
    "security_win_kerberoasting_rc4": [
        (KERBEROAST, True),
        (KERBEROAST | {"EventID": "4768"}, False),
    ],
    "security_win_asrep_roasting": [(ASREP, True), (ASREP | {"EventID": "4771"}, False)],
    "security_win_shadow_credentials": [(SHADOW, True), (SHADOW | {"EventID": "5137"}, False)],
    "security_win_hunting_account_lockout": [
        (LOCKOUT, True),
        (LOCKOUT | {"EventID": "4625"}, False),
    ],
    "security_win_hunting_failed_logon": [
        (FAILED, True),
        (FAILED | {"IpAddress": "2001:db8::10"}, True),
        (FAILED | {"IpAddress": "::ffff:192.0.2.10"}, True),
        (FAILED | {"EventID": "4624"}, False),
        (FAILED | {"EventID": "4776"}, False),
        (without(FAILED, "IpAddress"), False),
        (without(FAILED, "TargetUserName"), False),
        (FAILED | {"TargetUserName": "-"}, False),
        (FAILED | {"TargetUserName": ""}, False),
        *[
            (FAILED | {"IpAddress": ip}, False)
            for ip in (
                "",
                "-",
                "not-an-ip",
                "127.0.0.2",
                "::1",
                "::ffff:127.0.0.2",
                "0.0.0.0",
                "::",
            )
        ],
    ],
}

LOCKOUT_CASES = [
    ("third lockout within one hour", [LOCKOUT, (1800, LOCKOUT), (3599, LOCKOUT)], 1),
    ("only two lockouts", [LOCKOUT, LOCKOUT], 0),
    ("different username", [LOCKOUT, LOCKOUT, LOCKOUT | {"TargetUserName": "bob"}], 0),
    ("missing username", [LOCKOUT, LOCKOUT, without(LOCKOUT, "TargetUserName")], 0),
    ("third lockout after one hour", [LOCKOUT, (1800, LOCKOUT), (3601, LOCKOUT)], 0),
]

USERS = [FAILED | {"TargetUserName": f"account-{i}"} for i in range(10)]
SPRAY_CASES = [
    ("ten distinct accounts in five minutes", [*USERS[:9], (299, USERS[9])], 1),
    ("nine distinct accounts", USERS[:9], 0),
    ("duplicate username is counted once", [*USERS[:9], USERS[0]], 0),
    ("separate source IP", [*USERS[:9], USERS[9] | {"IpAddress": "192.0.2.20"}], 0),
    ("loopback source IP", [event | {"IpAddress": "::ffff:127.0.0.2"} for event in USERS], 0),
    ("tenth failure after five minutes", [*USERS[:9], (301, USERS[9])], 0),
    ("tenth event is a successful logon", [*USERS[:9], USERS[9] | {"EventID": "4624"}], 0),
    ("tenth event has a placeholder username", [*USERS[:9], USERS[9] | {"TargetUserName": "-"}], 0),
]


def security_cases(rule, metadata):
    return SECURITY_CASES[rule] + [
        (entry["fields"], False) for entry in metadata.get("rustinel", {}).get("negatives", [])
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    engine = parser.parse_args().engine.resolve()
    rules = {artifact.path.stem: artifact for artifact in lib.load_all_artifacts()}
    for rule in SECURITY_CASES:
        artifact = rules[rule]
        cases = [
            (str(fields), [fields], int(fires))
            for fields, fires in security_cases(rule, artifact.meta)
        ]
        check_cases(engine, artifact, cases)
    check_cases(engine, rules["security_win_account_lockout_burst"], LOCKOUT_CASES)
    check_cases(engine, rules["security_win_password_spray_burst"], SPRAY_CASES)


if __name__ == "__main__":
    main()
