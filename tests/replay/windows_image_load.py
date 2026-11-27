"""Replay the Windows driver and DLL rules on normalized ETW events.

Live recordings omit deferred Authenticode results. The synthetic verdicts
below exercise how the real engine matches those fields when supplied, and
the missing-field cases model an inconclusive verification.
"""

import argparse
from pathlib import Path

from advanced_negatives import build_events, lib, replay

DRIVER_PATH = "driver_load_win_susp_user_writable_path"
DRIVER_SIGNATURE = "driver_load_win_unsigned_or_invalid_signature"
DRIVER_NAME = "driver_load_win_loldrivers_names"
DLL_SIDELOAD = "image_load_win_susp_unsigned_sideload_dll"
DLL_HUNTING = "image_load_win_hunting_unsigned_dll_userwritable"

DRIVERS = r"C:\Windows\System32\drivers"
DRIVER = {"ImageLoaded": DRIVERS + r"\lab.sys"}
UNSIGNED = {"Signed": "false", "SignatureStatus": "Unavailable"}
VALID = {"Signed": "true", "SignatureStatus": "Valid"}

BYOVD_NAMES = (
    "RTCore64.sys",
    "RTCore32.sys",
    "DBUtil_2_3.sys",
    "dbutildrv2.sys",
    "AsIO64.sys",
    "AsIO32.sys",
    "gdrv.sys",
    "iqvw64e.sys",
    "procexp152.sys",
    "zam64.sys",
    "zamguard64.sys",
    "TrueSight.sys",
    "WinRing0x64.sys",
    "WinRing0.sys",
    "ene.sys",
    "MsIo64.sys",
    "GLCKIo2.sys",
    "ATSZIO64.sys",
    "ProcessHacker.sys",
    "KProcessHacker.sys",
)
SIDELOAD_NAMES = (
    "version.dll",
    "dbghelp.dll",
    "wtsapi32.dll",
    "cryptsp.dll",
    "profapi.dll",
    "uxtheme.dll",
    "dwmapi.dll",
    "netapi32.dll",
    "userenv.dll",
    "winmm.dll",
    "dwrite.dll",
)


CASES = {
    DRIVER_PATH: [
        ({"ImageLoaded": r"D:\uSeRs\Public\lab.sys"}, True),
        ({"ImageLoaded": r"C:\ProgramData\Setup\lab.sys"}, True),
        ({"ImageLoaded": r"C:\Temp\lab.sys"}, True),
        ({"ImageLoaded": r"\Device\HarddiskVolume12\WiNdOwS\TeMp\lab.sys"}, True),
        ({"ImageLoaded": r"\SystemRoot\Temp\lab.sys"}, True),
        ({"ImageLoaded": r"C:\Program Files\Vendor\Temp\lab.sys"}, False),
        ({"ImageLoaded": r"C:\UsersBackup\Public\lab.sys"}, False),
        ({"ImageLoaded": r"C:\Windows\TempBackup\lab.sys"}, False),
        ({"ImageLoaded": r"\Device\HarddiskVolume12x\Temp\lab.sys"}, False),
        ({"ImageLoaded": r"C:Temp\lab.sys"}, False),
        ({"Image": r"C:\Users\Public\installer.exe"}, False),
        (DRIVER, False),
    ],
    DRIVER_SIGNATURE: [
        (DRIVER | UNSIGNED, True),
        (DRIVER | {"Signed": "false"}, True),
        *[
            (DRIVER | {"Signed": "true", "SignatureStatus": status}, True)
            for status in ("Expired", "Revoked", "Invalid")
        ],
        (DRIVER | VALID, False),
        (DRIVER, False),
        (DRIVER | {"SignatureStatus": "Unavailable"}, False),
        (DRIVER | {"SignatureStatus": "Invalidated"}, False),
    ],
    DRIVER_NAME: [
        *[({"ImageLoaded": f"{DRIVERS}\\{name.upper()}"}, True) for name in BYOVD_NAMES],
        ({"ImageLoaded": r"\Device\HarddiskVolume2\OEM\rtcore64.sys"}, True),
        ({"ImageLoaded": f"{DRIVERS}\\acme-RTCore64.sys"}, False),
        ({"ImageLoaded": f"{DRIVERS}\\RTCore64.sys.bak"}, False),
        ({"ImageLoaded": f"{DRIVERS}\\RTCore64.sys\\lab.sys"}, False),
        (DRIVER | {"OriginalFileName": "RTCore64.sys"}, False),
    ],
    DLL_SIDELOAD: [
        *[
            (UNSIGNED | {"ImageLoaded": rf"C:\Users\alice\Downloads\{name.upper()}"}, True)
            for name in SIDELOAD_NAMES
        ],
        (UNSIGNED | {"ImageLoaded": r"C:\ProgramData\Tools\version.dll"}, True),
        (UNSIGNED | {"ImageLoaded": r"C:\Temp\dbghelp.dll"}, True),
        (UNSIGNED | {"ImageLoaded": r"D:\Profiles\alice\AppData\Local\winmm.dll"}, True),
        (UNSIGNED | {"ImageLoaded": r"\Device\HarddiskVolume4\Temp\dwrite.dll"}, True),
        (VALID | {"ImageLoaded": r"C:\Temp\version.dll"}, False),
        (
            {"Signed": "true", "SignatureStatus": "Invalid", "ImageLoaded": r"C:\Temp\version.dll"},
            False,
        ),
        ({"ImageLoaded": r"C:\Temp\version.dll"}, False),
        (UNSIGNED | {"ImageLoaded": r"C:\Windows\System32\version.dll"}, False),
        (UNSIGNED | {"ImageLoaded": r"C:\ProgramDataBackup\version.dll"}, False),
        (UNSIGNED | {"ImageLoaded": r"C:\Temp\app-version.dll"}, False),
        (UNSIGNED | {"ImageLoaded": r"C:\Temp\version.dll.old"}, False),
        (UNSIGNED | {"Image": r"C:\Temp\version.dll"}, False),
    ],
    DLL_HUNTING: [
        (UNSIGNED | {"ImageLoaded": r"C:\Users\alice\Downloads\helper.dll"}, True),
        (UNSIGNED | {"ImageLoaded": r"C:\ProgramData\App\helper.dll"}, True),
        (UNSIGNED | {"ImageLoaded": r"\Device\HarddiskVolume4\tEmP\HELPER.DLL"}, True),
        (UNSIGNED | {"ImageLoaded": r"D:\Profiles\alice\AppData\Local\helper.dll"}, True),
        (UNSIGNED | {"ImageLoaded": r"C:\Temp\helper.exe"}, False),
        (UNSIGNED | {"ImageLoaded": r"C:\Windows\System32\helper.dll"}, False),
        (UNSIGNED | {"ImageLoaded": r"D:\Profiles\alice\AppDataBackup\helper.dll"}, False),
        (VALID | {"ImageLoaded": r"C:\Temp\helper.dll"}, False),
        ({"ImageLoaded": r"C:\Temp\helper.dll"}, False),
    ],
}


def check_cases(engine, artifact, cases):
    events = build_events(artifact, [{"fields": fields} for fields, _ in cases])
    expected = {i for i, (_, match) in enumerate(cases, 1) if match}

    # With the same positive fields, the other load category must stay silent.
    positives = [event for event in events if event["ingest_seq"] in expected]
    for event in positives:
        category, event_id = (
            ("ImageLoad", 7) if event["category"] == "DriverLoad" else ("DriverLoad", 6)
        )
        events.append(
            {
                **event,
                "category": category,
                "event_id": event_id,
                "fields": dict(event["fields"]),
                "ingest_seq": len(events) + 1,
            }
        )

    for event in events:
        event["fields"]["ProcessId"] = "4" if event["category"] == "DriverLoad" else "6340"

    alerts = replay(engine, artifact, events)
    actual = {alert["edr.event.ingest_seq"] for alert in alerts}
    rule_id = f"sigma::{artifact.id}"
    if (
        actual != expected
        or len(alerts) != len(expected)
        or any(alert["rule.id"] != rule_id for alert in alerts)
    ):
        missing = [events[i - 1] for i in sorted(expected - actual)]
        unexpected = [events[i - 1] for i in sorted(actual - expected)]
        raise RuntimeError(
            f"{artifact.path.name}: expected {len(expected)} alerts, got {len(alerts)}. "
            f"Missing: {missing}. Unexpected: {unexpected}."
        )
    print(f"Passed {len(events)} replay cases for {artifact.path.stem} ({len(expected)} alerts).")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    engine = parser.parse_args().engine.resolve()
    rules = {artifact.path.stem: artifact for artifact in lib.load_all_artifacts()}
    for name, cases in CASES.items():
        check_cases(engine, rules[name], cases)


if __name__ == "__main__":
    main()
