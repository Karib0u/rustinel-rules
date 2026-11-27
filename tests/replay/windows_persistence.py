"""Replay Windows persistence detections with normalized ETW events."""

import argparse
from pathlib import Path

from advanced_negatives import build_events, lib, replay

CLSID = r"CLSID\{12345678-1234-4234-8234-123456789abc}"
USER_CLASSES = rf"\REGISTRY\USER\S-1-5-21-111-222-333-1001_Classes\{CLSID}"
LSA = r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa"
APPINIT = r"Microsoft\Windows NT\CurrentVersion\Windows"
SERVICE = r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Fixture\ImagePath"
POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


def registry(target, details=None):
    fields = {"TargetObject": target}
    if details is not None:
        fields["Details"] = details
    return fields


def file_event(target, image=None):
    fields = {"TargetFilename": target}
    if image is not None:
        fields["Image"] = image
    return fields


POSITIVES = {
    "registry_set_win_user_com_server": [
        registry(USER_CLASSES + r"\InprocServer32", r"%LOCALAPPDATA%\Fixture\fixture.dll"),
        registry(USER_CLASSES + r"\InprocServer32", r"\\?\C:\Users\alice\fixture.dll"),
        registry(
            rf"HKCU\Software\Classes\{CLSID}\LocalServer32\(Default)",
            r'"D:\Users\alice\Local Server\fixture.exe" /Embedding',
        ),
        registry(
            rf"HKU\S-1-5-21-111-222-333-1001\Software\Classes\Wow6432Node\{CLSID}\LocalServer32",
            r'"C:\Program Files\Fixture\fixture.vbs"',
        ),
    ],
    "registry_set_win_lsa_package_registration": [
        registry(LSA + r"\SECURITY PACKAGES", "msv1_0\nFixturePackage"),
        registry(LSA + r"\OSConfig\Security Packages"),
        registry(
            r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages",
            "msv1_0\nFixturePackage",
        ),
        registry(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages",
            "scecli\nFixtureFilter",
        ),
    ],
    "registry_set_win_netsh_appinit_dll": [
        registry(r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\NetSh\Fixture", r"C:\Temp\fixture.dll"),
        registry(r"HKLM\SOFTWARE\Wow6432Node\Microsoft\NetSh\Fixture"),
        registry(rf"HKEY_LOCAL_MACHINE\SOFTWARE\{APPINIT}\AppInit_DLLs", r"C:\Temp\fixture.dll"),
        registry(
            rf"\REGISTRY\MACHINE\SOFTWARE\Wow6432Node\{APPINIT}\LoadAppInit_DLLs",
            "DWORD (0x00000001)",
        ),
    ],
    "registry_set_win_service_imagepath_user_writable": [
        registry(SERVICE, r'"D:\Users\alice\Service Tools\fixture.exe" --quiet'),
        registry(SERVICE, r"C:\Users\Public\fixture.exe"),
        registry(SERVICE, r"C:\Public\fixture.exe"),
        registry(SERVICE, r"C:\Temp\fixture.exe"),
        registry(SERVICE, r"%ProgramData%\Fixture\fixture.exe"),
        registry(SERVICE, r"%SystemDrive%\ProgramData\Fixture\fixture.exe"),
        registry(SERVICE, r"\SystemRoot\Temp\fixture.exe"),
        registry(SERVICE, r"\Device\HarddiskVolume3\tEmP\fixture.exe"),
        registry(SERVICE, r"\??\C:\Temp\fixture.sys"),
    ],
    "file_event_win_accessibility_binary_write": [
        *[
            file_event(rf"C:\Windows\System32\{name}.exe", POWERSHELL)
            for name in (
                "sethc",
                "utilman",
                "osk",
                "magnify",
                "narrator",
                "displayswitch",
                "atbroker",
            )
        ],
        file_event(r"\Device\HarddiskVolume2\WINDOWS\System32\SETHC.EXE"),
        file_event(r"\SystemRoot\System32\utilman.exe", r"C:\Temp\TrustedInstaller.exe"),
        file_event(r"C:\Windows\System32\osk.exe", r"C:\Windows\Temp\msiexec.exe"),
    ],
    "file_event_win_office_startup_drop": [
        file_event(
            r"C:\Users\alice\AppData\Roaming\Microsoft\Excel\XLSTART\PERSONAL.XLSB", POWERSHELL
        ),
        file_event(r"D:\Temp\fixture\XLSTART\fixture.xlam", POWERSHELL),
        file_event(
            r"C:\Program Files\Microsoft Office\root\Office16\XLSTART\fixture.xll", POWERSHELL
        ),
        file_event(
            r"C:\Users\alice\AppData\Roaming\Microsoft\Word\STARTUP\fixture.dotm", POWERSHELL
        ),
        file_event(
            r"C:\Program Files\Microsoft Office\root\Office16\STARTUP\fixture.wll", POWERSHELL
        ),
        file_event(r"C:\Users\alice\AppData\Roaming\Microsoft\Outlook\VbaProject.OTM", POWERSHELL),
    ],
}

EXTRA_NEGATIVES = {
    "registry_set_win_user_com_server": [
        registry(USER_CLASSES + r"\InprocServer32"),
        registry(USER_CLASSES + r"\InprocServer32\ThreadingModel", r"C:\Temp\fixture.dll"),
        registry(
            rf"HKCU\Software\Classes\{CLSID}\LocalServer32",
            r'"C:\Program Files\Fixture\fixture.exe" --log C:\Temp\fixture.log',
        ),
    ],
    "registry_set_win_lsa_package_registration": [
        registry(LSA + r"\OSConfig\Notification Packages", "FixturePackage"),
    ],
    "registry_set_win_netsh_appinit_dll": [
        registry(r"HKLM\SOFTWARE\Microsoft\NetSh"),
        registry(r"HKCU\SOFTWARE\Microsoft\NetSh\Fixture", "Fixture.dll"),
        registry(rf"HKLM\SOFTWARE\{APPINIT}\AppInit_DLLs", "  "),
        registry(rf"HKLM\SOFTWARE\{APPINIT}\LoadAppInit_DLLs"),
    ],
    "registry_set_win_service_imagepath_user_writable": [
        registry(SERVICE),
        registry(SERVICE, r"C:\Program Files\Vendor\Temp\fixture.exe"),
        registry(SERVICE, r"C:\UsersBackup\fixture.exe"),
        registry(
            r"HKCU\SYSTEM\CurrentControlSet\Services\Fixture\ImagePath", r"C:\Temp\fixture.exe"
        ),
    ],
    "file_event_win_accessibility_binary_write": [
        file_event(r"C:\Users\alice\Downloads\utilman.exe", POWERSHELL),
        file_event(
            r"C:\Windows\System32\atbroker.exe",
            r"C:\Windows\WinSxS\amd64_microsoft-windows-servicingstack_31bf3856ad364e35_"
            r"10.0.26100.1_none_1234567890abcdef\TiWorker.exe",
        ),
        file_event(r"C:\Windows\System32\narrator.exe", r"C:\Windows\SysWOW64\msiexec.exe"),
    ],
    "file_event_win_office_startup_drop": [
        file_event(r"C:\Temp\XLSTART\archive\fixture.xlam", POWERSHELL),
        file_event(r"C:\Temp\XLSTART-Backup\fixture.xlam", POWERSHELL),
        file_event(r"C:\Temp\STARTUP\fixture.dotm", POWERSHELL),
        file_event(r"C:\Temp\VbaProject.OTM", POWERSHELL),
    ],
}


def check_cases(engine, artifact, positives):
    name = artifact.path.stem
    events = build_events(
        artifact,
        [
            *({"fields": fields} for fields in positives),
            *artifact.meta["rustinel"]["negatives"],
            *({"fields": fields} for fields in EXTRA_NEGATIVES[name]),
        ],
    )
    expected = set(range(1, len(positives) + 1))
    sample = events[0]
    if sample["category"] == "Registry":
        variants = [(12, 36, False), (12, 38, False)]
    else:
        for event in events:
            event["opcode"] = 64
        variants = [(65, 65, True), (71, 71, True), (23, 70, False)]
    for event_id, opcode, match in variants:
        sequence = len(events) + 1
        events.append({**sample, "ingest_seq": sequence, "event_id": event_id, "opcode": opcode})
        if match:
            expected.add(sequence)

    alerts = replay(engine, artifact, events)
    actual = [(alert["rule.id"], alert["edr.event.ingest_seq"]) for alert in alerts]
    wanted = [(f"sigma::{artifact.id}", sequence) for sequence in sorted(expected)]
    if sorted(actual) != wanted:
        raise RuntimeError(f"{name}: expected alert sequences {wanted}, got {actual}")
    print(f"Passed {len(events)} replay cases for {name} ({len(expected)} alerts).")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    engine = parser.parse_args().engine.resolve()
    rules = {artifact.path.stem: artifact for artifact in lib.load_all_artifacts()}
    for name, positives in POSITIVES.items():
        check_cases(engine, rules[name], positives)


if __name__ == "__main__":
    main()
