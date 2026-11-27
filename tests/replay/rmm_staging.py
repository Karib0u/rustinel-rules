"""Replay staged remote management launches and benign lookalikes."""

import argparse
from pathlib import Path

import advanced_negatives as base

import lib

# Positive Image paths by rule filename. Each rule supplies its own benign controls.
POSITIVES = {
    "proc_creation_win_hunting_rmm_staging_path.yml": [
        r"C:\Users\Alice\Downloads\AnyDesk.exe",
        r"C:\Users\Alice\AppData\Local\Temp\ANYDESK-acme.EXE",
        r"C:\ProgramData\ScreenConnect Client (12)\ScreenConnect.ClientService.exe",
        r"D:\Downloads\ScreenConnect.WindowsClient.exe",
        r"C:\Windows\SystemTemp\ScreenConnect.ClientSetup (6).exe",
        r"C:\Temp\AteraAgent.exe",
        r"\Device\HarddiskVolume3\Temp\Splashtop_Streamer_Windows.exe",
        r"C:\Temp\RustDesk-1.4.6-x86_64.exe",
        r"C:\ProgramData\MeshAgent64.exe",
        r"\SystemRoot\Temp\SimpleHelpCustomer.exe",
        r"C:\Users\Alice\Downloads\TeamViewerQS.exe",
    ],
    "proc_creation_lnx_rmm_staging_path.yml": [
        "/tmp/anydesk",
        "/var/tmp/ateraagent",
        "/dev/shm/srserver",
        "/home/alice/Downloads/rustdesk-1.4.6-x86_64.AppImage",
        "/tmp/meshagent",
        "/var/tmp/simplehelp",
        "/home/alice/teamviewer",
        "/home/rustinel-atomic-rmm.fixture/rustdesk",
    ],
    "proc_creation_macos_rmm_staging_path.yml": [
        "/tmp/AnyDesk.app/Contents/MacOS/AnyDesk",
        "/private/tmp/fixture/TeamViewer",
        "/private/var/tmp/meshagent",
        "/Users/Shared/Splashtop Streamer.app/Contents/MacOS/Splashtop Streamer",
        "/Users/Alice/Downloads/RustDesk.app/Contents/MacOS/RustDesk",
        "/Downloads/Remote Access.app/Contents/MacOS/osxwrapper",
        "/Users/Alice/Downloads/ScreenConnect.app/Contents/MacOS/ScreenConnect",
        "/Users/Shared/AteraAgent",
    ],
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    engine = parser.parse_args().engine.resolve()
    rules = {artifact.path.name: artifact for artifact in lib.load_all_artifacts()}
    for filename, images in POSITIVES.items():
        rule = rules[filename]
        title = rule.meta["title"]
        cases = [{"fields": {"Image": image}} for image in images]
        cases.extend(rule.meta["rustinel"]["negatives"])
        alerts = base.replay(engine, rule, base.build_events(rule, cases))
        actual = [(int(alert["process.pid"]), alert["rule.name"]) for alert in alerts]
        expected = [(pid, title) for pid in range(1, len(images) + 1)]
        if actual != expected:
            raise RuntimeError(f"{filename}: expected {expected}, got {actual}")
        print(f"Passed {len(images)} positive and {len(cases) - len(images)} benign cases: {title}")


if __name__ == "__main__":
    main()
