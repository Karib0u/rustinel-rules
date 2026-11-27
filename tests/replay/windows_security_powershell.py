"""Replay Windows Security, PowerShell, and privilege-escalation detection fixtures."""

import argparse
from pathlib import Path

from advanced_negatives import build_events, lib, replay
from windows_correlations import check_cases, without

CMD = r"C:\Windows\System32\cmd.exe"
PIPE = r"\\.\pipe\rustinel-replay"
RBCD = {
    "EventID": "5136",
    "AttributeLDAPDisplayName": "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "ObjectClass": "computer",
    "ObjectDN": "CN=APP01,OU=Servers,DC=example,DC=test",
    "SubjectUserName": "directory_operator",
    "OperationType": "%%14674",
}
SYSTEM_SHELL = {
    "Image": CMD,
    "ParentUser": r"IIS APPPOOL\DefaultAppPool",
    "User": r"NT AUTHORITY\SYSTEM",
}
HISTORY = (
    r"C:\Users\Alice\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine"
    r"\ConsoleHost_history.txt"
)

# These strings are recorded event fields. Replay does not execute them.
SCRIPT_CASES = [
    ("Invoke-Mimikatz call", "Invoke-Mimikatz", True),
    ("scoped function definition", "\nfunction script:Invoke-Mimikatz { }", True),
    ("quoted cmdlet behind call operator", "& 'Invoke-Mimikatz'", True),
    ("Kerberoast call after a separator", "Get-Date; INVOKE-KERBEROAST", True),
    ("minidump pipeline", "Get-Process | Out-Minidump", True),
    ("GPP function", "Get-GPPPassword", True),
    ("BloodHound collector", "Invoke-BloodHound", True),
    ("SharpHound function", "Invoke-SharpHound", True),
    ("SharpHound native collector", r"& 'C:\Lab\SharpHound.exe'", True),
    ("SharpHound script", r". .\SharpHound.ps1", True),
    ("sekurlsa namespace", "$sample = 'SeKuRlSa::fixture'", True),
    ("namespace stored without a suffix", "$sample = 'sekurlsa::'", True),
    ("lsadump namespace", "$sample = 'lsadump::fixture'", True),
    ("cmdlet name as an argument", "Write-Output 'Invoke-Kerberoast'", False),
    ("documentation mentions a cmdlet", "# Get-GPPPassword is listed in the review", False),
    ("similarly named cmdlet", "Get-GPPPasswordReport", False),
    ("ordinary namespace string", "$sample = 'reflection::fixture'", False),
]

MODULE_CASES = [
    ("original marker", 'CommandInvocation(Invoke-Mimikatz): "Invoke-Mimikatz"', True),
    ("Kerberoast invocation", 'CommandInvocation(Invoke-Kerberoast): "Invoke-Kerberoast"', True),
    ("GPP password invocation", 'CommandInvocation(Get-GPPPassword): "Get-GPPPassword"', True),
    (
        "minidump invocation after another cmdlet",
        'CommandInvocation(Get-Process): "Get-Process"\r\n'
        'CommandInvocation(Out-Minidump): "Out-Minidump"',
        True,
    ),
    ("BloodHound invocation", 'CommandInvocation(Invoke-BloodHound): "Invoke-BloodHound"', True),
    ("SharpHound invocation", 'CommandInvocation(Invoke-SharpHound): "Invoke-SharpHound"', True),
    (
        "Microsoft manifest cmdlets are parameters",
        'ParameterBinding(Import-Module): name="Name"; value="Microsoft.PowerShell.Utility"',
        False,
    ),
    (
        "collector name in help",
        'ParameterBinding(Get-Help): name="Name"; value="Invoke-BloodHound"',
        False,
    ),
]

PIPE_CASES = [
    ("bare cmd, tightly spaced redirect", f"cmd /c echo check>{PIPE}", True),
    ("quoted executable and command", f'"{CMD}" /D /S /C "echo check > {PIPE}"', True),
    ("quoted pipe path", f'cmd.exe /q /c echo "check" > "{PIPE}"', True),
    ("case-insensitive pipe prefix", f"cmd /C ECHO check > {PIPE.upper()}", True),
    ("pipe on a remote host", r"cmd /c echo check > \\server\pipe\rustinel-replay", False),
    ("escaped redirect", f"cmd /c echo check ^> {PIPE}", False),
    ("pipe path in another command", f"cmd /c type fixture.txt > {PIPE}", False),
    (
        "redirect belongs to a later command",
        f"cmd /c echo check & type fixture.txt > {PIPE}",
        False,
    ),
    ("echo is an argument to a script", f"cmd /c fixture.cmd echo check > {PIPE}", False),
    (
        "a path ending in cmd in the arguments is data",
        rf"cmd /c verify C:\fixture\cmd.exe /c echo check > {PIPE}",
        False,
    ),
    ("missing pipe name", "cmd /c echo check > \\\\.\\pipe\\", False),
]

CASES = {
    "ps_script_win_credential_tool_markers": [
        (name, [{"ScriptBlockText": script}], int(fires)) for name, script, fires in SCRIPT_CASES
    ],
    "ps_module_win_susp_offensive_cmdlet": [
        (name, [{"Payload": payload}], int(fires)) for name, payload, fires in MODULE_CASES
    ],
    "security_win_rbcd_attribute_modified": [
        ("delegation value added", [RBCD], 1),
        ("delegation value removed", [RBCD | {"OperationType": "%%14675"}], 1),
        ("machine account modifies delegation", [RBCD | {"SubjectUserName": "WS01$"}], 1),
        (
            "attribute casing differs",
            [RBCD | {"AttributeLDAPDisplayName": RBCD["AttributeLDAPDisplayName"].upper()}],
            1,
        ),
        ("different event ID", [RBCD | {"EventID": "5137"}], 0),
        ("attribute unavailable", [without(RBCD, "AttributeLDAPDisplayName")], 0),
        (
            "attribute prefix lookalike",
            [RBCD | {"AttributeLDAPDisplayName": RBCD["AttributeLDAPDisplayName"] + "Backup"}],
            0,
        ),
    ],
    "proc_creation_win_named_pipe_echo": [
        *(
            (name, [{"Image": CMD, "CommandLine": command}], int(fires))
            for name, command, fires in PIPE_CASES
        ),
        (
            "pipe command appears on a different executable",
            [{"Image": r"C:\Temp\other.exe", "CommandLine": f"cmd /c echo check > {PIPE}"}],
            0,
        ),
        ("missing command line", [{"Image": CMD}], 0),
    ],
    "service_creation_win_susp_service_binary": [
        (
            "System 7045 service starts a shell with a named-pipe redirect",
            [{"ServiceFileName": f"{CMD} /c echo check > {PIPE}"}],
            1,
        ),
    ],
    "security_win_service_installed_susp_binary": [
        (
            "Security 4697 service invokes COMSPEC with a named-pipe redirect",
            [{"EventID": "4697", "ServiceFileName": f"%COMSPEC% /c echo check > {PIPE}"}],
            1,
        ),
    ],
    "proc_creation_win_service_account_system_shell": [
        ("IIS app-pool parent", [SYSTEM_SHELL], 1),
        ("named SQL Server instance", [SYSTEM_SHELL | {"ParentUser": r"nt service\MSSQL$APP"}], 1),
        ("Local Service", [SYSTEM_SHELL | {"ParentUser": "LOCAL SERVICE"}], 1),
        (
            "Network Service launches PowerShell",
            [
                SYSTEM_SHELL
                | {
                    "ParentUser": r"NT AUTHORITY\NETWORK SERVICE",
                    "Image": r"C:\Program Files\PowerShell\7\pwsh.exe",
                }
            ],
            1,
        ),
        (
            "identities returned as SIDs",
            [SYSTEM_SHELL | {"ParentUser": "S-1-5-20", "User": "S-1-5-18"}],
            1,
        ),
        ("domain account named SYSTEM", [SYSTEM_SHELL | {"User": r"EXAMPLE\SYSTEM"}], 0),
        (
            "parent is a domain service account",
            [SYSTEM_SHELL | {"ParentUser": r"EXAMPLE\MSSQL"}],
            0,
        ),
        ("parent account missing", [without(SYSTEM_SHELL, "ParentUser")], 0),
        ("child account missing", [without(SYSTEM_SHELL, "User")], 0),
    ],
    "file_delete_win_powershell_history": [
        ("default console history", [{"TargetFilename": HISTORY}], 1),
        (
            "redirected profile with different casing",
            [{"TargetFilename": r"D:\Users\Alice\CONSOLEHOST_HISTORY.TXT"}],
            1,
        ),
        ("no filename", [{"Image": CMD}], 0),
    ],
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, type=Path)
    engine = parser.parse_args().engine.resolve()
    rules = {artifact.path.stem: artifact for artifact in lib.load_all_artifacts()}
    for rule, cases in CASES.items():
        artifact = rules[rule]
        negatives = [
            (entry["reason"], [entry["fields"]], 0)
            for entry in artifact.meta["rustinel"]["negatives"]
        ]
        check_cases(engine, artifact, cases + negatives)

    # Ordinary PSReadLine writes and renames can carry exactly the same filename.
    history = rules["file_delete_win_powershell_history"]
    events = build_events(history, [{"fields": {"TargetFilename": HISTORY}}] * 2)
    for event, event_id in zip(events, (11, 71), strict=True):
        event["event_id"] = event_id
    if replay(engine, history, events):
        raise RuntimeError("Ordinary console-history file creation or rename alerted.")
    print("Passed 2 PowerShell history replay cases for non-deletion file events.")


if __name__ == "__main__":
    main()
