# ruff: noqa: E501
"""Positive/negative fixtures for the ps_module, ps_classic_start, Defender,
Application and WMI-Activity rules, plus the account-creation correlation shape.

Reuses the minimal Sigma evaluator from test_powershell_rules. The PowerShell
negative corpus includes Microsoft module manifests, which name the same cmdlets
as data without invoking them.
"""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml
from test_powershell_rules import RULES, _load, fires


def _binding(cmd: str, name: str, value: str) -> str:
    return (
        f'CommandInvocation({cmd}): "{cmd}"\n'
        f'ParameterBinding({cmd}): name="{name}"; value="{value}"'
    )


class DefenderTamperPsModuleTests(unittest.TestCase):
    det = _load("ps_module_win_susp_defender_tamper.yml")

    def check(self, payload: str, expected: bool) -> None:
        self.assertEqual(fires(self.det, {"Payload": payload}), expected, payload)

    def test_positive(self) -> None:
        self.check(_binding("Add-MpPreference", "ExclusionPath", r"C:\Temp"), True)
        self.check(_binding("Set-MpPreference", "ExclusionExtension", ".exe"), True)
        self.check(_binding("Add-MpPreference", "ExclusionProcess", "evil.exe"), True)
        self.check(_binding("Set-MpPreference", "DisableRealtimeMonitoring", "True"), True)
        self.check(_binding("Set-MpPreference", "DisableIOAVProtection", "1"), True)
        self.check(_binding("set-mppreference", "disablescriptscanning", "True"), True)

    def test_negative(self) -> None:
        for payload in (
            # Re-enabling protection, and unrelated Defender cmdlets.
            _binding("Set-MpPreference", "DisableRealtimeMonitoring", "False"),
            _binding("Set-MpPreference", "ScanScheduleDay", "3"),
            _binding("Get-MpPreference", "ExclusionPath", "x"),
            _binding("Remove-MpPreference", "ExclusionPath", r"C:\Temp"),
            # Microsoft module manifest: names listed, nothing invoked.
            "@{ RootModule = 'MSFT_MpPreference.cdxml'; ModuleVersion = '1.0'\n"
            "  FunctionsToExport = 'Add-MpPreference','Set-MpPreference','Remove-MpPreference'\n"
            "  CmdletsToExport = 'Get-MpComputerStatus' }",
            # Help text that quotes the parameter names.
            "Add-MpPreference -ExclusionPath adds a path. Set-MpPreference -DisableRealtimeMonitoring $true",
        ):
            self.check(payload, False)


class OffensiveCmdletPsModuleTests(unittest.TestCase):
    det = _load("ps_module_win_susp_offensive_cmdlet.yml")

    def check(self, payload: str, expected: bool) -> None:
        self.assertEqual(fires(self.det, {"Payload": payload}), expected, payload)

    def test_positive(self) -> None:
        for name in ("Invoke-Mimikatz", "Invoke-Kerberoast", "Get-GPPPassword", "invoke-dcsync"):
            self.check(f'CommandInvocation({name}): "{name}"', True)

    def test_negative(self) -> None:
        for payload in (
            'CommandInvocation(Get-Process): "Get-Process"',
            'ParameterBinding(Write-Output): name="InputObject"; value="Invoke-Mimikatz"',
            # Module manifests (PowerSploit-style and Microsoft) list names without invoking.
            "@{ ModuleVersion = '3.0.0.0'; GUID = 'x'\n"
            "  FunctionsToExport = @('Invoke-Mimikatz', 'Invoke-Kerberoast', 'Get-GPPPassword') }",
            "@{ ModuleVersion = '3.1.0.0'; HelpInfoUri = 'https://go.microsoft.com/fwlink/?linkid=1'\n"
            "  CmdletsToExport = 'Invoke-WebRequest','Invoke-RestMethod','Invoke-Expression' }",
            'CommandInvocation(Invoke-MimikatzHelper): "x"',
        ):
            self.check(payload, False)


class PowerShellV2Tests(unittest.TestCase):
    det = _load("ps_classic_start_win_powershell_v2_downgrade.yml")

    def test_cases(self) -> None:
        v2 = "NewEngineState=Available\nHostName=ConsoleHost\nHostVersion=5.1\nEngineVersion=2.0\nRunspaceId=x"
        v5 = v2.replace("EngineVersion=2.0", "EngineVersion=5.1.19041.1")
        self.assertTrue(fires(self.det, {"Data": v2}))
        self.assertFalse(fires(self.det, {"Data": v5}))


class DefenderChannelTests(unittest.TestCase):
    def test_realtime_disabled(self) -> None:
        det = _load("windefend_win_realtime_protection_disabled.yml")
        self.assertTrue(fires(det, {"EventID": 5001}))
        self.assertFalse(fires(det, {"EventID": 5000}))  # enabled

    def test_exclusion_added(self) -> None:
        det = _load("windefend_win_exclusion_added.yml")
        base = r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\%s\C:\Temp = 0x0"
        for kind in ("Paths", "Extensions", "Processes", "IpAddresses"):
            self.assertTrue(fires(det, {"EventID": 5007, "NewValue": base % kind}), kind)
        self.assertFalse(
            fires(det, {"EventID": 5007, "NewValue": r"HKLM\SOFTWARE\Microsoft\Windows Defender\Scan\AvgCPULoadFactor = 0x32"})
        )
        self.assertFalse(fires(det, {"EventID": 5008, "NewValue": base % "Paths"}))


class AuditCveTests(unittest.TestCase):
    det = _load("application_win_audit_cve.yml")

    def test_cases(self) -> None:
        self.assertTrue(fires(self.det, {"EventID": 1, "Provider_Name": "Microsoft-Windows-Audit-CVE"}))
        self.assertTrue(fires(self.det, {"EventID": 1, "Provider_Name": "Audit-CVE"}))
        self.assertFalse(fires(self.det, {"EventID": 1, "Provider_Name": "Application Error"}))
        self.assertFalse(fires(self.det, {"EventID": 2, "Provider_Name": "Audit-CVE"}))


class WmiBindingTests(unittest.TestCase):
    det = _load("wmi_win_permanent_consumer_binding.yml")

    def test_cases(self) -> None:
        self.assertTrue(fires(self.det, {"EventID": 5861, "ConsumerClass": "CommandLineEventConsumer"}))
        self.assertTrue(fires(self.det, {"EventID": 5861, "ConsumerClass": "ActiveScriptEventConsumer"}))
        self.assertFalse(fires(self.det, {"EventID": 5861, "ConsumerClass": "NTEventLogEventConsumer"}))
        self.assertFalse(fires(self.det, {"EventID": 5860, "ConsumerClass": "CommandLineEventConsumer"}))


class AccountCorrelationTests(unittest.TestCase):
    def test_references_and_grouping(self) -> None:
        corr = yaml.safe_load((RULES / "security_win_account_created_and_privileged.yml").read_text())["correlation"]
        ids = {yaml.safe_load(p.read_text()).get("id"): p.name for p in Path(RULES).glob("*.yml")}
        self.assertEqual(corr["type"], "temporal")
        self.assertEqual(corr["group-by"], ["SubjectLogonId"])
        for rid in corr["rules"]:
            self.assertIn(rid, ids)

    def test_base_rule(self) -> None:
        det = _load("security_win_hunting_user_account_created.yml")
        self.assertTrue(fires(det, {"EventID": 4720}))
        self.assertFalse(fires(det, {"EventID": 4722}))


if __name__ == "__main__":
    unittest.main()
