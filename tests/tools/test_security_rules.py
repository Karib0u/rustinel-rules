"""Positive/negative fixtures for the Windows Security-channel rules.

Reuses the minimal Sigma evaluator from test_powershell_rules. Each case is a
Security event reduced to the fields the rule selects on.
"""

from __future__ import annotations

import unittest

from test_powershell_rules import _load, fires


class SecurityRuleCase(unittest.TestCase):
    rule = ""

    def check(self, event: dict, expected: bool) -> None:
        if not self.rule:
            self.skipTest("abstract")
        det = _load(self.rule)
        self.assertEqual(fires(det, event), expected, event)


class LogClearedTests(SecurityRuleCase):
    rule = "security_win_audit_log_cleared.yml"

    def test_cases(self) -> None:
        self.check({"EventID": 1102}, True)
        self.check({"EventID": 4719}, False)


class AuditPolicyTests(SecurityRuleCase):
    rule = "security_win_audit_policy_disabled.yml"

    def test_cases(self) -> None:
        self.check({"EventID": 4719, "AuditPolicyChanges": "%%8448"}, True)  # success removed
        self.check({"EventID": 4719, "AuditPolicyChanges": "%%8450, %%8449"}, True)  # failure removed
        self.check({"EventID": 4719, "AuditPolicyChanges": "%%8449"}, False)  # success added
        self.check({"EventID": 4719, "AuditPolicyChanges": "%%8451"}, False)  # failure added
        self.check({"EventID": 4720, "AuditPolicyChanges": "%%8448"}, False)


class PrivilegedGroupTests(SecurityRuleCase):
    rule = "security_win_privileged_group_member_added.yml"
    dom = "S-1-5-21-1004336348-1177238915-682003330"

    def test_cases(self) -> None:
        self.check({"EventID": 4732, "TargetSid": "S-1-5-32-544"}, True)
        self.check({"EventID": 4732, "TargetSid": "S-1-5-32-545"}, False)  # Users
        self.check({"EventID": 4732, "TargetSid": "S-1-5-32-555"}, False)  # Remote Desktop Users
        self.check({"EventID": 4728, "TargetSid": f"{self.dom}-512"}, True)
        self.check({"EventID": 4756, "TargetSid": f"{self.dom}-519"}, True)
        self.check({"EventID": 4728, "TargetSid": f"{self.dom}-513"}, False)  # Domain Users
        self.check({"EventID": 4728, "TargetSid": f"{self.dom}-1512"}, False)  # custom group
        self.check({"EventID": 4728, "TargetSid": "S-1-5-32-544"}, False)  # wrong event
        self.check({"EventID": 4733, "TargetSid": "S-1-5-32-544"}, False)  # member removed


class ServiceInstallTests(SecurityRuleCase):
    rule = "security_win_service_installed_susp_binary.yml"

    def test_cases(self) -> None:
        self.check({"EventID": 4697, "ServiceFileName": "cmd.exe /c whoami"}, True)
        self.check({"EventID": 4697, "ServiceFileName": "%COMSPEC% /c x"}, True)
        self.check({"EventID": 4697, "ServiceFileName": r"C:\Users\Public\a.exe"}, True)
        self.check({"EventID": 4697, "ServiceFileName": r"C:\Windows\PSEXESVC.exe"}, True)
        self.check({"EventID": 4697, "ServiceFileName": r"C:\Windows\system32\svchost.exe -k x"}, False)
        self.check({"EventID": 4697, "ServiceFileName": r"C:\Program Files\App\app.exe"}, False)
        self.check({"EventID": 4698, "ServiceFileName": "cmd.exe /c whoami"}, False)


class SidHistoryAndDsrmTests(unittest.TestCase):
    def test_sid_history(self) -> None:
        det = _load("security_win_sid_history_added.yml")
        for eid, expected in ((4765, True), (4766, True), (4738, False), (4720, False)):
            self.assertEqual(fires(det, {"EventID": eid}), expected, eid)

    def test_dsrm(self) -> None:
        det = _load("security_win_dsrm_password_set.yml")
        self.assertTrue(fires(det, {"EventID": 4794}))
        self.assertFalse(fires(det, {"EventID": 4793}))


if __name__ == "__main__":
    unittest.main()
