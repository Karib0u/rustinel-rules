"""Regression checks for derived Rustinel engine requirements."""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[2] / "tools"))
import engine_contract  # noqa: E402
import lib  # noqa: E402


def sigma(product, category, *fields):
    return lib.Artifact(
        f"{product}-{category}",
        "sigma",
        Path("test.yml"),
        {
            "logsource": {"product": product, "category": category},
            "detection": {
                "selection": {f"{field}|contains": "x" for field in fields},
                "condition": "selection",
            },
        },
        "",
    )


def row(field, availability="conditional", since=None, **kwargs):
    return {
        "platform": "windows",
        "category": "process_creation",
        "provider": "etw",
        "source": "Kernel-Process",
        "field": field,
        "availability": availability,
        "since": since,
        **({"reason": "not carried"} if availability == "never" else {}),
        **kwargs,
    }


def contract(*rows, schema=2):
    return json.dumps({"schema_version": schema, "entries": list(rows)}).encode()


class EngineRequirementTests(unittest.TestCase):
    def test_macos_artifact_requires_first_macos_release(self):
        artifact = lib.Artifact(
            "macos-test",
            "sigma",
            Path("macos-test.yml"),
            {
                "logsource": {"product": "macos", "category": "process_creation"},
                "detection": {"selection": {"Image|endswith": "/test"}, "condition": "selection"},
            },
            "",
        )

        minimum, reasons = lib.artifact_min_engine(artifact)

        self.assertEqual(minimum, "1.1.0")
        self.assertTrue(any("macOS" in reason for reason in reasons))

    def test_pack_platform_floor_also_covers_non_sigma_content(self):
        artifact = lib.Artifact("macos-yara", "yara", Path("macos-test.yar"), {}, "")

        minimum, _ = lib.pack_min_engine([artifact.id], {artifact.id: artifact}, platform="macos")

        self.assertEqual(minimum, "1.1.0")

    def test_linux_keeps_repository_baseline(self):
        minimum, _ = lib.pack_min_engine([], {}, platform="linux")

        self.assertEqual(minimum, "1.0.2")

    def test_vendored_contract_dates_fields_after_the_platform_baseline(self):
        for product, category, field, version in (
            ("windows", "process_creation", "ParentUser", "1.8.0"),
            ("windows", "process_creation", "Hashes", "1.8.0"),
            ("windows", "network_connection", "Initiated", "1.4.1"),
            ("windows", "registry_set", "Details", "1.4.0"),
            ("linux", "process_creation", "ContainerId", "1.8.0"),
            ("macos", "process_creation", "TeamId", "1.6.0"),
        ):
            with self.subTest(field=field):
                minimum, reasons = lib.artifact_min_engine(sigma(product, category, field))
                self.assertEqual(minimum, version)
                self.assertTrue(any(field in reason for reason in reasons))

    def test_baseline_fields_do_not_raise_the_floor_or_add_reasons(self):
        minimum, reasons = lib.artifact_min_engine(
            sigma("windows", "process_creation", "CommandLine", "Image")
        )
        self.assertEqual(minimum, lib.BASELINE_ENGINE)
        self.assertEqual(reasons, [])


class FieldSinceTests(unittest.TestCase):
    def test_earliest_available_source_wins_and_never_rows_are_ignored(self):
        since = engine_contract.parse_field_since(
            contract(
                row("A", since="1.8.0"),
                row("A", since="1.4.1"),
                row("B", since="1.4.1"),
                row("B", since=None),
                row("C", availability="never", since="1.0.2"),
            ),
            "9.9.9",
        )
        fields = since[("windows", "process_creation")]
        self.assertEqual(fields["A"], "1.4.1")
        self.assertIsNone(fields["B"])
        self.assertNotIn("C", fields)

    def test_schema_1_has_no_release_data(self):
        raw = json.dumps(
            {"schema_version": 1, "entries": [{**row("A"), "since": "1.8.0"}]}
        ).encode()
        self.assertEqual(engine_contract.parse_field_since(raw, "1.6.0"), {})

    def test_since_correction_applies_only_to_its_pinned_release(self):
        raw = contract(row("A", since="1.7.1"))
        fixed = engine_contract.parse_field_since(raw, "1.8.0")
        untouched = engine_contract.parse_field_since(raw, "1.9.0")
        self.assertEqual(fixed[("windows", "process_creation")]["A"], "1.8.0")
        self.assertEqual(untouched[("windows", "process_creation")]["A"], "1.7.1")

    def test_explicit_field_map_overrides_the_vendored_contract(self):
        minimum, _ = lib.artifact_min_engine(
            sigma("windows", "process_creation", "A"),
            {("windows", "process_creation"): {"A": "2.0.0"}},
        )
        self.assertEqual(minimum, "2.0.0")


if __name__ == "__main__":
    unittest.main()
