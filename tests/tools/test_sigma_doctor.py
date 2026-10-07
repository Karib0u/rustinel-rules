"""Policy tests for tools/sigma_doctor.py, driven by a fake `rustinel` binary."""

import json
import os
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import sigma_doctor  # noqa: E402


def doc(source, verdict, *codes):
    return {"source": source, "verdict": verdict, "reasons": [{"code": c} for c in codes]}


class SigmaDoctorTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.dist = self.root / "dist"
        self.preview = self.root / "preview"
        for pack_id, os_name in (("windows-essential", "windows"), ("linux-essential", "linux")):
            (self.dist / pack_id / "sigma").mkdir(parents=True)
            (self.dist / pack_id / "pack.yml").write_text(f"id: {pack_id}\nos: {os_name}\n")
        (self.preview / "windows").mkdir(parents=True)

    def engine(self, reports):
        """A fake binary printing reports[rules dir name] as (exit code, stdout)."""
        path = self.root / "rustinel"
        path.write_text(
            f"#!{sys.executable}\n"
            "import json, sys\n"
            f"reports = json.loads({json.dumps(json.dumps(reports))})\n"
            "rules = sys.argv[sys.argv.index('--rules') + 1].replace('\\\\', '/').split('/')\n"
            "key = rules[-2] if rules[-1] == 'sigma' else rules[-1]\n"
            "code, out = reports[key]\n"
            "sys.stdout.write(out if isinstance(out, str) else json.dumps(out))\n"
            "sys.exit(code)\n"
        )
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    def run_main(self, engine, *extra):
        argv = ["sigma_doctor.py", "--engine", str(engine), "--dist", str(self.dist)]
        argv += ["--preview", str(self.preview), *extra]
        out, err = StringIO(), StringIO()
        with (
            mock.patch.object(sys, "argv", argv),
            mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "", "GITHUB_STEP_SUMMARY": ""}),
            redirect_stdout(out),
            redirect_stderr(err),
        ):
            code = sigma_doctor.main()
        return code, out.getvalue(), err.getvalue()

    @staticmethod
    def report(*docs):
        return {"schema_version": 1, "documents": list(docs)}

    def test_degraded_only_warns(self):
        ok = self.report(doc("a.yml", "degraded", "derived_field"), doc("b.yml", "can-fire"))
        engine = self.engine(
            {"windows-essential": (1, ok), "linux-essential": (0, ok), "windows": (1, ok)}
        )
        code, out, err = self.run_main(engine)
        self.assertEqual(code, 0, err)
        self.assertIn("warning: 1 degraded document(s) (derived_field=1)", out)

    def test_can_never_fire_fails_production(self):
        bad = self.report(doc("dead.yml", "can-never-fire", "unavailable_field"))
        fine = self.report(doc("a.yml", "can-fire"))
        engine = self.engine(
            {"windows-essential": (1, bad), "linux-essential": (0, fine), "windows": (0, fine)}
        )
        code, _, err = self.run_main(engine)
        self.assertEqual(code, 1)
        self.assertIn("windows-essential: dead.yml can never fire (unavailable_field)", err)
        self.assertNotIn("linux-essential", err)

    def test_parse_failure_exit_2_fails(self):
        fine = self.report(doc("a.yml", "can-fire"))
        engine = self.engine(
            {"windows-essential": (2, "boom"), "linux-essential": (0, fine), "windows": (0, fine)}
        )
        code, _, err = self.run_main(engine)
        self.assertEqual(code, 1)
        self.assertIn("windows-essential: sigma doctor failed (exit 2: boom)", err)

    def test_unsupported_schema_and_garbage_fail(self):
        fine = self.report(doc("a.yml", "can-fire"))
        for bad in ({"schema_version": 2, "documents": []}, "not json"):
            with self.subTest(bad=bad):
                engine = self.engine(
                    {
                        "windows-essential": (0, bad),
                        "linux-essential": (0, fine),
                        "windows": (0, fine),
                    }
                )
                code, _, err = self.run_main(engine)
                self.assertEqual(code, 1)
                self.assertIn("sigma doctor failed", err)

    def test_preview_is_report_only(self):
        fine = self.report(doc("a.yml", "can-fire"))
        engine = self.engine(
            {
                "windows-essential": (0, fine),
                "linux-essential": (0, fine),
                "windows": (1, self.report(doc("p.yml", "degraded", "derived_field"))),
            }
        )
        code, out, _ = self.run_main(engine)
        self.assertEqual(code, 0)
        self.assertIn("preview/windows/p.yml is now degraded: promotion candidate", out)

        engine = self.engine(
            {
                "windows-essential": (0, fine),
                "linux-essential": (0, fine),
                "windows": (2, "boom"),
            }
        )
        code, out, _ = self.run_main(engine)
        self.assertEqual(code, 0)
        self.assertIn("could not report", out)

    def test_platform_filter(self):
        fine = self.report(doc("a.yml", "can-fire"))
        engine = self.engine({"linux-essential": (0, fine)})
        code, out, err = self.run_main(engine, "--platform", "linux")
        self.assertEqual(code, 0, err)
        self.assertIn("linux-essential", out)
        self.assertNotIn("windows", out)


if __name__ == "__main__":
    unittest.main()
