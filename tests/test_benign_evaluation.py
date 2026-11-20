import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "bench" / "evaluate_benign.py"


class BenignEvaluationTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(RUNNER), *map(str, args)],
                              capture_output=True, text=True, cwd=ROOT)

    def test_warning_budget_and_json(self):
        result = self.run_cli("--json", "--max-flagged", 0)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["tools_scanned"], 15)
        self.assertEqual(report["flagged_tools"], 0)
        self.assertEqual(report["by_highest_severity"]["info"], 1)

    def test_info_budget_failure(self):
        result = self.run_cli("--json", "--threshold", "info", "--max-flagged", 0)
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["flagged_tools"], 1)
        self.assertAlmostEqual(report["false_positive_rate"], 1 / 15)

    def test_empty_and_duplicate_tools_are_input_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "invalid.json"
            for tools in ([], [{"name": "same"}, {"name": "same"}]):
                with self.subTest(tools=tools):
                    fixture.write_text(json.dumps({"tools": tools}), encoding="utf-8")
                    self.assertEqual(self.run_cli(fixture).returncode, 2)
