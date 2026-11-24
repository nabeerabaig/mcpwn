import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]


class HoldoutEvaluationTests(unittest.TestCase):
    def test_frozen_holdout_is_separate_and_reports_metrics(self):
        result = subprocess.run([sys.executable, str(ROOT / "bench/evaluate_holdout.py"), "--json"],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(len(report["cases"]), 12)
        self.assertEqual(report["summary"]["malicious_cases"], 6)
        self.assertEqual(report["summary"]["benign_cases"], 6)
        self.assertEqual(report["summary"]["true_positives"] + report["summary"]["false_negatives"], 6)
        self.assertEqual(report["summary"]["true_negatives"] + report["summary"]["false_positives"], 6)
        self.assertIn("not independently", report["provenance"].lower())
        self.assertIn("by_source_type", report)
        self.assertIn("malicious_layer_hits", report)


if __name__ == "__main__":
    unittest.main()
