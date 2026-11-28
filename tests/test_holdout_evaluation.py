import hashlib
import json
import tempfile
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
        self.assertIn("not used to tune", report["provenance"].lower())
        self.assertIn("independently sourced", report["provenance"].lower())
        self.assertIn("by_source_type", report)
        self.assertIn("malicious_layer_hits", report)

    def run_holdout(self, *args):
        return subprocess.run([sys.executable, str(ROOT / "bench/evaluate_holdout.py"), *map(str, args)],
                              capture_output=True, text=True, timeout=30)

    def test_checksum_must_match_exact_input_bytes(self):
        bundled = ROOT / 'bench/holdout-v1.json'
        digest = hashlib.sha256(bundled.read_bytes()).hexdigest()
        result = self.run_holdout('--expected-sha256', digest, '--json', '--require-complete')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['sha256'], digest)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'changed.json'
            path.write_bytes(bundled.read_bytes() + b'\n')
            mismatch = self.run_holdout('--dataset', path, '--expected-sha256', digest)
            self.assertEqual(mismatch.returncode, 2)
            self.assertIn('does not match', mismatch.stderr)

    def test_incomplete_coverage_preserves_report_but_fails_strict_run(self):
        data = json.loads((ROOT / 'bench/holdout-v1.json').read_bytes())
        data['cases'][0]['tool']['inputSchema'] = {'default': 'x' * 1_000_001}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'incomplete.json'
            path.write_text(json.dumps(data), encoding='utf-8')
            result = self.run_holdout('--dataset', path, '--json', '--require-complete')
            self.assertEqual(result.returncode, 2)
            self.assertFalse(json.loads(result.stdout)['complete_coverage'])
            self.assertIn('should not be used for comparison', result.stderr)


if __name__ == "__main__":
    unittest.main()
