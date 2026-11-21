import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bench'))
from detection_gate import compare


class DetectionGateTests(unittest.TestCase):
    @staticmethod
    def row(name, flagged):
        return {'category': 'test', 'name': name, 'flagged': flagged,
                'top': 0.8 if flagged else 0.0, 'rules': []}

    def test_aggregate_improvement_cannot_hide_an_existing_detection_regression(self):
        expected = {'malicious': {'test:a': True, 'test:b': False, 'test:c': False},
                    'benign': {'test:d': False}}
        results = {'malicious': [self.row('a', False), self.row('b', True), self.row('c', True)],
                   'benign': [self.row('d', False)]}
        report = compare(expected, results)
        self.assertFalse(report['passed'])
        self.assertEqual([r['id'] for r in report['regressions']], ['test:a'])
        self.assertEqual(len(report['improvements']), 2)

    def test_new_false_positive_is_regression(self):
        report = compare({'malicious': {'test:a': True}, 'benign': {'test:b': False}},
                         {'malicious': [self.row('a', True)], 'benign': [self.row('b', True)]})
        self.assertFalse(report['passed'])
        self.assertEqual(report['regressions'][0]['label'], 'benign')

    def test_case_removal_is_input_error(self):
        with self.assertRaisesRegex(ValueError, 'identities differ'):
            compare({'malicious': {'test:a': True}, 'benign': {'test:b': False}},
                    {'malicious': [], 'benign': [self.row('b', False)]})

    def test_local_baseline_passes_but_reports_existing_misses(self):
        result = subprocess.run([sys.executable, str(ROOT / 'bench/detection_gate.py'), '--json'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        parsed = json.loads(result.stdout)
        self.assertEqual(parsed['summary']['malicious'], {'cases': 52, 'flagged': 48})
        self.assertEqual(len(parsed['known_mismatches']), 4)

    def test_invalid_baseline_fails_with_exit_two(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'baseline.json'
            path.write_text('{"version":1,"version":1}', encoding='utf-8')
            result = subprocess.run([sys.executable, str(ROOT / 'bench/detection_gate.py'),
                                     '--baseline', str(path)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertIn('duplicate JSON field', result.stderr)
