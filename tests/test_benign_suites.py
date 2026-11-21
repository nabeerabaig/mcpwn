import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / 'bench/evaluate_suites.py'


class SuiteTests(unittest.TestCase):
    def cli(self, *args):
        return subprocess.run([sys.executable, str(CLI), *map(str, args)], cwd=ROOT,
                              capture_output=True, text=True, timeout=10)

    def test_bundled_suites_are_separate_and_pinned(self):
        result = self.cli('--json')
        self.assertEqual(result.returncode, 0, result.stderr)
        suites = {s['id']: s for s in json.loads(result.stdout)['suites']}
        self.assertEqual({name: s['tools_scanned'] for name, s in suites.items()},
                         {'synthetic-pilot': 5, 'public-docs': 10, 'upstream-mcp-git': 14})
        upstream = suites['upstream-mcp-git']
        self.assertEqual(upstream['thresholds']['info']['flagged'], 1)
        self.assertEqual(upstream['thresholds']['warning']['flagged'], 0)

    def test_suite_selection(self):
        result = self.cli('--json', '--suite', 'upstream-mcp-git')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(json.loads(result.stdout)['suites']), 1)
        self.assertEqual(self.cli('--suite', 'does-not-exist').returncode, 2)

    def test_gate_failure_then_changed_fixture_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            fixture = folder / 'sample.json'
            fixture.write_bytes((ROOT / 'bench/benign_pilot.json').read_bytes())
            manifest = folder / 'suites.json'
            manifest.write_text(json.dumps({'version': 1, 'suites': [{
                'id': 'sample', 'kind': 'synthetic', 'source': 'test fixture',
                'fixture': fixture.name, 'sha256': hashlib.sha256(fixture.read_bytes()).hexdigest(),
                'max_flagged': {'info': 0},
            }]}), encoding='utf-8')
            report = self.cli('--manifest', manifest, '--json')
            self.assertEqual(report.returncode, 1, report.stderr)
            self.assertFalse(json.loads(report.stdout)['passed'])
            fixture.write_bytes(fixture.read_bytes() + b'\n')
            mismatch = self.cli('--manifest', manifest)
            self.assertEqual(mismatch.returncode, 2, mismatch.stderr)
            self.assertIn('SHA-256 mismatch', mismatch.stderr)
