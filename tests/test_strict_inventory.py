import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / 'scanner/run.py'


class StrictInventoryTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.snapshot = self.root / 'tools.json'
        self.baseline = self.root / 'baseline.json'

    def cli(self, *args):
        return subprocess.run([sys.executable, str(RUN), *map(str, args)], cwd=self.root,
                              capture_output=True, text=True, timeout=10)

    def test_strict_scan_rejects_malformed_or_unscoped_inputs(self):
        for text in ('{}', '{"tools":[{}]}', '{"tools":[{"name":"a"},{"name":"a"}]}',
                     '{"docs":{"tools":[]},"docs":{"tools":[]}}', '{'):
            with self.subTest(text=text):
                self.snapshot.write_text(text, encoding='utf-8')
                result = self.cli('scan', '--strict', '--tools-json', self.snapshot, '--format', 'json')
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, '')

    def test_failed_collection_does_not_overwrite_baseline(self):
        config = self.root / 'config.json'
        config.write_text(json.dumps({'mcpServers': {'broken': {'command': str(self.root / 'missing')}}}),
                          encoding='utf-8')
        self.baseline.write_text('keep baseline', encoding='utf-8')
        result = self.cli('pin', '--config', config, '--baseline', self.baseline)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(self.baseline.read_text(encoding='utf-8'), 'keep baseline')
        self.assertEqual(self.cli('scan', '--strict', '--config', config).returncode, 2)

    def test_strict_drift_reports_absent_server_but_respects_only(self):
        self.snapshot.write_text('{"docs":{"tools":[]},"archive":{"tools":[{"name":"lookup"}]}}',
                                 encoding='utf-8')
        result = self.cli('pin', '--tools-json', self.snapshot, '--baseline', self.baseline)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.snapshot.write_text('{"docs":{"tools":[]}}', encoding='utf-8')
        args = ('drift', '--strict', '--baseline', self.baseline, '--tools-json', self.snapshot, '--format', 'json')
        result = self.cli(*args)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual([f['rule_id'] for f in json.loads(result.stdout)['findings']], ['T4-SERVER-REMOVED'])
        self.assertEqual(self.cli(*args, '--only', 'docs').returncode, 0)
        self.assertEqual(self.cli(*args, '--only', 'archive').returncode, 2)

    def test_invalid_baseline_fails_instead_of_reporting_clean(self):
        self.snapshot.write_text('{"tools":[]}', encoding='utf-8')
        self.baseline.write_text('{"version":1,"servers":{"docs":{"lookup":{}}}}', encoding='utf-8')
        result = self.cli('drift', '--strict', '--baseline', self.baseline, '--tools-json', self.snapshot)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('invalid baseline', result.stderr)
