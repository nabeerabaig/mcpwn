import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / 'scanner/run.py'


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.out = self.root / 'snapshot.json'

    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(CLI), *map(str, args)],
                              cwd=ROOT, capture_output=True, text=True, timeout=15)

    def test_offline_roundtrip_preserves_server_names(self):
        original = self.root / 'original.json'
        original.write_text(json.dumps({'tools': {'tools': [{'name': 'lookup', 'description': 'Look up data'}]},
                                        'empty': {'tools': []}}), encoding='utf-8')
        result = self.run_cli('snapshot', '--tools-json', original, '--output', self.out)
        self.assertEqual(result.returncode, 0, result.stderr)
        saved = json.loads(self.out.read_text(encoding='utf-8'))
        self.assertEqual(saved['empty']['tools'], [])
        self.assertEqual(saved['tools']['tools'][0]['name'], 'lookup')
        result = self.run_cli('scan', '--tools-json', self.out, '--format', 'json')
        self.assertEqual(json.loads(result.stdout)['tools_scanned'], 1)

    def test_refuses_to_overwrite(self):
        self.out.write_text('keep me', encoding='utf-8')
        result = self.run_cli('snapshot', '--connect', '--output', self.out)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.out.read_text(encoding='utf-8'), 'keep me')

    def test_duplicate_input_server_is_rejected(self):
        fixture = ROOT / 'bench/benign_pilot.json'
        result = self.run_cli('snapshot', '--tools-json', fixture, fixture, '--output', self.out)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.out.exists())

    def test_capture_requires_opt_in_and_does_not_save_on_failure(self):
        config = self.root / 'config.json'
        config.write_text(json.dumps({'mcpServers': {
            'a_mock': {'command': sys.executable, 'args': [str(ROOT / 'tests/fixtures/mock_server.py')],
                       'env': {'MOCK_MODE': 'clean', 'SAMPLE_SECRET': 'never-export-this'}},
            'b_missing': {'command': str(self.root / 'missing-executable')},
        }}), encoding='utf-8')
        args = ('snapshot', '--config', config, '--output', self.out)
        for flags in ((), ('--connect',)):
            result = self.run_cli(*args, *flags)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertFalse(self.out.exists())
        result = self.run_cli(*args, '--connect', '--only', 'a_mock')
        self.assertEqual(result.returncode, 0, result.stderr)
        text = self.out.read_text(encoding='utf-8')
        self.assertNotIn('never-export-this', text)
        self.assertEqual(len(json.loads(text)['a_mock']['tools']), 3)

    def test_diff_reports_changes_without_echoing_metadata(self):
        before = self.root / 'before.json'
        after = self.root / 'after.json'
        before.write_text(json.dumps({'docs': {'tools': [
            {'name': 'lookup', 'description': 'private-before'}, {'name': 'obsolete'}]},
            'old-empty': {'tools': []}}), encoding='utf-8')
        after.write_text(json.dumps({'docs': {'tools': [
            {'name': 'lookup', 'description': 'private-after', 'inputSchema': {'type': 'object'}},
            {'name': 'new'}]}, 'new-empty': {'tools': []}}), encoding='utf-8')
        result = self.run_cli('snapshot-diff', before, after, '--format', 'json', '--fail-on-change')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn('private-', result.stdout)
        report = json.loads(result.stdout)
        self.assertEqual(report['servers_added'], ['new-empty'])
        self.assertEqual(report['servers_removed'], ['old-empty'])
        self.assertEqual({row['change'] for row in report['tools']}, {'added', 'removed', 'modified'})
        self.assertEqual(report['tools'][0]['fields'], ['description', 'inputSchema'])

    def test_diff_ignores_json_key_order(self):
        before = self.root / 'before.json'
        after = self.root / 'after.json'
        for path, keys in ((before, ('a', 'b')), (after, ('b', 'a'))):
            path.write_text(json.dumps({'docs': {'tools': [
                {'name': 'lookup', 'inputSchema': {'properties': {k: {'type': 'string'} for k in keys}}}
            ]}}), encoding='utf-8')
        result = self.run_cli('snapshot-diff', before, after, '--fail-on-change')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('No snapshot changes', result.stdout)

    def test_diff_rejects_duplicate_tool_names(self):
        self.out.write_text('{"docs":{"tools":[{"name":"same"},{"name":"same"}]}}', encoding='utf-8')
        self.assertEqual(self.run_cli('snapshot-diff', self.out, self.out).returncode, 2)
