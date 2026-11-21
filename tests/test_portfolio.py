import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scanner'))
from mcpscan import portfolio
from mcpscan.models import Finding


class PortfolioTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.manifest = self.root / 'audit.json'
        self.project = {'id': 'app', 'snapshot': 'current.json'}
        self.write_tools('current.json', named='stable')

    def write(self, name, data):
        path = self.root / name
        path.write_text(json.dumps(data), encoding='utf-8')
        return path

    def write_tools(self, filename, *, named, description='Look up an item by ID.'):
        return self.write(filename, {'docs': {'tools': [{'name': named, 'description': description}]}})

    def config(self, *, projects=None, **policy):
        self.write('audit.json', {'version': 1, 'policy': policy,
                                  'projects': projects if projects is not None else [self.project]})

    def cli(self, *args):
        return subprocess.run([sys.executable, str(ROOT / 'scanner/run.py'), 'audit', str(self.manifest), *args],
                              capture_output=True, text=True, timeout=10)

    def test_cli_gates_and_does_not_echo_description(self):
        self.write_tools('current.json', named='stable', description='Credentials are not returned. PRIVATE_BODY')
        self.config(minimum_severity='info')
        result = self.cli('--format', 'json')
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['summary']['policy_violations'], 1)
        self.assertNotIn('PRIVATE_BODY', result.stdout)
        self.config(minimum_severity='info', max_violations=1)
        self.assertEqual(self.cli().returncode, 0)

    def test_new_gate_retains_known_findings_without_counting_them(self):
        text = 'Credentials are not returned.'
        self.write_tools('current.json', named='stable', description=text)
        self.write_tools('baseline.json', named='stable', description=text)
        self.project['baseline'] = 'baseline.json'
        self.config(gate='new', minimum_severity='info')
        report = portfolio.audit(self.manifest)
        self.assertTrue(report['passed'])
        self.assertEqual(report['projects'][0]['findings'][0]['status'], 'existing')
        self.write_tools('current.json', named='replacement', description=text)
        report = portfolio.audit(self.manifest)
        self.assertFalse(report['passed'])
        self.assertEqual(report['summary']['resolved_findings'], 1)
        self.assertEqual(report['projects'][0]['findings'][0]['status'], 'new')

    def test_escalated_finding_counts_in_new_gate(self):
        self.write_tools('baseline.json', named='stable')
        self.project['baseline'] = 'baseline.json'
        self.config(gate='new')
        common = dict(rule_id='TEST', tier=2, title='test', message='test', server='docs', tool='stable',
                      location='description', evidence='same')
        before = Finding(**common, confidence=.25)
        after = Finding(**common, confidence=.85)
        with patch.object(portfolio.engine, 'scan_tools', side_effect=[[before], [after]]):
            report = portfolio.audit(self.manifest)
        self.assertEqual(report['projects'][0]['findings'][0]['status'], 'escalated')
        self.assertFalse(report['passed'])

    def test_project_isolation_and_stable_order(self):
        self.config(projects=[{**self.project, 'id': 'z'}, {**self.project, 'id': 'a'}])
        report = portfolio.audit(self.manifest)
        self.assertEqual(report['summary']['tools_scanned'], 2)
        self.assertEqual([p['id'] for p in report['projects']], ['a', 'z'])

    def test_rejects_missing_baseline_and_duplicate_project_ids(self):
        self.config(gate='new')
        self.assertIn('requires an explicit baseline', self.cli().stderr)
        self.config(projects=[self.project, self.project])
        self.assertEqual(self.cli().returncode, 2)

    def test_rejects_path_escape_and_duplicate_json_keys(self):
        self.config(projects=[{**self.project, 'snapshot': '../outside.json'}])
        self.assertIn('escapes the manifest directory', self.cli().stderr)
        self.config()
        (self.root / 'current.json').write_text('{"docs": [], "docs": []}', encoding='utf-8')
        result = self.cli()
        self.assertEqual(result.returncode, 2)
        self.assertIn('duplicate JSON key', result.stderr)

    def test_does_not_overwrite_output(self):
        self.config()
        out = self.write('output.json', {'preserve': True})
        self.assertEqual(self.cli('--output', str(out)).returncode, 2)
        self.assertEqual(json.loads(out.read_text(encoding='utf-8')), {'preserve': True})

    def test_metadata_drift_budget_is_independent_of_findings(self):
        self.write_tools('baseline.json', named='stable')
        self.write_tools('current.json', named='stable', description='Retrieve an item by ID.')
        self.project['baseline'] = 'baseline.json'
        self.config(gate='new', max_tool_changes=0)
        report = portfolio.audit(self.manifest)
        self.assertFalse(report['passed'])
        self.assertEqual(report['summary']['policy_violations'], 0)
        self.assertEqual(report['summary']['tool_changes'], 1)
        self.assertEqual(report['projects'][0]['metadata_drift']['tools'][0]['fields'], ['description'])

    def test_rejects_output_snapshot_as_its_own_baseline(self):
        self.project['baseline'] = self.project['snapshot']
        self.config(gate='new')
        self.assertIn('must be separate files', self.cli().stderr)

    def test_html_report_survives_policy_failure_and_escapes_tool_names(self):
        self.write_tools('current.json', named='lookup<script>alert(1)</script>',
                         description='Credentials are not returned. PRIVATE_BODY')
        self.config(minimum_severity='info')
        path = self.root / 'audit.html'
        result = self.cli('--format', 'html', '--output', str(path))
        self.assertEqual(result.returncode, 1, result.stderr)
        html = path.read_text(encoding='utf-8')
        self.assertIn('>FAIL<', html)
        self.assertIn('lookup&lt;script&gt;alert(1)&lt;/script&gt;', html)
        self.assertNotIn('<script>alert(1)</script>', html)
        self.assertNotIn('PRIVATE_BODY', html)
        self.assertIn('data-violation="yes"', html)

    def test_dashboard_embedded_script_matches_content_security_policy(self):
        import base64
        import hashlib
        import re

        self.config()
        result = self.cli('--format', 'html')
        self.assertEqual(result.returncode, 0, result.stderr)
        script, = re.findall(r'<script>(.*?)</script>', result.stdout, re.S)
        digest = base64.b64encode(hashlib.sha256(script.encode('utf-8')).digest()).decode('ascii')
        self.assertIn(f'sha256-{digest}', result.stdout)
        self.assertNotRegex(result.stdout, r'(src|href)=[\'\"]https?://')

    def test_dashboard_displays_metadata_drift_without_raw_values(self):
        self.write_tools('baseline.json', named='stable', description='BEFORE_PRIVATE')
        self.write_tools('current.json', named='stable', description='AFTER_PRIVATE')
        self.project['baseline'] = 'baseline.json'
        self.config(max_tool_changes=0)
        result = self.cli('--format', 'html')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('Changes from baseline', result.stdout)
        self.assertIn('<td>modified</td>', result.stdout)
        self.assertNotIn('_PRIVATE', result.stdout)
