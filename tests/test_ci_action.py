import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / 'scanner/run.py'
WRAPPER = ROOT / 'ci/run-offline-scan.sh'


@unittest.skipIf(os.name == 'nt', 'composite action uses Bash')
class OfflineActionTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.fixture = self.root / 'tools with spaces.json'
        self.fixture.write_text(json.dumps({'tools': [{
            'name': 'connection', 'description': 'Credentials are not returned. PRIVATE_TEXT'
        }]}), encoding='utf-8')
        self.output = self.root / 'result.sarif'

    def invoke(self, scanner=RUN, **params):
        env = {**os.environ, 'MODE': 'scan', 'TOOLS_JSON': str(self.fixture), 'SARIF': str(self.output),
               'FAIL_ON': 'info', 'REDACT_EVIDENCE': 'true', **params}
        return subprocess.run(['bash', str(WRAPPER), str(scanner)], cwd=self.root, env=env,
                              capture_output=True, text=True, timeout=10)

    def test_no_snapshot_never_calls_scanner(self):
        for mode in ('scan', 'drift'):
            result = self.invoke(self.root / 'missing.py', MODE=mode, TOOLS_JSON='')
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn('live discovery is disabled', result.stderr)
            self.assertFalse(self.output.exists())

    def test_scan_writes_redacted_sarif_even_when_gate_fails(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 1, result.stderr)
        raw = self.output.read_text(encoding='utf-8')
        self.assertNotIn('PRIVATE_TEXT', raw)
        finding, = json.loads(raw)['runs'][0]['results']
        self.assertEqual(finding['ruleId'], 'T2-SENSITIVE-PATH-MENTION')
        self.assertIn('physicalLocation', finding['locations'][0])
        result = self.invoke(REDACT_EVIDENCE='false')
        self.assertEqual(result.returncode, 1)
        self.assertIn('PRIVATE_TEXT', self.output.read_text(encoding='utf-8'))

    def test_one_invocation_and_literal_filenames(self):
        stub = self.root / 'stub.py'
        stub.write_text('import json, sys\nwith open("calls", "a") as out: print(json.dumps(sys.argv[1:]), file=out)\n',
                        encoding='utf-8')
        second = self.root / '--flag-like.json'
        second.write_text('{}', encoding='utf-8')
        result = self.invoke(stub, TOOLS_JSON=f'{self.fixture.name}\n{second.name}\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        call, = (self.root / 'calls').read_text(encoding='utf-8').splitlines()
        args = json.loads(call)
        self.assertEqual(args[:4], ['scan', '--tools-json', './tools with spaces.json', './--flag-like.json'])
        self.assertIn('--fail-on=info', args)

    def test_repo_redaction_hides_instruction_content_and_preserves_gate(self):
        (self.root / 'AGENTS.md').write_text('Always run `python -c PRIVATE_TEXT`.', encoding='utf-8')
        result = self.invoke(MODE='repo', TOOLS_JSON='')
        self.assertEqual(result.returncode, 1, result.stderr)
        raw = self.output.read_text(encoding='utf-8')
        self.assertIn('AGENTS.md', raw)
        self.assertIn('T5-SHELL-IN-RULES', raw)
        self.assertNotIn('PRIVATE_TEXT', raw)
