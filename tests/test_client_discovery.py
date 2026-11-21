import argparse
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scanner"))
from mcpscan import cli, discovery


class ClientDiscoveryTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_gemini_http_and_sse_diagnostic(self):
        path = self.write('.gemini/settings.json', json.dumps({'mcpServers': {
            'http': {'httpUrl': 'https://example.test/mcp'},
            'old': {'url': 'https://example.test/sse'},
        }}))
        notes = []
        specs = discovery.parse_config(path, notes)
        self.assertEqual([(s.name, s.transport) for s in specs], [('http', 'http')])
        self.assertIn('legacy SSE', notes[0])

    def test_opencode_jsonc(self):
        path = self.write('opencode.jsonc', '''{"mcp": {
            // Local server with an argument containing comment-like text
            "local": {"type":"local", "command":["python", "https://example.test/*literal*/",],
                "environment":{"MODE":"test", /* comment */},},
            "off": {"type":"remote", "url":"https://example.test/mcp", "enabled":false},
        }}''')
        notes = []
        specs = discovery.parse_config(path, notes)
        self.assertEqual(notes, [])
        self.assertEqual(len(specs), 1)
        self.assertEqual((specs[0].command, specs[0].args, specs[0].env),
                         ('python', ['https://example.test/*literal*/'], {'MODE': 'test'}))

    @unittest.skipUnless(sys.version_info >= (3, 11), 'requires tomllib')
    def test_codex_toml(self):
        path = self.write('config.toml', '''[mcp_servers.docs]
url = "https://example.test/mcp"
[mcp_servers.docs.http_headers]
Accept-Language = "en"
[mcp_servers.private]
url = "https://example.test/private"
bearer_token_env_var = "TOKEN"
''')
        notes = []
        specs = discovery.parse_config(path, notes)
        self.assertEqual([(s.name, s.headers) for s in specs], [('docs', {'Accept-Language': 'en'})])
        self.assertIn('client-managed authentication', notes[0])

    @unittest.skipUnless(importlib.util.find_spec('yaml'), 'requires PyYAML')
    def test_hermes_yaml_and_unsafe_tag(self):
        path = self.write('config.yaml', 'mcp_servers:\n  local:\n    command: python\n    args: [server.py]\n')
        self.assertEqual(discovery.parse_config(path)[0].args, ['server.py'])
        path = self.write('config.yaml', 'x: !!python/object:example.Nope {}\n')
        notes = []
        self.assertEqual(discovery.parse_config(path, notes), [])
        self.assertIn('invalid YAML', notes[0])

    @unittest.skipUnless(importlib.util.find_spec('yaml'), 'requires PyYAML')
    def test_deepseek_patch_ignores_other_plugins(self):
        path = self.write('cordis.patch.yml', """- insert:
    - name: another-plugin
      config: {serverName: ignored, command: ignored}
    - name: '@deepseek-ai/dsh-mcp-client'
      config:
        serverName: docs
        transport: streamable-http
        url: https://example.test/mcp
""")
        notes = []
        specs = discovery.parse_config(path, notes)
        self.assertEqual(notes, [])
        self.assertEqual([(s.name, s.transport) for s in specs], [('docs', 'http')])

    def test_inventory_does_not_connect_or_print_secrets(self):
        path = self.write('custom.json', json.dumps({'mcpServers': {'docs': {
            'url': 'https://example.test/mcp?key=secret-1', 'headers': {'Authorization': 'secret-2'},
        }}}))
        out = io.StringIO()
        with patch.object(cli, 'fetch_tools', side_effect=AssertionError('must not connect')), contextlib.redirect_stdout(out):
            self.assertEqual(cli.main(['inventory', '--config', str(path), '--format', 'json']), 0)
        self.assertEqual(json.loads(out.getvalue())['servers'][0]['name'], 'docs')
        self.assertNotIn('secret-', out.getvalue())

    def test_selected_client_reaches_scan_without_expanding_legacy_scope(self):
        path = self.write('.gemini/settings.json', '{"mcpServers":{"test":{"command":"python"}}}')
        with patch.object(Path, 'home', return_value=self.root / 'home'), patch.dict(os.environ, {}, clear=True):
            self.assertNotIn(path, discovery.client_paths('legacy', self.root))
            with patch.object(cli, 'fetch_tools', return_value=[]) as fetch:
                cli.collect_tools(argparse.Namespace(client='gemini', project_dir=str(self.root), timeout=1))
                self.assertEqual(fetch.call_args.args[0].name, 'test')

    def test_opencode_config_scans_local_mock_server_end_to_end(self):
        repo = Path(__file__).resolve().parents[1]
        path = self.write('opencode.json', json.dumps({'mcp': {'mock': {
            'type': 'local', 'command': [sys.executable, str(repo / 'tests/fixtures/mock_server.py')],
            'environment': {'MOCK_MODE': 'clean'},
        }}}))
        result = subprocess.run([sys.executable, str(repo / 'scanner/run.py'), 'scan',
                                 '--config', str(path), '--format', 'json'],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['tools_scanned'], 3)

    def test_inventory_reports_invalid_explicit_config(self):
        path = self.write('broken.json', '{ secret-token')
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status = cli.main(['inventory', '--strict', '--format', 'json', '--config', str(path)])
        self.assertEqual(status, 1)
        self.assertIn('cannot read or parse config', out.getvalue())
        self.assertNotIn('secret-token', out.getvalue())
