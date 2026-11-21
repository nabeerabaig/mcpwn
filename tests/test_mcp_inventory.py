"""Defensive checks for complete, portable MCP metadata collection."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
from mcpscan import mcp_client
from mcpscan.models import ServerSpec


class InventoryReliabilityTests(unittest.TestCase):
    def test_stdio_reads_utf8_and_ignores_non_object_logs(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / 'server.py'
            script.write_text('''import json, sys
for line in sys.stdin:
    message = json.loads(line)
    if 'id' not in message:
        continue
    result = {'tools': [{'name': 'lookup', 'description': 'caf\\u00e9'}]} if message['method'] == 'tools/list' else {}
    reply = {'jsonrpc': '2.0', 'id': message['id'], 'result': result}
    sys.stdout.buffer.write(('startup log\\n42\\n' + json.dumps(reply, ensure_ascii=False) + '\\n').encode('utf-8'))
    sys.stdout.buffer.flush()
''', encoding='utf-8')
            specs = mcp_client.fetch_tools(ServerSpec('local', sys.executable, [str(script)]), timeout=5)
            self.assertEqual([tool.description for tool in specs], ['caf\u00e9'])

    def test_valid_pagination_collects_every_page(self):
        requested = []

        def request(method, params):
            self.assertEqual(method, 'tools/list')
            requested.append(params)
            if 'cursor' not in params:
                return {'tools': [{'name': 'one'}], 'nextCursor': 'page-two'}
            return {'tools': [{'name': 'two'}]}

        tools = mcp_client._list_tools(ServerSpec('local', ''), request)
        self.assertEqual(requested, [{}, {'cursor': 'page-two'}])
        self.assertEqual([tool.name for tool in tools], ['one', 'two'])

    def test_repeated_cursor_and_page_limit_reject_partial_inventory(self):
        spec = ServerSpec('local', '')
        with self.assertRaisesRegex(mcp_client.McpError, 'repeated'):
            mcp_client._list_tools(spec, lambda *_: {'tools': [], 'nextCursor': 'again'})
        with patch.object(mcp_client, 'MAX_TOOL_PAGES', 1):
            with self.assertRaisesRegex(mcp_client.McpError, 'page limit'):
                mcp_client._list_tools(spec, lambda *_: {'tools': [{'name': 'one'}], 'nextCursor': 'next'})

    def test_invalid_page_and_duplicate_names_are_rejected(self):
        cases = [({}, 'tools array'), ({'tools': [42]}, 'valid name'),
                 ({'tools': [{'name': 'one', 'inputSchema': []}]}, 'inputSchema'),
                 ({'tools': [{'name': 'one'}, {'name': 'one'}]}, 'duplicate'),
                 ({'tools': [], 'nextCursor': 1}, 'nextCursor')]
        for response, error in cases:
            with self.subTest(response=response):
                with self.assertRaisesRegex(mcp_client.McpError, error):
                    mcp_client._list_tools(ServerSpec('local', ''), lambda *_: response)

    def test_http_reply_id_and_crlf_sse(self):
        self.assertIsNone(mcp_client._parse_http_body('{"id":9,"result":{}}', 'application/json', 1))
        response = 'data: {"id":9,"result":{}}\r\n\r\ndata: {"id":1,"result":{"tools":[]}}\r\n\r\n'
        self.assertEqual(mcp_client._parse_http_body(response, 'text/event-stream', 1)['result'], {'tools': []})
