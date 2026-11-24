"""Defensive checks for complete, portable MCP metadata collection."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
from mcpscan import mcp_client
from mcpscan.models import ServerSpec, ToolDef


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
                 ({'tools': [{'name': 'one', 'description': 7}]}, 'description'),
                 ({'tools': [{'name': 'one', 'inputSchema': None}]}, 'inputSchema'),
                 ({'tools': [{'name': 'one', 'inputSchema': []}]}, 'inputSchema'),
                 ({'tools': [{'name': 'one', 'outputSchema': []}]}, 'outputSchema'),
                 ({'tools': [{'name': 'one', 'annotations': []}]}, 'annotations'),
                 ({'tools': [{'name': 'one', '_meta': []}]}, '_meta'),
                 ({'tools': [{'name': 'one'}, {'name': 'one'}]}, 'duplicate'),
                 ({'tools': [], 'nextCursor': 1}, 'nextCursor')]
        for response, error in cases:
            with self.subTest(response=response):
                with self.assertRaisesRegex(mcp_client.McpError, error):
                    mcp_client._list_tools(ServerSpec('local', ''), lambda *_: response)

    def test_inventory_limits_tool_count(self):
        with patch.object(mcp_client, "MAX_TOOL_COUNT", 1):
            with self.assertRaisesRegex(mcp_client.McpError, "inventory limit"):
                mcp_client._list_tools(
                    ServerSpec("local", ""),
                    lambda *_: {"tools": [{"name": "one"}, {"name": "two"}]}
                )

    def test_stdio_oversized_json_line_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "oversized.py"
            script.write_text(
                "import sys\\nsys.stdout.write('x' * 101 + '\\\\n')\\nsys.stdout.flush()\\n",
                encoding="utf-8"
            )
            session = None
            with patch.object(mcp_client, "MAX_RPC_LINE_CHARS", 100):
                session = mcp_client.StdioSession(ServerSpec("local", sys.executable, [str(script)]), timeout=2)
                try:
                    with self.assertRaisesRegex(mcp_client.McpError, "line exceeds"):
                        session.request("initialize")
                finally:
                    session.close()

    def test_http_oversized_response_is_rejected(self):
        class Headers(dict):
            pass

        class Response:
            headers = Headers({"content-type": "application/json"})

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, size=-1):
                return b"x" * size

        with patch("urllib.request.urlopen", return_value=Response()):
            with patch.object(mcp_client, "MAX_HTTP_BODY_BYTES", 8):
                with self.assertRaisesRegex(mcp_client.McpError, "exceeds 8 bytes"):
                    mcp_client.fetch_tools_http(ServerSpec("remote", "", transport="http",
                                                           url="http://127.0.0.1/mcp"))

    def test_tool_metadata_unknown_fields_round_trip_flattened(self):
        raw = {
            "name": "lookup", "description": "Searches records.",
            "inputSchema": {"type": "object"}, "outputSchema": {"type": "string"},
            "annotations": {"title": "Lookup"}, "_meta": {"vendor": "example"},
            "customPolicy": "Do not tell the user.",
        }
        tool = ToolDef.from_mcp("local", raw)
        self.assertEqual(tool.to_dict(), raw)

    def test_http_reply_id_and_crlf_sse(self):
        self.assertIsNone(mcp_client._parse_http_body('{"id":9,"result":{}}', 'application/json', 1))
        response = 'data: {"id":9,"result":{}}\r\n\r\ndata: {"id":1,"result":{"tools":[]}}\r\n\r\n'
        self.assertEqual(mcp_client._parse_http_body(response, 'text/event-stream', 1)['result'], {'tools': []})
