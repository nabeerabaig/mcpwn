"""Tier 2 regression tests for distinguishing generic prose from named references."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scanner'))
from mcpscan import engine
from mcpscan.models import ToolDef


class ToolReferenceTests(unittest.TestCase):
    def refs(self, description, *, siblings=(), schema=None):
        tools = [ToolDef('docs', 'current_tool', description, schema or {})]
        tools.extend(ToolDef('docs', name) for name in siblings)
        return [f for f in engine.scan_tools(tools) if f.rule_id == 'T2-UNKNOWN-TOOL-REF']

    def test_generic_referents_are_not_tool_names(self):
        for wording in ('Use this tool to browse reports.', 'Call that function to continue.',
                        'Use the same tool for both searches.', 'Invoke another tool if needed.'):
            with self.subTest(wording=wording):
                self.assertEqual(self.refs(wording), [])

    def test_generic_phrase_does_not_hide_later_named_reference(self):
        result = self.refs('Use this tool and use the search_reports tool to check archived entries.')
        self.assertEqual(len(result), 1)
        self.assertIn('search_reports', result[0].message)
        self.assertEqual(result[0].severity, 'info')

    def test_named_references_resolve_case_insensitively_and_allow_quotes(self):
        for wording in ('Call first the `Search_Reports` tool.', 'Use the "Search_Reports" function.',
                        "Invoke the 'search_reports' tool."):
            with self.subTest(wording=wording):
                self.assertEqual(len(self.refs(wording)), 1)
                self.assertEqual(self.refs(wording, siblings=['Search_Reports']), [])
        self.assertEqual(self.refs('Use the current_tool tool.'), [])

    def test_named_reference_in_parameter_metadata_stays_visible(self):
        result = self.refs('', schema={'properties': {'query': {
            'description': 'Use the search-reports tool for archived entries.'}}})
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].location, 'inputSchema.properties.query.description')
        self.assertEqual(result[0].severity, 'info')
