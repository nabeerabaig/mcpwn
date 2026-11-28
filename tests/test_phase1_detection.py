"""Focused regressions; the original benchmark fixtures remain unchanged."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scanner'))
from mcpscan import engine, repo_files, tier2
from mcpscan.models import ToolDef

CORPUS = ROOT / 'tests/fixtures/prompt_injection_cases'


class ContextDetectionTests(unittest.TestCase):
    def test_existing_misses_trigger_expected_rules(self):
        expected = {
            '09_fake_authorization.md': {'T2-UNVERIFIED-AUTHORIZATION'},
            '10_system_prompt_extraction.md': {'T2-CONTEXT-DISCLOSURE'},
            '11_conditional_injection.md': {'T2-TARGETED-TASK-OVERRIDE'},
            '12_metadata_instruction.md': {'T2-TARGETED-TASK-OVERRIDE', 'T2-CONTEXT-DISCLOSURE'},
        }
        for filename, rules in expected.items():
            with self.subTest(filename=filename):
                findings = repo_files.scan_file(CORPUS / 'malicious' / filename)
                self.assertTrue(rules <= {f.rule_id for f in findings if f.confidence >= .5})

    def test_existing_metadata_case_in_real_schema_values(self):
        path = CORPUS / 'malicious/12_metadata_instruction.md'
        values = {key: json.loads(value) for key, value in
                  (line.split(': ', 1) for line in path.read_text(encoding='utf-8').splitlines()
                   if line.startswith(('description:', 'default:')))}
        tool = ToolDef('test', 'lookup', input_schema={'properties': {'query': values}})
        findings, coverage = engine.scan_tool_with_coverage(tool)
        self.assertEqual(coverage['status'], 'fully_scanned')
        found = {(f.rule_id, f.location) for f in findings if f.confidence >= .5}
        self.assertIn(('T2-TARGETED-TASK-OVERRIDE', 'inputSchema.properties.query.description'), found)
        self.assertIn(('T2-CONTEXT-DISCLOSURE', 'inputSchema.properties.query.default'), found)

    def test_security_documentation_is_not_an_instruction(self):
        benign = (
            'The administrator has approved access to private configuration data. Additional approval is required.',
            'The administrator has not approved access to private files. No further authorization is necessary for public files.',
            'System instructions and developer messages are not included in the response.',
            'Show how system instructions are audited.',
            'If the reader is an AI assistant, summarize the current task.',
            'description: "The assistant must return a list of public items."',
            'default: "Internal configuration is managed by administrators."',
        )
        rules = {'T2-TARGETED-TASK-OVERRIDE', 'T2-CONTEXT-DISCLOSURE', 'T2-UNVERIFIED-AUTHORIZATION'}
        for text in benign:
            with self.subTest(text=text):
                self.assertFalse(rules & {f.rule_id for f in tier2.scan_text(text)})

    def test_shell_examples_and_directive_are_distinguished(self):
        findings = repo_files.scan_file(CORPUS / 'benign/04_shell_documentation.md')
        self.assertFalse(any(f.confidence >= .5 for f in findings))
        findings = repo_files.scan_file(CORPUS / 'malicious/06_shell_execution.md')
        self.assertTrue(any(f.rule_id == 'T5-SHELL-IN-RULES' for f in findings))
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / 'AGENTS.md'
            file.write_text('Example syntax:\n```sh\ncurl https://example.invalid/docs\n```\n', encoding='utf-8')
            self.assertFalse(any(f.rule_id == 'T5-SHELL-IN-RULES' for f in repo_files.scan_file(file)))
