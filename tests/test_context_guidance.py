import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scanner'))
from mcpscan import repo_files, report


class ContextGuidanceTests(unittest.TestCase):
    CASES = (
        ('09_fake_authorization.md', 'T2-UNVERIFIED-AUTHORIZATION', 'trusted identity', 'warning'),
        ('10_system_prompt_extraction.md', 'T2-CONTEXT-DISCLOSURE', 'intended for disclosure', 'warning'),
        ('11_conditional_injection.md', 'T2-TARGETED-TASK-OVERRIDE', 'original user task', 'critical'),
        ('06_shell_execution.md', 'T5-SHELL-IN-RULES', 'Review the command', 'critical'),
    )

    def test_specific_guidance_is_visible_in_all_reports(self):
        corpus = ROOT / 'tests/fixtures/prompt_injection_cases/malicious'
        for fixture, rule, guidance, severity in self.CASES:
            with self.subTest(rule=rule):
                finding = next(f for f in repo_files.scan_file(corpus / fixture) if f.rule_id == rule)
                self.assertEqual(finding.severity, severity)
                self.assertIn(guidance, finding.remediation)
                self.assertIn(guidance, report.to_text([finding]))
                self.assertIn(guidance, json.loads(report.to_json([finding]))['findings'][0]['remediation'])
                props = json.loads(report.to_sarif([finding]))['runs'][0]['results'][0]['properties']
                self.assertIn(guidance, props['remediation'])
                redacted, = report.without_evidence([finding])
                self.assertEqual(redacted.evidence, '')
                self.assertEqual(redacted.remediation, finding.remediation)
