import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scanner"))

from mcpscan import tier3
from mcpscan.models import Finding, ToolDef


class Tier3ValidationTests(unittest.TestCase):
    def setUp(self):
        self.tool = ToolDef("server", "lookup", "Looks up a record.", {"type": "object"})

    def test_parse_accepts_only_well_typed_verdicts(self):
        valid = tier3._parse('{"injection": false, "confidence": 0.8, "reason": "ordinary documentation"}')
        self.assertEqual(valid, {"injection": False, "confidence": 0.8, "reason": "ordinary documentation"})

        invalid = [
            '{"injection": "false", "confidence": 0.9, "reason": "wrong boolean type"}',
            '{"injection": 0, "confidence": 0.9, "reason": "wrong boolean type"}',
            '{"injection": true, "confidence": true, "reason": "boolean is not a score"}',
            '{"injection": true, "confidence": NaN, "reason": "non-finite"}',
            '{"injection": true, "confidence": Infinity, "reason": "non-finite"}',
            '{"injection": true, "confidence": 0.9, "confidence": 0.1, "reason": "duplicate field"}',
            '{"injection": true, "confidence": 9999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999, "reason": "oversized integer"}',
            '{"injection": true, "confidence": -0.1, "reason": "out of range"}',
            '{"injection": true, "confidence": 1.1, "reason": "out of range"}',
            '{"injection": true, "confidence": 0.9, "reason": 12}',
            'not json',
        ]
        for raw in invalid:
            with self.subTest(raw=raw):
                self.assertIsNone(tier3._parse(raw))

    def test_parse_bounds_reason_length(self):
        parsed = tier3._parse('{"injection": false, "confidence": 0.7, "reason": "' + ("x" * 500) + '"}')
        self.assertIsNotNone(parsed)
        self.assertEqual(len(parsed["reason"]), 300)

    def test_invalid_verdict_cannot_confirm_or_clear_findings(self):
        finding = Finding("T2-TEST", 2, "Test", "Test finding", 0.8)
        for verdict in (
            {"injection": "false", "confidence": 1.0, "reason": "bad type"},
            {"injection": False, "confidence": float("nan"), "reason": "bad score"},
            {"injection": True, "confidence": 0.9, "reason": 1},
        ):
            with self.subTest(verdict=verdict):
                original = finding.confidence
                with patch.object(tier3, "classify", return_value=verdict):
                    self.assertEqual(tier3.apply(self.tool, [finding]), [])
                self.assertEqual(finding.confidence, original)

    def test_valid_negative_verdict_only_demotes_tier_two(self):
        tier_one = Finding("T1-TEST", 1, "Structural", "Hidden marker", 0.9)
        tier_two = Finding("T2-TEST", 2, "Context", "Contextual flag", 0.8)
        with patch.object(tier3, "classify", return_value={
            "injection": False, "confidence": 0.9, "reason": "No manipulation found"
        }):
            self.assertEqual(tier3.apply(self.tool, [tier_one, tier_two]), [])
        self.assertEqual(tier_one.confidence, 0.9)
        self.assertEqual(tier_two.confidence, 0.32)

    def test_valid_positive_verdict_adds_finding(self):
        with patch.object(tier3, "classify", return_value={
            "injection": True, "confidence": 0.8, "reason": "Untrusted directive"
        }):
            findings = tier3.apply(self.tool, [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "T3-LLM-CONFIRMED")
        self.assertEqual(findings[0].confidence, 0.9)


if __name__ == "__main__":
    unittest.main()
