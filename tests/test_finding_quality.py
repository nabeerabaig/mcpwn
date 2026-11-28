import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scanner'))
from mcpscan import engine
from mcpscan.models import Finding
from mcpscan.normalize import NORMALIZED_SUFFIX, OriginalEvidence, normalize_text


class FindingQualityTests(unittest.TestCase):
    def finding(self, evidence, *, location='file', source='AGENTS.md', confidence=.6):
        return Finding('TEST', 2, 'Title', 'Message', confidence, location=location,
                       source=source, evidence=evidence)

    def test_normalized_excerpt_comes_from_late_original_line(self):
        original = 'intro ' * 100 + '\nA ｃａｆé entry\n'
        restored = OriginalEvidence(normalize_text(original)).restore('café entry')
        self.assertEqual(restored, 'ｃａｆé entry')

    def test_ambiguous_or_fabricated_excerpt_is_omitted(self):
        evidence = OriginalEvidence(normalize_text('ｃａｆé beside café'))
        self.assertEqual(evidence.restore('café'), '')
        self.assertEqual(evidence.restore('missing'), '')

    def test_same_evidence_in_both_views_prefers_raw_on_a_tie(self):
        raw = self.finding('exact phrase')
        normalized = self.finding('exact phrase', location='file' + NORMALIZED_SUFFIX)
        self.assertEqual(engine.dedupe([normalized, raw]), [raw])
        stronger = self.finding('exact phrase', location='file' + NORMALIZED_SUFFIX, confidence=.9)
        self.assertEqual(engine.dedupe([raw, stronger]), [stronger])

    def test_distinct_sources_locations_and_full_excerpt_stay_separate(self):
        prefix = 'x' * 60
        rows = [self.finding(prefix + ' one'), self.finding(prefix + ' two'),
                self.finding(prefix + ' one', source='CLAUDE.md'),
                self.finding(prefix + ' one', location='file#key')]
        self.assertEqual(engine.dedupe(rows), rows)
