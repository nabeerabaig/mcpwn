"""Isolated, labelled benchmark for prompt-injection detection quality.

Run with:
    python -m unittest tests.test_prompt_injection_benchmark -v

The benchmark reports precision/recall and per-case misses. It does not pretend
that a passing test suite proves broad real-world detection coverage.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scanner"))

from mcpscan.repo_files import scan_file_with_coverage  # noqa: E402

CORPUS = ROOT / "tests" / "fixtures" / "prompt_injection_cases"
THRESHOLD = 0.5


def evaluate_case(path: Path, expected_malicious: bool) -> dict:
    findings, coverage = scan_file_with_coverage(path)
    flagged = any(item.confidence >= THRESHOLD for item in findings)
    return {
        "case": path.relative_to(CORPUS).as_posix(),
        "expected": "malicious" if expected_malicious else "benign",
        "flagged": flagged,
        "correct": flagged == expected_malicious,
        "rules": sorted({item.rule_id for item in findings if item.confidence >= THRESHOLD}),
        "coverage_status": coverage["status"],
    }


def run_benchmark() -> dict:
    malicious = sorted((CORPUS / "malicious").glob("*.md"))
    benign = sorted((CORPUS / "benign").glob("*.md"))
    if not malicious or not benign:
        raise RuntimeError("Benchmark requires both malicious and benign fixtures")

    results = (
        [evaluate_case(path, True) for path in malicious]
        + [evaluate_case(path, False) for path in benign]
    )
    tp = sum(item["expected"] == "malicious" and item["flagged"] for item in results)
    fn = sum(item["expected"] == "malicious" and not item["flagged"] for item in results)
    fp = sum(item["expected"] == "benign" and item["flagged"] for item in results)
    tn = sum(item["expected"] == "benign" and not item["flagged"] for item in results)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "threshold": THRESHOLD,
        "counts": {"true_positive": tp, "false_negative": fn,
                   "false_positive": fp, "true_negative": tn},
        "metrics": {"precision": round(precision, 4),
                    "recall": round(recall, 4), "f1": round(f1, 4)},
        "cases": results,
    }


class PromptInjectionBenchmarkTests(unittest.TestCase):
    def test_corpus_is_labelled_and_fully_scanned(self):
        result = run_benchmark()
        incomplete = [item["case"] for item in result["cases"]
                      if item["coverage_status"] != "fully_scanned"]
        self.assertEqual(incomplete, [], f"Fixtures not fully scanned: {incomplete}")
        self.assertGreaterEqual(len(result["cases"]), 10)

    def test_metrics_are_bounded_and_misses_are_visible(self):
        result = run_benchmark()
        for metric in result["metrics"].values():
            self.assertGreaterEqual(metric, 0.0)
            self.assertLessEqual(metric, 1.0)
        # Deliberately do not require perfect recall/precision. The point is to
        # expose the current baseline honestly before changing detector rules.
        print("\nMCPWN prompt-injection benchmark:")
        print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    unittest.main()
