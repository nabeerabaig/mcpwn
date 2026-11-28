#!/usr/bin/env python3
"""Evaluate the frozen, author-curated holdout set without changing detector thresholds."""
from __future__ import annotations

import argparse
import hashlib
import re
import json
from pathlib import Path
import sys
import subprocess
import platform
from datetime import datetime, timezone
from collections import Counter, defaultdict

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scanner"))

from mcpscan import engine
from mcpscan.models import ToolDef

DEFAULT = Path(__file__).with_name("holdout-v1.json")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key in dataset")
        result[key] = value
    return result


def evaluate(path: Path = DEFAULT, *, expected_digest: str | None = None) -> dict:
    raw_dataset = path.read_bytes()
    digest = hashlib.sha256(raw_dataset).hexdigest()
    if expected_digest is not None:
        if not re.fullmatch(r"[a-fA-F0-9]{64}", expected_digest):
            raise ValueError("expected SHA-256 must be 64 hexadecimal digits")
        if digest != expected_digest.lower():
            raise ValueError("dataset SHA-256 does not match the reviewed copy")
    data = json.loads(raw_dataset, object_pairs_hook=unique_object)
    if (not isinstance(data, dict) or type(data.get("version")) is not int or data["version"] != 1
            or not isinstance(data.get("cases"), list) or not data["cases"]):
        raise ValueError("expected a nonempty version 1 holdout dataset")
    threshold = data.get("threshold", 0.5)
    if type(threshold) not in (int, float) or not 0 < threshold <= 1:
        raise ValueError("threshold must be greater than 0 and at most 1")
    seen = set()
    rows = []
    for case in data["cases"]:
        if (not isinstance(case, dict) or set(case) != {"id", "label", "category", "source_type", "tool"}
                or case["label"] not in ("malicious", "benign")
                or not isinstance(case["id"], str) or not case["id"] or case["id"] in seen
                or not isinstance(case["category"], str) or not isinstance(case["source_type"], str)
                or not isinstance(case["tool"], dict)):
            raise ValueError("invalid or duplicate holdout case")
        seen.add(case["id"])
        raw = case["tool"]
        if (not isinstance(raw.get("name"), str) or not raw["name"].strip()
                or not isinstance(raw.get("description", ""), str)
                or not isinstance(raw.get("inputSchema", {}), dict)):
            raise ValueError(f"{case['id']}: malformed tool definition")
        tool = ToolDef.from_mcp("holdout", raw, source=str(path))
        findings, coverage = engine.scan_tool_with_coverage(tool)
        top = max((finding.confidence for finding in findings), default=0.0)
        tiers = sorted({finding.tier for finding in findings if finding.confidence >= threshold})
        flagged = top >= threshold
        outcome = (
            "TP" if case["label"] == "malicious" and flagged else
            "FN" if case["label"] == "malicious" else
            "FP" if flagged else "TN"
        )
        rows.append({
            "id": case["id"], "label": case["label"],
            "predicted_label": "malicious" if flagged else "benign",
            "outcome": outcome,
            "category": case["category"],
            "source_type": case["source_type"], "flagged": flagged,
            "top_confidence": top, "tiers": tiers,
            "rules": sorted({finding.rule_id for finding in findings if finding.confidence >= threshold}),
            "coverage_status": coverage["status"],
            "fields_discovered": coverage["fields_discovered"],
            "fields_scanned": coverage["fields_scanned"],
        })
    malicious = [row for row in rows if row["label"] == "malicious"]
    benign = [row for row in rows if row["label"] == "benign"]
    if not malicious or not benign:
        raise ValueError("holdout requires both benign and malicious labels")
    tp = sum(row["flagged"] for row in malicious)
    fn = len(malicious) - tp
    fp = sum(row["flagged"] for row in benign)
    tn = len(benign) - fp
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision is not None and precision + recall else 0.0
    categories = defaultdict(lambda: {"cases": 0, "flagged": 0})
    source_types = defaultdict(lambda: {"cases": 0, "flagged": 0})
    layer_hits = Counter()
    for row in rows:
        for bucket, key in ((categories, row["category"]), (source_types, row["source_type"])):
            bucket[key]["cases"] += 1
            bucket[key]["flagged"] += int(row["flagged"])
        if row["label"] == "malicious":
            layer_hits.update(row["tiers"])

    try:
        scanner_commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        ).stdout.strip()
    except (subprocess.SubprocessError, OSError):
        scanner_commit = None

    evaluated_at = datetime.now(timezone.utc).isoformat()
    false_positives = [row["id"] for row in rows if row["outcome"] == "FP"]
    false_negatives = [row["id"] for row in rows if row["outcome"] == "FN"]
    incomplete_coverage_cases = [
        row["id"] for row in rows if row["coverage_status"] != "fully_scanned"
    ]

    return {
        "dataset": data.get("name", path.name),
        "scanner_commit": scanner_commit,
        "python_version": platform.python_version(),
        "evaluated_at_utc": evaluated_at,
        "evaluation_scope": {
            "includes": "MCP tool metadata scanning (tool names, descriptions, and input schemas)",
            "excludes": [
                "agent instruction-file scanning",
                "runtime model behaviour",
                "end-to-end agent execution",
            ],
        },
        "provenance": data.get("provenance", ""),
        "threshold": threshold,
        "sha256": digest,
        "complete_coverage": all(row["coverage_status"] == "fully_scanned" for row in rows),
        "summary": {
            "true_positives": tp, "false_positives": fp,
            "true_negatives": tn, "false_negatives": fn,
            "precision": precision, "recall": recall, "f1": f1,
            "malicious_cases": len(malicious), "benign_cases": len(benign),
            "scan_failures": sum(row["coverage_status"] == "failed" for row in rows),
            "unsupported_cases": sum(row["coverage_status"] in ("unsupported", "partially_scanned") for row in rows),
        },
        "false_positive_cases": false_positives,
        "false_negative_cases": false_negatives,
        "incomplete_coverage_cases": incomplete_coverage_cases,
        "by_category": dict(categories),
        "by_source_type": dict(source_types),
        "malicious_layer_hits": {f"tier_{tier}": layer_hits[tier] for tier in range(1, 7)},
        "cases": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--expected-sha256", help="verify exact dataset bytes before evaluation")
    parser.add_argument("--require-complete", action="store_true",
                        help="emit report but exit 2 if any case was not fully scanned")
    args = parser.parse_args()
    try:
        result = evaluate(args.dataset, expected_digest=args.expected_sha256)
    except (OSError, ValueError, TypeError, RecursionError, KeyError) as exc:
        parser.exit(2, f"holdout evaluation failed: {exc}\n")
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"{result['dataset']} at threshold {result['threshold']}")
        print(json.dumps(result["summary"], indent=2))
        print(f"Dataset SHA-256: {result['sha256']}")
        print(f"Provenance: {result['provenance'] or 'not supplied'}")
    if args.require_complete and not result["complete_coverage"]:
        print("holdout evaluation incomplete: metrics should not be used for comparison", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
