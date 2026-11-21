#!/usr/bin/env python3
"""Evaluate separately sourced benign MCP suites with pinned fixture bytes."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

from evaluate_benign import evaluate, SEVERITY_ORDER

DEFAULT = Path(__file__).with_name("benign-suites.json")
KINDS = ("synthetic", "doc-derived", "upstream-snapshot")
FIELDS = {"id", "kind", "fixture", "source", "sha256", "max_flagged"}
SUITE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")


def run(manifest: Path, selected: set[str]) -> dict:
    manifest = manifest.resolve()
    root = manifest.parent
    data = json.loads(manifest.read_text(encoding="utf-8"))
    if (not isinstance(data, dict) or set(data) != {"version", "suites"}
            or type(data["version"]) is not int or data["version"] != 1
            or not isinstance(data["suites"], list) or not data["suites"]):
        raise ValueError("expected a nonempty version 1 suite manifest")
    plans = {}
    used_paths = set()
    for spec in data["suites"]:
        if not isinstance(spec, dict) or set(spec) != FIELDS:
            raise ValueError("invalid suite fields")
        name = spec["id"]
        if not isinstance(name, str) or not SUITE_ID.fullmatch(name) or name in plans:
            raise ValueError("invalid or duplicate suite ID")
        if spec["kind"] not in KINDS or not isinstance(spec["source"], str) or not spec["source"].strip():
            raise ValueError(f"{name}: invalid provenance")
        fixture = spec["fixture"]
        if not isinstance(fixture, str) or not fixture or Path(fixture).is_absolute():
            raise ValueError(f"{name}: expected a relative fixture path")
        path = (root / fixture).resolve()
        if not path.is_relative_to(root) or path in used_paths:
            raise ValueError(f"{name}: fixture escapes the manifest directory or is reused")
        used_paths.add(path)
        if not isinstance(spec["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", spec["sha256"]):
            raise ValueError(f"{name}: expected a lowercase SHA-256")
        budget = spec["max_flagged"]
        if (not isinstance(budget, dict) or not budget or set(budget) - set(SEVERITY_ORDER)
                or any(type(v) is not int or v < 0 for v in budget.values())):
            raise ValueError(f"{name}: expected valid nonnegative threshold budgets")
        plans[name] = (spec, path)
    if selected - plans.keys():
        raise ValueError("unknown suite selection")

    suites = []
    for name, (spec, path) in sorted(plans.items()):
        if selected and name not in selected:
            continue
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != spec["sha256"]:
            raise ValueError(f"{name}: missing fixture or SHA-256 mismatch")
        result = evaluate([path])
        counts = result["by_highest_severity"]
        n = result["tools_scanned"]
        thresholds = {}
        for severity, rank in SEVERITY_ORDER.items():
            flagged = sum(counts[s] for s, r in SEVERITY_ORDER.items() if r >= rank)
            budget = spec["max_flagged"].get(severity)
            thresholds[severity] = {"flagged": flagged, "rate": flagged / n, "max_flagged": budget,
                                    "passed": None if budget is None else flagged <= budget}
        tools = [{k: v for k, v in row.items() if k not in ("fixture", "flagged")}
                 for row in result["tools"] if row["highest_severity"] is not None]
        suites.append({**spec, "tools_scanned": n, "thresholds": thresholds, "flagged_tools": tools,
                       "passed": all(t["passed"] is not False for t in thresholds.values())})
    return {"version": 1, "passed": all(suite["passed"] for suite in suites), "suites": suites}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT)
    parser.add_argument("--suite", action="append", default=[], help="only run this suite (repeatable)")
    parser.add_argument("--json", action="store_true", help="emit per-suite machine-readable results")
    args = parser.parse_args()
    try:
        report = run(args.manifest, set(args.suite))
    except (ValueError, OSError, TypeError, RecursionError) as exc:
        parser.exit(2, f"Invalid benchmark suite: {exc}\n")
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for suite in report["suites"]:
            outcome = "PASS" if suite["passed"] else "FAIL"
            n = suite["tools_scanned"]
            counts = ", ".join(f"{key}+: {cell['flagged']}/{n}" for key, cell in suite["thresholds"].items())
            print(f"{outcome} {suite['id']} ({suite['kind']}): {counts}")
    return int(not report["passed"])


if __name__ == "__main__":
    sys.exit(main())
