#!/usr/bin/env python3
"""Measure false positives on saved, known-benign MCP tool definitions."""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scanner"))

from mcpscan import engine
from mcpscan.cli import collect_tools
from mcpscan.models import SEVERITY_ORDER

DEFAULT_FIXTURES = [ROOT / "bench" / name for name in
                    ("benign_pilot.json", "benign_public.json")]


def evaluate(paths: list[Path], threshold: str = "warning") -> dict:
    """Count each tool once; treat files as independent server snapshots."""
    def load():
        for path in paths:
            tools, _ = collect_tools(argparse.Namespace(tools_json=[path]))
            yield path, tools
    return evaluate_loaded(load(), threshold)


def evaluate_loaded(snapshots, threshold: str = "warning") -> dict:
    """Apply the same tool-level scoring to every input format."""
    rows = []
    for path, tools in snapshots:
        keys = [(tool.server, tool.name) for tool in tools]
        if not keys or any(not name.strip() for _, name in keys):
            raise ValueError(f"{path}: expected a nonempty set of named tools")
        if len(set(keys)) != len(keys):
            raise ValueError(f"{path}: duplicate tool name within a server")
        by_tool = defaultdict(list)
        for finding in engine.scan_tools(tools):
            by_tool[finding.server, finding.tool].append(finding)
        for server, tool in sorted(keys):
            findings = by_tool[server, tool]
            highest = max((f.severity for f in findings),
                          key=SEVERITY_ORDER.__getitem__, default=None)
            rows.append({
                "fixture": str(path), "server": server, "tool": tool,
                "highest_severity": highest,
                "flagged": highest is not None and
                SEVERITY_ORDER[highest] >= SEVERITY_ORDER[threshold],
                "rules": sorted({f.rule_id for f in findings}),
            })
    if not rows:
        raise ValueError("at least one fixture is required")
    flagged = sum(row["flagged"] for row in rows)
    counts = Counter(row["highest_severity"] or "none" for row in rows)
    return {"threshold": threshold, "tools_scanned": len(rows),
            "flagged_tools": flagged, "false_positive_rate": flagged / len(rows),
            "by_highest_severity": {key: counts[key] for key in ("none", *SEVERITY_ORDER)},
            "tools": rows}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixtures", nargs="*", type=Path,
                        help="Known-benign --tools-json snapshots (default: both bundled fixtures)")
    parser.add_argument("--threshold", choices=SEVERITY_ORDER, default="warning")
    parser.add_argument("--json", action="store_true", help="Print machine-readable results")
    parser.add_argument("--max-flagged", type=int,
                        help="Exit 1 if more than this many tools are flagged")
    args = parser.parse_args(argv)
    if args.max_flagged is not None and args.max_flagged < 0:
        parser.error("--max-flagged must be nonnegative")
    paths = args.fixtures or DEFAULT_FIXTURES
    if len({path.resolve() for path in paths}) != len(paths):
        parser.error("the same fixture cannot be counted twice")
    try:
        result = evaluate(paths, args.threshold)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        parser.exit(2, f"Invalid benign fixture: {exc}\n")
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"{result['flagged_tools']}/{result['tools_scanned']} benign tools flagged "
              f"at {args.threshold} or higher ({result['false_positive_rate']:.1%}).")
        for row in result["tools"]:
            if row["highest_severity"]:
                print(f"  {row['fixture']}: {row['server']}/{row['tool']} "
                      f"({row['highest_severity']}): {', '.join(row['rules'])}")
    return int(args.max_flagged is not None and result["flagged_tools"] > args.max_flagged)


if __name__ == "__main__":
    sys.exit(main())
