#!/usr/bin/env python3
"""Measure detection rate and false-positive rate of the static engine on bench/corpus.py.

  python3 bench/benchmark.py                 # static only
  python3 bench/benchmark.py --dynamic       # also confirm/clear with a test model (needs a backend)
  python3 bench/benchmark.py --json out.json

A sample counts as 'flagged' when its highest-confidence finding reaches --threshold (default 0.5, warning).
"""
import argparse
import json
import os
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "scanner"))
sys.path.insert(0, HERE)

from corpus import BENIGN, MALICIOUS  # noqa: E402
from mcpscan import dynamic, engine  # noqa: E402
from mcpscan.models import ToolDef  # noqa: E402


def run(samples, use_dynamic, threshold):
    tools = [ToolDef("bench", f"{cat}:{name}", desc, schema) for cat, name, desc, schema in samples]
    results = []
    findings_by = {}
    for t in tools:
        findings_by[t.name] = engine.scan_tool(t, {"list_files", "git_status", "create_customer", "run_tests", "search",
                                                   "get_row", "get_ticket", "start_export"})
    if use_dynamic:
        allf = [f for fs in findings_by.values() for f in fs]
        for t in tools:
            for f in findings_by[t.name]:
                f.tool = t.name
        allf, notes, stats = dynamic.apply(tools, allf)
        for n in notes:
            print("note:", n, file=sys.stderr)
        print("dynamic stats:", stats, file=sys.stderr)
        findings_by = {t.name: [f for f in allf if f.tool == t.name] for t in tools}
    for (cat, name, *_), t in zip(samples, tools):
        fs = findings_by[t.name]
        top = max((f.confidence for f in fs), default=0.0)
        results.append({"category": cat, "name": name, "top": top, "flagged": top >= threshold,
                        "rules": sorted({f.rule_id for f in fs if f.confidence >= threshold})})
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--dynamic", action="store_true")
    ap.add_argument("--json")
    a = ap.parse_args()

    mal = run(MALICIOUS, a.dynamic, a.threshold)
    ben = run(BENIGN, a.dynamic, a.threshold)
    tp = sum(r["flagged"] for r in mal)
    fp = sum(r["flagged"] for r in ben)
    print(f"mode: {'static + dynamic' if a.dynamic else 'static'}   threshold: {a.threshold}")
    print(f"malicious: {len(mal)}  detected: {tp}  detection rate: {tp / len(mal):.1%}")
    print(f"benign:    {len(ben)}  flagged:  {fp}  false-positive rate: {fp / len(ben):.1%}")
    flagged_total = tp + fp
    if flagged_total:
        print(f"precision: {tp / flagged_total:.1%}")
    print("\nper-category detection:")
    cats = defaultdict(lambda: [0, 0])
    for r in mal:
        cats[r["category"]][1] += 1
        cats[r["category"]][0] += r["flagged"]
    for c, (d, n) in cats.items():
        print(f"  {c:10s} {d}/{n}")
    misses = [r for r in mal if not r["flagged"]]
    if misses:
        print("\nmissed malicious samples:")
        for r in misses:
            print(f"  - {r['category']}:{r['name']} (top confidence {r['top']})")
    fps = [r for r in ben if r["flagged"]]
    if fps:
        print("\nfalse positives:")
        for r in fps:
            print(f"  - {r['category']}:{r['name']} (top confidence {r['top']}, rules {r['rules']})")
    if a.json:
        with open(a.json, "w") as f:
            json.dump({"malicious": mal, "benign": ben}, f, indent=2)


if __name__ == "__main__":
    main()
