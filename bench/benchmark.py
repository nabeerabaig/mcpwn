#!/usr/bin/env python3
"""Measure detection rate and false-positive rate of the static engine on bench/corpus.py.

  python3 bench/benchmark.py                 # static only
  python3 bench/benchmark.py --dynamic       # also confirm/clear with a test model (needs a backend)
  python3 bench/benchmark.py --json out.json

A sample counts as 'flagged' when its highest-confidence finding reaches --threshold (default 0.5, warning).
"""
import argparse
import json
import math
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
    coverage_by = {}
    siblings = {"list_files", "git_status", "create_customer", "run_tests", "search",
                "get_row", "get_ticket", "start_export"}
    for t in tools:
        findings_by[t.name], coverage_by[t.name] = engine.scan_tool_with_coverage(t, siblings)
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
        for source_id, verdict in stats.get("tool_verdicts", {}).items():
            record = coverage_by.get(source_id.split("/", 1)[-1])
            if record is not None:
                record["dynamic_validation_performed"] = True
                record["dynamic_validation_status"] = verdict
    for (cat, name, *_), t in zip(samples, tools):
        fs = findings_by[t.name]
        top = max((f.confidence for f in fs), default=0.0)
        coverage = coverage_by[t.name]
        results.append({"category": cat, "name": name, "source_type": "mcp_tool_definition",
                        "top": top, "flagged": top >= threshold,
                        "tiers": sorted({f.tier for f in fs if f.confidence >= threshold}),
                        "coverage_status": coverage["status"],
                        "fields_discovered": coverage["fields_discovered"],
                        "fields_scanned": coverage["fields_scanned"],
                        "unsupported_fields": len(coverage["unsupported_fields"]),
                        "dynamic_validation_performed": coverage["dynamic_validation_performed"],
                        "dynamic_validation_status": coverage["dynamic_validation_status"],
                        "rules": sorted({f.rule_id for f in fs if f.confidence >= threshold})})
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--dynamic", action="store_true")
    ap.add_argument("--json")
    a = ap.parse_args()
    if not math.isfinite(a.threshold) or not 0.0 <= a.threshold <= 1.0:
        ap.error("--threshold must be finite and between 0 and 1")

    mal = run(MALICIOUS, a.dynamic, a.threshold)
    ben = run(BENIGN, a.dynamic, a.threshold)
    tp = sum(r["flagged"] for r in mal)
    fp = sum(r["flagged"] for r in ben)
    print(f"mode: {'static + dynamic' if a.dynamic else 'static'}   threshold: {a.threshold}")
    print(f"malicious: {len(mal)}  detected: {tp}  detection rate: {tp / len(mal):.1%}")
    print(f"benign:    {len(ben)}  flagged:  {fp}  false-positive rate: {fp / len(ben):.1%}")
    fn = len(mal) - tp
    tn = len(ben) - fp
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision is not None and precision + recall else 0.0
    print(f"confusion matrix: TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"precision: {precision:.1%}" if precision is not None else "precision: n/a (no flagged samples)")
    print(f"recall:    {recall:.1%}")
    print(f"F1:        {f1:.1%}")
    print("per-layer contribution (cases with a finding at threshold; layers may overlap):")
    for tier in (1, 2, 3, 4, 5, 6):
        hits = sum(tier in row["tiers"] for row in mal)
        print(f"  tier {tier}: {hits}/{len(mal)} malicious cases")
    print("source types:", "mcp_tool_definition across all current corpus cases")
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
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump({
                "summary": {
                    "true_positives": tp, "false_positives": fp,
                    "true_negatives": tn, "false_negatives": fn,
                    "precision": precision, "recall": recall, "f1": f1,
                    "source_type": "mcp_tool_definition",
                    "scan_failures": sum(row["coverage_status"] == "failed" for row in mal + ben),
                    "unsupported_cases": sum(row["coverage_status"] in ("unsupported", "partially_scanned")
                                              for row in mal + ben),
                    "fields_discovered": sum(row["fields_discovered"] for row in mal + ben),
                    "fields_scanned": sum(row["fields_scanned"] for row in mal + ben),
                    "dynamic_validation_performed": sum(row["dynamic_validation_performed"] for row in mal + ben),
                    "dynamic_inconclusive": sum(row["dynamic_validation_status"] == "inconclusive" for row in mal + ben),
                    "dynamic_confirmed": sum(row["dynamic_validation_status"] == "confirmed" for row in mal + ben),
                    "dynamic_cleared": sum(row["dynamic_validation_status"] == "cleared" for row in mal + ben),
                },
                "malicious": mal, "benign": ben,
            }, f, indent=2)


if __name__ == "__main__":
    main()
