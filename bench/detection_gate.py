#!/usr/bin/env python3
"""Detect case-level regressions in the existing labeled static corpus."""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import sys

from benchmark import BENIGN, MALICIOUS, run

BASELINE = Path(__file__).with_name('detection-baseline.json')
LABELS = ('malicious', 'benign')


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON field')
        result[key] = value
    return result


def load_baseline(path):
    data = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=unique_object)
    if (not isinstance(data, dict) or set(data) != {'version', 'threshold', 'cases'}
            or type(data['version']) is not int or data['version'] != 1):
        raise ValueError('expected version 1 detection baseline')
    threshold = data['threshold']
    if type(threshold) not in (int, float) or not 0 < threshold <= 1 or not math.isfinite(threshold):
        raise ValueError('threshold must be greater than 0 and at most 1')
    expected = data['cases']
    if (not isinstance(expected, dict) or set(expected) != set(LABELS)
            or any(not isinstance(group, dict) or not group
                   or any(type(value) is not bool for value in group.values()) for group in expected.values())):
        raise ValueError('baseline must map both case groups to boolean alert states')
    if expected['malicious'].keys() & expected['benign'].keys():
        raise ValueError('case identities must be unique across groups')
    return threshold, expected


def compare(expected, results):
    summary, regressions, improvements, remaining = {}, [], [], []
    for label in LABELS:
        rows = results[label]
        actual = {f"{row['category']}:{row['name']}": row for row in rows}
        if len(actual) != len(rows) or actual.keys() != expected[label].keys():
            raise ValueError(f'{label} case identities differ from baseline; review corpus changes explicitly')
        should_flag = label == 'malicious'
        summary[label] = {'cases': len(rows), 'flagged': sum(row['flagged'] for row in rows)}
        for case, row in sorted(actual.items()):
            old, new = expected[label][case], row['flagged']
            entry = {'label': label, 'id': case, 'before': old, 'now': new,
                     'confidence': row['top'], 'rules': row['rules']}
            if old != new:
                (improvements if new == should_flag else regressions).append(entry)
            elif new != should_flag:
                remaining.append(entry)
    return {'passed': not regressions, 'summary': summary, 'regressions': regressions,
            'improvements': improvements, 'known_mismatches': remaining}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, default=BASELINE)
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()
    try:
        threshold, expected = load_baseline(args.baseline)
        results = {'malicious': run(MALICIOUS, False, threshold), 'benign': run(BENIGN, False, threshold)}
        report = {'threshold': threshold, **compare(expected, results)}
    except (OSError, ValueError, RecursionError) as exc:
        print(f'detection gate: {exc}', file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        status = 'PASS' if report['passed'] else 'FAIL'
        print(f"{status}: {len(report['regressions'])} regressions, {len(report['improvements'])} improvements, "
              f"{len(report['known_mismatches'])} unchanged mismatches at threshold {threshold}.")
        for group in ('regressions', 'improvements', 'known_mismatches'):
            for row in report[group]:
                print(f"  {group}: {row['label']}/{row['id']} (confidence {row['confidence']})")
    return int(not report['passed'])


if __name__ == '__main__':
    sys.exit(main())
