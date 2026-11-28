# Phase 1 detection review

Base: `4bdd436` (PR #17). Scope: the four known misses and the shell documentation false alarm. No fixture labels, global confidence thresholds, or benchmark budgets were changed.

Tier 2 now combines bounded grammatical and object cues: authorization must mention both private data and bypassing further approval; disclosure must ask for private instruction context; task override must target an agent by subject or condition. These checks run on repo text and tool metadata via the shared Tier 2 pipeline. The repo shell rule now requires an execution imperative rather than treating the presence of an inline command as a directive. Existing detectors still run. These are scoped heuristics, not proof of intent or a general-purpose semantic classifier.

| Evaluation | Before | After |
| --- | --- | --- |
| 17-case repo benchmark (threshold 0.5) | 8 TP, 4 FN, 1 FP, 4 TN | 12 TP, 0 FN, 0 FP, 5 TN |
| Repo benchmark precision / recall / F1 | 88.89% / 66.67% / 76.19% | 100% / 100% / 100% |
| Unchanged author-curated holdout (12 cases) | 3 TP, 3 FN, 1 FP, 5 TN | 3 TP, 3 FN, 1 FP, 5 TN |
| Existing development detection gate | 48/52 injection fixtures detected | Same; no case-level regressions |
| Exact upstream benign tool fixtures | 0 warning-or-higher / 47 | Same |

The 17-case corpus was used to guide this work, so its new score is a regression result, not independent evidence. The holdout did not improve. A stronger follow-up would use fresh examples labeled by someone who didn't tune the rules, freeze those labels before evaluation, and report misses without changing thresholds afterward.

```sh
python3 -m unittest discover -s tests -p test_phase1_detection.py -v
python3 -m unittest discover -s tests -p test_prompt_injection_benchmark.py -v
python3 bench/evaluate_holdout.py --json
python3 bench/detection_gate.py
python3 bench/evaluate_suites.py
python3 -m unittest discover -s tests
```
