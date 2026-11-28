# Independent holdout review

The bundled `bench/holdout-v1.json` is an author-curated reference set. Do not call it an independent evaluation. Have a reviewer who did not tune the scanner select and label a new corpus; keep its contents away from detector authors until the detector revision and dataset are fixed. Choose diverse benign documentation and authorized, reviewed security evaluation examples. Do not include secrets or private config files. This runner evaluates MCP tool metadata only, not agent instruction files or model behavior.

Use the bundled file as a format reference. Record inclusion and labeling criteria, source or provenance, and any exclusions. Freeze the version 1 JSON file with both label types and a fixed `threshold`, and share its SHA-256 separately. On Windows CMD, get the checksum with `certutil -hashfile review-set.json SHA256`. Keep the holdout private if data or licensing requires it.

Run against the same file, digest, and threshold from a checkout of each scanner revision. Replace `REVIEWED_SHA256` with the 64-character checksum supplied by the reviewer:

```cmd
py -3 bench/evaluate_holdout.py --dataset review-set.json --expected-sha256 REVIEWED_SHA256 --require-complete --json > holdout-report.json
```

Record the scanner commit and Python version with each report. Compare per-case outcomes, precision, recall, F1, false positives, and false negatives. Report coverage and sample counts. A checksum mismatch or incomplete scan exits with code 2; an incomplete report may still be emitted for diagnosis, but do not compare its accuracy metrics. A successful evaluation means it ran, not that the scanner met an accuracy target. Any dataset exposed to the detector authors or used to tune rules should be retired as an independent holdout.
