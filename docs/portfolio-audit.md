# Audit several MCP projects offline

The `audit` command runs the static scanner against saved MCP snapshots. It does not read client configs, launch MCP servers, call tools, or contact an LLM. Teams can run it on pull requests and compare each new snapshot to a trusted baseline.

Try it from the repository root:

```bash
python3 scanner/run.py audit bench/audit-manifest.json
python3 scanner/run.py audit bench/audit-manifest.json --format json --output audit-report.json
```

The example checks the two bundled benign datasets as separate projects. For your own audit, save the manifest alongside the snapshots it references. A baseline and current snapshot should represent the **same project and scope**. Prefer snapshots created by `mcp-scan snapshot`, which preserve server names; for bare `{"tools": [...]}` inputs the filename stem becomes the server identity, so matching stems are needed across directories.

```json
{
  "version": 1,
  "policy": {
    "minimum_severity": "warning",
    "gate": "new",
    "max_violations": 0,
    "max_tool_changes": 3
  },
  "projects": [
    {"id": "docs", "snapshot": "current/docs.json", "baseline": "baseline/docs.json"},
    {"id": "support", "snapshot": "current/support.json", "baseline": "baseline/support.json"}
  ]
}
```

## Policy and reports

| Policy field | Default | Meaning |
|---|---|---|
| `minimum_severity` | `warning` | Lowest severity that counts toward the findings budget (`info`, `warning`, `critical`) |
| `gate` | `all` | Count all findings at or above the threshold, or just `new` and `escalated` findings with `new` |
| `max_violations` | `0` | Maximum number of matching findings across all projects |
| `max_tool_changes` | Omitted | Optional independent budget on added, removed, or modified tools across baselined projects; even clean metadata changes count |

`gate: new` and `max_tool_changes` require an explicit baseline for **every** project. `gate: all` still reports baseline comparisons if provided. A finding is matched using server, tool, rule, location, and a digest of the scanner's evidence. A changed match is new, and a matched finding that moves to a higher severity is escalated. Both snapshots are scanned using the same current detector. This is not a comparison of two scanner versions. Findings not seen in the current snapshot count as resolved, which can also happen when tools are removed. Review removed servers and tools in the JSON report; an incomplete input is not proof that findings were fixed. Tool metadata drift compares descriptions and input schemas; server-only changes with no tools are listed separately and do not spend the tool budget.

Reports omit raw descriptions, schemas, and evidence, but include identifiers and locations that may be private. Treat snapshots as potentially sensitive. `--output` creates a new file only; the CLI won't replace an existing report. Exit codes: `0` policy passed, `1` policy failed (report is still emitted), `2` invalid input or output error.

## Put it in CI

Use a trusted copy of the manifest and baselines. If untrusted pull requests can replace their own baseline, policy, or audit code, they can make a gate pass. Protect those files with review, or run a trusted audit harness against snapshots supplied by the branch. Preserve the audit step's nonzero exit code and upload the JSON report as an artifact if appropriate. Never collect live snapshots from untrusted PR configs.

The manifest accepts up to 100 projects. Each referenced snapshot must be a JSON file within the manifest directory (including subdirectories), at most 8 MiB and 5,000 tools. Unknown manifest fields, duplicate JSON keys, and duplicate tool names within a server are rejected.
