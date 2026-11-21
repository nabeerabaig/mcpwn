# Benign benchmark suites

Run `python3 bench/evaluate_suites.py` from the repo root. Use `--json` for results by severity, or `--suite upstream-mcp-git` to run only the upstream Git snapshot. No MCP processes start and no network is used.

| Dataset | Provenance | Info or higher | Warning or higher | Critical |
|---|---|---:|---:|---:|
| Synthetic pilot | Handwritten | 1/5 | 0/5 | 0/5 |
| Public docs | Paraphrased descriptions and reconstructed schemas | 0/10 | 0/10 | 0/10 |
| MCP Git reference server | Exact checked-in `tools/list` test snapshot | 1/14 | 0/14 | 0/14 |

The upstream result retains the actual tool names, descriptions, and input schemas. It is the unmodified upstream JSON, not a live capture by this project. The only upstream hit is an informational `T2-SENSITIVE-PATH-MENTION` on `git_remote`; there were no warning or critical alerts. The scanner was not changed for this evaluation.

These numbers describe the selected benign fixtures, not recall, precision, or a reliable estimate of real-world false-positive rates. The exact upstream sample currently comes from **one server**. Keep it separate from the other samples rather than pooling counts into a headline metric. This fixture is public and now visible to developers, so treat it as regression coverage, not a permanent blind holdout.

## Add another exact fixture

1. Choose a pinned upstream revision and review the tool metadata for benign labels and private information. Prefer checked-in test snapshots or reviewed captures that preserve server names, descriptions, and schemas. Do not launch untrusted servers to obtain fixtures.
2. Save the raw fixture bytes under `upstream/` and preserve the applicable upstream license or notices. For the MCP Git fixture, see [the pinned source](https://github.com/modelcontextprotocol/servers/blob/c799c8552b0f27b7a33a7b9233773da144dddcf5/src/git/tests/snapshots/list_tools.json) and [upstream license](upstream/MCP-SERVERS-LICENSE.txt).
3. Add a suite in `benign-suites.json` with a unique ID, relative path, source, SHA-256 of the raw bytes, and explicit severity budgets agreed in review. Preserve fixture bytes across checkouts in `.gitattributes`. Keep detector changes separate from fixture additions so the starting measurement is visible.

The runner counts tools, not findings: a tool with multiple rules firing counts once at each threshold it meets. CI exits `1` if a threshold exceeds its suite budget and `2` for invalid inputs or an unexpected fixture digest. Keep the manifest and fixture changes under review: a digest pins the input, but it does not independently establish that a fixture is representative or benign.
