# Benign benchmark suites

Run `python3 bench/evaluate_suites.py` from the repo root. Use `--json` for results by severity, or `--suite upstream-mcp-git` to run only the upstream Git snapshot. No MCP processes start and no network is used.

| Dataset | Provenance | Info or higher | Warning or higher | Critical |
|---|---|---:|---:|---:|
| Synthetic pilot | Handwritten | 1/5 | 0/5 | 0/5 |
| Public docs | Paraphrased descriptions and reconstructed schemas | 0/10 | 0/10 | 0/10 |
| MCP Git reference server | Exact checked-in `tools/list` test snapshot | 1/14 | 0/14 | 0/14 |
| GitHub sweep fixture | Published GitHub MCP subset captured by mcp-catalog-snap | 3/12 | 0/12 | 0/12 |
| Kronicle Lite | Published catalog; document storage and verification | 0/9 | 0/9 | 0/9 |
| Sea Lite | Published catalog; ticket and workflow management | 0/12 | 0/12 | 0/12 |

The upstream inputs preserve tool names, descriptions, and input schemas. They are unmodified JSON files pinned to their source revisions in the manifest, not captures made by this project. The GitHub fixture is a subset, not the full GitHub server inventory. The catalog adapter scans `catalog.tools` only; it does not evaluate prompts, resource templates, output schemas, or annotations. No detector rules changed.

The upstream alerts were informational: `T2-SENSITIVE-PATH-MENTION` on `git_remote`, and `T2-UNKNOWN-TOOL-REF` on `actions_get`, `actions_list`, and `list_pull_requests`. For `actions_get` and `actions_list`, the parser treated the ordinary phrase “Use this tool” as a tool reference. The `list_pull_requests` description actually names `search_pull_requests`, which is absent from this published subset. Neither is evidence that the full server has a broken dependency. The three new inputs are from the same [pinned catalog repository](https://github.com/rafe-walker/mcp-catalog-snap/tree/87b5a06bcf150e545dd06a9f347125ad09da0c66). Its license and notices are in [catalog-snap/](upstream/catalog-snap/).

These numbers describe the selected benign fixtures, not recall, precision, or a reliable estimate of real-world false-positive rates. The exact upstream sample covers four published tool sets (47 tool entries); it is a convenience sample and three were published in the same repository. Keep it separate from the other samples rather than pooling counts into a headline metric. This fixture is public and now visible to developers, so treat it as regression coverage, not a permanent blind holdout.

## Add another exact fixture

1. Choose a pinned upstream revision and review the tool metadata for benign labels and private information. Prefer checked-in test snapshots or reviewed captures that preserve server names, descriptions, and schemas. Do not launch untrusted servers to obtain fixtures.
2. Save the raw fixture bytes under `upstream/` and preserve the applicable upstream license or notices. For the MCP Git fixture, see [the pinned source](https://github.com/modelcontextprotocol/servers/blob/c799c8552b0f27b7a33a7b9233773da144dddcf5/src/git/tests/snapshots/list_tools.json) and [upstream license](upstream/MCP-SERVERS-LICENSE.txt).
3. Add a suite in `benign-suites.json` with a unique ID, relative path, source, SHA-256 of the raw bytes, and explicit severity budgets reviewed by the maintainer. Set `format: "mcp-catalog-snap/1"` for that envelope; omit `format` for an ordinary `tools/list` fixture. Preserve fixture bytes across checkouts in `.gitattributes`. Keep detector changes separate from fixture additions so the starting measurement is visible.

The runner counts tools, not findings: a tool with multiple rules firing counts once at each threshold it meets. CI exits `1` if a threshold exceeds its suite budget and `2` for invalid inputs or an unexpected fixture digest. Keep the manifest and fixture changes under review: a digest pins the input, but it does not independently establish that a fixture is representative or benign.
