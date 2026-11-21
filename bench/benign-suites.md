# Benign benchmark suites

Run `python3 bench/evaluate_suites.py` from the repo root. Use `--json` for results by severity, or `--suite upstream-mcp-git` to run only the upstream Git snapshot. No MCP processes start and no network is used.

| Dataset | Provenance | Info or higher | Warning or higher | Critical |
|---|---|---:|---:|---:|
| Synthetic pilot | Handwritten | 1/5 | 0/5 | 0/5 |
| Public docs | Paraphrased descriptions and reconstructed schemas | 0/10 | 0/10 | 0/10 |
| MCP Git reference server | Exact checked-in `tools/list` test snapshot | 1/14 | 0/14 | 0/14 |
| GitHub sweep fixture | Published GitHub MCP subset captured by mcp-catalog-snap | 1/12 | 0/12 | 0/12 |
| Kronicle Lite | Published catalog; document storage and verification | 0/9 | 0/9 | 0/9 |
| Sea Lite | Published catalog; ticket and workflow management | 0/12 | 0/12 | 0/12 |

The upstream inputs preserve tool names, descriptions, and input schemas. They are unmodified JSON files pinned to their source revisions in the manifest, not captures made by this project. The GitHub fixture is a subset, not the full GitHub server inventory. The catalog adapter scans `catalog.tools` only; it does not evaluate prompts, resource templates, output schemas, or annotations.

The remaining upstream alerts are informational: `T2-SENSITIVE-PATH-MENTION` on `git_remote`, and `T2-UNKNOWN-TOOL-REF` on `list_pull_requests`. Before the reference-parser fix, the GitHub subset triggered three informational alerts: two from ordinary “Use this tool” wording and one from the explicit `search_pull_requests` reference. Only the explicit reference remains. That tool name is absent from this subset, which does not establish a broken dependency in the full server. The raw fixture and its digest did not change. The three new inputs are from the same [pinned catalog repository](https://github.com/rafe-walker/mcp-catalog-snap/tree/87b5a06bcf150e545dd06a9f347125ad09da0c66). Its license and notices are in [catalog-snap/](upstream/catalog-snap/).

These numbers describe the selected benign fixtures, not recall, precision, or a reliable estimate of real-world false-positive rates. The exact upstream sample covers four published tool sets (47 tool entries); it is a convenience sample and three were published in the same repository. Keep it separate from the other samples rather than pooling counts into a headline metric. This fixture is public and now visible to developers, so treat it as regression coverage, not a permanent blind holdout.

## Add another exact fixture

1. Choose a pinned upstream revision and review the tool metadata for benign labels and private information. Prefer checked-in test snapshots or reviewed captures that preserve server names, descriptions, and schemas. Do not launch untrusted servers to obtain fixtures.
2. Save the raw fixture bytes under `upstream/` and preserve the applicable upstream license or notices. For the MCP Git fixture, see [the pinned source](https://github.com/modelcontextprotocol/servers/blob/c799c8552b0f27b7a33a7b9233773da144dddcf5/src/git/tests/snapshots/list_tools.json) and [upstream license](upstream/MCP-SERVERS-LICENSE.txt).
3. Add a suite in `benign-suites.json` with a unique ID, relative path, source, SHA-256 of the raw bytes, and explicit severity budgets reviewed by the maintainer. Set `format: "mcp-catalog-snap/1"` for that envelope; omit `format` for an ordinary `tools/list` fixture. Preserve fixture bytes across checkouts in `.gitattributes`. Keep detector changes separate from fixture additions so the starting measurement is visible.

The runner counts tools, not findings: a tool with multiple rules firing counts once at each threshold it meets. CI exits `1` if a threshold exceeds its suite budget and `2` for invalid inputs or an unexpected fixture digest. Keep the manifest and fixture changes under review: a digest pins the input, but it does not independently establish that a fixture is representative or benign.

## Check that detection did not regress

`python3 bench/detection_gate.py --json` runs the existing labeled development corpus with the static engine. It compares each case to `detection-baseline.json` at confidence `0.5`. Losing any previously detected case or newly flagging a previously quiet benign case fails CI, even if aggregate scores improve. Newly detected cases and cleared false alerts are reported separately. Known misses stay visible and do not fail CI until a previously passing case regresses. A corpus ID addition, rename, or removal requires an explicit baseline review.

The initial baseline is 48/52 labeled injection cases detected and 0/58 labeled benign cases flagged. That is a regression floor on a development corpus, not independent accuracy evidence. When an improvement is reviewed, update its baseline outcome in the same PR so future checks protect it. Do not update the baseline merely to make a regression pass. Exit codes: `0` no regressions, `1` regression, `2` invalid baseline or case mismatch. The separate upstream benign-suites check still runs independently.
