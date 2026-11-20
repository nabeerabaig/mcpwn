# mcp-injection-scanner (Claude Code plugin)

A plugin that scans MCP servers and agent instruction files for prompt injection, with a confidence score per finding instead of a binary flag. Pure Python standard library.

Status: **v0.2.0.**

## Install locally

```
claude --plugin-dir /path/to/mcp-injection-scanner
```

## Commands

| Command | What it does |
|---|---|
| `/mcp-injection-scanner:scan` | Connects to each configured stdio MCP server (initialize, tools/list) and scans names, descriptions, parameter names, enums, defaults |
| `/mcp-injection-scanner:chains` | Cross-server capability graph and kill-chain report |
| `/mcp-injection-scanner:pin` | Records SHA-256 baseline of every tool definition |
| `/mcp-injection-scanner:drift` | Diffs current definitions against the baseline (rug-pull detection) |
| `/mcp-injection-scanner:scan-repo` | Scans CLAUDE.md, .cursorrules, .windsurfrules, copilot-instructions, issue/PR templates; prints a 0-100 agent security score |

A `SessionStart` hook runs a quiet static repo scan and only speaks up if it finds warning-level or worse issues. The `injection-triage` skill tells Claude how to judge findings and to treat scanned text as untrusted data.

## Detection tiers

1. **Tier 1, structural:** zero-width / bidi / tag Unicode (tag characters are decoded), base64 payloads (decoded and re-scanned), override and concealment phrases.
2. **Tier 2, contextual:** sensitive paths, secrets, exfiltration and execution phrasing. Only *directive* language aimed at the agent scores high; descriptive text ("Reads a file") and same-server dependency docs ("call list_files first") stay below warning. Instruction-like parameter names.
3. **Tier 3, LLM (opt-in, `--llm`):** `MCPSCAN_LLM_CMD` (stdin JSON, stdout JSON) or `ANTHROPIC_API_KEY` (+ optional `MCPSCAN_LLM_MODEL`). Can lower Tier 2 findings it judges benign; can never clear Tier 1 hits.

Severity: confidence >= 0.8 critical, >= 0.5 warning, otherwise info.

## CLI (used by the commands, also runnable directly)

```
python3 scanner/run.py scan --fail-on critical --format sarif --output out.sarif
python3 scanner/run.py scan --tools-json saved_tools.json      # offline, starts nothing
python3 scanner/run.py chains --format html --output chains.html
python3 scanner/run.py pin && python3 scanner/run.py drift --fail-on critical
python3 scanner/run.py watch --interval 300 --webhook https://hooks.slack.com/...
python3 scanner/run.py repo . --include-mcp --format json
python3 scanner/run.py proxy --server-name x --block-critical -- npx some-server
```

## Safety notes

- `scan`, `chains`, `pin`, `drift`, `watch` launch your configured stdio servers to read their tool lists. Use `--tools-json` to avoid starting anything.
- stdio and streamable-HTTP servers are supported. For HTTP servers, scanning only sends MCP requests to the configured URL (with any headers from your config). Legacy SSE servers are reported as FAILED.

## Phase 2: dynamic confirmation

`scan --dynamic` simulates an agent against a **test model** twice per flagged tool: once with the real description, once with the description stripped (control). The model only *proposes* tool calls as JSON; nothing is executed. Decoy tools and a planted canary secret reveal whether the description caused a harmful action.

- `confirmed`: behavior deviates only with the real description. Adds `D-CONFIRMED` (0.98).
- `cleared`: no deviation. Findings are *demoted* (critical becomes warning; lower ones x0.6) but not erased, because a model ignoring an injection does not prove other agents will. Tier 1 hits (hidden characters, base64) are never demoted.
- `inconclusive`: the model returned nothing parseable.

Backends: `MCPSCAN_AGENT_CMD`, `MCPSCAN_OLLAMA_MODEL` (local, Ollama), or `ANTHROPIC_API_KEY`. With none set, the step is skipped and says so. `--sandbox docker` launches scanned servers in a locked-down container (`--network none`, read-only, caps dropped); servers that need the network to start (e.g. `npx`) need `--sandbox-network bridge` or a prebuilt image.

## Benchmark (`python3 bench/benchmark.py`)

Static engine on `bench/corpus.py`, a corpus I wrote (52 malicious incl. hard semantic cases, 58 benign incl. dependency-doc wording and sensitive-sounding vocabulary), threshold 0.5:

| | Result |
|---|---|
| Detection rate | 92.3% (48/52) |
| False-positive rate | 0.0% (0/58) |
| Misses | 1 schema (`system_prompt` param, deliberately ambiguous) and 3 semantic paraphrases |

**Read this carefully:** this is *not* the AppSecSanta/Cisco audit set, which I did not have, so the "<10% FP vs 78%" comparison has not been made. The detectors were also iterated while looking at this corpus, so the numbers are optimistic. Treat them as a regression baseline, not evidence of real-world accuracy. No real LLM was run for Tier 3 or dynamic mode; dynamic mode is tested only with a deterministic mock agent.

## Other features

- **Streamable HTTP** MCP servers (JSON and SSE replies) are scanned; legacy SSE transport is not.
- **Egress monitoring** (`proxy --egress --allow-host H --block-egress`): the server's HTTP(S) goes through a local logging proxy that flags non-allowlisted hosts and credential-shaped data (AWS/GitHub/Slack/JWT/private keys). HTTPS is a CONNECT tunnel, so only the host is visible, not the body. Only programs that honor `HTTP(S)_PROXY` are seen; use a container with no network for hard enforcement. The stdio proxy also scans `tools/call` arguments and results for credentials, unlisted URLs, and instructions in tool results.
- **PR mode**: `repo --changed-since <base-sha> --format markdown` scans only changed agent files and emits a review-comment table.
- **CI**: `action.yml` (composite action) and `ci/github-workflow-example.yml`. These are files only; nothing is installed or pushed anywhere else.
