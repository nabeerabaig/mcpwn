# mcp-injection-scanner

A standalone CLI and Claude Code plugin that scan MCP servers and agent instruction files for prompt injection. The core scanner uses the Python standard library; YAML config discovery uses optional PyYAML.

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

## Use with other agents

Use the standalone CLI with Python 3.11+. The Claude Code plugin still works as before; the other clients do not need to load a Claude plugin.

| Client | `--client` | Supported config discovery |
|---|---|---|
| Claude, Cursor, VS Code, Windsurf | `legacy` (default for scans) | Existing JSON locations |
| Gemini CLI | `gemini` | Project and user `.gemini/settings.json` (`command` or `httpUrl`; legacy `url`/SSE is skipped) |
| OpenCode | `opencode` | Project and user `opencode.json` / `.jsonc`, plus `OPENCODE_CONFIG` and `OPENCODE_CONFIG_DIR` overrides as candidate paths |
| Codex | `codex` | Project `.codex/config.toml` and `$CODEX_HOME/config.toml` (default `~/.codex`) |
| Hermes Agent | `hermes` | `$HERMES_HOME/config.yaml` (default `~/.hermes`); requires PyYAML |
| DeepSeek Harness | `deepseek` | Literal `@deepseek-ai/dsh-mcp-client` entries in `cordis.yml` and `cordis.patch.yml`, including profile patch files under `$DSH_HOME` (default `~/.dsh`); requires PyYAML |
| Other clients | `--config PATH` | Explicit JSON/JSONC, TOML or YAML containing a supported MCP server block (`mcpServers`, `servers`, `mcp`, or `mcp_servers`), or use `--tools-json` |

```bash
# Optional: only needed for YAML configs (Hermes and DeepSeek)
python3 -m pip install PyYAML

# Discovery only: no processes launched, no network connections opened
python3 scanner/run.py inventory --format json
python3 scanner/run.py inventory --client deepseek --strict

# Inspect tool definitions from a reviewed config
python3 scanner/run.py scan --client gemini --only docs --format json
python3 scanner/run.py scan --config /path/to/opencode.jsonc --only docs

# Offline alternative when config uses client-specific features
python3 scanner/run.py scan --tools-json saved_tools.json
```

`inventory` lists eligible server names, transports and config paths but omits command lines, headers, URLs and environment values. Discovery does not reproduce each client's config precedence, profile activation, or per-tool filters. When multiple files define the same server, use `--config` to select the one you intend to scan. Client-managed OAuth, variable interpolation, custom working directories, and legacy SSE are not supported. DeepSeek YAML with dynamic tags such as `!!js` is rejected, not evaluated. Use a plain static config or an exported tool list in these cases. New client discovery is opt-in for live scans; inventory defaults to all known clients. **Only live-scan servers and configs you trust.**

## Save tool definitions and scan them offline

```bash
# Read only the selected trusted server's tool definitions and save them once.
python3 scanner/run.py snapshot --connect --client opencode --only docs --output docs-tools.json

# Later, scan the saved definitions with no server startup or network requests.
python3 scanner/run.py scan --tools-json docs-tools.json --format json

# Combine existing snapshots from distinct servers without connecting.
python3 scanner/run.py snapshot --tools-json first.json second.json --output combined.json
```

Snapshots do not copy config commands, URLs, headers, or environment values. They do retain tool descriptions and schemas verbatim as parsed, and those may themselves contain sensitive data. Review before sharing and keep snapshots outside version control unless they are intended as public fixtures. The command refuses to overwrite existing files and doesn't write a partial snapshot if discovery or collection fails. It captures metadata, not tool responses or proof of server safety.

### Review snapshot changes in CI

```bash
python3 scanner/run.py snapshot-diff before.json after.json --format json --fail-on-change
```

Compare two captured snapshots without connecting to any server. The report lists added and removed servers and tools, and whether a retained tool's description or input schema changed. It does not print the metadata values. JSON object key order does not matter. Exit codes: `0` for a successful comparison by default, `1` for changes with `--fail-on-change`, and `2` for invalid input. A change is a review signal, not a finding of malicious behavior; use `scan --tools-json after.json` to evaluate the new metadata separately.

## Audit a group of projects

Run `python3 scanner/run.py audit bench/audit-manifest.json --format json` to see a multi-project audit entirely offline. The [audit guide](docs/portfolio-audit.md) explains how to set a shared policy, compare against trusted baselines, and gate CI on new findings or tool metadata changes.

## Safety notes

- `scan`, `chains`, `pin`, `drift`, `watch` launch your configured stdio servers to read their tool lists. Use `--tools-json` to avoid starting anything.
- stdio and streamable-HTTP servers are supported. For HTTP servers, scanning only sends MCP requests to the configured URL (with any headers from your config). Legacy SSE servers are skipped with a diagnostic.

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

See the [offline benign-tool pilot](bench/benign_pilot.md) for a separate five-tool smoke test and reproducible CLI command.

The [public MCP tool evaluation](bench/benign_public.md) adds ten doc-derived benign fixtures from two public reference servers.

Run the offline false-positive regression check with `python3 bench/evaluate_benign.py --max-flagged 0`. Add `--json` for per-tool results, or pass paths to your own known-benign `--tools-json` snapshots. GitHub Actions runs the bundled check on pushes and pull requests.

The [benign benchmark suites](bench/benign-suites.md) report exact upstream snapshots separately from synthetic and doc-derived fixtures. Run `python3 bench/evaluate_suites.py` to reproduce the CI check.

## Other features

- **Streamable HTTP** MCP servers (JSON and SSE replies) are scanned; legacy SSE transport is not.
- **Egress monitoring** (`proxy --egress --allow-host H --block-egress`): the server's HTTP(S) goes through a local logging proxy that flags non-allowlisted hosts and credential-shaped data (AWS/GitHub/Slack/JWT/private keys). HTTPS is a CONNECT tunnel, so only the host is visible, not the body. Only programs that honor `HTTP(S)_PROXY` are seen; use a container with no network for hard enforcement. The stdio proxy also scans `tools/call` arguments and results for credentials, unlisted URLs, and instructions in tool results.
- **PR mode**: `repo --changed-since <base-sha> --format markdown` scans only changed agent files and emits a review-comment table.
- **CI**: `action.yml` (composite action) and `ci/github-workflow-example.yml`. These are files only; nothing is installed or pushed anywhere else.
