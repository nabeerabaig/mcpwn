---
description: Pin a baseline of all MCP tool definitions (hashes) for later rug-pull detection
argument-hint: "[--baseline .mcp-scan/baseline.json]"
allowed-tools: Bash(python3:*)
---

Run a scan first and only pin if nothing critical was found, because pinning blesses the current definitions.

```
python3 "${CLAUDE_PLUGIN_ROOT}/scanner/run.py" scan --fail-on critical
```

If that exits 0:

```
python3 "${CLAUDE_PLUGIN_ROOT}/scanner/run.py" pin $ARGUMENTS
```

If it reported critical findings, show them and ask the user before pinning.
