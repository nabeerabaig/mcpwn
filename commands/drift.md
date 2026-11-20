---
description: Compare current MCP tool definitions to the pinned baseline (rug-pull detection)
argument-hint: "[--baseline .mcp-scan/baseline.json] [--fail-on warning]"
allowed-tools: Bash(python3:*)
---

```
python3 "${CLAUDE_PLUGIN_ROOT}/scanner/run.py" drift $ARGUMENTS
```

For every changed tool, show the side-by-side diff of the description, say whether the new text trips the detectors, and recommend whether to re-pin (only after the user reviews the change) or remove the server.
