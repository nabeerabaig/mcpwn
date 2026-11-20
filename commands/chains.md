---
description: Find cross-server exploit chains (e.g. read_file on one server + send_http on another)
argument-hint: "[--cross-server-only] [--format text|json|html] [--output file]"
allowed-tools: Bash(python3:*)
---

```
python3 "${CLAUDE_PLUGIN_ROOT}/scanner/run.py" chains $ARGUMENTS
```

Explain the top chains in plain language: what an attacker who controls one tool's input could make the agent do across servers, and which single server removal would break the most chains. Capability classification is heuristic (name and description keywords), so say when a classification looks wrong.
