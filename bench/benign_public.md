# Public MCP tool evaluation

This corpus contains 10 benign fixtures adapted from two public MCP reference servers. Tool names and documented argument shapes are retained, descriptions are paraphrased, and schemas are reconstructed from the docs. These are **not** verbatim `tools/list` captures; changes in wording can affect detection.

| Fixtures | Source (pinned revision) | Why labeled benign |
| --- | --- | --- |
| `create_entities`, `create_relations`, `add_observations`, `delete_entities`, `delete_observations`, `delete_relations`, `read_graph`, `search_nodes`, `open_nodes` | [Memory tool documentation](https://github.com/modelcontextprotocol/servers/blob/c799c8552b0f27b7a33a7b9233773da144dddcf5/src/memory/README.md#tools) | These descriptions document graph operations; the instruction to look up a relation type is normal tool usage. A delete operation is state-changing, but describing it is not prompt injection. |
| `get_current_time` | [Time server documentation](https://github.com/modelcontextprotocol/servers/blob/c799c8552b0f27b7a33a7b9233773da144dddcf5/src/time/README.md#available-tools) | The description explains a timezone lookup and its default behavior. |

From the repo root:

```sh
python3 scanner/run.py scan --tools-json bench/benign_public.json --format json --fail-on none
```

The scan reads only the fixture; it doesn't start servers or call a model.

**Result on scanner v0.2.0 (base commit `0135a27`):** 10 tools scanned, 0 with warnings or critical findings, and 0 informational findings. Count each tool at most once at the warning-or-higher threshold. No detector changes were made.

This is a small sample dominated by one server. It does not establish a real-world false-positive rate, measure recall, or support comparisons with other scanners. An independent review and a broader set of exact tool definitions would make the benchmark stronger.
