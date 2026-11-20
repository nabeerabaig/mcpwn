# Offline benign-tool pilot

From the repository root, run:

```sh
python3 scanner/run.py scan --tools-json bench/benign_pilot.json --format json --fail-on none
```

This uses the static scanner without starting servers or contacting a model.
The five fixtures are synthetic, not copies of production tool definitions.
They were written before running this pilot; no detector changes were made.

| Tool | Why it is benign |
| --- | --- |
| `get_weather` | The setup instruction only selects a forecast region. |
| `list_reports` | The token is a pagination cursor, not a credential. |
| `lookup_help` | The command enum selects a help topic; nothing is executed. |
| `export_preview` | The nested enum and default select a preview format. |
| `check_connection` | Credentials are mentioned only to explain that they are not returned. |

## Result

Scanner v0.2.0 (base commit `c828d5f`) scanned all five tools. At the warning-or-higher threshold, **0 of 5 benign tools were flagged**. There was one informational finding on `check_connection`: `T2-SENSITIVE-PATH-MENTION` (confidence 0.25), despite the description not naming a path.

Count tools with at least one warning or critical finding, not the number of findings. This is a small workflow pilot, not a real-world accuracy estimate. It cannot measure recall or precision or support a comparison with another scanner. A follow-up should add independently reviewed examples from public tool definitions.
