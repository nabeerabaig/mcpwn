# Phase 2 review: deduplication and evidence

This increment builds on the local Phase 1 review patch. It does not change detector thresholds, labels, or the severity scale.

- Findings deduplicate on rule, source, server, tool, location, and full evidence, not just a prefix. Identical original and normalized findings at the same location merge; distinct paths and evidence remain visible. On a severity tie, the original view is preferred.
- Normalized findings use an excerpt verified against the original text instead of substituting the first 200 characters. The scanner omits evidence when it can't locate an unambiguous excerpt and explains that limitation. Original paths stay intact; the normalized view is identified in the finding location.
- Unicode-obfuscation findings require a signal not present in the original view. Finding confidence and the global severity bands are unchanged.

This does not collapse different rule IDs, rework severity policy, or supply exact spans for all existing detectors. Those are separate review items.

## Rule-specific guidance follow-up

The Phase 1 authorization, private-context disclosure, agent-targeted override, and shell execution rules now explain different impacts and review actions in terminal, JSON, and SARIF reports. Guidance is static and remains available when evidence is redacted. These actions explain what to verify; the scanner does not demonstrate that access was granted, data was disclosed, or a command ran. Confidence thresholds and CI severity behavior are intentionally unchanged pending independent validation.
