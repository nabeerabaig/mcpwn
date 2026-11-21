#!/usr/bin/env bash
# Called by action.yml. MCP modes deliberately have no live-discovery fallback.
set -euo pipefail
run=$1
mode=${MODE:-repo}
severity=${FAIL_ON:-critical}
output=${SARIF:-mcpscan.sarif}
redact=${REDACT_EVIDENCE:-true}

case "$mode" in repo|scan|drift) ;; *) echo 'Invalid mode: expected repo, scan or drift.' >&2; exit 2;; esac
case "$severity" in none|info|warning|critical) ;; *) echo 'Invalid fail-on severity.' >&2; exit 2;; esac
case "$redact" in true|false) ;; *) echo 'redact-evidence must be true or false.' >&2; exit 2;; esac

args=("$mode")
if [[ "$mode" == repo ]]; then
    if [[ -n ${TOOLS_JSON:-} ]]; then
        echo 'tools-json is only supported in scan and drift modes.' >&2
        exit 2
    fi
    args+=(.)
    if [[ -n ${CHANGED_SINCE:-} ]]; then args+=("--changed-since=$CHANGED_SINCE"); fi
else
    files=()
    # Prefer one path per line (preserves spaces); keep the legacy space-separated input.
    if [[ ${TOOLS_JSON:-} == *$'\n'* ]]; then
        while IFS= read -r file; do
            [[ -z "$file" ]] || files+=("$file")
        done <<< "$TOOLS_JSON"
    elif [[ -n ${TOOLS_JSON:-} && -f "$TOOLS_JSON" ]]; then
        files=("$TOOLS_JSON")
    else
        read -r -a files <<< "${TOOLS_JSON:-}"
    fi
    if [[ ${#files[@]} == 0 ]]; then
        echo 'scan and drift require saved tools-json snapshots; live discovery is disabled in CI.' >&2
        exit 2
    fi
    safe_files=()
    for file in "${files[@]}"; do
        if [[ ! -f "$file" ]]; then echo 'A tools-json snapshot is missing.' >&2; exit 2; fi
        case "$file" in /*|./*|../*) safe_files+=("$file");; *) safe_files+=("./$file");; esac
    done
    args+=(--tools-json "${safe_files[@]}")
    if [[ "$mode" == drift ]]; then args+=("--baseline=${BASELINE:-.mcp-scan/baseline.json}"); fi
fi
if [[ "$redact" == true ]]; then args+=(--redact-evidence); fi
exec python3 "$run" "${args[@]}" --format sarif "--output=$output" "--fail-on=$severity"
