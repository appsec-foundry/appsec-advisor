#!/usr/bin/env bash
# Write a per-component progress file polled by the orchestrator.
#
# Usage: agent_progress.sh <component_id> <component_name> <step> <total> <label>
# Env:   OUTPUT_DIR (required)
#
# Contract: never blocks the analysis. Any failure (unwritable dir, missing var,
# bad arg) exits 0 silently — progress is an optional UX layer.

set -u

if [ "$#" -ne 5 ] || [ -z "${OUTPUT_DIR:-}" ]; then
  exit 0
fi

component_id="$1"
component_name="$2"
step="$3"
total="$4"
label="$5"

# Strip characters that would break the JSON. The poll script tolerates
# missing files but not malformed JSON.
component_name="${component_name//\\/}"
component_name="${component_name//\"/}"
label="${label//\\/}"
label="${label//\"/}"

mkdir -p "$OUTPUT_DIR/.progress" 2>/dev/null || exit 0

printf '{"component_id":"%s","component_name":"%s","step":%d,"total":%d,"label":"%s","updated_at":"%s"}' \
  "$component_id" "$component_name" "$step" "$total" "$label" \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  > "$OUTPUT_DIR/.progress/$component_id.json" 2>/dev/null || true

exit 0
