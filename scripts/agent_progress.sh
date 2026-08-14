#!/usr/bin/env bash
# Write a per-component progress file polled by the orchestrator.
#
# Usage: agent_progress.sh <component_id> <component_name> <step> <total> <label>
# Env:   OUTPUT_DIR (required)
#
# The writer validates the current component plan and obtains analysis.depth
# from it. Model-authored labels can never select or restate the depth.

set -u

if [ "$#" -ne 5 ] || [ -z "${OUTPUT_DIR:-}" ]; then
  exit 0
fi

python3 "${CLAUDE_PLUGIN_ROOT:?}/scripts/write_stride_progress.py" \
  "$OUTPUT_DIR" "$1" "$2" "$3" "$4" "$5" \
  --plugin-root "$CLAUDE_PLUGIN_ROOT"
