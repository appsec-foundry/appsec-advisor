#!/usr/bin/env bash
# Write a per-component progress file polled by the orchestrator.
#
# Usage: agent_progress.sh <component_id> <component_name> <step> <total> <label>
# Env:   OUTPUT_DIR (required)
#
# The writer validates the current component plan and obtains analysis.depth
# from it. Model-authored labels can never select or restate the depth.

set -u

# A misconfigured call must not fail the agent that made it — progress reporting
# is auxiliary. It must still say so: exiting 0 without a word made the whole
# component's progress silently vanish while the run looked healthy, the one
# silent failure among the scripts that need OUTPUT_DIR (the others all abort
# loudly). The caller reads this on its own stderr and can correct the call.
if [ "$#" -ne 5 ]; then
  echo "agent_progress: skipped — expected 5 arguments (component_id, component_name, step, total, label), got $#" >&2
  exit 0
fi
if [ -z "${OUTPUT_DIR:-}" ]; then
  echo "agent_progress: skipped — OUTPUT_DIR is empty; pass the absolute output directory, shell state does not persist between calls" >&2
  exit 0
fi

python3 "${CLAUDE_PLUGIN_ROOT:?}/scripts/write_stride_progress.py" \
  "$OUTPUT_DIR" "$1" "$2" "$3" "$4" "$5" \
  --plugin-root "$CLAUDE_PLUGIN_ROOT"
