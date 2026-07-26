#!/usr/bin/env bash
#
# ci_triage.sh - Fetch the artifacts of a dispatched run (fixture-e2e-dispatch.yml
#                or threat-model-dispatch.yml) and print a triage summary plus the
#                OUTPUT_DIR to hand to fix-run-issues.
#
# Read-only with respect to this repository: it only downloads into --into.
# The heavy lifting is already done by the plugin itself - every run writes
# $OUTPUT_DIR/.run-issues.json with structured fix_recommendation entries, and
# that file ships in the artifact. This script just gets it onto your disk and
# tells you which directory to point at.
#
# Example:
#   ./scripts/ci_triage.sh --run-id 18234567890
#
set -euo pipefail

RUN_ID=""
INTO=".appsec-ci"

usage() {
    cat <<'EOF'
Usage: ci_triage.sh --run-id <github run id> [--into <dir>]

  --run-id   Run id of a dispatch run (from its Actions URL). List with:
               gh run list --workflow fixture-e2e-dispatch.yml -L 10
               gh run list --workflow threat-model-dispatch.yml -L 10
  --into     Download destination (default: .appsec-ci)
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --run-id) RUN_ID="${2:-}"; shift 2 ;;
        --into)   INTO="${2:-}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "ERROR: unknown argument '$1'" >&2; usage >&2; exit 1 ;;
    esac
done

[ -n "$RUN_ID" ] || { echo "ERROR: --run-id is required" >&2; usage >&2; exit 1; }
command -v gh >/dev/null 2>&1 || { echo "ERROR: 'gh' CLI not on PATH." >&2; exit 3; }

mkdir -p "$INTO"
# Artifacts live 30 days; a miss here usually means the retention window closed.
if ! gh run download "$RUN_ID" --dir "$INTO" \
        --pattern 'fixture-e2e-*' --pattern 'threat-model-*'; then
    echo "ERROR: no fixture-e2e-* or threat-model-* artifacts for run $RUN_ID" >&2
    echo "       (expired, wrong id, or the run never uploaded)." >&2
    exit 4
fi

python3 - "$INTO" "$RUN_ID" <<'PY'
import json
import sys
from pathlib import Path

root, run_id = Path(sys.argv[1]), sys.argv[2]
results = sorted(root.rglob("e2e-result.json"))

# Only fixture runs classify themselves per fixture; a threat-model run is a
# single scan that either finished or did not. Fall back to listing what came
# down, which is all the local loop needs.
if not results:
    dirs = sorted(d for d in root.iterdir() if d.is_dir())
    if not dirs:
        print(f"\nNothing downloaded into {root}.")
        sys.exit(0)
    print(f"\nCI triage — {root}\n")
    for d in dirs:
        print(f"  {d.name}")
        print(f"    export OUTPUT_DIR={d}")
        print("    # then run the fix-run-issues skill (APPSEC_PLUGIN_DEV=1 to write)")
        if not (d / ".run-issues.json").is_file():
            print("    # no .run-issues.json — if there are no dotfiles at all, the run")
            print("    # predates `include-hidden-files: true` on the upload step")
    print(f"\n  # or in CI: gh workflow run <workflow> -f repair_run_id={run_id}")
    sys.exit(0)

print(f"\nCI triage — {root}\n")
failed = []
for path in results:
    try:
        r = json.loads(path.read_text())
    except (OSError, ValueError):
        print(f"  ?  unreadable: {path}")
        continue
    mark = "ok" if r["exit_code"] == 0 else "FAIL"
    print(f"  {mark:>4}  {r['fixture']} ({r['depth']}, {r['driver']})"
          f"  exit {r['exit_code']} — {r['failure_kind']}")
    if r["exit_code"] != 0:
        failed.append((path.parent, r))

if not failed:
    print("\nAll fixtures passed.")
    sys.exit(0)

for out_dir, r in failed:
    print(f"\n─── {r['fixture']} ───")
    if not (out_dir / ".run-issues.json").is_file():
        # Pre-`include-hidden-files: true` artifacts carry no dotfiles at all.
        print("  No .run-issues.json. If the directory has no dotfiles at all,")
        print("  the run predates `include-hidden-files: true` on the upload.")
    if r["failure_kind"] == "oracle":
        print("  Oracle recall miss: decide yourself whether the plugin or the")
        print("  oracle is wrong. Repair mode deliberately does not touch these.")

    print(f"    export OUTPUT_DIR={out_dir}")
    print("    # then run the fix-run-issues skill (APPSEC_PLUGIN_DEV=1 to write)")
    # Only offered where repair mode actually acts: exit 1/2/3.
    if r.get("repairable"):
        print(f"    # or in CI: gh workflow run fixture-e2e-dispatch.yml -f repair_run_id={run_id}")
PY
