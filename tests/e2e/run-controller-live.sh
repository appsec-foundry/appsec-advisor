#!/bin/sh
# ─────────────────────────────────────────────────────────────────────────────
# run-controller-live.sh — Live smoke run of the deterministic assessment
# controller with the real `claude` CLI.
#
# The offline suite (`make e2e-controller`) proves the pipeline with contract-
# valid fake replies. Only a live run shows how real models answer the tool-less
# exchanges. This script runs one quick controller assessment through
# scripts/run-headless.sh and checks that a valid model was published.
#
# Triggered ONLY manually (`make e2e-controller-live`). It spends real money:
# the hard budget (default 3 USD) bounds every model call.
#
# Usage:
#   tests/e2e/run-controller-live.sh [--repo PATH] [--depth quick|standard|thorough] [--budget USD]
#
# Without --repo, a git copy of tests/fixtures/e2e/synthetic-repo is assessed.
# Output and per-call host event logs stay in the printed work directory.
#
# Exit codes:
#   0  report published and its model validates
#   1  run-headless.sh failed (see the printed log and host-events directory)
#   2  the published model failed validation
#   3  pre-flight failed
# ─────────────────────────────────────────────────────────────────────────────

set -eu

PLUGIN_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REPO=""
DEPTH="quick"
BUDGET="3"

while [ $# -gt 0 ]; do
    case "$1" in
        --repo)   REPO="$2"; shift 2 ;;
        --depth)  DEPTH="$2"; shift 2 ;;
        --budget) BUDGET="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 3 ;;
    esac
done

command -v "${APPSEC_CLAUDE_EXECUTABLE:-claude}" >/dev/null 2>&1 || {
    echo "ERROR: 'claude' CLI not on PATH. Install Claude Code first." >&2; exit 3; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/appsec-controller-live.XXXXXX")"
if [ -z "$REPO" ]; then
    REPO="$WORK/synthetic-repo"
    cp -R "$PLUGIN_ROOT/tests/fixtures/e2e/synthetic-repo" "$REPO"
    git -C "$REPO" init -q
    git -C "$REPO" add -A
    git -C "$REPO" -c user.name=E2E -c user.email=e2e@example.invalid commit -q -m fixture
fi
[ -d "$REPO" ] || { echo "ERROR: repository not found: $REPO" >&2; exit 3; }
OUT="$WORK/out"
LOG="$WORK/run.log"

echo "Work directory: $WORK"
echo "Log:            $LOG"
APPSEC_SINGLE_REPO_CONTROLLER=1 "$PLUGIN_ROOT/scripts/run-headless.sh" \
    --repo "$REPO" --output "$OUT" --assessment-depth "$DEPTH" --hard-budget "$BUDGET" --no-pdf 2>&1 | tee "$LOG" || true
# Plain sh has no pipefail, so the runner's verdict line and the model file decide.
if ! grep -q "^✓ " "$LOG" || [ ! -f "$OUT/threat-model.yaml" ]; then
    echo "✗ live controller run failed. Per-call host events: $OUT/.assessment-work/host-events" >&2
    exit 1
fi

python3 -c '
import sys
from pathlib import Path
import yaml
sys.path.insert(0, sys.argv[2] + "/scripts")
from validators.validate_intermediate import validate_threat_model_output
model = yaml.safe_load(Path(sys.argv[1]).read_text())
ok, errors = validate_threat_model_output(model)[:2]
if not ok:
    print("✗ published model failed validation:", *errors[:10], sep="\n  ", file=sys.stderr)
    sys.exit(2)
print(f"✓ live controller run published {len(model.get(\"threats\") or [])} threats; model validates")
' "$OUT/threat-model.yaml" "$PLUGIN_ROOT" || exit 2
