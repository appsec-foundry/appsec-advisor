#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# QA-active E2E repair variant — exercises the REAL Stage-3 Re-Render Loop and
# the appsec-fragment-fixer dispatch (M2b) in a live headless skill run.
#
# A clean standard run normally needs no repair. This variant guarantees one:
#   1. Seed from the bundled E2E's immediately preceding clean standard run.
#   2. Corrupt §7.2 by removing its required `Controls covered` label.
#   3. Running headless with `--rerender --no-enrich-arch` (and QA on): the skill
#      skips Stage 1 and the incremental no-op gate, re-renders Stage 2 from the
#      existing fragments, then runs the Stage-3 QA gate → build_repair_plan flags
#      §7.2 → Re-Render Loop dispatches `appsec-advisor:appsec-fragment-fixer` →
#      recompose → clean.
#
#   `--no-enrich-arch` is LOAD-BEARING. At standard depth ENRICH_ARCH_FRAGMENTS
#   defaults ON, so the `secarch` renderer re-authors the fragment before Stage 3
#   sees it. Disabling enrichment lets `control_subsection_coverage` reach the
#   real Re-Render Loop / fragment-fixer.
#
# Then asserts the real loop fired the fixer and converged to contract-clean.
#
# `--rerender` is the render-recovery entry point added for exactly this: a flat
# `--resume` on a complete seed auto-selects INCREMENTAL and hits the no-op
# fast-path (skips Stage 2/3 → fixer never fires), and `--full` regenerates §7.2
# cleanly (no violation). `--rerender` bypasses both: it re-renders the existing
# fragments + re-runs QA, which is what reliably fires the live fixer loop.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

PLUGIN_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SEED="${APPSEC_E2E_REPAIR_SEED:-$PLUGIN_ROOT/tests/fixtures/e2e/_last-run}"
REPO="${APPSEC_E2E_REPAIR_REPO:-$PLUGIN_ROOT/tests/fixtures/e2e/_last-repo}"
OUTPUT_DIR="$PLUGIN_ROOT/tests/fixtures/e2e/_repair-run"
MAXDUR="${APPSEC_E2E_REPAIR_MAXDUR:-2400}"

echo "─────────────────────────────────────────────────────────────────────"
echo "appsec-advisor — QA-active E2E repair variant (M2b real-loop)"
echo "─────────────────────────────────────────────────────────────────────"
echo "  seed:    $SEED"
echo "  repo:    $REPO"
echo "  output:  $OUTPUT_DIR"
echo "─────────────────────────────────────────────────────────────────────"

[ -f "$SEED/threat-model.md" ] || { echo "ERROR: seed has no threat-model.md: $SEED" >&2; exit 3; }
[ -f "$SEED/.fragments/security-architecture.md" ] || { echo "ERROR: seed lacks §7 fragment" >&2; exit 3; }
[ -d "$REPO" ] || { echo "ERROR: analyzed fixture repo missing: $REPO" >&2; exit 3; }
python3 - "$SEED/.skill-config.json" <<'PY' || exit 3
import json
import sys

path = sys.argv[1]
try:
    config = json.load(open(path, encoding="utf-8"))
except (OSError, ValueError) as exc:
    print(f"ERROR: cannot read standard seed config {path}: {exc}", file=sys.stderr)
    raise SystemExit(1)
if config.get("assessment_depth") != "standard" or config.get("skip_qa") is not False:
    print("ERROR: repair seed must be a standard run with Stage-3 QA enabled", file=sys.stderr)
    raise SystemExit(1)
PY

# 1. Fresh copy of the clean baseline.
rm -rf "$OUTPUT_DIR"
cp -r "$SEED" "$OUTPUT_DIR"
# Drop stale lock/progress so the resume starts clean.
rm -f "$OUTPUT_DIR/.appsec-lock" "$OUTPUT_DIR/.qa-repair-plan.json" "$OUTPUT_DIR/.qa-status.json"

# 2. Remove the first required §7 `Controls covered` label.
FRAG="$OUTPUT_DIR/.fragments/security-architecture.md"
if grep -qE '^\*\*Controls covered:\*\*' "$FRAG"; then
    sed -i '0,/^\*\*Controls covered:\*\*/s//**Control inventory:**/' "$FRAG"
    echo "→ corrupted §7 Controls covered label → Control inventory"
else
    echo "ERROR: expected a '**Controls covered:**' label not found in seed fragment" >&2
    exit 3
fi

# Prove deterministically that fixture drift has not invalidated the trigger.
python3 "$PLUGIN_ROOT/scripts/compose_threat_model.py" \
    --output-dir "$OUTPUT_DIR" --strict >/dev/null 2>&1 || {
  echo "ERROR: corruption no longer composes; expected a post-render QA defect" >&2
  exit 3
}
python3 "$PLUGIN_ROOT/scripts/qa_checks.py" \
    repair_plan "$OUTPUT_DIR/threat-model.md" "$OUTPUT_DIR" >/dev/null 2>&1 || true
python3 - "$OUTPUT_DIR/.qa-repair-plan.json" <<'PY' || exit 3
import json
import sys

plan = json.load(open(sys.argv[1], encoding="utf-8"))
types = {action.get("type") for action in plan.get("actions", [])}
if "control_subsection_coverage" not in types:
    print(f"ERROR: corruption did not trigger control_subsection_coverage; got {sorted(types)}", file=sys.stderr)
    raise SystemExit(1)
PY

FIXER_BEFORE=$(grep -hciE 'appsec-fragment-fixer|fragment-fixer' \
    "$OUTPUT_DIR/.hook-events.log" "$OUTPUT_DIR/.agent-run.log" 2>/dev/null \
    | awk '{s+=$1} END{print s+0}')

# 3. Drop the checkpoint so nothing looks mid-run; --rerender drives the flow.
rm -f "$OUTPUT_DIR/.appsec-checkpoint"

# 4. Run the real skill headless, WITH QA (no --no-qa), via --rerender:
#    skips Stage 1 + the incremental no-op, re-renders Stage 2 from the existing
#    (corrupted) fragments, then runs Stage 3 QA + the Re-Render Loop.
#    --no-enrich-arch stops the secarch renderer from re-authoring §7 (which would
#    pre-heal the corruption before QA — see header).
echo ""
echo "[1/2] running create-threat-model --rerender --no-enrich-arch (QA ON) ..."
START_TS=$(date +%s)
RUN_STATUS=0
"$PLUGIN_ROOT/scripts/run-headless.sh" \
    --repo "$REPO" \
    --output "$OUTPUT_DIR" \
    --assessment-depth standard \
    --rerender \
    --no-enrich-arch \
    --keep-runtime-files \
    --max-duration "$MAXDUR" \
    || RUN_STATUS=$?
ELAPSED=$(( $(date +%s) - START_TS ))
echo ""
echo "→ pipeline exit code: $RUN_STATUS"
echo "→ wall-time: ${ELAPSED}s"

if [ "$RUN_STATUS" -ne 0 ]; then
    echo "PIPELINE FAILED — repair assertions are not valid." >&2
    echo "Artifacts: $OUTPUT_DIR" >&2
    exit 1
fi

# 5. Assertions — did the REAL loop fire the fixer and converge?
echo ""
echo "[2/2] repair-loop assertions ..."
PASS=0; FAIL=0
chk() { if eval "$2"; then echo "  ✓ $1"; PASS=$((PASS+1)); else echo "  ✗ $1"; FAIL=$((FAIL+1)); fi; }

# (a) a new fragment-fixer dispatch occurred after the seeded corruption
FIXER_AFTER=$(grep -hciE 'appsec-fragment-fixer|fragment-fixer' \
    "$OUTPUT_DIR/.hook-events.log" "$OUTPUT_DIR/.agent-run.log" 2>/dev/null \
    | awk '{s+=$1} END{print s+0}')
chk "fragment-fixer dispatched after corruption" "[ \"$FIXER_AFTER\" -gt \"$FIXER_BEFORE\" ]"

# (b) the required §7 label was restored
chk "§7 Controls covered label restored" "grep -q '^\\*\\*Controls covered:\\*\\*' '$FRAG'"

# (c) final document is contract-clean with respect to the seeded defect
CLAUDE_PLUGIN_ROOT="$PLUGIN_ROOT" python3 "$PLUGIN_ROOT/scripts/qa_checks.py" repair_plan "$OUTPUT_DIR/threat-model.md" "$OUTPUT_DIR" >/dev/null 2>&1
CONTROL_AFTER=$(python3 -c "import json,sys;
try:
  p=json.load(open('$OUTPUT_DIR/.qa-repair-plan.json'));
  t=[a.get('type') for a in p.get('actions',[])];
  print('control_present' if 'control_subsection_coverage' in t else 'clean')
except FileNotFoundError:
  print('clean')" 2>/dev/null)
chk "control_subsection_coverage violation cleared in final doc" "[ \"$CONTROL_AFTER\" = clean ]"

QA_STATUS=$(python3 -c "import json; print(json.load(open('$OUTPUT_DIR/.qa-status.json')).get('status',''))" 2>/dev/null)
chk "Stage-3 QA status is pass" "[ \"$QA_STATUS\" = pass ]"

echo ""
echo "─────────────────────────────────────────────────────────────────────"
if [ "$FAIL" -eq 0 ]; then
    echo "  RESULT: PASS — M2b real-loop verified ($PASS checks)"
else
    echo "  RESULT: FAIL — $FAIL/$((PASS+FAIL)) checks failed (see above)"
fi
echo "  Artifacts: $OUTPUT_DIR"
echo "─────────────────────────────────────────────────────────────────────"
[ "$FAIL" -eq 0 ]
