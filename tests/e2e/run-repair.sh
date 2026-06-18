#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# QA-active E2E repair variant — exercises the REAL Stage-3 Re-Render Loop and
# the appsec-fragment-fixer dispatch (M2b) in a live headless skill run.
#
# Why this exists: `run-full.sh` hardcodes `--no-qa`, so Stage 3 / the Re-Render
# Loop / the fragment-fixer NEVER run in the normal E2E. And a clean render
# triggers no repair anyway. This variant GUARANTEES a repair by:
#   1. Seeding a known-good, full (standard-depth) output as the baseline.
#   2. Corrupting §7.2 — the analyst-authored `security-architecture.md` fragment
#      (the renderer never regenerates it, so the corruption survives recompose).
#   3. Running headless with `--rerender` (and QA on): the skill skips Stage 1
#      and the incremental no-op gate, re-renders Stage 2 from the existing
#      fragments (the renderer never regenerates §7.2, so the corruption stands),
#      then runs the Stage-3 QA gate → build_repair_plan flags §7.2 → Re-Render
#      Loop dispatches `appsec-advisor:appsec-fragment-fixer` → recompose → clean.
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
SEED="${APPSEC_E2E_REPAIR_SEED:-/home/mrohr/juice-shop/docs/security}"
REPO="${APPSEC_E2E_REPAIR_REPO:-/home/mrohr/juice-shop}"
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

# 1. Fresh copy of the clean baseline.
rm -rf "$OUTPUT_DIR"
cp -r "$SEED" "$OUTPUT_DIR"
# Drop stale lock/progress so the resume starts clean.
rm -f "$OUTPUT_DIR/.appsec-lock" "$OUTPUT_DIR/.qa-repair-plan.json" "$OUTPUT_DIR/.qa-status.json"

# 2. Corrupt §7.2 — turn a canonical mechanism heading into a FORBIDDEN primitive.
#    Match the §7.2.2 heading by NUMBER, not by its (drift-prone) wording: the
#    seed is a real run output whose mechanism title changes across regenerations
#    (e.g. "MFA / TOTP" → "Multi-Factor Authentication (TOTP)"). Replacing the
#    whole heading line with the forbidden "Login Rate Limiting" primitive still
#    trips the auth_method_decomposition rule regardless of the original wording.
FRAG="$OUTPUT_DIR/.fragments/security-architecture.md"
if grep -qE '^#### 7\.2\.2 ' "$FRAG"; then
    sed -i -E 's|^#### 7\.2\.2 .*|#### 7.2.2 Login Rate Limiting|' "$FRAG"
    echo "→ corrupted §7.2.2 heading → 'Login Rate Limiting' (forbidden primitive)"
else
    echo "ERROR: expected a '#### 7.2.2 ...' heading not found in seed fragment" >&2
    exit 3
fi

# 3. Drop the checkpoint so nothing looks mid-run; --rerender drives the flow.
rm -f "$OUTPUT_DIR/.appsec-checkpoint"

# 4. Run the real skill headless, WITH QA (no --no-qa), via --rerender:
#    skips Stage 1 + the incremental no-op, re-renders Stage 2 from the existing
#    (corrupted) fragments, then runs Stage 3 QA + the Re-Render Loop.
echo ""
echo "[1/2] running create-threat-model --rerender (QA ON) ..."
START_TS=$(date +%s)
RUN_STATUS=0
"$PLUGIN_ROOT/scripts/run-headless.sh" \
    --repo "$REPO" \
    --output "$OUTPUT_DIR" \
    --assessment-depth standard \
    --rerender \
    --keep-runtime-files \
    --max-duration "$MAXDUR" \
    || RUN_STATUS=$?
ELAPSED=$(( $(date +%s) - START_TS ))
echo ""
echo "→ pipeline exit code: $RUN_STATUS"
echo "→ wall-time: ${ELAPSED}s"

# 5. Assertions — did the REAL loop fire the fixer and converge?
echo ""
echo "[2/2] repair-loop assertions ..."
PASS=0; FAIL=0
chk() { if eval "$2"; then echo "  ✓ $1"; PASS=$((PASS+1)); else echo "  ✗ $1"; FAIL=$((FAIL+1)); fi; }

# (a) fragment-fixer was dispatched in the real loop (hook log / agent-run log)
FIXER_SPAWN=$(grep -ciE 'appsec-fragment-fixer|fragment-fixer' "$OUTPUT_DIR/.hook-events.log" "$OUTPUT_DIR/.agent-run.log" 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')
chk "fragment-fixer dispatched in the live loop (>=1 log hit)" "[ \"$FIXER_SPAWN\" -ge 1 ]"

# (b) §7.2.2 heading was repaired back to a canonical mechanism (not the primitive)
chk "§7.2.2 no longer the forbidden 'Login Rate Limiting' heading" "! grep -q '^#### 7\.2\.2 Login Rate Limiting' '$FRAG'"

# (c) final document is contract-clean w.r.t. the auth rule
CLAUDE_PLUGIN_ROOT="$PLUGIN_ROOT" python3 "$PLUGIN_ROOT/scripts/qa_checks.py" repair_plan "$OUTPUT_DIR/threat-model.md" "$OUTPUT_DIR" >/dev/null 2>&1
AUTH_AFTER=$(python3 -c "import json,sys;
try:
  p=json.load(open('$OUTPUT_DIR/.qa-repair-plan.json'));
  t=[a.get('type') for a in p.get('actions',[])];
  print('auth_present' if 'auth_method_decomposition' in t else 'clean')
except FileNotFoundError:
  print('clean')" 2>/dev/null)
chk "auth_method_decomposition violation cleared in final doc" "[ \"$AUTH_AFTER\" = clean ]"

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
