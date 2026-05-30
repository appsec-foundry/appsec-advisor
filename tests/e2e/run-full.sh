#!/bin/sh
# ─────────────────────────────────────────────────────────────────────────────
# run-full.sh — Manual full-run E2E driver for appsec-advisor.
#
# Runs scripts/run-headless.sh against a fixed synthetic repo, routes output
# to tests/fixtures/e2e/_last-run/, then invokes the pytest assertion suite.
#
# Triggered ONLY manually — from `make e2e-full` or the /e2e-full slash command.
# Never wire this into PR / push / cron hooks. See README "Manual full-run check".
#
# Auth: uses whatever `claude` is logged in with — subscription (default) or
# ANTHROPIC_API_KEY if set. Pre-flight only checks the binary exists.
#
# Usage:
#   tests/e2e/run-full.sh [--repo PATH] [--depth quick|standard|thorough] [--keep]
#
# Exit codes:
#   0  pipeline + assertions passed
#   1  pipeline failed (run-headless.sh non-zero exit)
#   2  assertions failed
#   3  pre-flight failed (missing claude binary / missing fixture repo)
# ─────────────────────────────────────────────────────────────────────────────

set -eu

PLUGIN_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEFAULT_REPO="$PLUGIN_ROOT/tests/fixtures/e2e/synthetic-repo"
OUTPUT_DIR="$PLUGIN_ROOT/tests/fixtures/e2e/_last-run"

REPO="$DEFAULT_REPO"
DEPTH="quick"
KEEP_PREVIOUS=0

while [ $# -gt 0 ]; do
    case "$1" in
        --repo)    REPO="$2"; shift 2 ;;
        --depth)   DEPTH="$2"; shift 2 ;;
        --keep)    KEEP_PREVIOUS=1; shift ;;
        -h|--help) sed -n '3,30p' "$0"; exit 0 ;;
        *)         echo "Unknown arg: $1" >&2; exit 3 ;;
    esac
done

# ── Pre-flight ──────────────────────────────────────────────────────────────
if ! command -v claude >/dev/null 2>&1; then
    echo "ERROR: 'claude' CLI not on PATH. Install Claude Code first." >&2
    exit 3
fi

if [ ! -d "$REPO" ]; then
    echo "ERROR: target repo not found: $REPO" >&2
    exit 3
fi

if [ ! -x "$PLUGIN_ROOT/scripts/run-headless.sh" ]; then
    echo "ERROR: scripts/run-headless.sh not executable" >&2
    exit 3
fi

# ── Optional export tooling (pdf/html need pandoc; pdf also weasyprint) ───────
# Gated so the E2E never fails just because a CI box lacks the converters —
# the matching pdf/html assertions skip themselves when the tool is absent.
PDF_FLAG=""
PDF_ATTEMPTED=0
HTML_CAPABLE=0
if command -v pandoc >/dev/null 2>&1; then
    HTML_CAPABLE=1
    if python3 -c 'import weasyprint' >/dev/null 2>&1; then
        PDF_FLAG="--pdf"
        PDF_ATTEMPTED=1
    else
        echo "  note: weasyprint missing → --pdf skipped (PDF assertions skip)." >&2
    fi
else
    echo "  note: pandoc missing → HTML/PDF export skipped (those assertions skip)." >&2
fi

# ── Auth banner ─────────────────────────────────────────────────────────────
if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
    AUTH_MODE="api-key"
else
    AUTH_MODE="subscription (~/.claude/)"
fi

cat <<EOF
─────────────────────────────────────────────────────────────────────
appsec-advisor — manual full-run E2E
─────────────────────────────────────────────────────────────────────
  repo:    $REPO
  output:  $OUTPUT_DIR
  depth:   $DEPTH
  auth:    $AUTH_MODE
─────────────────────────────────────────────────────────────────────
EOF

# ── Clean previous run unless --keep ────────────────────────────────────────
if [ -d "$OUTPUT_DIR" ] && [ "$KEEP_PREVIOUS" -eq 0 ]; then
    echo "→ wiping previous _last-run/"
    rm -rf "$OUTPUT_DIR"
fi
mkdir -p "$OUTPUT_DIR"

# ── Stage 1: run the threat-model pipeline ──────────────────────────────────
echo ""
echo "[1/2] running create-threat-model pipeline ..."
START_TS=$(date +%s)

RUN_STATUS=0
"$PLUGIN_ROOT/scripts/run-headless.sh" \
    --repo "$REPO" \
    --output "$OUTPUT_DIR" \
    --assessment-depth "$DEPTH" \
    --sarif \
    --pentest-tasks \
    --requirements \
    --keep-runtime-files \
    $PDF_FLAG \
    --no-qa \
    --max-duration 1800 \
    || RUN_STATUS=$?

ELAPSED=$(( $(date +%s) - START_TS ))

echo ""
echo "→ pipeline exit code: $RUN_STATUS"
echo "→ wall-time: ${ELAPSED}s"

if [ "$RUN_STATUS" -ne 0 ]; then
    echo ""
    echo "PIPELINE FAILED — skipping assertions." >&2
    echo "Artifacts (for debugging): $OUTPUT_DIR" >&2
    exit 1
fi

# ── Stage 1b: HTML export (best-effort; needs pandoc) ────────────────────────
# PDF is produced in-pipeline via --pdf; HTML has no create-threat-model flag,
# so we drive export_html.py directly here (deterministic, no LLM tokens).
HTML_DONE=0
if [ "$HTML_CAPABLE" -eq 1 ]; then
    echo ""
    echo "[1b] exporting HTML ..."
    if python3 "$PLUGIN_ROOT/scripts/export_html.py" \
            "$OUTPUT_DIR/threat-model.md" \
            --output "$OUTPUT_DIR/threat-model.html"; then
        HTML_DONE=1
    else
        echo "HTML export failed (non-fatal)." >&2
    fi
fi

# ── Stage 2: assertion suite ────────────────────────────────────────────────
echo ""
echo "[2/2] running assertion suite ..."
echo ""

ASSERT_STATUS=0
APPSEC_E2E_FULL=1 \
APPSEC_E2E_OUTPUT_DIR="$OUTPUT_DIR" \
APPSEC_E2E_TARGET_REPO="$REPO" \
APPSEC_E2E_DEPTH="$DEPTH" \
APPSEC_E2E_PIPELINE_ELAPSED="$ELAPSED" \
APPSEC_E2E_PDF="$PDF_ATTEMPTED" \
APPSEC_E2E_HTML="$HTML_DONE" \
    python3 -m pytest \
        "$PLUGIN_ROOT/tests/test_full_run_e2e.py" \
        -v --tb=short --no-header \
    || ASSERT_STATUS=$?

echo ""
echo "─────────────────────────────────────────────────────────────────────"
if [ "$ASSERT_STATUS" -eq 0 ]; then
    echo "  RESULT: PASS  (pipeline ${ELAPSED}s, assertions OK)"
    echo "  Artifacts: $OUTPUT_DIR"
    echo "─────────────────────────────────────────────────────────────────────"
    exit 0
else
    echo "  RESULT: FAIL  (pipeline OK but assertions failed)"
    echo "  Artifacts: $OUTPUT_DIR"
    echo "─────────────────────────────────────────────────────────────────────"
    exit 2
fi
