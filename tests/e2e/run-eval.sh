#!/bin/sh
# Semantic quality gate for the most recent bundled full-run E2E.
set -eu

PLUGIN_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUN_DIR="$PLUGIN_ROOT/tests/fixtures/e2e/_last-run"
REPO="$PLUGIN_ROOT/tests/fixtures/e2e/_last-repo"
OUT="$PLUGIN_ROOT/tests/fixtures/e2e/_eval-run"
MAXDUR="${APPSEC_E2E_EVAL_MAXDUR:-2400}"

command -v claude >/dev/null 2>&1 || {
    echo "ERROR: 'claude' CLI not on PATH" >&2
    exit 3
}
[ -f "$RUN_DIR/threat-model.yaml" ] || {
    echo "ERROR: run make e2e-full first; missing $RUN_DIR/threat-model.yaml" >&2
    exit 3
}
[ -d "$REPO" ] || {
    echo "ERROR: analyzed fixture copy missing: $REPO" >&2
    exit 3
}

rm -rf "$OUT"
mkdir -p "$OUT"

PROMPT="/appsec-advisor:eval-threat-model RUN_DIR=$RUN_DIR OUT=$OUT REPO=$REPO"
STATUS=0
if command -v timeout >/dev/null 2>&1; then
    timeout --preserve-status "${MAXDUR}s" \
        claude -p "$PROMPT" \
        --plugin-dir "$PLUGIN_ROOT" \
        --allowedTools "Read,Write,Glob,Grep,Bash,Agent" \
        --permission-mode bypassPermissions \
        --output-format text \
        --no-session-persistence \
        || STATUS=$?
else
    claude -p "$PROMPT" \
        --plugin-dir "$PLUGIN_ROOT" \
        --allowedTools "Read,Write,Glob,Grep,Bash,Agent" \
        --permission-mode bypassPermissions \
        --output-format text \
        --no-session-persistence \
        || STATUS=$?
fi

[ "$STATUS" -eq 0 ] || {
    echo "ERROR: eval-threat-model invocation failed with exit $STATUS" >&2
    exit 1
}
[ -f "$OUT/eval-results.json" ] || {
    echo "ERROR: eval produced no eval-results.json" >&2
    exit 2
}

python3 - "$OUT/eval-results.json" <<'PY'
import json
import sys

path = sys.argv[1]
data = json.load(open(path, encoding="utf-8"))
summary = data.get("summary") or {}
counts = summary.get("by_severity") or {}
gating = int(counts.get("critical", 0)) + int(counts.get("high", 0))
print(
    "semantic E2E: "
    f"{summary.get('confirmed_total', 0)} confirmed defect(s), "
    f"{gating} High/Critical; review={path.rsplit('/', 1)[0]}/EVAL-REVIEW.md"
)
raise SystemExit(1 if gating else 0)
PY
