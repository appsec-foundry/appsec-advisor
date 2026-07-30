#!/usr/bin/env bash
# Copilot capacity spike — see docs/internal/analysis/plan-copilot-capacity-spike-2026-07-30.md
#
#   ./spike/run.sh A          run tier A
#   ./spike/run.sh B          run tier B
#   ./spike/run.sh C          run tier C
#
# Runs one tier against a throwaway copy of the synthetic fixture, gates the
# result with validate_fragment.py, and compares it against the Claude oracle.
# Needs an authenticated Copilot CLI and network access, so it does not run
# inside a restricted sandbox.
set -uo pipefail

TIER="${1:-}"
case "$TIER" in
  A|B|C) ;;
  *) echo "usage: $0 <A|B|C>" >&2; exit 2 ;;
esac

PLUGIN_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE="$PLUGIN_ROOT/tests/fixtures/e2e/synthetic-repo"
ORACLE="$PLUGIN_ROOT/tests/fixtures/e2e/_last-run/.components.json"
CREDITS="${MAX_AI_CREDITS:-30}"

command -v copilot >/dev/null || { echo "copilot CLI not on PATH" >&2; exit 2; }
[ -d "$FIXTURE" ] || { echo "fixture missing: $FIXTURE" >&2; exit 2; }
[ -f "$ORACLE" ]  || { echo "oracle missing: $ORACLE" >&2; exit 2; }

SPIKE="${SPIKE_DIR:-$(mktemp -d -t copilot-spike-XXXXXX)}"
REPO="$SPIKE/repo-$TIER"
OUT="$SPIKE/out-$TIER"
rm -rf "$REPO" "$OUT"; mkdir -p "$OUT"
cp -r "$FIXTURE" "$REPO"

PROMPT="$(sed -e "s|%%OUTPUT_DIR%%|$OUT|g" -e "s|%%PLUGIN_ROOT%%|$PLUGIN_ROOT|g" \
          "$PLUGIN_ROOT/spike/prompt-$TIER.md")"

echo "tier=$TIER  prompt=${#PROMPT} chars  repo=$REPO  out=$OUT"
echo "--- running (cap ${CREDITS} AI credits) ---"

# Tier C reads the phase body from the plugin checkout, so that path is added
# read-only for that tier only.
EXTRA=()
[ "$TIER" = "C" ] && EXTRA+=(--add-dir "$PLUGIN_ROOT/agents")

START=$(date +%s)
copilot -p "$PROMPT" \
  -C "$REPO" \
  --add-dir "$OUT" "${EXTRA[@]}" \
  --allow-tool shell --allow-tool write \
  --no-ask-user \
  --output-format json \
  --max-ai-credits "$CREDITS" \
  > "$SPIKE/log-$TIER.jsonl" 2> "$SPIKE/err-$TIER.txt"
RC=$?
ELAPSED=$(( $(date +%s) - START ))

echo "--- result ---"
echo "exit=$RC  wall_clock=${ELAPSED}s"
if [ $RC -ne 0 ]; then
  echo "stderr (tail):"; tail -5 "$SPIKE/err-$TIER.txt"
  echo "NOTE: a permission refusal here is the tool-scoping finding, not a setup error."
fi

echo "--- schema gate ---"
python3 "$PLUGIN_ROOT/scripts/validate_fragment.py" components "$OUT/.components.json" \
  && echo "GATE PASS" || echo "GATE FAIL"

echo "--- oracle comparison ---"
python3 "$PLUGIN_ROOT/spike/compare.py" "$OUT/.components.json" "$ORACLE"

echo "--- usage (last JSONL objects) ---"
tail -3 "$SPIKE/log-$TIER.jsonl" 2>/dev/null

echo
echo "artifacts in $SPIKE  (re-use with SPIKE_DIR=$SPIKE $0 <tier>)"
