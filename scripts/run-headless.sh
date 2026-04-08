#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# run-headless.sh — Run the AppSec plugin non-interactively via
#                   Claude Code's headless mode (claude -p).
#
# Usage:
#   ./scripts/run-headless.sh [options]
#
# Options:
#   --repo <path>           Repository to analyze (default: current directory)
#   --output <path>         Output directory (default: <repo>/docs/security)
#   --yaml                  Also write threat-model.yaml
#   --sarif                 Also write threat-model.sarif.json (SARIF v2.1.0)
#   --requirements          Include requirements compliance check (Phase 7b)
#   --with-sca              Run dependency vulnerability scan (npm audit, etc.)
#   --dry-run               Preview scope without running the full pipeline
#   --incremental           Delta analysis based on git diff
#   --resume                Continue from last checkpoint
#   --max-budget <usd>      Stop when estimated cost exceeds this amount
#   --model <model>         Override the Claude model (default: sonnet)
#   --json                  Return structured JSON output
#   --verbose               Show detailed turn-by-turn output
#
# Skill selection:
#   --check-requirements    Run check-appsec-requirements instead of threat model
#   --category <filter>     Category filter for requirements check (e.g. SEC-AUTH)
#   --save-report           Save requirements report (--md --json)
#
# Environment:
#   ANTHROPIC_API_KEY       Required — your Anthropic API key
#   CLAUDE_PLUGIN_DIR       Override plugin directory (default: auto-detected)
# ──────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Colors & helpers ────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}▶${NC} $*"; }
ok()    { echo -e "${GREEN}✓${NC} $*"; }
warn()  { echo -e "${YELLOW}⚠${NC} $*"; }
err()   { echo -e "${RED}✗${NC} $*" >&2; }
die()   { err "$@"; exit 1; }

# ── Locate plugin directory ─────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_DIR="${CLAUDE_PLUGIN_DIR:-"$(dirname "$SCRIPT_DIR")/plugin"}"

if [[ ! -f "$PLUGIN_DIR/.claude-plugin/plugin.json" ]]; then
    die "Plugin not found at $PLUGIN_DIR — set CLAUDE_PLUGIN_DIR or run from the appsec-plugin repo root"
fi

# ── Verify prerequisites ────────────────────────────────────────────
command -v claude >/dev/null 2>&1 || die "Claude Code CLI not found. Install it first: https://claude.ai/download"

if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
    die "ANTHROPIC_API_KEY is not set. Export it before running this script."
fi

# ── Parse arguments ─────────────────────────────────────────────────
REPO_PATH=""
OUTPUT_PATH=""
SKILL_FLAGS=""
MAX_BUDGET=""
MODEL=""
OUTPUT_FORMAT="text"
VERBOSE=""
SKILL="create-threat-model"
CATEGORY_FILTER=""
SAVE_REPORT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --repo)
            REPO_PATH="$2"; shift 2 ;;
        --output)
            OUTPUT_PATH="$2"; shift 2 ;;
        --yaml|--sarif|--requirements|--with-sca|--dry-run|--incremental|--resume)
            SKILL_FLAGS="$SKILL_FLAGS $1"; shift ;;
        --max-budget)
            MAX_BUDGET="$2"; shift 2 ;;
        --model)
            MODEL="$2"; shift 2 ;;
        --json)
            OUTPUT_FORMAT="json"; shift ;;
        --verbose)
            VERBOSE="--verbose"; shift ;;
        --check-requirements)
            SKILL="check-appsec-requirements"; shift ;;
        --category)
            CATEGORY_FILTER="$2"; shift 2 ;;
        --save-report)
            SAVE_REPORT="--save"; shift ;;
        --help|-h)
            head -30 "$0" | tail -28; exit 0 ;;
        *)
            # Pass unknown args as scope constraints
            SKILL_FLAGS="$SKILL_FLAGS $1"; shift ;;
    esac
done

# ── Resolve paths ───────────────────────────────────────────────────
if [[ -n "$REPO_PATH" ]]; then
    REPO_PATH="$(cd "$REPO_PATH" 2>/dev/null && pwd)" || die "Repository path does not exist: $REPO_PATH"
fi

if [[ -n "$OUTPUT_PATH" ]]; then
    mkdir -p "$OUTPUT_PATH" 2>/dev/null || die "Cannot create output directory: $OUTPUT_PATH"
    OUTPUT_PATH="$(cd "$OUTPUT_PATH" && pwd)"
fi

# ── Build the skill command ─────────────────────────────────────────
if [[ "$SKILL" == "create-threat-model" ]]; then
    PROMPT="/appsec-plugin:create-threat-model"

    # Append --repo / --output if specified
    [[ -n "$REPO_PATH" ]]   && PROMPT="$PROMPT --repo $REPO_PATH"
    [[ -n "$OUTPUT_PATH" ]] && PROMPT="$PROMPT --output $OUTPUT_PATH"

    # Append remaining flags
    PROMPT="$PROMPT$SKILL_FLAGS"

elif [[ "$SKILL" == "check-appsec-requirements" ]]; then
    PROMPT="/appsec-plugin:check-appsec-requirements"

    # Category filter comes first (positional arg in the skill)
    [[ -n "$CATEGORY_FILTER" ]] && PROMPT="$PROMPT $CATEGORY_FILTER"

    # Save flags
    [[ -n "$SAVE_REPORT" ]] && PROMPT="$PROMPT $SAVE_REPORT"

    # Pass any extra flags
    PROMPT="$PROMPT$SKILL_FLAGS"
fi

# ── Build claude CLI arguments ──────────────────────────────────────
CLAUDE_ARGS=(
    -p "$PROMPT"
    --plugin-dir "$PLUGIN_DIR"
    --allowedTools "Read,Write,Glob,Grep,Bash,Agent"
    --permission-mode "bypassPermissions"
    --output-format "$OUTPUT_FORMAT"
    --no-session-persistence
)

# Max turns: threat model needs more turns than requirements check
if [[ "$SKILL" == "create-threat-model" ]]; then
    CLAUDE_ARGS+=(--max-turns 150)
else
    CLAUDE_ARGS+=(--max-turns 60)
fi

# Optional arguments
[[ -n "$MAX_BUDGET" ]] && CLAUDE_ARGS+=(--max-budget-usd "$MAX_BUDGET")
[[ -n "$MODEL" ]]      && CLAUDE_ARGS+=(--model "$MODEL")
[[ -n "$VERBOSE" ]]    && CLAUDE_ARGS+=($VERBOSE)

# ── Print summary ───────────────────────────────────────────────────
echo ""
info "AppSec Plugin — Headless Mode"
echo "  Skill      : $SKILL"
echo "  Plugin     : $PLUGIN_DIR"
[[ -n "$REPO_PATH" ]]   && echo "  Repository : $REPO_PATH"
[[ -n "$OUTPUT_PATH" ]] && echo "  Output     : $OUTPUT_PATH"
[[ -n "$SKILL_FLAGS" ]] && echo "  Flags      :$SKILL_FLAGS"
[[ -n "$MAX_BUDGET" ]]  && echo "  Budget cap : \$$MAX_BUDGET"
[[ -n "$CATEGORY_FILTER" ]] && echo "  Category   : $CATEGORY_FILTER"
echo ""

# ── Execute ─────────────────────────────────────────────────────────
info "Starting Claude Code in headless mode..."
echo ""

claude "${CLAUDE_ARGS[@]}"
EXIT_CODE=$?

echo ""
if [[ $EXIT_CODE -eq 0 ]]; then
    ok "Assessment completed successfully."

    # Show output location
    if [[ "$SKILL" == "create-threat-model" ]]; then
        RESULT_DIR="${OUTPUT_PATH:-"${REPO_PATH:-.}/docs/security"}"
        if [[ -f "$RESULT_DIR/threat-model.md" ]]; then
            ok "Threat model: $RESULT_DIR/threat-model.md"
            [[ "$SKILL_FLAGS" == *"--yaml"* ]]  && [[ -f "$RESULT_DIR/threat-model.yaml" ]]      && ok "YAML export: $RESULT_DIR/threat-model.yaml"
            [[ "$SKILL_FLAGS" == *"--sarif"* ]] && [[ -f "$RESULT_DIR/threat-model.sarif.json" ]] && ok "SARIF export: $RESULT_DIR/threat-model.sarif.json"
        fi
    fi
else
    err "Assessment exited with code $EXIT_CODE"
    warn "Check intermediate files or run with --resume to continue."
fi

exit $EXIT_CODE
