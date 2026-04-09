#!/bin/sh
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
#   --requirements [<url>]   Enable requirements check (optionally from URL)
#   --no-requirements        Skip requirements even when enabled in config
#   --with-sca              Run dependency vulnerability scan (npm audit, etc.)
#   --dry-run               Preview scope without running the full pipeline
#   --incremental           Delta analysis based on git diff
#   --resume                Continue from last checkpoint
#   --max-budget <usd>      Stop when estimated cost exceeds this amount
#   --model <model>         Override the Claude model (default: sonnet)
#   --stride-model <model>  Override model for STRIDE analyzers (e.g. opus)
#   --json                  Return structured JSON output
#   --verbose               Show real-time hook event log on stderr
#
# Skill selection:
#   --check-requirements    Run check-appsec-requirements instead of threat model
#   --category <filter>     Category filter for requirements check (e.g. SEC-AUTH)
#   --save-report           Save requirements report (--md --json)
#
# Environment:
#   ANTHROPIC_API_KEY       Anthropic API key (optional — uses subscription if unset)
#   CLAUDE_PLUGIN_DIR       Override plugin directory (default: auto-detected)
# ──────────────────────────────────────────────────────────────────────
set -eu

# ── Colors & helpers ────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { printf "${CYAN}▶${NC} %s\n" "$*"; }
ok()    { printf "${GREEN}✓${NC} %s\n" "$*"; }
warn()  { printf "${YELLOW}⚠${NC} %s\n" "$*"; }
err()   { printf "${RED}✗${NC} %s\n" "$*" >&2; }
die()   { err "$@"; exit 1; }

usage() {
    cat <<'HELP'
Usage: run-headless.sh [options]

Run the AppSec plugin non-interactively via Claude Code's headless mode.

Options:
  --repo <path>              Repository to analyze (default: current directory)
  --output <path>            Output directory (default: <repo>/docs/security)
  --yaml                     Also write threat-model.yaml
  --sarif                    Also write threat-model.sarif.json (SARIF v2.1.0)
  --requirements [<url>]     Enable requirements check, optionally from URL
  --no-requirements          Skip requirements even when enabled in config
  --with-sca                 Run dependency vulnerability scan (npm audit, etc.)
  --dry-run                  Preview scope without running the full pipeline
  --incremental              Delta analysis based on git diff
  --resume                   Continue from last checkpoint
  --max-budget <usd>         Stop when estimated cost exceeds this amount
  --model <model>            Override the Claude model (default: sonnet)
  --stride-model <model>     Override model for STRIDE analyzers (e.g. opus)
  --json                     Return structured JSON output
  --verbose                  Show real-time hook event log on stderr

Skill selection:
  --check-requirements       Run check-appsec-requirements instead of threat model
  --category <filter>        Category filter for requirements check (e.g. SEC-AUTH)
  --save-report              Save requirements report (--md --json)

  -h, --help                 Show this help message and exit

Environment:
  ANTHROPIC_API_KEY          Anthropic API key (optional — uses subscription auth if unset)
  CLAUDE_PLUGIN_DIR          Override plugin directory (default: auto-detected)
HELP
    exit 0
}

# ── Early --help check (before prerequisites) ──────────────────────
for arg in "$@"; do
    case "$arg" in --help|-h) usage ;; esac
done

# ── Locate plugin directory ─────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_DIR="${CLAUDE_PLUGIN_DIR:-"$(dirname "$SCRIPT_DIR")/plugin"}"

if [ ! -f "$PLUGIN_DIR/.claude-plugin/plugin.json" ]; then
    die "Plugin not found at $PLUGIN_DIR — set CLAUDE_PLUGIN_DIR or run from the appsec-plugin repo root"
fi

# ── Verify prerequisites ────────────────────────────────────────────
command -v claude >/dev/null 2>&1 || die "Claude Code CLI not found. Install it first: https://claude.ai/download"

if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
    warn "ANTHROPIC_API_KEY is not set — using Claude Code subscription auth."
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

while [ $# -gt 0 ]; do
    case "$1" in
        --repo)
            REPO_PATH="$2"; shift 2 ;;
        --output)
            OUTPUT_PATH="$2"; shift 2 ;;
        --yaml|--sarif|--no-requirements|--with-sca|--dry-run|--incremental|--resume)
            SKILL_FLAGS="$SKILL_FLAGS $1"; shift ;;
        --requirements)
            # --requirements [<url>] — enable requirements, optionally from URL
            if [ $# -gt 1 ] && echo "$2" | grep -qE '^https?://'; then
                SKILL_FLAGS="$SKILL_FLAGS --requirements $2"; shift 2
            else
                SKILL_FLAGS="$SKILL_FLAGS --requirements"; shift
            fi
            ;;
        --with-requirements)
            warn "--with-requirements is deprecated — use --requirements"
            SKILL_FLAGS="$SKILL_FLAGS --requirements"; shift ;;
        --ignore-requirements)
            warn "--ignore-requirements is deprecated — use --no-requirements"
            SKILL_FLAGS="$SKILL_FLAGS --no-requirements"; shift ;;
        --requirements-url)
            warn "--requirements-url is deprecated — use --requirements <url>"
            SKILL_FLAGS="$SKILL_FLAGS --requirements $2"; shift 2 ;;
        --max-budget)
            MAX_BUDGET="$2"; shift 2 ;;
        --model)
            MODEL="$2"; shift 2 ;;
        --stride-model)
            SKILL_FLAGS="$SKILL_FLAGS --stride-model $2"; shift 2 ;;
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
            usage ;;
        *)
            # Pass unknown args as scope constraints
            SKILL_FLAGS="$SKILL_FLAGS $1"; shift ;;
    esac
done

# ── Resolve paths ───────────────────────────────────────────────────
if [ -n "$REPO_PATH" ]; then
    REPO_PATH="$(cd "$REPO_PATH" 2>/dev/null && pwd)" || die "Repository path does not exist: $REPO_PATH"
fi

if [ -n "$OUTPUT_PATH" ]; then
    mkdir -p "$OUTPUT_PATH" 2>/dev/null || die "Cannot create output directory: $OUTPUT_PATH"
    OUTPUT_PATH="$(cd "$OUTPUT_PATH" && pwd)"
fi

# ── Build the skill command ─────────────────────────────────────────
if [ "$SKILL" = "create-threat-model" ]; then
    PROMPT="/appsec-plugin:create-threat-model"

    # Append --repo / --output if specified
    [ -n "$REPO_PATH" ]   && PROMPT="$PROMPT --repo $REPO_PATH"
    [ -n "$OUTPUT_PATH" ] && PROMPT="$PROMPT --output $OUTPUT_PATH"

    # Append remaining flags
    PROMPT="$PROMPT$SKILL_FLAGS"

elif [ "$SKILL" = "check-appsec-requirements" ]; then
    PROMPT="/appsec-plugin:check-appsec-requirements"

    # Category filter comes first (positional arg in the skill)
    [ -n "$CATEGORY_FILTER" ] && PROMPT="$PROMPT $CATEGORY_FILTER"

    # Save flags
    [ -n "$SAVE_REPORT" ] && PROMPT="$PROMPT $SAVE_REPORT"

    # Pass any extra flags
    PROMPT="$PROMPT$SKILL_FLAGS"
fi

# ── Build claude CLI command ───────────────────────────────────────
CLAUDE_CMD="claude -p \"$PROMPT\""
CLAUDE_CMD="$CLAUDE_CMD --plugin-dir \"$PLUGIN_DIR\""
CLAUDE_CMD="$CLAUDE_CMD --allowedTools \"Read,Write,Glob,Grep,Bash,Agent\""
CLAUDE_CMD="$CLAUDE_CMD --permission-mode bypassPermissions"
CLAUDE_CMD="$CLAUDE_CMD --output-format $OUTPUT_FORMAT"
CLAUDE_CMD="$CLAUDE_CMD --no-session-persistence"

# Optional arguments
[ -n "$MAX_BUDGET" ] && CLAUDE_CMD="$CLAUDE_CMD --max-budget-usd $MAX_BUDGET"
[ -n "$MODEL" ]      && CLAUDE_CMD="$CLAUDE_CMD --model $MODEL"
[ -n "$VERBOSE" ]    && CLAUDE_CMD="$CLAUDE_CMD $VERBOSE"

# ── Print summary ───────────────────────────────────────────────────
echo ""
info "AppSec Plugin — Headless Mode"
echo "  Skill      : $SKILL"
echo "  Plugin     : $PLUGIN_DIR"
[ -n "$REPO_PATH" ]        && echo "  Repository : $REPO_PATH"
[ -n "$OUTPUT_PATH" ]      && echo "  Output     : $OUTPUT_PATH"
[ -n "$SKILL_FLAGS" ]      && echo "  Flags      :$SKILL_FLAGS"
[ -n "$MAX_BUDGET" ]       && echo "  Budget cap : \$$MAX_BUDGET"
[ -n "$CATEGORY_FILTER" ]  && echo "  Category   : $CATEGORY_FILTER"
[ -n "$VERBOSE" ]          && echo "  Verbose    : real-time hook event log on stderr"
echo ""

# ── Execute ─────────────────────────────────────────────────────────
TAIL_PID=""
TAIL_RUN_PID=""

if [ -n "$VERBOSE" ]; then
    # Determine log directory for tail -f
    RESULT_DIR="${OUTPUT_PATH:-"${REPO_PATH:-.}/docs/security"}"
    mkdir -p "$RESULT_DIR" 2>/dev/null || true
    LOG_FILE="$RESULT_DIR/.hook-events.log"
    RUN_LOG_FILE="$RESULT_DIR/.agent-run.log"
    touch "$LOG_FILE" "$RUN_LOG_FILE"

    # Export env var so the hook logger also writes to stderr (belt + suspenders)
    export APPSEC_VERBOSE=1

    # Start tailing both log files in background — real-time output to stderr
    tail -f "$LOG_FILE" >&2 &
    TAIL_PID=$!
    tail -f "$RUN_LOG_FILE" >&2 &
    TAIL_RUN_PID=$!

    info "Starting Claude Code in headless mode (verbose: tailing $LOG_FILE and $RUN_LOG_FILE)..."
else
    info "Starting Claude Code in headless mode..."
fi
echo ""

eval "$CLAUDE_CMD"
EXIT_CODE=$?

# Clean up tail processes
if [ -n "$TAIL_PID" ]; then
    kill "$TAIL_PID" 2>/dev/null
    wait "$TAIL_PID" 2>/dev/null || true
fi
if [ -n "$TAIL_RUN_PID" ]; then
    kill "$TAIL_RUN_PID" 2>/dev/null
    wait "$TAIL_RUN_PID" 2>/dev/null || true
fi

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    ok "Assessment completed successfully."

    # Show output location
    if [ "$SKILL" = "create-threat-model" ]; then
        RESULT_DIR="${OUTPUT_PATH:-"${REPO_PATH:-.}/docs/security"}"
        if [ -f "$RESULT_DIR/threat-model.md" ]; then
            ok "Threat model: $RESULT_DIR/threat-model.md"
            case "$SKILL_FLAGS" in *--yaml*)  [ -f "$RESULT_DIR/threat-model.yaml" ]      && ok "YAML export: $RESULT_DIR/threat-model.yaml" ;; esac
            case "$SKILL_FLAGS" in *--sarif*) [ -f "$RESULT_DIR/threat-model.sarif.json" ] && ok "SARIF export: $RESULT_DIR/threat-model.sarif.json" ;; esac
        fi
    fi
else
    err "Assessment exited with code $EXIT_CODE"
    warn "Check intermediate files or run with --resume to continue."
fi

exit $EXIT_CODE
