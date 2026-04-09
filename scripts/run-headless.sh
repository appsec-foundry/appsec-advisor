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
#   --incremental           Force delta analysis based on git diff
#   --full                  Force full scan even when prior output exists
#   --resume                Continue from last checkpoint
#   --max-budget <usd>      Stop when estimated cost exceeds this amount
#   --model <model>         Override the Claude model (default: sonnet)
#   --stride-model <model>  Override model for STRIDE analyzers (e.g. opus)
#   --assessment-depth <l>  Assessment depth: quick, standard (default), thorough
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
  --incremental              Force delta analysis based on git diff
  --full                     Force full scan even when prior output exists
  --resume                   Continue from last checkpoint
  --max-budget <usd>         Stop when estimated cost exceeds this amount
  --model <model>            Override the Claude model (default: sonnet)
  --stride-model <model>     Override model for STRIDE analyzers (e.g. opus)
  --assessment-depth <level> Assessment depth: quick (~15min), standard (~25min), thorough (~40min)
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

# ── Read external context config ────────────────────────────────────
CONFIG_FILE="$PLUGIN_DIR/config.json"
CONTEXT_INFO="not configured"
if [ -f "$CONFIG_FILE" ]; then
    CTX_ENABLED=$(grep -o '"enabled"[[:space:]]*:[[:space:]]*[a-z]*' "$CONFIG_FILE" | head -1 | grep -o '[a-z]*$')
    CTX_URL=$(grep -o '"rest_url"[[:space:]]*:[[:space:]]*"[^"]*"' "$CONFIG_FILE" | head -1 | sed 's/.*"rest_url"[[:space:]]*:[[:space:]]*"//' | sed 's/"$//')
    if [ "$CTX_ENABLED" = "false" ]; then
        CONTEXT_INFO="disabled"
    elif [ -n "$CTX_URL" ]; then
        CONTEXT_INFO="REST endpoint → $CTX_URL"
    else
        CONTEXT_INFO="repo files only (no REST endpoint configured)"
    fi
fi

# ── Verify prerequisites ────────────────────────────────────────────
command -v claude >/dev/null 2>&1 || die "Claude Code CLI not found. Install it first: https://claude.ai/download"

if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
    BILLING_MODE="api"
else
    BILLING_MODE="subscription"
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
ASSESSMENT_DEPTH=""

while [ $# -gt 0 ]; do
    case "$1" in
        --repo)
            REPO_PATH="$2"; shift 2 ;;
        --output)
            OUTPUT_PATH="$2"; shift 2 ;;
        --yaml|--sarif|--no-requirements|--with-sca|--dry-run|--incremental|--full|--resume)
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
        --assessment-depth)
            case "$2" in
                quick|standard|thorough)
                    ASSESSMENT_DEPTH="$2"
                    SKILL_FLAGS="$SKILL_FLAGS --assessment-depth $2"; shift 2 ;;
                *)
                    die "Invalid --assessment-depth value: $2 (must be quick, standard, or thorough)" ;;
            esac
            ;;
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

# ── Pre-flight auth check ────────────────────────────────────────────
if [ "$BILLING_MODE" = "subscription" ]; then
    AUTH_JSON=$(claude auth status 2>/dev/null) || AUTH_JSON="{}"
    if ! echo "$AUTH_JSON" | grep -q '"loggedIn": true'; then
        die "Not authenticated for subscription billing.\n  • To use subscription: run 'claude auth login'\n  • To use API billing:  export ANTHROPIC_API_KEY=<your-key>"
    fi
fi

# ── API billing mode adjustments ────────────────────────────────────
if [ "$BILLING_MODE" = "api" ]; then
    # In API billing mode a model must be explicit (billed per-token).
    # Default to sonnet when the caller didn't specify one.
    if [ -z "$MODEL" ]; then
        MODEL="claude-sonnet-4-5"
        info "API billing mode: defaulting to model '$MODEL' (use --model to override)"
    fi
    # Warn if spending is uncapped — easy to run up unexpected charges.
    if [ -z "$MAX_BUDGET" ]; then
        warn "API billing mode active with no budget cap — consider --max-budget <usd>"
    fi
else
    # Subscription mode: budget cap flag is not supported; drop it with a warning.
    if [ -n "$MAX_BUDGET" ]; then
        warn "--max-budget is only effective in API billing mode (ANTHROPIC_API_KEY unset); ignoring"
        MAX_BUDGET=""
    fi
fi

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
echo "  Billing    : $BILLING_MODE"
[ -n "$MODEL" ]            && echo "  Model      : $MODEL"
echo "  Depth      : ${ASSESSMENT_DEPTH:-standard}"
echo "  Context    : $CONTEXT_INFO"
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

# ── Parse duration and files from log ──────────────────────────────
RESULT_DIR="${OUTPUT_PATH:-"${REPO_PATH:-.}/docs/security"}"
ASSESSMENT_DURATION=""
LOG_FILE="$RESULT_DIR/.hook-events.log"
if [ -f "$LOG_FILE" ]; then
    ASSESSMENT_DURATION=$(grep "ASSESSMENT_SUMMARY" "$LOG_FILE" | tail -1 | sed -n 's/.*duration=\([^ ]*\).*/\1/p')
fi

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    ok "Assessment completed successfully."
    [ -n "$ASSESSMENT_DURATION" ] && ok "Duration: $ASSESSMENT_DURATION"

    # List all written files with full paths
    if [ "$SKILL" = "create-threat-model" ]; then
        echo ""
        echo "  Output files:"
        [ -f "$RESULT_DIR/threat-model.md" ]          && ok "  $RESULT_DIR/threat-model.md"
        [ -f "$RESULT_DIR/threat-model.yaml" ]        && ok "  $RESULT_DIR/threat-model.yaml"
        [ -f "$RESULT_DIR/threat-model.sarif.json" ]  && ok "  $RESULT_DIR/threat-model.sarif.json"

        echo "  Intermediate files:"
        [ -f "$RESULT_DIR/.threat-modeling-context.md" ] && echo "    $RESULT_DIR/.threat-modeling-context.md"
        [ -f "$RESULT_DIR/.recon-summary.md" ]           && echo "    $RESULT_DIR/.recon-summary.md"
        [ -f "$RESULT_DIR/.dep-scan.json" ]              && echo "    $RESULT_DIR/.dep-scan.json"
        for f in "$RESULT_DIR"/.stride-*.json; do
            [ -f "$f" ] && echo "    $f"
        done
        echo "  Log files:"
        [ -f "$RESULT_DIR/.agent-run.log" ]    && echo "    $RESULT_DIR/.agent-run.log"
        [ -f "$RESULT_DIR/.hook-events.log" ]  && echo "    $RESULT_DIR/.hook-events.log"
    fi
else
    err "Assessment exited with code $EXIT_CODE"
    [ -n "$ASSESSMENT_DURATION" ] && echo "  Duration: $ASSESSMENT_DURATION"
    warn "Check intermediate files or run with --resume to continue."
fi

exit $EXIT_CODE
