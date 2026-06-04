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
#   --yaml                  (no-op) yaml is always written by default
#   --no-yaml               Suppress threat-model.yaml (BREAKS incremental mode!)
#   --sarif                 Also write threat-model.sarif.json (SARIF v2.1.0)
#   --requirements [<url>]   Enable requirements check (optionally from URL)
#   --no-requirements        Skip requirements even when enabled in config
#   --dry-run               Preview scope without running the full pipeline
#   --incremental           Force delta analysis based on git diff
#   --full                  Force full scan even when prior output exists
#   --resume                Continue from last checkpoint
#   --base <ref>            Git ref to diff HEAD against for incremental / PR mode
#                           (default: commit_sha recorded in prior threat-model.yaml)
#   --pr-mode               Produce a focused delta report for a MR/PR; implies
#                           --incremental and uses --base <ref> (target branch)
#   --fail-on <level>       Exit non-zero when delta contains threats at or above
#                           <level> (critical, high, medium); PR-gate friendly
#   --no-qa                 Skip the Stage-3 QA reviewer (faster CI runs)
#   --trust-mode <mode>     trusted (default) | untrusted — when untrusted, runs
#                           preflight_untrusted.py first (rejects repo-owned hooks
#                           and out-of-repo symlinks), enforces --strict-urls on
#                           related-repos fetches, enables APPSEC_LOG_REDACT_PATHS,
#                           and aborts the pipeline on preflight findings
#   --strict-urls           Require APPSEC_URL_ALLOWLIST for all remote fetches
#                           (implied by --trust-mode untrusted)
#   --restore-from <path>   Hydrate $OUTPUT_DIR from a prior-run artifact before
#                           running (CI cache restore)
#   --max-duration <sec>    Abort the run if it exceeds <sec> seconds
#   --max-budget <usd>      Stop when estimated cost exceeds this amount
#   --clean-cache           Delete cache & transient files (keeps the model); exits
#   --clean-all             Delete everything in <output-dir> (with confirmation); exits
#   --force                 Skip confirmation for --clean-all (auto in CI)
#   --model <model>         Override the Claude model (default: sonnet)
#   --stride-model <model>  Override model for STRIDE analyzers (e.g. opus)
#   --assessment-depth <l>  Assessment depth: quick, standard (default), thorough
#   --json                  Return structured JSON output
#   --verbose               Show real-time hook event log on stderr
#
# Skill selection:
#   --audit-requirements    Run audit-security-requirements instead of threat model
#   --check-requirements    Legacy alias for --audit-requirements
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
  --yaml                     (no-op) yaml is always written by default
  --no-yaml                  Suppress threat-model.yaml output — WARNING: breaks
                             incremental mode on future runs against this output
                             directory (yaml is the canonical baseline)
  --sarif                    Also write threat-model.sarif.json (SARIF v2.1.0)
  --requirements [<url>]     Enable requirements check, optionally from URL
  --no-requirements          Skip requirements even when enabled in config
  --dry-run                  Preview scope without running the full pipeline
  --incremental              Force delta analysis based on git diff
  --full                     Force full scan even when prior output exists
  --rerender                 Re-render Stage 2 + re-run Stage 3 QA from the
                             EXISTING Stage-1 fragments (no Stage 1, no no-op).
                             For fragment/renderer/QA changes; not for code changes.
  --resume                   Continue from last checkpoint
  --base <ref>               Git ref to diff HEAD against (default: baseline commit)
  --pr-mode                  MR/PR delta report — implies --incremental
  --fail-on <level>          Non-zero exit on delta threats >= critical|high|medium
  --no-qa                    Skip Stage-3 QA reviewer (faster CI runs)
  --restore-from <path>      Hydrate \$OUTPUT_DIR from a prior artifact
  --max-duration <seconds>   Abort the run if it exceeds the given duration
  --max-budget <usd>         Stop when estimated cost exceeds this amount
  --clean-cache              Delete cache & transient files in \$OUTPUT_DIR; keeps
                             the threat model and audit logs. Exits without running.
  --clean-all                Delete everything in \$OUTPUT_DIR (interactive confirm
                             unless --force / CI=true). Exits without running.
  --force                    Skip the interactive confirmation for --clean-all
  --model <model>            Override the Claude model (default: sonnet)
  --stride-model <model>     Override model for STRIDE analyzers (e.g. opus)
  --assessment-depth <level> Assessment depth: quick (~15min), standard (~25min), thorough (~40min)
  --json                     Return structured JSON output
  --verbose                  Show real-time hook event log on stderr

Skill selection:
  --audit-requirements       Run audit-security-requirements instead of threat model
  --check-requirements       Legacy alias for --audit-requirements
  --category <filter>        Category filter for requirements check (e.g. SEC-AUTH)
  --save-report              Save requirements report (--md --json)

  -h, --help                 Show this help message and exit

Environment:
  ANTHROPIC_API_KEY          Anthropic API key (optional — uses subscription auth if unset)
  CLAUDE_PLUGIN_DIR          Override plugin directory (default: auto-detected)
  CI=true                    Enables CI mode (skips stale-lock wait, bumps caches,
                             adjusts defaults for non-interactive runners)
HELP
    exit 0
}

# ── Early --help check (before prerequisites) ──────────────────────
for arg in "$@"; do
    case "$arg" in --help|-h) usage ;; esac
done

# ── Locate plugin directory ─────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_DIR="${CLAUDE_PLUGIN_DIR:-"$(dirname "$SCRIPT_DIR")"}"

if [ ! -f "$PLUGIN_DIR/.claude-plugin/plugin.json" ]; then
    die "Plugin not found at $PLUGIN_DIR — set CLAUDE_PLUGIN_DIR or run from the appsec-advisor repo root"
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
BASE_REF=""
PR_MODE=0
FAIL_ON=""
NO_QA=0
RESTORE_FROM=""
MAX_DURATION=""
INCREMENTAL_REQUESTED=0
CLEAN_MODE=""
CLEAN_FORCE=0
CLEAN_DRY_RUN=0
TRUST_MODE="trusted"
STRICT_URLS=0

# CI mode auto-detect — when running under a CI runner we prefer silent,
# deterministic defaults.
if [ "${CI:-}" = "true" ] || [ -n "${GITHUB_ACTIONS:-}" ] || [ -n "${GITLAB_CI:-}" ]; then
    CI_MODE=1
else
    CI_MODE=0
fi

while [ $# -gt 0 ]; do
    case "$1" in
        --repo)
            REPO_PATH="$2"; shift 2 ;;
        --output)
            OUTPUT_PATH="$2"; shift 2 ;;
        --yaml|--no-yaml|--sarif|--no-requirements|--dry-run|--full|--resume|--rerender)
            SKILL_FLAGS="$SKILL_FLAGS $1"; shift ;;
        --incremental)
            INCREMENTAL_REQUESTED=1
            SKILL_FLAGS="$SKILL_FLAGS $1"; shift ;;
        --base)
            BASE_REF="$2"; shift 2 ;;
        --pr-mode)
            PR_MODE=1
            INCREMENTAL_REQUESTED=1
            SKILL_FLAGS="$SKILL_FLAGS --incremental"
            shift ;;
        --fail-on)
            case "$2" in
                critical|high|medium) FAIL_ON="$2"; shift 2 ;;
                *) die "Invalid --fail-on value: $2 (must be critical, high, or medium)" ;;
            esac
            ;;
        --no-qa)
            NO_QA=1; shift ;;
        --trust-mode)
            case "$2" in
                trusted|untrusted) TRUST_MODE="$2"; shift 2 ;;
                *) die "Invalid --trust-mode value: $2 (must be trusted or untrusted)" ;;
            esac
            ;;
        --strict-urls)
            STRICT_URLS=1; shift ;;
        --restore-from)
            RESTORE_FROM="$2"; shift 2 ;;
        --max-duration)
            MAX_DURATION="$2"; shift 2 ;;
        --clean-cache)
            CLEAN_MODE="cache"; shift ;;
        --clean-all)
            CLEAN_MODE="all"; shift ;;
        --force)
            CLEAN_FORCE=1; shift ;;
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
        --audit-requirements|--check-requirements)
            SKILL="audit-security-requirements"; shift ;;
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
else
    REPO_PATH="$(pwd)"
fi

if [ -n "$OUTPUT_PATH" ]; then
    mkdir -p "$OUTPUT_PATH" 2>/dev/null || die "Cannot create output directory: $OUTPUT_PATH"
    OUTPUT_PATH="$(cd "$OUTPUT_PATH" && pwd)"
else
    OUTPUT_PATH="$REPO_PATH/docs/security"
fi

# ── Trust mode: preflight + strict defaults ─────────────────────────
# --trust-mode untrusted forces every defence we have today: reject
# repo-owned Claude hooks, refuse out-of-repo symlinks, require an
# explicit URL allowlist for related-repos fetches, redact paths in
# the run log. Findings abort the assessment before any LLM dispatch.
if [ "$TRUST_MODE" = "untrusted" ]; then
    STRICT_URLS=1
    export APPSEC_LOG_REDACT_PATHS=1
    info "trust-mode: untrusted — running preflight safety checks"
    PREFLIGHT_SCRIPT="$PLUGIN_DIR/scripts/preflight_untrusted.py"
    if [ ! -f "$PREFLIGHT_SCRIPT" ]; then
        die "preflight script not found: $PREFLIGHT_SCRIPT"
    fi
    if ! python3 "$PREFLIGHT_SCRIPT" --repo-root "$REPO_PATH" --strict --strict-urls --format text --output - >/dev/null; then
        die "preflight findings present — refusing to scan in untrusted mode (run preflight_untrusted.py manually for details)"
    fi
    info "preflight: clean"
fi
if [ "$STRICT_URLS" = "1" ]; then
    export APPSEC_RELATED_REPOS_STRICT_URLS=1
fi

# ── Cleanup-only mode (--clean-cache / --clean-all) ────────────────
# Executes before anything else. When triggered, we delegate to the Python
# helper (which owns the file classification) and exit — no Claude dispatch.
if [ -n "$CLEAN_MODE" ]; then
    # Detect --dry-run in SKILL_FLAGS so it applies to the clean operation
    # instead of the (not-happening) assessment.
    if echo "$SKILL_FLAGS" | grep -q -- '--dry-run'; then
        CLEAN_DRY_RUN=1
    fi
    CLEAN_ARGS="clean --output-dir $OUTPUT_PATH --mode $CLEAN_MODE"
    [ "$CLEAN_FORCE" = "1" ] && CLEAN_ARGS="$CLEAN_ARGS --force"
    [ "$CLEAN_DRY_RUN" = "1" ] && CLEAN_ARGS="$CLEAN_ARGS --dry-run"
    # CI auto-force: in CI the TTY-confirmation is never reachable, so
    # --clean-all would otherwise abort with exit 1.
    if [ "$CI_MODE" = "1" ] && [ "$CLEAN_MODE" = "all" ]; then
        echo "$CLEAN_ARGS" | grep -q -- '--force' || CLEAN_ARGS="$CLEAN_ARGS --force"
    fi
    info "Cleanup — mode=$CLEAN_MODE target=$OUTPUT_PATH"
    python3 "$PLUGIN_DIR/scripts/baseline_state.py" $CLEAN_ARGS
    exit $?
fi

# ── Hydrate from CI cache (--restore-from) ─────────────────────────
if [ -n "$RESTORE_FROM" ]; then
    if [ ! -d "$RESTORE_FROM" ]; then
        die "--restore-from directory does not exist: $RESTORE_FROM"
    fi
    info "Restoring baseline state from: $RESTORE_FROM"
    mkdir -p "$OUTPUT_PATH"
    for f in threat-model.yaml threat-model.md threat-model.sarif.json; do
        if [ -f "$RESTORE_FROM/$f" ]; then
            cp "$RESTORE_FROM/$f" "$OUTPUT_PATH/$f"
        fi
    done
    if [ -d "$RESTORE_FROM/.appsec-cache" ]; then
        rm -rf "$OUTPUT_PATH/.appsec-cache"
        cp -r "$RESTORE_FROM/.appsec-cache" "$OUTPUT_PATH/.appsec-cache"
    fi
    # Copy any .stride-*.json for per-component carry-forward
    find "$RESTORE_FROM" -maxdepth 1 -name '.stride-*.json' -exec cp {} "$OUTPUT_PATH/" \; 2>/dev/null || true
    ok "Restored $(ls -1 "$OUTPUT_PATH" 2>/dev/null | wc -l) files into $OUTPUT_PATH"
fi

# ── Fast-Path Preflight ─────────────────────────────────────────────
# When an incremental run is requested and a baseline exists, check whether
# anything actually changed BEFORE dispatching Claude. If the repo is
# unchanged and the plugin hasn't drifted, we can skip the entire run in
# a fraction of a second — the killer optimisation for CI.
FAST_PATH_TAKEN=0
if [ "$INCREMENTAL_REQUESTED" = "1" ] || [ "$PR_MODE" = "1" ]; then
    if [ -f "$OUTPUT_PATH/threat-model.yaml" ]; then
        CHECK_ARGS="check-changes --output-dir $OUTPUT_PATH --repo-root $REPO_PATH"
        if [ -n "$BASE_REF" ]; then
            CHECK_ARGS="$CHECK_ARGS --base-ref $BASE_REF"
        fi
        set +e
        FAST_PATH_OUTPUT="$(python3 "$PLUGIN_DIR/scripts/baseline_state.py" $CHECK_ARGS 2>/dev/null)"
        FAST_PATH_EXIT=$?
        set -e
        case "$FAST_PATH_EXIT" in
            0)
                ok "No changes since last scan — threat model is up to date."
                if [ "$CI_MODE" = "1" ]; then
                    echo "$FAST_PATH_OUTPUT"
                fi
                FAST_PATH_TAKEN=1
                exit 0
                ;;
            10)
                warn "Source unchanged, but plugin version drifted since the last run."
                echo "$FAST_PATH_OUTPUT" | grep -i 'message' || true
                warn "Consider running with --full to pick up new capabilities."
                if [ "$CI_MODE" = "1" ]; then
                    # In CI, honour the signal and still fast-abort — the CI can
                    # schedule a full run separately (e.g. weekly).
                    ok "Fast-abort (CI mode): use a scheduled --full job to refresh."
                    FAST_PATH_TAKEN=1
                    exit 0
                fi
                ;;
            *)
                # status=changed or error — fall through to the normal run
                ;;
        esac
    fi
fi

# ── Build the skill command ─────────────────────────────────────────
if [ "$SKILL" = "create-threat-model" ]; then
    PROMPT="/appsec-advisor:create-threat-model"

    # Append --repo / --output if specified
    [ -n "$REPO_PATH" ]   && PROMPT="$PROMPT --repo $REPO_PATH"
    [ -n "$OUTPUT_PATH" ] && PROMPT="$PROMPT --output $OUTPUT_PATH"

    # Forward base-ref / pr-mode / no-qa so the skill can propagate them
    # via env-vars to the orchestrator.
    [ -n "$BASE_REF" ]   && PROMPT="$PROMPT --base $BASE_REF"
    [ "$PR_MODE" = "1" ] && PROMPT="$PROMPT --pr-mode"
    [ "$NO_QA" = "1" ]   && PROMPT="$PROMPT --no-qa"

    # Append remaining flags
    PROMPT="$PROMPT$SKILL_FLAGS"

elif [ "$SKILL" = "audit-security-requirements" ]; then
    PROMPT="/appsec-advisor:audit-security-requirements"

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

# Wrap with timeout(1) when --max-duration is set; the skill would otherwise
# need to self-police, which is not reliable in an LLM-driven orchestrator.
if [ -n "$MAX_DURATION" ]; then
    if command -v timeout >/dev/null 2>&1; then
        CLAUDE_CMD="timeout --preserve-status ${MAX_DURATION}s $CLAUDE_CMD"
    else
        warn "--max-duration requested but 'timeout' binary not available; ignoring"
    fi
fi

# Export env-vars the skill/orchestrator can pick up
[ "$NO_QA" = "1" ]         && export APPSEC_SKIP_QA=1
[ "$PR_MODE" = "1" ]       && export APPSEC_PR_MODE=1
[ -n "$BASE_REF" ]         && export APPSEC_BASE_REF="$BASE_REF"
[ "$CI_MODE" = "1" ]       && export APPSEC_CI_MODE=1
[ -n "$FAIL_ON" ]          && export APPSEC_FAIL_ON="$FAIL_ON"
# Full-M1 opt-in: forward the parallel-STRIDE switch into the headless skill env
# (inherited from the caller's environment) so the skill's Bash tool sees it.
[ "${APPSEC_PARALLEL_STRIDE:-0}" = "1" ] && export APPSEC_PARALLEL_STRIDE=1

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

cleanup_tails() {
    if [ -n "$TAIL_PID" ]; then
        kill "$TAIL_PID" 2>/dev/null || true
        wait "$TAIL_PID" 2>/dev/null || true
        TAIL_PID=""
    fi
    if [ -n "$TAIL_RUN_PID" ]; then
        kill "$TAIL_RUN_PID" 2>/dev/null || true
        wait "$TAIL_RUN_PID" 2>/dev/null || true
        TAIL_RUN_PID=""
    fi
}

if [ -n "$VERBOSE" ]; then
    # Determine log directory for tail -f
    RESULT_DIR="${OUTPUT_PATH:-"${REPO_PATH:-.}/docs/security"}"
    mkdir -p "$RESULT_DIR" 2>/dev/null || true
    LOG_FILE="$RESULT_DIR/.hook-events.log"
    RUN_LOG_FILE="$RESULT_DIR/.agent-run.log"
    touch "$LOG_FILE" "$RUN_LOG_FILE"

    # Kill any stale `tail -f` processes from previous interrupted runs
    # that leaked past the cleanup trap. Without this, a second verbose
    # invocation stacks a second tail on the same file and every new log
    # line is emitted to stderr twice.
    for stale_log in "$LOG_FILE" "$RUN_LOG_FILE"; do
        stale_pids=$(pgrep -f "tail -f $stale_log" 2>/dev/null || true)
        if [ -n "$stale_pids" ]; then
            warn "Killing stale tail -f on $stale_log (pids: $(echo $stale_pids | tr '\n' ' '))"
            # shellcheck disable=SC2086
            kill $stale_pids 2>/dev/null || true
        fi
    done

    # Ensure tails are cleaned up on any exit path (normal, signal, error).
    # Without this trap, Ctrl-C or a crashed claude-code leaks tail processes
    # that pile up and duplicate stderr output on the next verbose run.
    trap 'cleanup_tails' EXIT INT TERM HUP

    # APPSEC_VERBOSE=1 makes agent_logger.py emit compact `[appsec] ▶ …`
    # progress lines to stderr. These are distinct from the raw log lines
    # tailed below, so they complement each other (they do NOT duplicate).
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

# Allow the claude subprocess to fail without tripping `set -e` so the
# trap cleanup still runs and we can surface the real exit code.
set +e
eval "$CLAUDE_CMD"
EXIT_CODE=$?
set -e

cleanup_tails

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

# ── Post-scan unmasked-secret check ────────────────────────────────
# Runs scripts/postscan_secret_check.py over the rendered report and
# headline intermediates. Catches the case where the agent forgot to
# redact a secret in prose (validate_intermediate.py only catches the
# structured `hardcoded_secrets[].snippet` field). Always-on so the
# trusted-mode default also gets the protection; fails the run when a
# real secret value lands in a published artefact.
if [ "$SKILL" = "create-threat-model" ] && [ $EXIT_CODE -eq 0 ] && [ -d "$OUTPUT_PATH" ]; then
    POSTSCAN_SCRIPT="$PLUGIN_DIR/scripts/postscan_secret_check.py"
    if [ -f "$POSTSCAN_SCRIPT" ]; then
        if ! python3 "$POSTSCAN_SCRIPT" --output-dir "$OUTPUT_PATH"; then
            err "post-scan secret check failed — see stderr above"
            EXIT_CODE=21
        fi
    fi
fi

# ── PR Gate: --fail-on <level> ──────────────────────────────────────
# When set, translate the run's semantic outcome (new threats introduced by
# the delta) into a CI-friendly exit code. We read the Change Summary from
# the freshly written threat-model.yaml's top changelog entry — any threat
# in `added` at or above the given severity fails the gate.
if [ -n "$FAIL_ON" ] && [ $EXIT_CODE -eq 0 ] && [ -f "$OUTPUT_PATH/threat-model.yaml" ]; then
    python3 - "$OUTPUT_PATH/threat-model.yaml" "$FAIL_ON" <<'PY' || EXIT_CODE=$?
import sys
try:
    import yaml
except ImportError:
    sys.exit(0)  # no pyyaml → skip gate quietly

path, level = sys.argv[1], sys.argv[2].lower()
rank = {"critical": 3, "high": 2, "medium": 1, "low": 0}
threshold = rank.get(level, 2)

try:
    with open(path) as f:
        doc = yaml.safe_load(f) or {}
except Exception:
    sys.exit(0)

changelog = doc.get("changelog") or []
if not changelog:
    sys.exit(0)
latest = changelog[0] if isinstance(changelog, list) else {}
added_ids = set((latest.get("added") or {}).get("threats") or [])
if not added_ids:
    sys.exit(0)

threats_by_id = {t.get("id"): t for t in (doc.get("threats") or []) if isinstance(t, dict)}
violators = []
for tid in added_ids:
    t = threats_by_id.get(tid)
    if not t:
        continue
    risk = (t.get("risk") or "").lower()
    if rank.get(risk, -1) >= threshold:
        violators.append(f"{tid}({risk})")

if violators:
    print(f"\n\033[0;31m✗\033[0m PR gate: {len(violators)} new threat(s) at or above '{level}': {', '.join(violators[:10])}", file=sys.stderr)
    sys.exit(20)
PY
    # Exit 20 is our PR-gate failure signal; surface it distinctly.
    if [ $EXIT_CODE -eq 20 ]; then
        err "PR gate triggered — new threats at or above '$FAIL_ON' severity."
    fi
fi

exit $EXIT_CODE
