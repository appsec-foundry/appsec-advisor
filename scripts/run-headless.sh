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
#   --no-yaml               Suppress threat-model.yaml
#   --sarif                 Also write threat-model.sarif.json (SARIF v2.1.0)
#   --threatdragon          Also write threat-model.threatdragon.json (ALPHA)
#   --requirements [<src>]   Enable requirements check (optionally from an
#                            http(s):// URL or a local file path)
#   --no-requirements        Skip requirements even when enabled in config
#   --context <src>          Business context for this run: an http(s):// URL or
#                            a file path (optional; used for this run only)
#   --dry-run               Unsupported for assessments; exits before dispatch
#   --incremental           Unsupported; use a fresh full or rebuild run
#   --full                  Force full scan even when prior output exists
#   --resume                Unsupported; use rerender or rebuild
#   --base <ref>            Unsupported because incremental mode is unavailable
#   --pr-mode               Unsupported because incremental mode is unavailable
#   --fail-on <level>       Exit non-zero when new threats are at or above
#                           <level> (critical, high, medium); PR-gate friendly
#   --no-qa                 Skip the Stage-3 QA reviewer (faster CI runs)
#   --trust-mode <mode>     untrusted (default) | trusted — untrusted runs
#                           preflight_untrusted.py first (rejects repo-owned hooks
#                           and out-of-repo symlinks), enforces --strict-urls on
#                           related-repos fetches, enables APPSEC_LOG_REDACT_PATHS,
#                           and aborts the pipeline on preflight findings
#   --strict-urls           Require APPSEC_URL_ALLOWLIST for all remote fetches
#                           (implied by --trust-mode untrusted)
#   --restore-from <path>   Unsupported because incremental mode is unavailable
#   --max-duration <sec>    Abort the run if it exceeds <sec> seconds
#   --max-budget <usd>      Stop when estimated cost exceeds this amount
#   --clean-cache           Delete cache & transient files (keeps the model); exits
#   --clean-all             Delete everything in <output-dir> (with confirmation); exits
#   --force                 Skip confirmation for --clean-all (auto in CI)
#   --model <model>         Override the session model (default: claude-sonnet-4-6, economy)
#   --reasoning-model <t>   Reasoning tier for STRIDE/triage/merger: opus,
#                           opus-cheap, sonnet, sonnet-economy
#   --assessment-depth <l>  Assessment depth: quick, standard (default), thorough
#   --evidence-verifier-cap <n>  Limit Phase-10a non-Critical verification work
#   --json                  Echo the raw `claude -p` result object on stdout
#                           (the run's token/cost readout is printed either way)
#   --verbose               Show the full real-time hook event log on stderr
#   --quiet                 Suppress live progress (default = milestone events)
#
# Skill selection:
#   --audit-requirements    Run audit-security-requirements instead of threat model
#   --check-requirements    Legacy alias for --audit-requirements
#   --category <filter>     Category filter for requirements check (e.g. SEC-AUTH)
#   --save-report           Save requirements report (--md --pdf --json)
#
# Environment:
#   ANTHROPIC_API_KEY       Anthropic API key (optional — uses subscription if unset)
#   APPSEC_CLAUDE_EXECUTABLE  Claude CLI or wrapper executable (default: claude)
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
  --no-yaml                  Suppress threat-model.yaml output
  --sarif                    Also write threat-model.sarif.json (SARIF v2.1.0)
  --threatdragon             Also write threat-model.threatdragon.json
                             (OWASP Threat Dragon v2 — ALPHA, opt-in only)
  --requirements [<src>]     Enable requirements check, optionally from an
                             http(s):// URL or a local file path
  --no-requirements          Skip requirements even when enabled in config
  --context <src>            Business context for this run: an http(s):// URL or
                             a file path. Optional; applies to this run only —
                             persist it by committing docs/business-context.md
  --dry-run                  Unsupported by the compact runtime; exits before dispatch
  --incremental              Unsupported by the compact runtime; exits before dispatch
  --full                     Force full scan even when prior output exists
  --rerender                 Re-render Stage 2 + re-run Stage 3 QA from the
                             EXISTING Stage-1 fragments (no Stage 1, no no-op).
                             For fragment/renderer/QA changes; not for code changes.
  --resume                   Unsupported; use --rerender or a fresh --rebuild
  --base <ref>               Reserved for incremental mode, which is unsupported
  --pr-mode                  Unsupported because incremental mode is unavailable
  --fail-on <level>          Non-zero exit on new threats >= critical|high|medium
  --no-qa                    Skip Stage-3 QA reviewer (faster CI runs)
  --restore-from <path>      Unsupported because incremental mode is unavailable
  --max-duration <seconds>   Abort the run if it exceeds the given duration
  --max-budget <usd>         Stop when estimated cost exceeds this amount
  --clean-cache              Delete cache & transient files in \$OUTPUT_DIR; keeps
                             the threat model and audit logs. Exits without running.
  --clean-all                Delete everything in \$OUTPUT_DIR (interactive confirm
                             unless --force / CI=true). Exits without running.
  --force                    Skip the interactive confirmation for --clean-all
  --model <model>            Override the session model (default: claude-sonnet-4-6, economy)
  --reasoning-model <tier>   Reasoning tier for STRIDE/triage/merger:
                             opus, opus-cheap, sonnet, sonnet-economy
  --assessment-depth <level> Assessment depth: quick (~15min), standard (~25min), thorough (~40min)
  --evidence-verifier-cap <N> Verify at most N non-Critical findings in
                             Phase 10a; Critical findings do not count toward the cap.
  --trust-mode <mode>         untrusted (default) | trusted. Untrusted mode rejects
                               repo-owned agent configuration before Claude starts.
  --strict-urls               Require APPSEC_URL_ALLOWLIST for remote related-repo fetches
  --json                     Echo the raw claude result object on stdout
  --verbose                  Show the full real-time hook event log on stderr
  --quiet                    Suppress live progress output (default shows
                             milestone events: phases, agent spawns, heartbeat)

Skill selection:
  --audit-requirements       Run audit-security-requirements instead of threat model
  --check-requirements       Legacy alias for --audit-requirements
  --category <filter>        Category filter for requirements check (e.g. SEC-AUTH)
  --save-report              Save requirements report (--md --pdf --json)

  -h, --help                 Show this help message and exit

Environment:
  ANTHROPIC_API_KEY          Anthropic API key (optional — uses subscription auth if unset)
  APPSEC_CLAUDE_EXECUTABLE   Claude CLI or wrapper executable (default: claude).
                              The value is one executable, not a shell command.
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
# An environment may need to launch Claude through a gateway or observability
# wrapper. Accept one executable so callers can provide that integration
# without turning configuration into a shell command. The command is invoked
# through positional parameters below, never evaluated as shell source.
CLAUDE_EXECUTABLE="${APPSEC_CLAUDE_EXECUTABLE:-claude}"
if ! command -v "$CLAUDE_EXECUTABLE" >/dev/null 2>&1; then
    if [ -n "${APPSEC_CLAUDE_EXECUTABLE:-}" ]; then
        die "Configured Claude executable not found or not executable. APPSEC_CLAUDE_EXECUTABLE must name one executable."
    fi
    die "Claude Code CLI not found. Install it first: https://claude.ai/download"
fi

if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
    BILLING_MODE="api"
else
    BILLING_MODE="subscription"
fi

# ── Parse arguments ─────────────────────────────────────────────────
REPO_PATH=""
OUTPUT_PATH=""
SKILL_FLAGS=""
REQUIREMENTS_INFO=""
REQUIREMENTS_SRC=""
MAX_BUDGET=""
MODEL=""
REASONING_TIER=""
EMIT_RAW_JSON=0
VERBOSE=""
QUIET=""
SKILL="create-threat-model"
CATEGORY_FILTER=""
SAVE_REPORT=""
ASSESSMENT_DEPTH=""
FAIL_ON=""
NO_QA=0
RESTORE_FROM=""
MAX_DURATION=""
INCREMENTAL_REQUESTED=0
CLEAN_MODE=""
CLEAN_FORCE=0
# Target repositories are untrusted by default. Opting into trusted mode is an
# explicit acknowledgement that repository-resident agent configuration may
# execute before this plugin establishes its own instruction boundary.
TRUST_MODE="untrusted"
STRICT_URLS=0
RESUME_REQUESTED=0
DRY_RUN_REQUESTED=0
UNSUPPORTED_RUNTIME_OPTION=""
RUNTIME_MODE_ARGS=""

# Preserve the raw invocation before the parser consumes it, so the failure
# path can reconstruct a re-run command (see the recovery hint below). POSIX sh
# has no arrays; args with embedded spaces are rare in headless use and degrade
# to word-splitting, acceptable for a copy-paste hint.
ORIG_ARGS=""
for _a in "$@"; do
    ORIG_ARGS="${ORIG_ARGS:+$ORIG_ARGS }$_a"
done

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
        --context)
            # Business context for this run: an http(s) URL or a file path. The
            # skill invocation travels as one prompt string, so a value with
            # whitespace would be split — reject it instead of mangling it.
            case "${2:-}" in
                ""|*[[:space:]]*)
                    die "--context takes an http(s) URL or a file path (no spaces). Put pasted text in a file." ;;
            esac
            SKILL_FLAGS="$SKILL_FLAGS --context $2"; shift 2 ;;
        --resume)
            RESUME_REQUESTED=1
            SKILL_FLAGS="$SKILL_FLAGS $1"; shift ;;
        --full)
            RUNTIME_MODE_ARGS="$RUNTIME_MODE_ARGS --full"
            SKILL_FLAGS="$SKILL_FLAGS $1"; shift ;;
        --dry-run)
            DRY_RUN_REQUESTED=1
            SKILL_FLAGS="$SKILL_FLAGS $1"; shift ;;
        --max-wall-time|--max-cost)
            UNSUPPORTED_RUNTIME_OPTION="$1"
            SKILL_FLAGS="$SKILL_FLAGS $1 ${2:-}"; shift 2 ;;
        --rerender)
            RUNTIME_MODE_ARGS="$RUNTIME_MODE_ARGS --rerender"
            SKILL_FLAGS="$SKILL_FLAGS $1"; shift ;;
        --rebuild)
            RUNTIME_MODE_ARGS="$RUNTIME_MODE_ARGS --rebuild"
            SKILL_FLAGS="$SKILL_FLAGS $1"; shift ;;
        --yaml|--no-yaml|--sarif|--threatdragon|--no-requirements|--enrich-arch|--no-enrich-arch)
            SKILL_FLAGS="$SKILL_FLAGS $1"; shift ;;
        --keep-runtime-files)
            # Preserve all transient runtime artifacts. runtime_cleanup.py reads
            # the KEEP_RUNTIME_FILES env gate (not a CLI flag at its skill-layer
            # call sites), so export it for the child claude process AND the
            # deterministic post-run cleanup backstop below. ALSO forward the flag
            # to the skill so resolve_config.py records keep_runtime_files=true in
            # .skill-config.json (resolve_config is CLI-driven, not env-driven).
            export KEEP_RUNTIME_FILES=true
            KEEP_RUNTIME_FILES_FLAG="--keep-runtime-files"
            SKILL_FLAGS="$SKILL_FLAGS $1"; shift ;;
        --incremental)
            INCREMENTAL_REQUESTED=1
            SKILL_FLAGS="$SKILL_FLAGS $1"; shift ;;
        --base)
            UNSUPPORTED_RUNTIME_OPTION="--base"; shift 2 ;;
        --pr-mode)
            UNSUPPORTED_RUNTIME_OPTION="--pr-mode"
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
            RESTORE_FROM="$2"
            UNSUPPORTED_RUNTIME_OPTION="--restore-from"
            shift 2 ;;
        --max-duration)
            MAX_DURATION="$2"; shift 2 ;;
        --clean-cache)
            CLEAN_MODE="cache"; shift ;;
        --clean-all)
            CLEAN_MODE="all"; shift ;;
        --force)
            CLEAN_FORCE=1; shift ;;
        --requirements)
            # --requirements [<src>] — enable requirements, optionally from an
            # http(s):// URL or a local file path. Consume the next token as the
            # source unless it is absent or another flag (so a bare
            # `--requirements --foo` does not swallow `--foo`).
            if [ $# -gt 1 ] && [ -n "${2:-}" ] && [ "${2#-}" = "$2" ]; then
                SKILL_FLAGS="$SKILL_FLAGS --requirements $2"
                REQUIREMENTS_INFO="enabled → $2"; REQUIREMENTS_SRC="$2"; shift 2
            else
                SKILL_FLAGS="$SKILL_FLAGS --requirements"
                REQUIREMENTS_INFO="enabled (source from config)"; shift
            fi
            ;;
        --with-requirements)
            warn "--with-requirements is deprecated — use --requirements"
            SKILL_FLAGS="$SKILL_FLAGS --requirements"
            REQUIREMENTS_INFO="enabled (source from config)"; shift ;;
        --ignore-requirements)
            warn "--ignore-requirements is deprecated — use --no-requirements"
            SKILL_FLAGS="$SKILL_FLAGS --no-requirements"; shift ;;
        --requirements-url)
            warn "--requirements-url is deprecated — use --requirements <url>"
            SKILL_FLAGS="$SKILL_FLAGS --requirements $2"
            REQUIREMENTS_INFO="enabled → $2"; REQUIREMENTS_SRC="$2"; shift 2 ;;
        --max-budget)
            MAX_BUDGET="$2"; shift 2 ;;
        --model)
            MODEL="$2"; shift 2 ;;
        --reasoning-model)
            REASONING_TIER="$2"
            SKILL_FLAGS="$SKILL_FLAGS --reasoning-model $2"; shift 2 ;;
        --evidence-verifier-cap)
            if [[ "${2:-}" =~ ^[1-9][0-9]*$ ]]; then
                SKILL_FLAGS="$SKILL_FLAGS --evidence-verifier-cap $2"; shift 2
            else
                die "Invalid --evidence-verifier-cap value: ${2:-<missing>} (must be a positive integer)"
            fi
            ;;
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
            EMIT_RAW_JSON=1; shift ;;
        --verbose)
            VERBOSE="--verbose"; shift ;;
        --quiet)
            QUIET="1"; shift ;;
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

# The single runtime has no safe compact implementation for these modes. Stop
# before resolving or creating the output directory, trust preflight, or model
# dispatch. Host-level --max-duration/--max-budget remain independent guards.
if [ "$SKILL" = "create-threat-model" ]; then
    [ "$RESUME_REQUESTED" = "1" ] && die "--resume is not supported by the compact runtime. Use --rerender for validated Stage-1 artifacts or --rebuild to start again."
    [ "$INCREMENTAL_REQUESTED" = "1" ] && die "--incremental is not supported by the compact runtime. Use --full or --rebuild."
    if [ "$DRY_RUN_REQUESTED" = "1" ] && [ -z "$CLEAN_MODE" ]; then
        die "--dry-run is not supported by the compact runtime. No scan was started."
    fi
    case "$UNSUPPORTED_RUNTIME_OPTION" in
        --max-wall-time|--max-cost)
            die "$UNSUPPORTED_RUNTIME_OPTION is not supported by the compact runtime. Use a host-level limit instead." ;;
        ?*)
            die "$UNSUPPORTED_RUNTIME_OPTION is not supported by the compact runtime. Use --full, --rebuild, or --rerender." ;;
    esac
    [ "${APPSEC_LIVE_PHASE:-}" = "1" ] && die "APPSEC_LIVE_PHASE=1 is not supported by the compact runtime."
fi

# ── Pre-flight auth check ────────────────────────────────────────────
if [ "$BILLING_MODE" = "subscription" ]; then
    if [ -n "${CLAUDE_CODE_OAUTH_TOKEN:-}" ]; then
        # Non-interactive subscription auth (CI / unattended). The CLI consumes
        # the OAuth token at request time, but `claude auth status` reflects only
        # stored credentials (~/.claude/) and would false-negative here — so we
        # trust the token and skip the interactive-login gate. An invalid token
        # still surfaces as a real error from `claude -p` downstream.
        info "Subscription auth via CLAUDE_CODE_OAUTH_TOKEN (non-interactive; skipping login preflight)"
    else
        AUTH_JSON=$("$CLAUDE_EXECUTABLE" auth status 2>/dev/null) || AUTH_JSON="{}"
        if ! echo "$AUTH_JSON" | grep -q '"loggedIn": true'; then
            die "Not authenticated for subscription billing.\n  • To use subscription: run 'claude auth login' (interactive) or set CLAUDE_CODE_OAUTH_TOKEN (CI / non-interactive)\n  • To use API billing:  export ANTHROPIC_API_KEY=<your-key>"
        fi
    fi
fi

# ── Economy default: session model (both billing modes) ─────────────
# The host session model drives the dominant cache-read cost AND every
# alias-following agent (renderer, abuse-verifier, orchestrator, qa-content).
# Default it to the cost-optimal Sonnet-4.6 (same price/token as Sonnet-5 but
# ~30% fewer tokens; the reasoning core is already 4.6-cost-pinned) — the single
# biggest saving on an unattended run. Opt out with --model <id>. In API billing
# mode a model MUST be explicit anyway (billed per-token), so this also satisfies
# that requirement. Quality buy-back per stage: --triage-model claude-sonnet-5,
# APPSEC_RENDERER_MODEL / APPSEC_ABUSE_VERIFIER_MODEL (see docs/threat-modeler.md).
if [ -z "$MODEL" ]; then
    MODEL="claude-sonnet-4-6"
    info "Economy default: session model '$MODEL' (use --model to override)"
fi

# ── API billing mode adjustments ────────────────────────────────────
if [ "$BILLING_MODE" = "api" ]; then
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
    case "$OUTPUT_PATH" in
        /*) : ;;
        *) OUTPUT_PATH="$(pwd)/$OUTPUT_PATH" ;;
    esac
else
    OUTPUT_PATH="$REPO_PATH/docs/security"
fi

# Resolve the effective mode with the same read-only owner used by the skill.
# This catches automatic incremental selection from an existing baseline before
# the headless Claude process is started and before this wrapper creates output.
if [ "$SKILL" = "create-threat-model" ] && [ -z "$CLEAN_MODE" ]; then
    set +e
    if [ -n "$RUNTIME_MODE_ARGS" ]; then
        ADMISSION_RESULT="$(python3 "$PLUGIN_DIR/scripts/orchestration_controller.py" \
            route -- $RUNTIME_MODE_ARGS --repo "$REPO_PATH" --output "$OUTPUT_PATH")"
    else
        ADMISSION_RESULT="$(python3 "$PLUGIN_DIR/scripts/orchestration_controller.py" \
            route -- --repo "$REPO_PATH" --output "$OUTPUT_PATH")"
    fi
    ADMISSION_EXIT=$?
    set -e
    if [ "$ADMISSION_EXIT" -ne 0 ]; then
        printf '%s\n' "$ADMISSION_RESULT" >&2
        exit "$ADMISSION_EXIT"
    fi
fi

mkdir -p "$OUTPUT_PATH" 2>/dev/null || die "Cannot create output directory: $OUTPUT_PATH"
OUTPUT_PATH="$(cd "$OUTPUT_PATH" && pwd)"

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
        # The findings are printed above. Name the two ways forward here --
        # without them the operator is told what is wrong but not what to do,
        # and the usual reaction is to go looking for a flag to silence the
        # check without understanding what it protects.
        printf '\n' >&2
        printf 'The paths above are loaded by the host tool BEFORE this plugin runs, so a\n' >&2
        printf 'repository you do not control could use them to steer the assessment.\n' >&2
        printf '\n' >&2
        printf 'If those paths are yours (your own Claude Code setup, or a repo you trust):\n' >&2
        printf '    --trust-mode trusted        skips this preflight, changes nothing else\n' >&2
        printf '\n' >&2
        printf 'If you did not write them, or the repo is third-party, do NOT use that flag.\n' >&2
        printf 'Move them out of the repo instead, then re-run:\n' >&2
        printf '    mv %s/.claude %s/.claude.off\n' "$REPO_PATH" "$REPO_PATH" >&2
        printf '\n' >&2
        printf 'Check ownership first — untracked files are usually yours, committed ones\n' >&2
        printf 'come from the repository:\n' >&2
        printf '    git -C %s ls-files .claude\n' "$REPO_PATH" >&2
        printf '\n' >&2
        die "preflight findings present — refusing to scan in untrusted mode"
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
    CLEAN_ARGS="clean --output-dir $OUTPUT_PATH --mode $CLEAN_MODE"
    [ "$CLEAN_FORCE" = "1" ] && CLEAN_ARGS="$CLEAN_ARGS --force"
    [ "$DRY_RUN_REQUESTED" = "1" ] && CLEAN_ARGS="$CLEAN_ARGS --dry-run"
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

# ── Build the skill command ─────────────────────────────────────────
if [ "$SKILL" = "create-threat-model" ]; then
    PROMPT="/appsec-advisor:create-threat-model"

    # Append --repo / --output if specified
    [ -n "$REPO_PATH" ]   && PROMPT="$PROMPT --repo $REPO_PATH"
    [ -n "$OUTPUT_PATH" ] && PROMPT="$PROMPT --output $OUTPUT_PATH"

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
# POSIX sh has no arrays, so use its positional parameters as the command argv.
# This preserves every argument boundary and keeps executable paths and prompt
# content out of shell evaluation.
set -- "$CLAUDE_EXECUTABLE" -p "$PROMPT"
set -- "$@" --plugin-dir "$PLUGIN_DIR"
set -- "$@" --allowedTools "Read,Write,Glob,Grep,Bash,Agent"
set -- "$@" --permission-mode bypassPermissions
# Always `json`, never `text`. The JSON result object is the only readout that
# carries the run's authoritative token/cost accounting (total_cost_usd +
# per-model modelUsage, sub-agents included) — see headless_usage.py. Its
# `result` field holds exactly the text that `--output-format text` would have
# printed, so nothing user-visible is lost; the wrapper re-emits it below.
set -- "$@" --output-format json
set -- "$@" --no-session-persistence

# Optional arguments
[ -n "$MAX_BUDGET" ] && set -- "$@" --max-budget-usd "$MAX_BUDGET"
[ -n "$MODEL" ]      && set -- "$@" --model "$MODEL"
[ -n "$VERBOSE" ]    && set -- "$@" "$VERBOSE"

# Wrap with timeout(1) when --max-duration is set; the skill would otherwise
# need to self-police, which is not reliable in an LLM-driven orchestrator.
if [ -n "$MAX_DURATION" ]; then
    if command -v timeout >/dev/null 2>&1; then
        set -- timeout --preserve-status "${MAX_DURATION}s" "$@"
    else
        warn "--max-duration requested but 'timeout' binary not available; ignoring"
    fi
fi

# Export env-vars the skill/orchestrator can pick up
# Headless marker: this run has no interactive user, so the skill must SKIP the
# interactive orchestrator-model prompt (AskUserQuestion would block/error) and
# proceed on the current session model. The compact full runtime owns the
# corresponding interactive model recommendation.
export APPSEC_HEADLESS=1
# Background-task wait ceiling: Claude Code's `-p` mode waits a default 600s for
# backgrounded tasks and then hard-kills the process. Controller-owned semantic
# jobs may exceed that ceiling. 0 waits indefinitely; the bound is the outer
# `timeout ${MAX_DURATION}s` wrapper above, so headless callers that care about
# a wall-clock cap must pass --max-duration (CI always does).
export CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS=0
[ "$NO_QA" = "1" ]         && export APPSEC_SKIP_QA=1
[ "$CI_MODE" = "1" ]       && export APPSEC_CI_MODE=1
[ -n "$FAIL_ON" ]          && export APPSEC_FAIL_ON="$FAIL_ON"

# ── Print summary ───────────────────────────────────────────────────
echo ""
info "AppSec Plugin — Headless Mode"
echo "  Skill      : $SKILL"
echo "  Billing    : $BILLING_MODE"
echo "  Depth      : ${ASSESSMENT_DEPTH:-standard}"
# Every model the run will use, grouped by model with the roles it drives.
# A bare "Model: <session>" line read as "the whole assessment runs on this",
# which is wrong and misleading in the direction that costs money: the session
# model is the dominant cost lever but drives orchestration, not analysis depth.
# Falls back to the session model alone if the lineup cannot be resolved.
MODEL_LINEUP=""
[ -n "$MODEL" ] && MODEL_LINEUP="$(python3 "$SCRIPT_DIR/model_lineup.py" \
    --session "$MODEL" \
    ${REASONING_TIER:+--reasoning "$REASONING_TIER"} \
    --depth "${ASSESSMENT_DEPTH:-standard}" 2>/dev/null || printf '%s' "$MODEL")"
[ -n "$MODEL_LINEUP" ]     && echo "  Models     : $MODEL_LINEUP"
echo "  Context    : $CONTEXT_INFO"
echo "  Plugin     : $PLUGIN_DIR"
[ -n "$REPO_PATH" ]        && echo "  Repository : $REPO_PATH"
[ -n "$OUTPUT_PATH" ]      && echo "  Output     : $OUTPUT_PATH"
[ -n "$SKILL_FLAGS" ]      && echo "  Flags      :$SKILL_FLAGS"
[ -n "$REQUIREMENTS_INFO" ] && echo "  Requirements: $REQUIREMENTS_INFO"
# One-line intake summary (req + blueprint counts, source names) when the
# requirements source is a readable local file. Fails soft for URLs / config.
[ -n "$REQUIREMENTS_SRC" ] && [ -f "$REQUIREMENTS_SRC" ] && \
    python3 "$SCRIPT_DIR/run_summary.py" requirements "$REQUIREMENTS_SRC" 2>/dev/null || true
[ -n "$MAX_BUDGET" ]       && echo "  Budget cap : \$$MAX_BUDGET"
[ -n "$CATEGORY_FILTER" ]  && echo "  Category   : $CATEGORY_FILTER"
[ -n "$VERBOSE" ]          && echo "  Verbose    : real-time hook event log on stderr"
echo ""

# ── Opus-orchestrator advisory ──────────────────────────────────────
# `--model opus` only raises the orchestrator (main loop) — it assembles and
# writes the report (composition, walkthroughs, banners). The actual
# threat-reasoning work (STRIDE/triage/merger) follows its own per-agent
# routing and is NOT affected. Opus tokens cost ~5x Sonnet's on that layer,
# and orchestration is ~half of an Opus-driven run, so this adds roughly
# +25-55% to the run total (proportional to repo size, not fixed) without
# finding more.
# The real levers are --reasoning-model opus (deeper analysis) and
# --assessment-depth thorough (wider coverage).
# Non-blocking: a deliberate Opus orchestrator is a legitimate choice.
case "$MODEL" in
    *opus*)
        warn "Opus on --model only raises the orchestrator that writes the report (~+25-55% on the run total, proportional to repo size, no extra findings). For deeper analysis use --reasoning-model opus, and/or --assessment-depth thorough for wider coverage." ;;
esac

# ── Execute ─────────────────────────────────────────────────────────
TAIL_PID=""
TAIL_RUN_PID=""
PROGRESS_PID=""

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
    if [ -n "$PROGRESS_PID" ]; then
        kill "$PROGRESS_PID" 2>/dev/null || true
        wait "$PROGRESS_PID" 2>/dev/null || true
        PROGRESS_PID=""
    fi
}

cleanup_live_tool_markers() {
    _cleanup_dir="${RESULT_DIR:-${OUTPUT_PATH:-"${REPO_PATH:-.}/docs/security"}}"
    OUTPUT_DIR="$_cleanup_dir" python3 "$PLUGIN_DIR/scripts/agent_logger.py" \
        --clear-active-tool-calls >/dev/null 2>&1 || true
}

cleanup_headless_runtime() {
    # Clear live state first. A stuck progress-monitor reap must not prevent
    # terminal marker cleanup after the Claude child has already exited.
    cleanup_live_tool_markers
    cleanup_tails
}

# Tail both logs in the background and pipe them through render_progress.py,
# which turns the raw event stream into a stateful, human-readable progress view
# (current phase, sub-agent invokes, sub-steps, wall-clock elapsed).
#
# A background shell pipeline's `$!` identifies only its final process on some
# `/bin/sh` implementations; killing that PID can leave `tail -F` alive with the
# caller's stdout/stderr pipe open. That makes a completed headless invocation
# (and any subprocess test capturing its output) wait forever for EOF. Run the
# whole monitor through run-interruptible.sh, which owns and reaps a dedicated
# process group. PROGRESS_PID is then the wrapper PID, and cleanup_tails can
# terminate one process while the wrapper reliably tears down the entire tree.
start_progress_monitor() {
    "$SCRIPT_DIR/run-interruptible.sh" /dev/null \
        sh -c 'tail -n 0 -F "$1" "$2" 2>/dev/null | python3 "$3"' \
        appsec-progress-monitor "$LOG_FILE" "$RUN_LOG_FILE" "$SCRIPT_DIR/render_progress.py" >&2 &
    PROGRESS_PID=$!
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
    trap 'cleanup_headless_runtime' EXIT INT TERM HUP

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
elif [ -z "$QUIET" ]; then
    # Default: lightweight live progress (milestone events only) so the run
    # isn't a silent black box. Use --verbose for the full firehose, --quiet
    # for no live output at all.
    RESULT_DIR="${OUTPUT_PATH:-"${REPO_PATH:-.}/docs/security"}"
    mkdir -p "$RESULT_DIR" 2>/dev/null || true
    LOG_FILE="$RESULT_DIR/.hook-events.log"
    RUN_LOG_FILE="$RESULT_DIR/.agent-run.log"
    touch "$LOG_FILE" "$RUN_LOG_FILE"

    trap 'cleanup_headless_runtime' EXIT INT TERM HUP
    start_progress_monitor

    info "Starting Claude Code in headless mode (live phase progress; --verbose for the raw event log, --quiet to silence)..."
else
    info "Starting Claude Code in headless mode..."
fi
echo ""

# Capture claude's stdout instead of letting it reach the terminal directly.
# stdout is now a single JSON result object, which is machine data, not a
# progress view — live progress comes from the hook-log monitor on stderr and
# is unaffected. Redirecting a plain `>` keeps claude a direct child, so the
# process-group signal handling below (kill -SIG -$CLAUDE_PID) still works; a
# pipe would make $! the reader's PID and break escalation.
RESULT_DIR="${OUTPUT_PATH:-"${REPO_PATH:-.}/docs/security"}"
mkdir -p "$RESULT_DIR" 2>/dev/null || true
# Hooks are separate processes of the Claude child. Export the resolved run
# directory before launching that child so Stop, Bash, and other non-Agent
# hooks use the same audit and lifecycle state as Agent hooks. Prompt recovery
# remains a compatibility fallback for interactive and older callers.
export OUTPUT_DIR="$RESULT_DIR"
RESULT_CAPTURE="$RESULT_DIR/.headless-result.json"
: > "$RESULT_CAPTURE" 2>/dev/null || RESULT_CAPTURE=""

# Print the run's token/cost readout. Two tiers, never blended:
#   1. The result object — Claude Code's own accounting, the same source the
#      interactive /cost reports, and the only one that includes sub-agent
#      spend. Exact; printed with a per-model breakdown.
#   2. Nothing survived (timeout, SIGKILL, Ctrl-C truncate the capture) — fall
#      back to the hook-log figure and label it an estimate. That figure covers
#      the host session only, so it is a lower bound and must never be shown
#      as if it were the run's cost.
print_usage_summary() {
    [ -n "$RESULT_CAPTURE" ] || return 0
    if python3 "$SCRIPT_DIR/headless_usage.py" "$RESULT_CAPTURE" 2>/dev/null; then
        return 0
    fi
    _usage_est=$(python3 "$SCRIPT_DIR/cost_running_total.py" "$RESULT_DIR" \
        --format banner 2>/dev/null || true)
    case "$_usage_est" in
        ""|*"n/a"*) return 0 ;;
    esac
    warn "Token usage & cost — ESTIMATE (the run did not exit cleanly, so no result object)."
    echo "  Host session only, from .hook-events.log — sub-agent spend is NOT included (lower bound)."
    printf '%s\n' "$_usage_est"
}

# The capture is wrapper-owned scratch, not a run artifact: it is read out by
# print_usage_summary and holds the assistant's final text, which can quote
# repository content. Drop it once consumed. An unparseable capture is KEPT so
# the raw object stays available for diagnosis; --keep-runtime-files keeps it
# unconditionally, matching the runtime_cleanup opt-out.
discard_capture_if_consumed() {
    [ -n "$RESULT_CAPTURE" ] && [ -f "$RESULT_CAPTURE" ] || return 0
    [ "${KEEP_RUNTIME_FILES:-}" != "true" ] || return 0
    if [ ! -s "$RESULT_CAPTURE" ] \
       || python3 "$SCRIPT_DIR/headless_usage.py" "$RESULT_CAPTURE" --format json >/dev/null 2>&1; then
        rm -f "$RESULT_CAPTURE"
    fi
}

# Allow the claude subprocess to fail without tripping `set -e` so the
# trap cleanup still runs and we can surface the real exit code.
set +e

# Run claude in its OWN process group and wait on it, rather than as a
# blocking foreground command. Two reasons:
#   1. As a foreground child, terminal Ctrl-C reaches claude but bash *defers*
#      its own INT trap until the child returns — so the parent can never
#      escalate (a second/third Ctrl-C does nothing). Backgrounding + `wait`
#      lets the trap fire immediately.
#   2. `set -m` puts claude in its own process group (PGID == $!), so the
#      terminal does NOT auto-deliver SIGINT to it; we forward signals
#      explicitly via the trap. That gives us full control over escalation
#      (graceful INT → TERM → KILL) and lets us signal the whole claude tree
#      with `kill -<sig> -$CLAUDE_PID`.
# stdin is redirected from /dev/null so the backgrounded group never blocks
# on a terminal read (SIGTTIN).
CLAUDE_PID=""
SIGINT_COUNT=0
ESCALATION_WATCHDOG_PID=""
# Auto-escalation delays (seconds). Overridable so tests can run fast.
INTERRUPT_TERM_SECS="${APPSEC_INTERRUPT_TERM_SECS:-10}"
INTERRUPT_KILL_SECS="${APPSEC_INTERRUPT_KILL_SECS:-10}"

# After a graceful first interrupt, claude may not stop — a stalled or already
# -aborted turn ignores a single SIGINT. And when this script runs under
# `make ... | tee`, `make` dies on the SAME Ctrl-C and hands the shell prompt
# back, orphaning us: no further Ctrl-C can reach the manual TERM/KILL
# escalation below (those keystrokes now go to the shell). Arm a timed watchdog
# so a SINGLE interrupt still guarantees teardown — escalate to SIGTERM, then
# SIGKILL, on a timer regardless of any further signals. Idempotent: armed once.
start_escalation_watchdog() {
    [ -n "$ESCALATION_WATCHDOG_PID" ] && return
    [ -n "$CLAUDE_PID" ] || return
    (
        sleep "$INTERRUPT_TERM_SECS"
        kill -0 "-$CLAUDE_PID" 2>/dev/null || exit 0
        warn "claude still running ${INTERRUPT_TERM_SECS}s after interrupt — sending SIGTERM to its process group."
        kill -TERM "-$CLAUDE_PID" 2>/dev/null || true
        sleep "$INTERRUPT_KILL_SECS"
        kill -0 "-$CLAUDE_PID" 2>/dev/null || exit 0
        warn "claude ignored SIGTERM — sending SIGKILL to its process group."
        kill -KILL "-$CLAUDE_PID" 2>/dev/null || true
    ) &
    ESCALATION_WATCHDOG_PID=$!
}

on_interrupt() {
    SIGINT_COUNT=$((SIGINT_COUNT + 1))
    [ -n "$CLAUDE_PID" ] || return
    if [ "$SIGINT_COUNT" -ge 3 ]; then
        warn "Third interrupt — sending SIGKILL to the claude process group."
        kill -KILL "-$CLAUDE_PID" 2>/dev/null || true
    elif [ "$SIGINT_COUNT" -eq 2 ]; then
        warn "Second interrupt — sending SIGTERM to the claude process group."
        kill -TERM "-$CLAUDE_PID" 2>/dev/null || true
    else
        warn "Interrupt — forwarding SIGINT to claude (auto-escalates to SIGTERM in ${INTERRUPT_TERM_SECS}s, then SIGKILL after a further ${INTERRUPT_KILL_SECS}s if it is ignored; press Ctrl-C again to escalate now)."
        kill -INT "-$CLAUDE_PID" 2>/dev/null || true
        start_escalation_watchdog
    fi
}
on_terminate() {
    [ -n "$CLAUDE_PID" ] || return
    kill -TERM "-$CLAUDE_PID" 2>/dev/null || true
    start_escalation_watchdog
}

# Print a paste-ready re-run command, choosing --resume vs --rebuild from what
# the resume-guard actually allows (an interrupt before Stage-1 checkpoints
# cannot resume → point at --rebuild instead). Reused by both the Ctrl-C abort
# path and the non-zero-exit failure path so the hint is never only on one.
print_recovery_hint() {
    _rh_dir="${OUTPUT_PATH:-"${REPO_PATH:-.}/docs/security"}"
    if [ "$SKILL" != "create-threat-model" ]; then
        warn "Check intermediate files or run with --resume to continue."
        return
    fi
    _rerun_cmd() {  # $1 = mode flag to append
        _cmd="$0"
        for _a in $ORIG_ARGS; do
            case "$_a" in
                --resume|--full|--rebuild|--rerender|--incremental) ;;
                *) _cmd="$_cmd $_a" ;;
            esac
        done
        printf '%s %s\n' "$_cmd" "$1"
    }
    warn "This runtime does not resume incomplete analysis — start fresh:"
    printf '    %s\n' "$(_rerun_cmd --rebuild)"
}

# Every mode, including --quiet, owns an EXIT backstop. Signal handlers may
# forward or escalate first, but once the wrapper exits no live marker remains.
trap 'cleanup_headless_runtime' EXIT

set -m
if [ -n "$RESULT_CAPTURE" ]; then
    "$@" < /dev/null > "$RESULT_CAPTURE" &
else
    "$@" < /dev/null &
fi
CLAUDE_PID=$!
set +m

trap 'on_interrupt' INT
trap 'on_terminate' TERM HUP

wait "$CLAUDE_PID"
EXIT_CODE=$?
# A trapped signal interrupts `wait` (exit > 128) before claude has finished
# its own shutdown; keep waiting until the process actually exits so we report
# its real code, not 128+signal.
while [ "$EXIT_CODE" -gt 128 ] && kill -0 "$CLAUDE_PID" 2>/dev/null; do
    wait "$CLAUDE_PID"
    EXIT_CODE=$?
done

# claude has exited — cancel the escalation watchdog if it is still counting
# down, so it never lingers past the run or signals a reused process group.
if [ -n "$ESCALATION_WATCHDOG_PID" ]; then
    kill "$ESCALATION_WATCHDOG_PID" 2>/dev/null || true
    ESCALATION_WATCHDOG_PID=""
fi

# Restore terminal cleanup for signals received after the Claude child exits.
trap 'cleanup_headless_runtime' INT TERM HUP
set -e

# PreToolUse markers are live-state, not audit evidence. Ctrl-C, capacity
# errors, and other CLI-level aborts may never emit the outer Stop hook that
# normally clears them, so close the lifecycle after the child is gone.
cleanup_live_tool_markers
cleanup_tails

# Re-emit what claude's stdout used to show. `result` holds the final assistant
# text verbatim (what `--output-format text` printed); --json additionally dumps
# the raw object for machine consumers. Both are no-ops on a truncated capture.
if [ -n "$RESULT_CAPTURE" ] && [ -s "$RESULT_CAPTURE" ]; then
    if python3 "$SCRIPT_DIR/headless_usage.py" "$RESULT_CAPTURE" --result-text 2>/dev/null; then
        [ "$EMIT_RAW_JSON" -eq 1 ] && cat "$RESULT_CAPTURE"
    else
        # No result object. The CLI wrote something else to stdout — an error it
        # does not route to stderr, an unrecognised format, a stubbed binary.
        # Pass it through rather than swallowing it; capturing stdout must not
        # cost us diagnosability. Truncated JSON is the one exception: a killed
        # run leaves a half-written object with nothing readable in it.
        case "$(head -c 1 "$RESULT_CAPTURE")" in
            "{"|"[") ;;
            *) cat "$RESULT_CAPTURE" ;;
        esac
    fi
fi

# If the run was interrupted by Ctrl-C, stop here instead of proceeding to
# artifact parsing — the user asked to abort.
if [ "$SIGINT_COUNT" -gt 0 ]; then
    warn "Run aborted by user (exit $EXIT_CODE). Skipping post-run parsing."
    # Post-run parsing is skipped, but the run still has to reach one terminal
    # state. Without this the lock stays held, the checkpoint stays mid-flight
    # and `appsec_status.py --live` reports an unknown phase until the
    # heartbeat ages out — the process that took the lock is already gone.
    python3 "$PLUGIN_DIR/scripts/terminate_run.py" \
        --output-dir "${RESULT_DIR:-${OUTPUT_PATH:-"${REPO_PATH:-.}/docs/security"}}" \
        --outcome interrupt --reason "operator interrupt (exit $EXIT_CODE)" \
        --repo-root "${REPO_PATH:-.}" --depth "${ASSESSMENT_DEPTH:-standard}" \
        >/dev/null 2>&1 || true
    echo ""
    print_usage_summary
    print_recovery_hint
    discard_capture_if_consumed
    exit "$EXIT_CODE"
fi

# ── Parse duration and files from log ──────────────────────────────
RESULT_DIR="${OUTPUT_PATH:-"${REPO_PATH:-.}/docs/security"}"
ASSESSMENT_DURATION=""
LOG_FILE="$RESULT_DIR/.hook-events.log"
if [ -f "$LOG_FILE" ]; then
    ASSESSMENT_DURATION=$(grep "ASSESSMENT_SUMMARY" "$LOG_FILE" | tail -1 | sed -n 's/.*duration=\([^ ]*\).*/\1/p')
fi

# ── Deterministic compose backstop (headless completion) ───────────
# The in-controller _compose_if_ready backstop (orchestration_controller.py
# `next`) only fires from an LLM finalize turn (SKILL-full-runtime.md §6). A
# hard process-kill removes that turn — e.g. CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS
# terminating `claude -p` while the parallel-render agents' fragments are on
# disk but threat-model.md was never composed — so nothing invokes it and the
# run leaves threat-model.yaml + a full .fragments/ set with no report. Invoke
# `next` here from the shell so the compose is guaranteed however the process
# ended. Self-gating: it only composes when the render fragments are present,
# and is a no-op when threat-model.md already exists. Runs regardless of
# EXIT_CODE so a killed-but-complete run is still salvaged.
if [ "$SKILL" = "create-threat-model" ] \
   && [ -s "$RESULT_DIR/threat-model.yaml" ] \
   && [ ! -s "$RESULT_DIR/threat-model.md" ]; then
    info "threat-model.md missing but yaml present — running deterministic compose backstop"
    python3 "$PLUGIN_DIR/scripts/orchestration_controller.py" \
        next --output-dir "$RESULT_DIR" >/dev/null 2>&1 || true
    [ -s "$RESULT_DIR/threat-model.md" ] && ok "compose backstop produced threat-model.md"
fi

# Artifact gate (fail-closed): a create-threat-model run MUST leave a
# composed threat-model.md. `claude -p` can exit 0 after a *graceful* stop that
# produced no report (a broken-Bash environment aborts every script, so the
# agent diagnoses and stops cleanly), and a bg-ceiling process-kill can leave
# threat-model.yaml + fragments but no composed report. The compose backstop
# above salvages the latter when the fragments are complete; this gate fails
# closed when threat-model.md is still absent — a run must never report success
# with no deliverable report. Checking md alone (not md-OR-yaml) closes the old
# fail-open path where yaml-without-md was reported as "completed successfully".
if [ "$SKILL" = "create-threat-model" ]; then
    if [ ! -s "$RESULT_DIR/threat-model.md" ]; then
        err "No threat-model.md in $RESULT_DIR — treating as failure (fail-closed)."
        [ "$EXIT_CODE" -eq 0 ] && EXIT_CODE=1
    fi
fi

# ── SARIF canonical-name backstop ──────────────────────────────────
# SARIF is deterministic from threat-model.yaml (scripts/export_sarif.py), but
# the LLM finalization that invokes it can write the artefact under a
# non-canonical name (observed 2026-06-18: threat-model.sarif, missing the
# .json suffix) or skip it. Every downstream consumer — CI upload,
# publish_threat_model.py, the e2e asserts — pins threat-model.sarif.json. When
# --sarif was requested and the canonical file is absent, regenerate it from
# the yaml so the artefact name can never depend on LLM behaviour.
if [ "$SKILL" = "create-threat-model" ] && [ "$EXIT_CODE" -eq 0 ] \
   && printf '%s' "$SKILL_FLAGS" | grep -q -- '--sarif' \
   && [ -s "$RESULT_DIR/threat-model.yaml" ] \
   && [ ! -f "$RESULT_DIR/threat-model.sarif.json" ]; then
    if python3 "$SCRIPT_DIR/export_sarif.py" \
            --threat-model "$RESULT_DIR/threat-model.yaml" \
            --output "$RESULT_DIR/threat-model.sarif.json" >/dev/null 2>&1; then
        rm -f "$RESULT_DIR/threat-model.sarif"
        info "SARIF backstop wrote $RESULT_DIR/threat-model.sarif.json from yaml"
    fi
fi

# ── Threat Dragon canonical-name backstop ──────────────────────────
# Same reasoning as the SARIF backstop above: the export is deterministic from
# threat-model.yaml (scripts/export_threat_dragon.py), so the artefact must not
# depend on whether the LLM finalization actually ran the substep.
if [ "$SKILL" = "create-threat-model" ] && [ "$EXIT_CODE" -eq 0 ] \
   && printf '%s' "$SKILL_FLAGS" | grep -q -- '--threatdragon' \
   && [ -s "$RESULT_DIR/threat-model.yaml" ] \
   && [ ! -f "$RESULT_DIR/threat-model.threatdragon.json" ]; then
    if python3 "$SCRIPT_DIR/export_threat_dragon.py" \
            --threat-model "$RESULT_DIR/threat-model.yaml" \
            --output "$RESULT_DIR/threat-model.threatdragon.json" >/dev/null 2>&1; then
        info "Threat Dragon backstop wrote $RESULT_DIR/threat-model.threatdragon.json from yaml"
    fi
fi

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    ok "Assessment completed successfully."
    [ -n "$ASSESSMENT_DURATION" ] && ok "Duration: $ASSESSMENT_DURATION"

    # List all written files with full paths
    if [ "$SKILL" = "create-threat-model" ]; then
        # Surface the Critical/High findings on the console (all modes).
        python3 "$SCRIPT_DIR/run_summary.py" findings "$RESULT_DIR/threat-model.yaml" 2>/dev/null || true

        echo ""
        echo "  Output files:"
        [ -f "$RESULT_DIR/threat-model.md" ]          && ok "  $RESULT_DIR/threat-model.md"
        [ -f "$RESULT_DIR/threat-model.yaml" ]        && ok "  $RESULT_DIR/threat-model.yaml"
        [ -f "$RESULT_DIR/threat-model.sarif.json" ]  && ok "  $RESULT_DIR/threat-model.sarif.json"
        [ -f "$RESULT_DIR/threat-model.threatdragon.json" ] && ok "  $RESULT_DIR/threat-model.threatdragon.json"

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

    # Surface diagnostics on the failure path. The rich Run Issues block is
    # normally rendered by the LLM Completion turn, which never runs on an
    # abort / bg-ceiling kill — so regenerate .run-issues.json from the logs
    # and render it here deterministically. Delivery gap, not detection.
    if [ "$SKILL" = "create-threat-model" ] && [ -f "$RESULT_DIR/.agent-run.log" ]; then
        PLUGIN_DEV_FLAG=""
        [ "${APPSEC_PLUGIN_DEV:-0}" = "1" ] && PLUGIN_DEV_FLAG="--plugin-dev"
        # The terminator owns the aggregation on this path, and additionally
        # releases the lock and closes the checkpoint the failed run left open.
        # A controller abort already wrote its own verdict; that one stands.
        python3 "$PLUGIN_DIR/scripts/terminate_run.py" \
            --output-dir "$RESULT_DIR" --outcome failure \
            --reason "wrapper exit $EXIT_CODE" --repo-root "${REPO_PATH:-.}" \
            --depth "${ASSESSMENT_DEPTH:-standard}" >/dev/null 2>&1 || true
        python3 "$PLUGIN_DIR/scripts/render_completion_summary.py" \
            --issues-only --output-dir "$RESULT_DIR" --repo-root "${REPO_PATH:-.}" \
            $PLUGIN_DEV_FLAG 2>/dev/null || true
    fi

    # Recovery hint — print a full, paste-ready fresh-run command without an
    # unsupported mode flag.
    print_recovery_hint
fi

# Token/cost readout on both paths — a failed run still spent the tokens.
echo ""
print_usage_summary

# ── Exact-value secret redaction ───────────────────────────────────
# Pattern-based masking (upstream + postscan below) only neutralises a secret
# in the form it can match; an LLM author who copies a raw secret VALUE into
# prose evades every pattern (2026-06-28 e2e leak). This deterministic pass
# scans the repo SOURCE for secret values and exact-string-replaces them across
# every artifact (md/yaml/sarif/html + .fragments + the JSON data pipeline),
# prose included. Runs on every depth; --write-scan-json guarantees the
# .qa-secret-scan.json gate artifact exists. Fails closed if a raw value somehow
# survives redaction.
if [ "$SKILL" = "create-threat-model" ] && [ $EXIT_CODE -eq 0 ] && [ -d "$OUTPUT_PATH" ]; then
    REDACT_SCRIPT="$PLUGIN_DIR/scripts/redact_known_secrets.py"
    if [ -f "$REDACT_SCRIPT" ]; then
        if ! python3 "$REDACT_SCRIPT" --repo-root "${REPO_PATH:-.}" --output-dir "$OUTPUT_PATH" --write-scan-json; then
            err "exact-value secret redaction left a residual raw secret — see stderr above"
            EXIT_CODE=21
        fi
    fi
fi

# ── Post-scan unmasked-secret check ────────────────────────────────
# Runs scripts/postscan_secret_check.py over the rendered report and
# headline intermediates. The rendered report + yaml are already masked
# deterministically upstream, but the LLM-authored intermediates
# (.recon-summary.md etc.) were only masked if the agent remembered to —
# so `--mask` runs the deterministic mask_file twin over every candidate
# first, neutralising any kept secret value (e.g. a `-----BEGIN PRIVATE
# KEY-----` marker the agent left in a "masked" table cell). The scan then
# verifies and only fails if masking could not neutralise something.
# Always-on so the trusted-mode default also gets the protection.
if [ "$SKILL" = "create-threat-model" ] && [ $EXIT_CODE -eq 0 ] && [ -d "$OUTPUT_PATH" ]; then
    POSTSCAN_SCRIPT="$PLUGIN_DIR/scripts/postscan_secret_check.py"
    if [ -f "$POSTSCAN_SCRIPT" ]; then
        if ! python3 "$POSTSCAN_SCRIPT" --output-dir "$OUTPUT_PATH" --mask; then
            err "post-scan secret check failed — see stderr above"
            EXIT_CODE=21
        fi
    fi
fi

# ── Deterministic runtime-cleanup backstop ─────────────────────────
# runtime_cleanup.py is supposed to run from the skill's Completion Summary,
# but that is an LLM-compliance dependency that headless --full runs have been
# observed to skip entirely (no RUNTIME_CLEANUP audit line, transient dirs left
# behind). Run it here unconditionally on success so the audit line is always
# emitted and the KEEP_RUNTIME_FILES opt-out is honoured deterministically.
# Idempotent + non-fatal; with --keep-runtime-files it self-skips and preserves
# every transient artifact (relied on by the E2E asserts).
if [ "$SKILL" = "create-threat-model" ] && [ $EXIT_CODE -eq 0 ] && [ -d "$OUTPUT_PATH" ]; then
    python3 "$PLUGIN_DIR/scripts/runtime_cleanup.py" "$OUTPUT_PATH" \
        --stage post-qa ${KEEP_RUNTIME_FILES_FLAG:-} 2>/dev/null || true
fi

# Seed the fail-on level from the active org profile when no --fail-on was
# passed: guardrails.fail_on rides in .org-profile-effective.json. CLI wins.
if [ -z "$FAIL_ON" ] && [ -f "$OUTPUT_PATH/.org-profile-effective.json" ]; then
    FAIL_ON="$(python3 -c "import json,sys;print((json.load(open(sys.argv[1])).get('defaults') or {}).get('fail_on') or '')" "$OUTPUT_PATH/.org-profile-effective.json" 2>/dev/null || true)"
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

discard_capture_if_consumed

exit $EXIT_CODE
