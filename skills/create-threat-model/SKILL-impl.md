# create-threat-model — full implementation

This file is loaded on demand by SKILL.md for non-help invocations. Do not modify the frontmatter routing logic; edit this file for implementation changes.

## Pipeline Overview (Stage-D, post-M2.13)

```
┌─────────────────────────────────────────────────────────────────────┐
│  Pre-flight                                                         │
│   • check_state.py --auto-clean   (kill orphan locks)               │
│   • validate_cache.py             (quarantine corrupt fragments)    │
│   • resolve_config.py --emit-file (parse args → .skill-config.json) │
│   • Rebuild/Full pre-flight wipe  (when --rebuild / --full)         │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │
┌──────────────────────────────────▼──────────────────────────────────┐
│  Stage 1 — Threat Model Orchestrator (Phases 1–10b)                 │
│  Agent: appsec-threat-analyst (Sonnet, maxTurns=120)                │
│  Env  : STAGE1_PHASE_LIMIT=10b                                      │
│  Out  : .recon-summary.md, .stride-*.json, .threats-merged.json,    │
│         .triage-flags.json, threat-model.yaml, checkpoint=10b       │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │
                                   ▼
                  ┌────── Phase-10b precondition gate ──────┐
                  │  All 4 mandatory artefacts present?     │
                  └────────────┬────────────────────────────┘
                               │ yes
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Pre-generate structural fragments (M2.11)                          │
│  pregenerate_fragments.py → 7 deterministic fragments (idempotent)  │
│  • system-overview.md      • assets.md         • use-cases.md       │
│  • architecture-diagrams.md• attack-surface.md                      │
│  • security-architecture.md• out-of-scope.md                        │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │
┌──────────────────────────────────▼──────────────────────────────────┐
│  Stage 2 — Composition (Phase 11) (M2.12 — fresh renderer budget)   │
│  Agent: appsec-threat-renderer (Sonnet)                             │
│  Env  : Stage-2 render configuration                                │
│  Does : write 2 LLM fragments (ms-verdict, ms-architecture-         │
│         assessment) + optionally attack-walkthroughs +              │
│         security-posture-attack-paths; then compose, patch          │
│         placeholders, run qa_checks all                             │
└──────────────────────────────────┬──────────────────────────────────┘
                                   │
                                   ▼
              ┌─────── Hard inline-shortcut gate (M2.10) ──────┐
              │  check_inline_shortcut.py --write-repair-plan   │
              │  Indicators: A1, A2, B, C + qa_checks fragments │
              └────┬───────────────────────────────────┬────────┘
                   │ exit 2                            │ exit 0
                   ▼                                   │
┌──────────────────────────────────────┐               │
│ Auto-Retry Loop (M2.13)              │               │
│  retry_count < MAX_INLINE_RETRIES=2  │               │
│   ├─ recovery: merge_threats +       │               │
│   │   triage + pregenerate           │               │
│   ├─ re-dispatch Stage 2             │               │
│   └─ re-run hard gate                │               │
│  retry_count == MAX_INLINE_RETRIES   │               │
│   └─ exit 2 + preserve repair plan   │               │
└──────────────────┬───────────────────┘               │
                   │ gate finally passed               │
                   ▼                                   ▼
                   ┌─────────────────────────────────────┐
                   │  Stage 3 — QA Review (sonnet, 120)  │
                   │  + Re-Render Loop (max 3 iter.)     │
                   └────────────────┬────────────────────┘
                                    │
                                    ▼
                   ┌─────────────────────────────────────┐
                   │  Stage 4 — Architect Review         │
                   │  (only at depth=thorough or         │
                   │   --architect-review)               │
                   └────────────────┬────────────────────┘
                                    │
                                    ▼
                   ┌─────────────────────────────────────┐
                   │  Completion summary + cleanup       │
                   │  render_completion_summary.py       │
                   │  runtime_cleanup.py post-qa         │
                   └─────────────────────────────────────┘
```

**Compliance contract.** No malformed `threat-model.md` is ever persisted to `$OUTPUT_DIR/`. Every path either produces a contract-clean document (composed by `compose_threat_model.py --strict` from schema-validated fragments) or aborts with exit 2 and a structured repair plan (`.inline-shortcut-repair-plan.json`) for inspection. The skill exits 0 only when Stage 3 has signed off on a compose-rendered MD.

**Composition transparency (M2.14 — Sprint 6).** Every successful compose writes `$OUTPUT_DIR/.compose-stats.json` with structured warnings + per-section retry counts. When that file shows non-clean status (or the `.inline-shortcut-retry-count` is > 0), the renderer adds a `## Appendix: Composition Notes` section to `threat-model.md` and the completion summary emits a `-- Composition Health --` block. On clean runs both are silently omitted. The MD-embedded form is the canonical persistence — it survives `runtime_cleanup`, git commits, and PR reviews.

## Prerequisites — Environment & Allow-Listed Commands

### `CLAUDE_PLUGIN_ROOT` discovery

Several downstream scripts (`plugin_meta.py`, `baseline_state.py`, `agent_logger.py`) expect `$CLAUDE_PLUGIN_ROOT` to point at the plugin directory. Claude Code sets this when a plugin command runs, but in some harness configurations (e.g. headless `claude -p`, older claude-code releases) the variable is **not** propagated into Bash sub-processes. Resolve it explicitly at the start of the skill and pass it through to every agent invocation:

```bash
if [ -z "$CLAUDE_PLUGIN_ROOT" ]; then
  CLAUDE_PLUGIN_ROOT=$(find /root /home /opt -maxdepth 6 \
    -path "*/appsec-advisor/skills/create-threat-model/SKILL.md" \
    2>/dev/null | head -1 | xargs -r dirname | xargs -r dirname | xargs -r dirname)
fi
export CLAUDE_PLUGIN_ROOT
if [ -z "$CLAUDE_PLUGIN_ROOT" ] || [ ! -d "$CLAUDE_PLUGIN_ROOT" ]; then
  echo "Error: CLAUDE_PLUGIN_ROOT could not be resolved — install the appsec-advisor or set the variable manually." >&2
  exit 2
fi
```

The resolved value must also be passed verbatim in the Stage 1 and Stage 3 agent prompts (see "Stage 1 — Threat Model Orchestrator" below).

### Early flag validation (fail-fast)

Before any preflight steps run (state cleanup, cache validation, session-bloat detection), validate the user's flags. Invalid flags must produce an immediate error — never silent inference, never preflight side-effects against an unrecognised invocation. The validator is `resolve_config.py --validate-only`: argparse rejects unknown flags with exit 2, the conflict detector rejects mutually-exclusive pairs with exit 1, and the script produces no output / writes no files on success.

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/resolve_config.py" --validate-only "$@"
VALIDATE_EXIT=$?
if [ "$VALIDATE_EXIT" -ne 0 ]; then
  # argparse / conflict detection already printed the user-facing reason
  # to stderr. Exit with the same code; no marker-file cleanup needed
  # because no markers have been touched yet.
  exit "$VALIDATE_EXIT"
fi
```

Behaviour contract:
- Unknown flag (e.g. `--qiuck` typo) → argparse prints `usage: …` and `error: unrecognized arguments: --qiuck` to stderr, exits 2. Skill exits 2 immediately.
- Conflicting flags (e.g. `--rebuild --incremental`) → resolver prints the conflict reason, exits 1. Skill exits 1 immediately.
- Skill-only flags (currently just `--force`) are stripped by the script before parsing, so they don't trigger false-positive failures here.
- Clean parse → exit 0, no output, skill proceeds to the preflight steps below.

This step costs ~50 ms and runs before `check_state.py`, `validate_cache.py`, the multi-day session detector, the cache_read bloat detector, and the full `resolve_config.py --emit-file` call further down. The full resolution still happens later in the Configuration Resolution section — `--validate-only` is a fail-fast gate, not a replacement.

### Bash commands the skill relies on

If you run Claude Code with a restrictive `permissions.allow` list in `settings.json`, the following command prefixes must be allow-listed for the skill to work end-to-end. Each one is invoked by the orchestrator, the sub-agents, or one of the plugin scripts:

| Command | Who runs it | Purpose |
|---------|-------------|---------|
| `git rev-parse`, `git log`, `git diff --name-only`, `git status`, `git show` | orchestrator, context-resolver | baseline SHA, changed-file delta, commit metadata |
| `git -C <repo> …` | all agents | when `--repo <path>` points outside the current working directory |
| `python3 <plugin>/scripts/*.py` | orchestrator, skill, qa-reviewer | `plugin_meta.py`, `baseline_state.py`, `wait_stride_progress.py`, `stride_progress.py`, `validate_intermediate.py`, `verify_run_costs.py` |
| `find /root /home /opt -maxdepth 6 …` | skill fallback | `CLAUDE_PLUGIN_ROOT` discovery when env is empty |
| `date -u +%Y-%m-%dT%H:%M:%SZ` / `date +%s` | all agents | log timestamps and phase-epoch tracking |
| `grep -c`, `wc -l`, `wc -c`, `awk`, `sed`, `stat`, `ls`, `basename` | all agents | count aggregation for PHASE_END/STEP_END lines |
| `mkdir -p`, `rm -f`, `cat`, `echo`, `printf`, `cp`, `mv` | all agents | intermediate file handling, checkpoints, lock |
| `sha256sum` / `shasum -a 256` | `baseline_state.py` | stride file fingerprinting |

**None** of the above are destructive against `$REPO_ROOT` — every write targets `$OUTPUT_DIR` (default `$REPO_ROOT/docs/security`) or a temp file under it. If you want a minimally-scoped allow-list, permit `Bash(git:*)`, `Bash(python3:*)`, `Bash(grep:*)`, `Bash(find:*)`, and `Bash(date:*)` plus the file-handling basics.

### Pre-flight stale-state recovery

Before any configuration resolution or agent dispatch, reap orphan run-state from a prior crashed session. A Claude Code session that was killed mid-assessment leaves `.appsec-lock`, `.appsec-checkpoint`, `.phase-epoch`, and `.session-agent-map` behind; the Claude Code UI and `/appsec-advisor:status` read those files and continue to report the skill as "scanning" until something clears them.

The `scripts/check_state.py` helper classifies the transient state and, with `--auto-clean`, removes only files that are demonstrably orphan (dead PID in the lock, or checkpoint without a matching complete marker). It never touches an active run and never exits non-zero on "nothing to do", so it is safe to call unconditionally at skill start:

```bash
# Determine OUTPUT_DIR best-effort from --output / --repo / defaults. The
# real resolution happens in resolve_config.py below; this pre-pass only
# needs the directory path to scan for orphan state.
OUTPUT_DIR_PREVIEW="${OUTPUT_DIR_PREVIEW:-${PWD}/docs/security}"
for arg in "$@"; do
  case "$arg" in
    --output=*)  OUTPUT_DIR_PREVIEW="${arg#--output=}" ;;
  esac
done
# --output <path> (space-separated) form is handled inside resolve_config.py
# after real arg parsing; the preview above covers the common --output=PATH
# form and the default location, which catches >95% of real usage.

# Detect --resume early so we can preserve checkpoint state for it. The full
# argument parser further below replaces this preview, but the auto-clean step
# runs before that and would otherwise wipe the very checkpoint --resume needs.
RESUME_REQUESTED=false
for arg in "$@"; do
  case "$arg" in
    --resume) RESUME_REQUESTED=true ;;
  esac
done

# Read prior checkpoint directly (no Python — cheap and dependency-free) for
# the dead-run hint below. The full classification still happens inside
# check_state.py; we only need phase/status here for user-facing messaging.
PRECHECK_PHASE="?"
PRECHECK_STATUS="?"
if [ -f "$OUTPUT_DIR_PREVIEW/.appsec-checkpoint" ]; then
  CP_LINE=$(head -n1 "$OUTPUT_DIR_PREVIEW/.appsec-checkpoint" 2>/dev/null || true)
  PRECHECK_PHASE=$(printf '%s' "$CP_LINE" | sed -n 's/.*phase=\([^ ]*\).*/\1/p')
  PRECHECK_STATUS=$(printf '%s' "$CP_LINE" | sed -n 's/.*status=\([^ ]*\).*/\1/p')
  [ -z "$PRECHECK_PHASE" ] && PRECHECK_PHASE="?"
  [ -z "$PRECHECK_STATUS" ] && PRECHECK_STATUS="?"
fi

# M4 — Auto-enable --tracing on a recovery run. When the pre-flight detector
# finds a dead prior run (phase != completed) and the user did not already
# pass --tracing on the command line, enable tracing so the next run
# produces .appsec-trace.log automatically. This means the second crash gets
# diagnosed without needing the user to remember the flag.
#
# Activation requires BOTH:
#   1. Setting APPSEC_TRACING=1 (works inside the skill's own bash blocks).
#   2. Touching the per-user marker file at ${TMPDIR}/.appsec-tracing-<uid>
#      so agent_logger.py picks up the mode in sub-sessions that do NOT
#      inherit env vars (Claude Code's Agent dispatch is one of them — this
#      was an early-version bug where the env var alone left .appsec-trace.log
#      empty even though the skill thought tracing was on).
# The marker file is cleaned up at every skill exit path along with the
# verbose marker — see "Tracing Mode — Marker File Lifecycle" further down.
RECOVERY_AUTO_TRACING=false

# F7 — fallback recovery-detection via .hook-events.log when --rebuild has
# already wiped the checkpoint. The hook log is an audit artifact (never
# wiped by --rebuild or --auto-clean) and a dead prior run leaves a
# distinctive footprint: AGENT_SPAWN entries WITHOUT a matching
# ASSESSMENT_SUMMARY closing entry. Counting the gap is cheap.
DEAD_PRIOR_BY_HOOKLOG=false
HOOK_LOG="$OUTPUT_DIR_PREVIEW/.hook-events.log"
if [ -f "$HOOK_LOG" ]; then
  HK_SPAWN=$(grep -c "AGENT_SPAWN.*appsec-threat-analyst" "$HOOK_LOG" 2>/dev/null || echo 0)
  HK_SUMMARY=$(grep -c "ASSESSMENT_SUMMARY" "$HOOK_LOG" 2>/dev/null || echo 0)
  # Each successful run produces exactly one AGENT_SPAWN of the orchestrator
  # and one ASSESSMENT_SUMMARY at the end. If spawns exceed summaries by ≥1
  # AND the most recent log entry is more than 5 minutes old, the prior run
  # died without finalizing.
  if [ "${HK_SPAWN:-0}" -gt "${HK_SUMMARY:-0}" ]; then
    HK_AGE=$(python3 -c "
import os, time
try:
    age = time.time() - os.path.getmtime('$HOOK_LOG')
    print(int(age))
except Exception:
    print(0)
" 2>/dev/null)
    if [ "${HK_AGE:-0}" -gt 300 ]; then
      DEAD_PRIOR_BY_HOOKLOG=true
    fi
  fi
fi

if { [ "$PRECHECK_PHASE" != "?" ] && [ "$PRECHECK_STATUS" != "completed" ]; } \
   || [ "$DEAD_PRIOR_BY_HOOKLOG" = "true" ]; then
  if [ "${TRACING:-false}" != "true" ]; then
    case " $* " in
      *' --tracing '*|*' --tracing='*) ;;
      *)
        RECOVERY_AUTO_TRACING=true
        export APPSEC_TRACING=1
        touch "${TMPDIR:-/tmp}/.appsec-tracing-$(id -u)" 2>/dev/null || true
        ;;
    esac
  fi
fi

# Surface a hint when the prior run did not finalize. Non-blocking — the user
# can still continue with a fresh run; the message just informs them that
# --resume is an option. Suppressed when --resume is already on the command
# line (the existing Resume from Checkpoint section will print its own banner).
if [ "$PRECHECK_PHASE" != "?" ] \
   && [ "$PRECHECK_STATUS" != "completed" ] \
   && [ "$RESUME_REQUESTED" = "false" ]; then
  printf '\n⚠ A prior assessment did not complete (last checkpoint: phase=%s status=%s).\n' \
      "$PRECHECK_PHASE" "$PRECHECK_STATUS" >&2
  printf '  • Continue from where it left off:  /appsec-advisor:create-threat-model --resume\n' >&2
  printf '  • Discard prior state and start fresh: continue (this run will auto-clean).\n' >&2
  if [ "$RECOVERY_AUTO_TRACING" = "true" ]; then
    printf '  • Auto-enabled --tracing for this run (writes .appsec-trace.log) so a second crash can be diagnosed.\n' >&2
  fi
  printf '\n' >&2
fi

if [ "$RESUME_REQUESTED" = "true" ] \
   && [ "$PRECHECK_PHASE" != "?" ] \
   && [ "$PRECHECK_STATUS" != "completed" ]; then
  # --resume was requested with a usable checkpoint. Skip auto-clean entirely:
  # the Resume from Checkpoint section below depends on .appsec-checkpoint
  # surviving, and acquire_lock.py handles dead-PID locks natively. Without
  # this guard the auto-clean step wipes the checkpoint before --resume reads
  # it — the historic "fresh skill run silently destroys resume state" bug.
  :
else
  python3 "$CLAUDE_PLUGIN_ROOT/scripts/check_state.py" \
      "$OUTPUT_DIR_PREVIEW" --auto-clean 2>/dev/null || true
fi
```

Behaviour contract:
- An active run (live lock PID) is never disturbed — the cleaner refuses and exits without touching files.
- A stale lock (dead PID or mtime > 1 h) is reaped; next `acquire_lock.py` call lands cleanly.
- An orphan checkpoint (no lock, `status=started` left behind) is cleared so the status UI stops reporting a phantom run.
- The `|| true` makes this pass non-fatal: if the helper itself fails (bad path, Python error), the skill falls through to `acquire_lock.py` which has its own dead-PID detection as a second line of defence.
- When `--resume` is on the command line **and** an incomplete checkpoint is on disk, the auto-clean is skipped so the Resume from Checkpoint section below has the data it needs. Without `--resume`, the user is informed once that `--resume` is an option, then auto-clean proceeds as before.

Users who need explicit control have `/appsec-advisor:clean-state` — same helper, same semantics, plus a `--force` escape hatch and a `--dry-run` reporting mode.

### Pre-flight cache integrity check

After run-state cleanup, sweep the intermediate JSON and Markdown files for truncation or corruption left behind by a crashed or hung prior run. A STRIDE output file that was only half-written because the orchestrator's session was killed mid-write will parse as invalid JSON and silently poison the Phase 9 merge — downstream T-IDs drift, the rendered Markdown loses findings, and the QA gate may or may not catch it. The cache validator moves corrupt files under `$OUTPUT_DIR/.quarantine/<iso-timestamp>/` so the next run regenerates them from scratch (no data loss — the raw findings were already unusable).

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/validate_cache.py" \
    "$OUTPUT_DIR_PREVIEW" --quarantine 2>/dev/null || true
```

Scope:
- `.stride-*.json`, `.threats-merged.json`, `.merge-candidates.json`, `.merge-decisions.json`, `.triage-flags.json`, `.triage-ranking.json`, `.pre-render-report.json` — parsed as JSON.
- `.appsec-cache/baseline.json` — parsed as JSON (schema checks remain in `baseline_state.py`).
- `.fragments/*.json` and `.fragments/*.md` — JSON-parsed / non-empty check.

The validator never touches `threat-model.md`, `threat-model.yaml`, or audit logs. It is always safe to run and its exit code is intentionally ignored by the skill — quarantining is best-effort; a move failure leaves the corrupt file in place so the subsequent validation gate (`validate_fragment.py` / `validate_intermediate.py`) can still hard-fail with a useful error.

### Multi-day skill-session detection (M3.4 — Phase-9-context-bloat fix)

**Problem this solves.** Claude Code skill sessions can persist across days. Repeated `/appsec-advisor:create-threat-model` invocations in one uncleared session grow the conversation prefix, increase compaction pressure, and slow long Phase-9 runs.

The skill cannot programmatically force a `/clear` — but it can warn the user up front so they have the choice to start a fresh session before burning 60 minutes on a stale one.

**Detection.** Scan `.hook-events.log` for `AGENT_SPAWN appsec-threat-analyst` events in the last 24 hours. Each `/appsec-advisor:create-threat-model` invocation emits exactly one such spawn; aborted runs never emit `ASSESSMENT_SUMMARY`, so counting spawns catches incomplete runs that the old ASSESSMENT_SUMMARY counter missed entirely (G-5 fix).

For session-scoped mode: match spawns to the current `$CLAUDE_SESSION_ID`. Fall back to repo-wide spawn count when the variable is unset (older harness).

```bash
HOOK_LOG="$OUTPUT_DIR_PREVIEW/.hook-events.log"
if [ -f "$HOOK_LOG" ]; then
  # 24h cut-off (UTC, ISO format)
  CUTOFF=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || python3 -c "import datetime;print((datetime.datetime.utcnow() - datetime.timedelta(hours=24)).strftime('%Y-%m-%dT%H:%M:%SZ'))")
  if [ -n "$CLAUDE_SESSION_ID" ]; then
    SID_SHORT=$(printf '%s' "$CLAUDE_SESSION_ID" | head -c 8)
    # Count orchestrator spawns in this session (includes aborted runs)
    PRIOR_RUNS=$(awk -v cutoff="$CUTOFF" -v sid="[$SID_SHORT]" \
        '$1 > cutoff && index($0, sid) && /AGENT_SPAWN.*appsec-threat-analyst/ {c++} END {print c+0}' \
        "$HOOK_LOG")
  else
    # Fallback: any orchestrator spawn in the last 24 h (session-unscoped)
    PRIOR_RUNS=$(awk -v cutoff="$CUTOFF" \
        '$1 > cutoff && /AGENT_SPAWN.*appsec-threat-analyst/ {c++} END {print c+0}' \
        "$HOOK_LOG")
  fi
  # Sprint 4A (M3.5): two-tier behaviour.
  #   PRIOR_RUNS in {2}      → advisory warning (legacy, non-blocking).
  #   PRIOR_RUNS >= 3        → interactive prompt [Y]es continue / [F]resh
  #                            session (abort) / [A]bort. Default: F after
  #                            30 s. Only when stdin is a TTY and
  #                            APPSEC_CI_MODE != 1 — non-interactive runs
  #                            keep the legacy advisory behaviour so CI
  #                            pipelines do not hang.
  if [ "${PRIOR_RUNS:-0}" -ge 3 ] \
      && [ -t 0 ] \
      && [ "${APPSEC_CI_MODE:-}" != "1" ] \
      && [ "${APPSEC_NO_CONFIRM:-}" != "1" ]; then
    cat <<EOF >&2

⚠ This Claude Code session has run /appsec-advisor:create-threat-model
  ${PRIOR_RUNS} times in the last 24 hours. Conversation context has grown
  enough that Phase 1 alone may take 4× longer than a fresh session
  (observed: 34s → 2m 12s on the 2026-04-27 juice-shop run). At this
  point a fresh session is faster overall than continuing.

  Options:
      [Y] Continue in this session (acknowledged tradeoff)
      [F] Abort this run; you /clear, then re-invoke (default in 30s)
      [A] Abort entirely

  Choice: 
EOF
    SESSION_TIMEOUT="${APPSEC_SESSION_TIMEOUT:-30}"
    if read -r -t "$SESSION_TIMEOUT" SESS_CHOICE 2>/dev/null; then
      SESS_CHOICE=$(printf '%s' "$SESS_CHOICE" | tr '[:upper:]' '[:lower:]' | tr -d ' ')
    else
      SESS_CHOICE="f"
      printf '\n  (timed out — defaulting to abort-and-clear)\n' >&2
    fi
    case "$SESS_CHOICE" in
      y|yes)
        printf '  Continuing in this session — expect ~%.0f%% slower Phase 1.\n\n' \
               "$(awk "BEGIN{print (${PRIOR_RUNS}-1)*15}")" >&2
        ;;
      a|abort)
        printf '  Aborted on user request.\n' >&2
        rm -f "${TMPDIR:-/tmp}/.appsec-verbose-$(id -u)" \
              "${TMPDIR:-/tmp}/.appsec-tracing-$(id -u)"
        exit 0
        ;;
      *)
        # 'f', empty, or anything else → abort with a clear /clear hint.
        printf '  Aborted. Run `/clear` and re-invoke for a fresh session.\n' >&2
        rm -f "${TMPDIR:-/tmp}/.appsec-verbose-$(id -u)" \
              "${TMPDIR:-/tmp}/.appsec-tracing-$(id -u)"
        exit 0
        ;;
    esac
  elif [ "${PRIOR_RUNS:-0}" -ge 2 ]; then
    cat <<EOF >&2

⚠ This Claude Code session has run /appsec-advisor:create-threat-model
  ${PRIOR_RUNS} times in the last 24 hours. Long-running sessions accumulate
  conversation context, which slows Phase 9 throughput and triggers more
  aggressive auto-compactions during long agent dispatches.

  Recommendation (interactive UI):
      /clear       (start a fresh chat, then re-run)
   or open a new terminal / Claude Code window.

  This is advisory — the run will continue normally. If you decide to
  proceed, factor in ~10-30 % slower Phase 9 vs a fresh session.

EOF
  fi
fi
```

The Sprint-4A escalation is **interactive only** — `APPSEC_CI_MODE=1`, `APPSEC_NO_CONFIRM=1`, or a non-TTY stdin (headless `claude -p`) all fall through to the legacy advisory warning so CI pipelines never hang on a prompt. The 2-run threshold remains advisory regardless of mode.

### M3.4 supplement — cache_read context-bloat detector

The spawn counter only catches previous `appsec-threat-analyst` invocations. Regular conversation turns (status checks, analysis, normal chat) also grow the session context and are completely invisible to `PRIOR_RUNS`. The `cache_read` value in the most-recent `SESSION_STOP` line of `.hook-events.log` is a direct, session-agnostic measure of how much cached context every sub-agent call will be forced to re-serve.

**Empirical threshold: 8 M tokens.** From 22 real assessment spawns in the `2026-04-29` juice-shop hook log: all clean runs had `cache_read < 6.5 M`; all bloated runs had `cache_read > 11 M`. The 8 M threshold gives a comfortable margin with zero false positives in the observed data. The reference incident: a 19 M-token session caused the context-resolver to take **37 minutes** instead of its normal 2 minutes — a 18× slowdown that was invisible to the PRIOR_RUNS counter because it was caused by non-assessment conversation turns, not prior scans.

This check runs **after** the PRIOR_RUNS block and is independent of it. When `PRIOR_RUNS >= 2` the existing M3.4 prompt already fires; this supplement only activates when the spawn counter stayed silent but the cache is large.

```bash
# M3.4 supplement — cache_read context-bloat detector
# Reads the last SESSION_STOP cache_read value from .hook-events.log.
# This is a session-agnostic signal: it catches bloat caused by ordinary
# conversation turns that the AGENT_SPAWN counter cannot see.
LAST_CACHE_READ=0
if [ -f "$HOOK_LOG" ]; then
  LAST_CACHE_READ=$(awk '/SESSION_STOP/ {
      match($0, /cache_read=([0-9,]+)/, a)
      if (a[1]) { gsub(/,/, "", a[1]); last = a[1]+0 }
    } END { print last+0 }' "$HOOK_LOG" 2>/dev/null || echo 0)
fi

if [ "${LAST_CACHE_READ:-0}" -ge 8000000 ] && [ "${PRIOR_RUNS:-0}" -lt 2 ]; then
  # PRIOR_RUNS didn't already fire a warning — emit a standalone bloat alert.
  BLOAT_M=$(awk "BEGIN{printf \"%.0f\", ${LAST_CACHE_READ}/1000000}")
  if [ -t 0 ] \
      && [ "${APPSEC_CI_MODE:-}" != "1" ] \
      && [ "${APPSEC_NO_CONFIRM:-}" != "1" ]; then
    cat <<EOF >&2

⚠ Session context is large (~${BLOAT_M}M cached tokens from prior conversation turns).
  --rebuild wipes all disk artifacts but cannot clear the in-process conversation
  context. Sub-agent inference will be significantly slower regardless of --rebuild:
  observed 37 min context-resolver (19M-token session) vs 2 min (fresh session).

  Options:
      [Y] Continue anyway (acknowledged tradeoff)
      [F] Abort — run /clear, then re-invoke (default in 30s)

  Choice: 
EOF
    BLOAT_TIMEOUT="${APPSEC_SESSION_TIMEOUT:-30}"
    if read -r -t "$BLOAT_TIMEOUT" BLOAT_CHOICE 2>/dev/null; then
      BLOAT_CHOICE=$(printf '%s' "$BLOAT_CHOICE" | tr '[:upper:]' '[:lower:]' | tr -d ' ')
    else
      BLOAT_CHOICE="f"
      printf '\n  (timed out — defaulting to abort)\n' >&2
    fi
    case "$BLOAT_CHOICE" in
      y|yes)
        printf '  Continuing with ~%sM token context overhead.\n\n' "$BLOAT_M" >&2
        ;;
      *)
        printf '  Aborted. Run /clear and re-invoke for a fresh session.\n' >&2
        rm -f "${TMPDIR:-/tmp}/.appsec-verbose-$(id -u)" \
              "${TMPDIR:-/tmp}/.appsec-tracing-$(id -u)"
        exit 0
        ;;
    esac
  else
    # Non-interactive / CI: advisory only, never blocks.
    printf '\n⚠ Session context is large (~%sM cached tokens). Run /clear before next assessment for full reset.\n\n' \
        "$BLOAT_M" >&2
  fi
fi
```

## Argument Parsing

Parse the user's arguments for the following flags:

| Flag | Variable | Default |
|------|----------|---------|
| `--yaml` | `WRITE_YAML=true` (no-op — yaml is always written) | `true` (always on) |
| `--no-yaml` | `WRITE_YAML=false` (escape hatch — suppresses yaml output) | `false` |
| `--sarif` | `WRITE_SARIF=true` | `false` |
| `--pentest-tasks` | `WRITE_PENTEST_TASKS=true` | `false` |
| `--pentest-format <generic\|strix>` | `PENTEST_FORMAT=<value>` | `generic` |
| `--pentest-target <url>` | `PENTEST_TARGET_URL=<url>` (base URL injected into meta.target) | (none) |
| `--pdf` | `WRITE_PDF=true` (calls `scripts/export_pdf.py` after all stages — see PDF Export below) | `false` |
| `--requirements` | `CHECK_REQUIREMENTS=true` | from config `enabled` |
| `--requirements <url>` | `CHECK_REQUIREMENTS=true`, `REQUIREMENTS_URL_OVERRIDE=<url>` | from config `enabled` |
| `--no-requirements` | `CHECK_REQUIREMENTS=false` | from config `enabled` |
| `--dry-run` | `DRY_RUN=true` | `false` |
| `--resume` | Resume from last checkpoint | n/a |
| `--incremental` | `INCREMENTAL=true` — assertion that a baseline exists (hard abort otherwise) | auto-detected from baseline |
| `--full` | `INCREMENTAL=false` — force full scan even when prior output exists. Conflicts with `--incremental`. Preserves prior `changelog[]` history and surfaces a delta against the previous baseline in the completion summary. | `false` |
| `--rebuild` | `REBUILD=true` — superset of `--full`: wipes prior model (md/yaml/sarif), cache (`.appsec-cache/`), and all intermediate files before running, then performs a fresh full assessment with no history carry-over. No delta computation, no T-ID stability. Conflicts with `--incremental` and `--resume`. Redundant with `--full` (implicitly forces full). | `false` |
| `--with-sca` | `WITH_SCA=true` | `false` |
| `--keep-runtime-files` | `KEEP_RUNTIME_FILES=true` (suppresses Phase 11 cleanup of transient artifacts — useful for debugging) | `false` |
| `--max-resumes <N>` | `MAX_STAGE1_RESUMES=<N>` — hard cap on automatic Stage 1 resume dispatches after turn-budget cut-offs. `0` disables resume entirely (single-shot run). See "Handling turn-budget cut-offs" below. | `1` |
| `--repo <path>` | `REPO_ROOT=<abs-path>` | current working directory |
| `--output <path>` | `OUTPUT_DIR=<abs-path>` | `$REPO_ROOT/docs/security` |
| `--reasoning-model <mode>` | `REASONING_MODEL=<sonnet\|opus-cheap\|opus\|haiku-economy>` → resolves to `STRIDE_MODEL`, `TRIAGE_MODEL`, `MERGER_MODEL` plus the extended-agent matrix | `haiku-economy` at quick (since 2026-05); `opus-cheap` at standard/thorough (see Reasoning Model Resolution) |
| `--stride-model <model>` | `STRIDE_MODEL=<model>` (punctual override, applied **after** `--reasoning-model` resolution) | (none — inherits from `--reasoning-model`) |
| `--assessment-depth <level>` | `ASSESSMENT_DEPTH=<quick\|standard\|thorough>` | `standard` |
| `--quick` | shortcut for `--assessment-depth quick` (mutually exclusive with `--thorough`) | n/a |
| `--thorough` | shortcut for `--assessment-depth thorough` (mutually exclusive with `--quick`) | n/a |
| `--architect-review` | `ARCHITECT_REVIEW=true` — enables Stage 4 (advisory architect-level review) | auto-on at `--assessment-depth thorough`, off otherwise |
| `--no-architect-review` | `ARCHITECT_REVIEW=false` — escape hatch to disable Stage 4 even at `--assessment-depth thorough` | n/a |
| `--architect-model <sonnet\|opus>` | `ARCHITECT_MODEL=<model>` — model for Stage 4 (ignored when `ARCHITECT_REVIEW=false`) | `opus` when Stage 4 is enabled |
| `--verbose` | `VERBOSE_REPORT=true` — also writes a per-user marker file that flips `agent_logger.py` into stderr-mirroring mode for the duration of this run (see "Verbose Mode — Marker File Lifecycle" below) | `false` |
| `--tracing` / `--no-tracing` | `TRACING=true` (default since M3.6) — writes a per-user marker file that activates per-agent token/turn/cost/wall-time tracking in `.appsec-trace.log`. At session end, `agent_logger.py` appends an ASSESSMENT_TRACE Markdown table to `.appsec-trace.log` (see "Tracing Mode — Marker File Lifecycle" below). Pass `--no-tracing` to disable. | `true` |
| `--base <ref>` | `BASE_REF=<ref>` — git ref to diff HEAD against for incremental mode (default: `commit_sha` recorded in the prior `threat-model.yaml`). Used in MR/PR mode to target the base branch. | (baseline commit) |
| `--pr-mode` | `PR_MODE=true` — produce a focused delta report limited to components affected by the `--base ... HEAD` diff. Implies `--incremental` and skips Stage 3 QA. | `false` |
| `--no-qa` | `SKIP_QA=true` — skip the Stage 3 QA reviewer (faster CI runs where the report is machine-consumed). Also honoured via `APPSEC_SKIP_QA=1`. | `false` |
| `--qa-scan-repo` | `QA_SCAN_REPO=true` — enable QA Check 2 Pass 2c (proactive repo-wide `find` for unlinked basenames). Off by default because it is expensive on large repos and only marginally useful (cosmetic linkification). | `false` |
| `--no-walkthroughs` | `SKIP_ATTACK_WALKTHROUGHS=true` — skip authoring `attack-walkthroughs.md` in Stage 2; the composer renders §3 with chain-overview-only fallback (no per-finding sequenceDiagram blocks). Saves ~1-2 min in Stage 2. | `false` |
| `--scan-manifest` | `SCAN_MANIFEST=true` — write a sorted, newline-separated list of every file the recon-scanner processed to `$OUTPUT_DIR/.scan-manifest.txt`. Useful for auditing which files were and weren't included in the assessment. | `false` |

**Deprecated aliases:** The old flags `--with-requirements`, `--ignore-requirements`, and `--requirements-url <url>` are accepted for backward compatibility. If encountered, print a deprecation warning and map them:
- `--with-requirements` → `--requirements`
- `--ignore-requirements` → `--no-requirements`
- `--requirements-url <url>` → `--requirements <url>`

Any remaining text (after extracting flags and their values) is treated as scope constraints (e.g., component name, subdirectory, focus area).

### Capture invocation arguments

Before any resolution steps, capture the **raw user input** (the full argument string as passed to the skill) verbatim into `INVOCATION_ARGS`. This preserves the exact invocation for reproducibility and is written into the Run Statistics appendix when `VERBOSE_REPORT=true`.

```
INVOCATION_ARGS="<raw user arguments as received by the skill>"
```

If the user passed no arguments at all, set `INVOCATION_ARGS=""` (empty string).

**Strip skill-only flags before passing to `resolve_config.py`.** `--force` is consumed entirely by the skill layer (rebuild guard at §"Rebuild guard") and is not recognised by `resolve_config.py`. Remove it from `INVOCATION_ARGS` so the script does not exit 2 with `unrecognized arguments: --force`:

```bash
# Remove --force from the args passed to resolve_config.py.
# --force is a skill-layer flag only; resolve_config.py does not accept it.
RESOLVE_ARGS=$(printf '%s' "$INVOCATION_ARGS" | sed 's/--force\b//g' | xargs)
```

Use `$RESOLVE_ARGS` (not `$INVOCATION_ARGS`) in all `resolve_config.py` invocations below. `INVOCATION_ARGS` is still passed verbatim to Stage 1/2 agent prompts so the orchestrator can see the original invocation.

### Verbose Mode — Marker File Lifecycle

`--verbose` has two distinct effects that must both be activated for the user to actually see verbose behaviour:

1. **`VERBOSE_REPORT=true`** — appends the `## Appendix: Run Statistics` section to `threat-model.md` (handled by the orchestrator via the variable passed in the Stage 1 agent prompt).
2. **Live stderr mirroring** — causes `scripts/agent_logger.py` to mirror each hook log line to stderr in real time, surfacing `PHASE_START`, `STEP_START`, `SCAN_START`, `AGENT_INVOKE`, `TOOL_ERROR` etc. to the terminal as the run progresses.

Effect (2) runs inside hook processes spawned by Claude Code itself, **not** inside the skill's Bash calls. Env vars set with `export` inside a skill Bash call therefore do **not** reach the hooks — Claude Code is the parent process of both, so the skill can only communicate with hooks through the filesystem (or through config.json, which is shared across runs).

The mechanism: when `VERBOSE_REPORT=true` is resolved, `touch` a per-user marker file that `agent_logger.py` checks alongside `APPSEC_VERBOSE` and `config.json → logging.verbose`. On skill exit (both success and failure paths), remove the marker so later non-verbose runs are not accidentally verbose.

```bash
VERBOSE_MARKER="${TMPDIR:-/tmp}/.appsec-verbose-$(id -u)"

if [ "$VERBOSE_REPORT" = "true" ]; then
  touch "$VERBOSE_MARKER"
fi
```

The cleanup is placed at the **end** of the Completion Summary section (both the dry-run and normal paths) and inside every error branch that exits non-zero. See "Completion Summary" and "Error Handling" below.

### Tracing Mode — Marker File Lifecycle

`--tracing` activates per-agent token/turn/cost/wall-time tracking. Like verbose mode, the hook processes that perform the tracing are spawned by Claude Code itself and cannot inherit env vars from skill Bash calls — the marker-file mechanism is used.

```bash
TRACING_MARKER="${TMPDIR:-/tmp}/.appsec-tracing-$(id -u)"

if [ "$TRACING" = "true" ]; then
  touch "$TRACING_MARKER"
fi
```

When active, `agent_logger.py` writes `AGENT_DISPATCH` events (at agent spawn time) and `AGENT_COMPLETE` events (at session end) to `.appsec-trace.log`, then appends an `ASSESSMENT_TRACE` Markdown table when the outer session ends.

Clean up `$TRACING_MARKER` at the same places as the verbose marker (Completion Summary, error branches, dry-run path). The trace log itself (`.appsec-trace.log`) is **not** cleaned up — it is a permanent audit artifact alongside `.agent-run.log` and `.hook-events.log`.

## Configuration Resolution

All flag parsing, conflict detection, per-resolver logic, and baseline detection live in a dedicated Python script: ``scripts/resolve_config.py``. The skill calls it once with the raw argv and receives a fully-resolved JSON:

```bash
RESOLVED_JSON=$(python3 "$CLAUDE_PLUGIN_ROOT/scripts/resolve_config.py" --emit-file $RESOLVE_ARGS)
RESOLVE_EXIT=$?
if [ "$RESOLVE_EXIT" -ne 0 ]; then
  # Conflict or hard-fail precondition — resolve_config.py already
  # printed an error to stderr. Run the verbose/tracing marker cleanup
  # (see §§ Error Handling) and exit with the same code.
  rm -f "${TMPDIR:-/tmp}/.appsec-verbose-$(id -u)"
  rm -f "${TMPDIR:-/tmp}/.appsec-tracing-$(id -u)"
  exit "$RESOLVE_EXIT"
fi
```

The script writes `$OUTPUT_DIR/.skill-config.json` (via ``--emit-file``) so downstream scripts — ``render_completion_summary.py`` and future helpers — can read the resolved config without re-parsing argv.

**Side effect: Configuration Summary on stderr.** The same ``--emit-file`` call also writes the human-readable Configuration Summary block (separator-wrapped) to **stderr**, so the user always sees the resolved configuration at skill start. JSON stays clean on stdout for the `$()` capture above; the summary is unconditional and cannot be suppressed. There is therefore no separate skill step needed to print it — the dedicated `## Configuration Summary` section further below is now a no-op fallback retained only for the rare case where a downstream change needs to re-render the box (e.g. after a mode upgrade in the Full-Scan Recommendation Prompt).

**Config-file presence check (G-11).** After the `resolve_config.py` call, verify the file was actually written — a race condition or a permissions error can silently suppress it without failing the Python exit code:

```bash
if [ ! -f "$OUTPUT_DIR/.skill-config.json" ]; then
  printf 'Warning: resolve_config.py --emit-file did not produce %s/.skill-config.json — downstream scripts will fall back to argv parsing.\n' "$OUTPUT_DIR" >&2
fi
```

Non-fatal: the warning is informational. `render_completion_summary.py` and other consumers already have argv-based fallbacks for the missing-file case.

The JSON contains, among others:

| Key | Type | Example |
|---|---|---|
| ``mode`` / ``mode_label`` | str | ``"incremental"`` / ``"incremental (auto)"`` |
| ``incremental`` / ``rebuild`` / ``dry_run`` | bool | |
| ``assessment_depth`` / ``depth_label`` | str | ``"standard"`` |
| ``reasoning_model`` / ``reasoning_label`` | str | ``"opus-cheap"`` |
| ``stride_model`` / ``triage_model`` / ``merger_model`` | str | ``"claude-sonnet-4-6"`` / ``"claude-opus-4-7"`` |
| ``architect_review`` / ``architect_model`` / ``architect_label`` | bool / str | |
| ``write_yaml`` / ``write_sarif`` / ``write_pentest_tasks`` | bool | |
| ``check_requirements`` / ``requirements_url_override`` / ``requirements_label`` | bool / str | |
| ``repo_root`` / ``output_dir`` / ``output_outside_repo`` | str / bool | |
| ``baseline_state`` | str | ``"empty"`` \| ``"legacy"`` \| ``"structured"`` |
| ``post_summary_note`` | str or null | | 
| ``plugin_version`` / ``analysis_version`` | str / int | |

Full schema + resolver semantics (conflict pairs, first-match-wins rules, env-var escape hatches, deprecated-alias mapping, quick-depth requirements override) are documented in ``scripts/resolve_config.py`` and covered by ``tests/test_resolve_config.py``. **Do not re-implement any resolution logic in the skill** — if a rule needs to change, edit the script and its tests.

Extract the variables from the JSON into shell env-vars for the Bash snippets that follow (Incremental Fast-Path, Plugin Version Compatibility Gate, Rebuild Pre-flight Wipe, etc.):

```bash
MODE=$(echo "$RESOLVED_JSON" | python3 -c "import json,sys;print(json.load(sys.stdin)['mode'])")
INCREMENTAL=$(echo "$RESOLVED_JSON" | python3 -c "import json,sys;print(str(json.load(sys.stdin)['incremental']).lower())")
REBUILD=$(echo "$RESOLVED_JSON" | python3 -c "import json,sys;print(str(json.load(sys.stdin)['rebuild']).lower())")
DRY_RUN=$(echo "$RESOLVED_JSON" | python3 -c "import json,sys;print(str(json.load(sys.stdin)['dry_run']).lower())")
OUTPUT_DIR=$(echo "$RESOLVED_JSON" | python3 -c "import json,sys;print(json.load(sys.stdin)['output_dir'])")
REPO_ROOT=$(echo "$RESOLVED_JSON"  | python3 -c "import json,sys;print(json.load(sys.stdin)['repo_root'])")
# …etc. for ARCHITECT_REVIEW, WRITE_YAML, etc.

# Reasoning core models (existing)
STRIDE_MODEL=$(echo "$RESOLVED_JSON" | python3 -c "import json,sys;print(json.load(sys.stdin)['stride_model'])")
TRIAGE_MODEL=$(echo "$RESOLVED_JSON" | python3 -c "import json,sys;print(json.load(sys.stdin)['triage_model'])")
MERGER_MODEL=$(echo "$RESOLVED_JSON" | python3 -c "import json,sys;print(json.load(sys.stdin)['merger_model'])")

# Extended-model routing (haiku-economy tier — see AGENTS.md).
# These default to claude-sonnet-4-6 when --reasoning-model is not haiku-economy
# (preserves backward-compat). When haiku-economy is active, individual fields
# resolve to claude-haiku-4-5 according to the per-depth routing matrix.
CONTEXT_RESOLVER_MODEL=$(echo "$RESOLVED_JSON" | python3 -c "import json,sys;print(json.load(sys.stdin).get('context_resolver_model','claude-sonnet-4-6'))")
RECON_SCANNER_MODEL=$(echo   "$RESOLVED_JSON" | python3 -c "import json,sys;print(json.load(sys.stdin).get('recon_scanner_model','claude-sonnet-4-6'))")
QA_ROUTINE_MODEL=$(echo      "$RESOLVED_JSON" | python3 -c "import json,sys;print(json.load(sys.stdin).get('qa_routine_model','claude-sonnet-4-6'))")
QA_CONTENT_MODEL=$(echo      "$RESOLVED_JSON" | python3 -c "import json,sys;print(json.load(sys.stdin).get('qa_content_model','claude-sonnet-4-6'))")
CONFIG_SCANNER_MODEL=$(echo  "$RESOLVED_JSON" | python3 -c "import json,sys;print(json.load(sys.stdin).get('config_scanner_model','claude-sonnet-4-6'))")
ORCHESTRATOR_MODEL=$(echo    "$RESOLVED_JSON" | python3 -c "import json,sys;print(json.load(sys.stdin).get('orchestrator_model','claude-sonnet-4-6'))")

# STRIDE depth profile (Quick-mode A-F reductions, only when
# --reasoning-model haiku-economy AND --assessment-depth quick).
# Emit as inline JSON for the orchestrator to forward in Phase 9 dispatches.
STRIDE_PROFILE_JSON=$(echo "$RESOLVED_JSON" | python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin).get('stride_profile', {'stride_profile_label':'full'})))")
STRIDE_PROFILE_LABEL=$(echo "$RESOLVED_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin).get('stride_profile',{}).get('stride_profile_label','full'))")
```

(A convenience: ``eval $(python3 ... --emit-env)`` is on the roadmap; for now the skill pulls individual keys via ``python3 -c``.)

### Verbose Mode — Marker File Lifecycle

``--verbose`` has two distinct effects that must both be activated for the user to see verbose behaviour:

1. ``verbose=true`` in the resolved JSON → the orchestrator appends the ``## Appendix: Run Statistics`` section to ``threat-model.md``.
2. Live stderr mirroring → ``scripts/agent_logger.py`` mirrors each hook log line to stderr in real time.

Effect 2 runs inside hook processes spawned by Claude Code itself, **not** inside the skill's Bash calls. Env vars set with ``export`` inside a skill Bash call therefore do **not** reach the hooks — Claude Code is the parent of both, so the skill can only communicate with hooks through the filesystem.

Mechanism: when ``verbose=true`` is resolved, ``touch`` a per-user marker file. On skill exit (success and failure paths), remove the marker so later non-verbose runs are not accidentally verbose.

```bash
VERBOSE_MARKER="${TMPDIR:-/tmp}/.appsec-verbose-$(id -u)"
[ "$(echo "$RESOLVED_JSON" | python3 -c 'import json,sys;print(str(json.load(sys.stdin)[\"verbose\"]).lower())')" = "true" ] && touch "$VERBOSE_MARKER"
```

Cleanup is placed at the **end** of the Completion Summary section and inside every error branch that exits non-zero.

### Tracing Mode — Marker File Lifecycle

Same mechanism as verbose — a per-user marker file at ``${TMPDIR:-/tmp}/.appsec-tracing-$(id -u)``. When active, ``scripts/agent_logger.py`` writes ``AGENT_DISPATCH`` / ``AGENT_COMPLETE`` events and an ``ASSESSMENT_TRACE`` table to ``.appsec-trace.log`` at session end.

```bash
TRACING_MARKER="${TMPDIR:-/tmp}/.appsec-tracing-$(id -u)"
[ "$(echo "$RESOLVED_JSON" | python3 -c 'import json,sys;print(str(json.load(sys.stdin)[\"tracing\"]).lower())')" = "true" ] && touch "$TRACING_MARKER"
```

Clean up the tracing marker at the same places as the verbose marker. The trace log itself (``.appsec-trace.log``) is **not** cleaned up — it is a permanent audit artifact alongside ``.agent-run.log`` and ``.hook-events.log``.

### Marker file EXIT trap (G-8)

Immediately after the two `touch` calls above, register a shell `trap` so the marker files are removed on **any** exit — including signals, `set -e` aborts, and early-return paths that omit an explicit `rm -f`:

```bash
trap 'rm -f "$VERBOSE_MARKER" "$TRACING_MARKER"' EXIT
```

The `EXIT` trap fires whether the shell exits via `exit N`, `return`, a signal, or an unhandled error. Because the trap is installed right after the marker files are conditionally created, any branch that subsequently calls `exit` — dry-run summary, error-handling, fast-path abort, incremental null-change — is covered automatically. The explicit `rm -f` calls in the Completion Summary and error branches remain in place as belt-and-suspenders (harmless double-removes are idempotent), but they are no longer load-bearing.

## Incremental Fast-Path (null-change abort)

When `MODE=incremental` and a baseline exists, run a **unified pre-check** *before* entering Stage 1. If nothing has changed (or only noise-only files changed) since the last run and the plugin hasn't drifted, exit immediately with a friendly message — no agents dispatched, no tokens burned.

Extract the `MODE_LABEL` from the resolved config so the fast-path can distinguish **auto-detected** incremental (`mode_label` contains `"(auto)"`) from **explicit** incremental (user passed `--incremental`). Only auto-detected mode may be upgraded to full via the confirmation prompt; explicit `--incremental` is always honored as-is.

```bash
MODE_LABEL=$(echo "$RESOLVED_JSON" | python3 -c "import json,sys;print(json.load(sys.stdin).get('mode_label',''))")
NO_CONFIRM=$(echo "$RESOLVED_JSON" | python3 -c "import json,sys;print(str(json.load(sys.stdin).get('no_confirm',False)).lower())")
# mode is auto-detected (not user-explicit) when mode_label contains "(auto)"
case "$MODE_LABEL" in
  *"(auto)"*) INCREMENTAL_IS_AUTO=true ;;
  *)          INCREMENTAL_IS_AUTO=false ;;
esac
```

```bash
if [ "$MODE" = "incremental" ]; then
  FAST_PATH_ARGS="check-changes --output-dir \"$OUTPUT_DIR\" --repo-root \"$REPO_ROOT\""
  [ -n "$BASE_REF" ] && FAST_PATH_ARGS="$FAST_PATH_ARGS --base-ref \"$BASE_REF\""
  FAST_PATH_OUTPUT=$(python3 "$CLAUDE_PLUGIN_ROOT/scripts/baseline_state.py" $FAST_PATH_ARGS 2>/dev/null || true)
  FAST_PATH_EXIT=$?

  case "$FAST_PATH_EXIT" in
    0)
      # No changes at all.
      echo "No changes detected since the last scan — threat model is up to date."
      echo "  Baseline : $(echo "$FAST_PATH_OUTPUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("baseline_sha","?")[:12])')"
      echo "  Current  : $(echo "$FAST_PATH_OUTPUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("head_sha","?")[:12])')"
      rm -f "${TMPDIR:-/tmp}/.appsec-verbose-$(id -u)" "${TMPDIR:-/tmp}/.appsec-tracing-$(id -u)"
      exit 0
      ;;
    2)
      # Files changed, but none are security-relevant (noise-only).
      echo "No security-relevant changes since the last scan — threat model is up to date."
      echo "  Baseline : $(echo "$FAST_PATH_OUTPUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("baseline_sha","?")[:12])')"
      echo "  Current  : $(echo "$FAST_PATH_OUTPUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("head_sha","?")[:12])')"
      echo "  Skipped (non-source): $(echo "$FAST_PATH_OUTPUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);files=d.get("noise_only_changes",[]); print(", ".join(files[:5]) + (" ..." if len(files)>5 else ""))')"
      rm -f "${TMPDIR:-/tmp}/.appsec-verbose-$(id -u)" "${TMPDIR:-/tmp}/.appsec-tracing-$(id -u)"
      exit 0
      ;;
    10)
      # No source changes, but plugin version has drifted.
      echo "Source unchanged, but plugin version has drifted since the last run."
      echo "$FAST_PATH_OUTPUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(" ",d["plugin_version"].get("message",""))'
      if [ "${APPSEC_CI_MODE:-}" = "1" ]; then
        # In CI we honour the drift signal and still abort — dedicated
        # full-refresh jobs should handle plugin upgrades.
        rm -f "${TMPDIR:-/tmp}/.appsec-verbose-$(id -u)" "${TMPDIR:-/tmp}/.appsec-tracing-$(id -u)"
        exit 0
      else
        # Interactive: fall through to the normal run
        # (the compat gate below may still hard-abort on analysis_version drift).
        echo "  Continuing with incremental run; pass --full to force a rebuild."
      fi
      ;;
    1)
      # Security-relevant changes detected — print a scope preview so the
      # user can abort before tokens are spent.
      SEC_FILES=$(echo "$FAST_PATH_OUTPUT" | python3 -c '
import json,sys
d=json.load(sys.stdin)
files=d.get("security_relevant_changes",[])
total=d.get("security_relevant_change_count",len(files))
preview=", ".join(files[:5])
suffix=" ..." if total>5 else ""
print(f"{total} security-relevant file(s): {preview}{suffix}")
')
      echo "Incremental run — ${SEC_FILES}"
      ;;
    *)
      : # error (exit 3) or unrecognised — fall through to full flow
      ;;
  esac
fi
```

The same pre-check is performed by `scripts/run-headless.sh` at shell level, so CI runners can fast-abort *before* even spawning Claude Code. The in-skill version is a safety net for interactive invocations.

## Full-Scan Recommendation Prompt (auto-incremental only)

After the fast-path and the Plugin Version Compatibility Gate, and **before** the Stage 1 Handoff Banner, evaluate whether the user should be offered a chance to switch to a full scan. This prompt fires **only** when all of the following are true:

1. `INCREMENTAL_IS_AUTO=true` — mode was auto-detected, not explicitly requested via `--incremental`
2. At least one recommendation trigger is present (see table below)
3. `NO_CONFIRM=false` — `--no-confirm` / `--yes` was not passed
4. `APPSEC_CI_MODE` is not `1`
5. stdin is a TTY (`[ -t 0 ]`)

| Trigger | Variable | Condition |
|---------|----------|-----------|
| Plugin version drifted | `COMPAT_LABEL` | `older-compatible` |
| Most components affected | `SEC_CHANGE_COUNT` vs `MAX_STRIDE_COMPONENTS` | `SEC_CHANGE_COUNT / MAX_STRIDE_COMPONENTS >= 0.8` (integer: `SEC_CHANGE_COUNT * 10 / MAX_STRIDE_COMPONENTS >= 8`) |

```bash
# Only evaluate when mode was auto-detected incremental.
if [ "$MODE" = "incremental" ] && [ "$INCREMENTAL_IS_AUTO" = "true" ] \
    && [ "$NO_CONFIRM" = "false" ] \
    && [ "${APPSEC_CI_MODE:-}" != "1" ] \
    && [ -t 0 ]; then

  # Collect trigger reasons.
  PROMPT_REASONS=""
  if [ "$COMPAT_LABEL" = "older-compatible" ]; then
    BASELINE_PLUGIN=$(echo "$FAST_PATH_OUTPUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("plugin_version",{}).get("baseline","?"))')
    CURRENT_PLUGIN=$(echo "$FAST_PATH_OUTPUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("plugin_version",{}).get("current","?"))')
    PROMPT_REASONS="${PROMPT_REASONS}    • Plugin version drifted (baseline: ${BASELINE_PLUGIN}, current: ${CURRENT_PLUGIN}) — incremental may miss analysis improvements\n"
  fi

  SEC_CHANGE_COUNT=$(echo "$FAST_PATH_OUTPUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("security_relevant_change_count",0))' 2>/dev/null || echo 0)
  # Integer arithmetic: count*10/max >= 8  ⟺  count/max >= 0.8
  if [ "$(( SEC_CHANGE_COUNT * 10 / MAX_STRIDE_COMPONENTS ))" -ge 8 ] && [ "$SEC_CHANGE_COUNT" -gt 0 ]; then
    PROMPT_REASONS="${PROMPT_REASONS}    • ${SEC_CHANGE_COUNT}/${MAX_STRIDE_COMPONENTS} components affected — full scan gives better T-ID stability at similar cost\n"
  fi

  if [ -n "$PROMPT_REASONS" ]; then
    printf "\n⚠ Incremental run not recommended:\n"
    printf "%b" "$PROMPT_REASONS"
    printf "\n  [I] Continue incremental   [F] Switch to full scan   [A] Abort\n"
    printf "  Choice (default: F in 30s): "

    # Read with timeout; default to 'f' on timeout or empty input.
    CONFIRM_TIMEOUT="${APPSEC_CONFIRM_TIMEOUT:-30}"
    if read -r -t "$CONFIRM_TIMEOUT" CONFIRM_CHOICE 2>/dev/null; then
      CONFIRM_CHOICE=$(echo "$CONFIRM_CHOICE" | tr '[:upper:]' '[:lower:]' | tr -d ' ')
    else
      CONFIRM_CHOICE="f"
      printf "\n  (timed out — defaulting to full scan)\n"
    fi

    case "$CONFIRM_CHOICE" in
      i|incremental)
        echo "  Continuing with incremental run."
        ;;
      a|abort)
        echo "  Aborted."
        rm -f "${TMPDIR:-/tmp}/.appsec-verbose-$(id -u)" "${TMPDIR:-/tmp}/.appsec-tracing-$(id -u)"
        exit 0
        ;;
      *)
        # 'f', empty, or anything else → switch to full.
        echo "  Switching to full scan."
        MODE="full"
        INCREMENTAL="false"
        MODE_UPGRADED_BY_PROMPT=true
        ;;
    esac
  fi
fi
```

**When the user chooses full:** override `MODE=full` and `INCREMENTAL=false` in shell scope, then continue with the Stage 1 Handoff Banner as normal. The orchestrator receives `INCREMENTAL=false` and runs a complete assessment.

## Plugin Version Compatibility Gate

Runs **only** when `MODE=incremental`. For full runs the gate is a no-op — a full rebuild always establishes a fresh baseline under the current plugin version, so there is nothing to validate.

The gate prevents an incremental run from silently carrying forward threats that were produced by a plugin version whose STRIDE prompts or CWE mappings no longer match the current release. It classifies the baseline into four outcomes and maps each to a concrete action:

| Classification | When | Action |
|---|---|---|
| **equal** | `baseline.analysis_version == current.analysis_version` | Continue silently. |
| **older-compatible** | `baseline.analysis_version < current` AND `baseline.analysis_version ∈ compatible_analysis_versions` | Continue with a **warning banner**. Set `RECOMMEND_FULL=true` so Phase 11 renders the baseline-older callout in the report and sets `meta.recommend_full_rerun: true` in yaml. |
| **incompatible** | `baseline.analysis_version ∉ compatible_analysis_versions` (too old, or missing) | **Hard abort (exit 2)** unless `--full` is passed. The baseline uses an analysis the current plugin cannot extend safely. |
| **legacy / missing** | `analysis_version` not present in either `threat-model.yaml` or `.appsec-cache/baseline.json` (pre-versioning baseline, M2 bootstrap path) | Treat as **older-compatible** — continue with the warning banner. This preserves the existing pre-M2 upgrade path: first run after upgrade warns but works, subsequent runs are clean. |

**Shell implementation (batched with the block directly above the Configuration Summary):**

```bash
if [ "$MODE" = "incremental" ]; then
  python3 "$CLAUDE_PLUGIN_ROOT/scripts/baseline_state.py" check-compat \
    --output-dir "$OUTPUT_DIR"
  COMPAT_EXIT=$?
else
  COMPAT_EXIT=0
fi

case "$COMPAT_EXIT" in
  0)
    COMPAT_LABEL="equal"
    ;;
  10|30)
    # 10 = older-but-compatible, 30 = legacy baseline without version field.
    # Both continue with a warning; treat them uniformly.
    COMPAT_LABEL="older-compatible"
    POST_SUMMARY_NOTE="Warning: baseline was produced by an older plugin version. Incremental run continues, but --full is recommended to pick up analysis improvements."
    ;;
  20)
    COMPAT_LABEL="incompatible"
    cat >&2 <<ERR
Error: baseline in $OUTPUT_DIR was produced by a plugin with an incompatible
  analysis_version. The current plugin cannot safely extend it.

  Fix: re-run with --full to rebuild the baseline.

  Details: $(python3 "$CLAUDE_PLUGIN_ROOT/scripts/baseline_state.py" check-compat --output-dir "$OUTPUT_DIR" 2>&1)
ERR
    exit 2
    ;;
  *)
    COMPAT_LABEL="unknown"
    ;;
esac
```

Store `COMPAT_LABEL` for the Configuration Summary. The gate runs **after** Incremental Mode Resolution has set `MODE`, so it already knows whether it is operative.

**Override:** there is no `--ignore-compat` flag on purpose. The only way to bypass the hard-fail path (`incompatible`) is to pass `--full`, which rebuilds the baseline against the current plugin in one step. Anything else would risk silent data rot in committed threat models.

## Configuration Summary

**Already emitted.** The Configuration Summary box was written to stderr by the ``resolve_config.py --emit-file`` call in the Configuration Resolution section above (single source of truth, unskippable side effect). Do **not** call ``--config-summary`` again here — it would print the box twice. Skip this section unless the Full-Scan Recommendation Prompt above mutated `MODE` from incremental → full, in which case re-emit so the user sees the post-upgrade state:

```bash
if [ "$MODE_UPGRADED_BY_PROMPT" = "true" ]; then
  printf '\n══════════════════ Configuration Summary (post mode-upgrade) ══════════════════\n' >&2
  python3 "$CLAUDE_PLUGIN_ROOT/scripts/resolve_config.py" --config-summary $RESOLVE_ARGS --full >&2
  printf '═══════════════════════════════════════════════════════════════════════════════\n\n' >&2
fi
```

The summary's two-tier layout is pinned in ``scripts/resolve_config.py → render_configuration_summary`` and covered by ``tests/test_resolve_config.py``:

- **Always-shown core** (six rows): Repository / Output / Plugin / Mode / Depth / Reasoning.
- **Optional rows** — rendered **only when the option is active or deviates from the silent default**: Requirements (when enabled), Architect (when enabled), Outputs (when sarif/pentest/--no-yaml), SCA (when --with-sca), QA (when --no-qa), Scope (when non-empty positional given), Run flags (dry-run/verbose/tracing/scan-manifest/keep-runtime-files/pr-mode/qa-scan-repo — comma-joined when ≥1 active), STRIDE Prof. (only when reduced via haiku-economy + quick), Deadline (when --max-wall-time or --max-cost set).
- **Post-summary notes** (preserved): output-outside-repo, rebuild-overwrite warning, incremental-tip, requirements-disabled tip, repo-size-cap.

No handwriting of the summary — if the format needs to change, edit the script.

### need_render intercept (G-1 — before Rebuild Pre-flight Wipe)

When `REBUILD=true`, check whether the prior run completed Stage 1 but never dispatched Stage 2. A blind `--rebuild` would silently discard all Phase-1–10b work (28+ threats, 3 STRIDE files, merged threats, triage) that is still perfectly valid. Intercept and warn before the wipe runs.

```bash
if [ "$REBUILD" = "true" ] && [ "$DRY_RUN" = "false" ]; then
  CP_FILE="$OUTPUT_DIR/.appsec-checkpoint"
  if [ -f "$CP_FILE" ] && [ ! -f "$OUTPUT_DIR/threat-model.md" ]; then
    CP_LINE=$(head -n1 "$CP_FILE" 2>/dev/null || true)
    CP_PHASE=$(printf '%s' "$CP_LINE"  | sed -n 's/.*phase=\([^ ]*\).*/\1/p')
    CP_RENDER=$(printf '%s' "$CP_LINE" | sed -n 's/.*need_render=\([^ ]*\).*/\1/p')
    if [ "$CP_PHASE" = "10b" ] && [ "$CP_RENDER" = "true" ]; then
      printf '\n⚠ Stage 1 is complete (phase=10b need_render=true) but Stage 2 was never dispatched.\n' >&2
      printf '  Phase 1–10b results (STRIDE files, merged threats, threat-model.yaml) are still on disk.\n' >&2
      printf '  --rebuild will DISCARD all of this work.\n\n' >&2
      printf '  Recommended:  /appsec-advisor:create-threat-model --resume   (dispatch Stage 2 only)\n' >&2
      printf '  To force:     /appsec-advisor:create-threat-model --rebuild --force\n\n' >&2
      # Check for --force to allow deliberate override
      REBUILD_FORCE=false
      for arg in "$@"; do
        case "$arg" in --force) REBUILD_FORCE=true ;; esac
      done
      if [ "$REBUILD_FORCE" = "false" ]; then
        rm -f "${TMPDIR:-/tmp}/.appsec-verbose-$(id -u)" \
              "${TMPDIR:-/tmp}/.appsec-tracing-$(id -u)"
        exit 0
      fi
      printf '  --force acknowledged — proceeding with rebuild.\n\n' >&2
    fi
  fi
fi
```

### Rebuild Pre-flight Wipe (only when `REBUILD=true`)

When `REBUILD=true` and `DRY_RUN=false`, wipe prior model and cached state **before** the Stage 1 handoff banner but **after** the Configuration Summary (so the user has already seen `Mode: rebuild (...)` and the `POST_SUMMARY_NOTE` warning).

Print the wipe header:

```

Rebuild: discarding prior threat model and all cached state.
  Removing from <OUTPUT_DIR>:
    threat-model.md / threat-model.yaml / threat-model.sarif.json / pentest-tasks.yaml (if present)
    .architect-review.md, .threat-modeling-context.md, .recon-summary.md, .dep-scan.json
    .stride-*.json, .threats-merged.json, .triage-flags.json, .triage-ranking.json, .merge-*.json
    .fragments/ (compose inputs from prior contract version — must not survive a rebuild)
    .appsec-cache/ (baseline cache directory)
    .progress/, .taxonomy-slices/ (runtime-only directories)
    .appsec-checkpoint, .phase-epoch, .session-agent-map, .assessment-summary-emitted
    .skill-config.json, .recon-patterns.json, .compose-stats.json
    .context-resolver.stdout, .ctx-resolver.pid, .recon-scanner.pid, .recon-scanner.stdout
    .coverage-gaps.json, .scan-manifest.txt, .requirements.yaml
    .prior-findings-index.json, .stage1-resume-count
    .run-issues.json, .run-issues-fixes.json
    .pre-render-repair-plan.json, .qa-repair-plan.json, .qa-content-repair-plan.json,
    .architect-repair-plan.json (if present)
  Preserved:
    .agent-run.log, .hook-events.log (audit trail — overwritten by next run's ASSESSMENT_START)
    .activity-throttle (session-rate counter — intentionally survives rebuild)
    .appsec-lock (managed separately by the lock acquire/release mechanism)
  Note: --rebuild clears disk artifacts only. The in-process session context
    (conversation history cached in the Claude process) cannot be wiped by a
    script. If the cache_read bloat detector above fired, run /clear before
    re-invoking for a genuinely clean start.
```

Then perform the wipe in a single Bash call:

```bash
cd "$OUTPUT_DIR" 2>/dev/null || true
WIPED_COUNT=$(find . -maxdepth 1 \
  \( -name "threat-model.md" -o -name "threat-model.yaml" -o -name "threat-model.sarif.json" \
     -o -name "pentest-tasks.yaml" -o -name ".architect-review.md" \
     -o -name ".threat-modeling-context.md" -o -name ".recon-summary.md" -o -name ".dep-scan.json" \
     -o -name ".stride-*.json" -o -name ".threats-merged.json" -o -name ".triage-flags.json" \
     -o -name ".merge-*.json" -o -name ".appsec-checkpoint" \
     -o -name ".pre-render-repair-plan.json" -o -name ".qa-repair-plan.json" \
     -o -name ".qa-content-repair-plan.json" -o -name ".architect-repair-plan.json" \
     -o -name ".stage-stats.jsonl" -o -name ".direct-write-blocked" \
     -o -name ".phase-epoch" -o -name ".session-agent-map" \
     -o -name ".assessment-summary-emitted" -o -name ".skill-config.json" \
     -o -name ".recon-patterns.json" -o -name ".compose-stats.json" \
     -o -name ".context-resolver.stdout" -o -name ".ctx-resolver.pid" \
     -o -name ".recon-scanner.pid" -o -name ".recon-scanner.stdout" \
     -o -name ".coverage-gaps.json" -o -name ".scan-manifest.txt" \
     -o -name ".requirements.yaml" \
     -o -name ".prior-findings-index.json" -o -name ".stage1-resume-count" \
     -o -name ".triage-ranking.json" \
     -o -name ".run-issues.json" -o -name ".run-issues-fixes.json" \) \
  -print -delete 2>/dev/null | wc -l)
# .fragments/ MUST be wiped — stale compose inputs from a prior contract
# version are the #1 cause of the Phase 11 compose-fix-loop (see Bug 1 /
# §7 numbering drift). A --rebuild that leaves them on disk silently
# reuses fragments that do not match the current `sections-contract.yaml`.
# Sprint 3C (M3.5): also wipe .stage-stats.jsonl and .direct-write-blocked
# so a fresh rebuild starts with empty observability state — without this,
# `record_stage_stats.py` saw stale entries from the prior run and refused
# to log any of run N+1's stages (the 2026-04-27 run produced no stage
# stats at all because it was the second --rebuild in a row).
# .progress/ and .taxonomy-slices/ are runtime-only dirs that must not
# survive a rebuild.
rm -rf .fragments .appsec-cache .progress .taxonomy-slices 2>/dev/null
echo "  Removed $WIPED_COUNT files + .fragments/ + .appsec-cache/ + .progress/ + .taxonomy-slices/"
```

If `$OUTPUT_DIR` does not exist or `find` fails, treat as no-op — the rebuild is starting from a clean slate anyway, which is the desired outcome.

After the wipe, set `BASELINE_STATE=empty` in memory (the baseline no longer exists on disk). The orchestrator will therefore run as a first-ever full assessment: no baseline snapshot, fresh `v1` changelog entry, no T-ID stability, no Change Summary block in the completion summary.

### Full-run Pre-flight Intermediate Wipe (only when `MODE=full` and `REBUILD=false`)

When `MODE=full` (user passed `--full` OR legacy bootstrap) and `REBUILD=false` and `DRY_RUN=false`, wipe **intermediate** files from prior runs so the orchestrator never reads stale STRIDE outputs, merged-threats snapshots, or triage flags as if they were fresh. The threat model itself (`threat-model.md`, `threat-model.yaml`, `threat-model.sarif.json`) and the `.appsec-cache/` baseline directory are **preserved** — a `--full` run overwrites those in place and keeps the changelog history. Only working-set artifacts are removed.

Print the wipe header:

```

Full run: discarding stale intermediate artifacts to avoid cross-contamination.
  Removing from <OUTPUT_DIR>:
    .stride-*.json, .threats-merged.json, .triage-flags.json, .merge-*.json
    .architect-review.md (will be regenerated by Stage 4 if enabled)
    .recon-summary.md (will be regenerated by Phase 2)
    .appsec-checkpoint (will be recreated from Phase 1)
    .progress/ (per-agent progress tracker — will be recreated)
    .fragments/ (compose inputs from prior contract version)
    .pre-render-repair-plan.json, .qa-repair-plan.json, .architect-repair-plan.json (stale repair signals)
  Preserved:
    threat-model.md, threat-model.yaml, threat-model.sarif.json (overwritten by orchestrator)
    .appsec-cache/ (baseline cache; used for incremental fingerprint comparison)
    .threat-modeling-context.md (context cache — orchestrator checks mtime vs HEAD)
    .agent-run.log, .hook-events.log (audit trail — appended to)
```

Then perform the wipe in a single Bash call:

```bash
cd "$OUTPUT_DIR" 2>/dev/null || true
WIPED_COUNT=$(find . -maxdepth 1 \
  \( -name ".stride-*.json" -o -name ".threats-merged.json" \
     -o -name ".triage-flags.json" -o -name ".merge-*.json" \
     -o -name ".architect-review.md" -o -name ".recon-summary.md" \
     -o -name ".appsec-checkpoint" \
     -o -name ".assessment-summary-emitted" -o -name ".phase-epoch" \
     -o -name ".session-agent-map" -o -name ".prior-findings-index.json" \
     -o -name ".pre-render-repair-plan.json" -o -name ".qa-repair-plan.json" \
     -o -name ".architect-repair-plan.json" \) \
  -print -delete 2>/dev/null | wc -l)
# .fragments/ MUST be wiped. Stale fragments from a previous contract
# version (e.g. §7 layout prior to the 7.8/7.9 insertion) are the
# single biggest cause of Phase 11 compose failures — the orchestrator
# re-reads them thinking they reflect the current run's findings and
# grinds compose against a mismatch it cannot resolve.
rm -rf .progress .fragments 2>/dev/null
echo "  Removed $WIPED_COUNT stale intermediate files + .progress/ + .fragments/"
```

If `$OUTPUT_DIR` does not exist or `find` fails, treat as no-op.

**Why this matters.** Without this step, a `--full` run against a directory that held, say, `T-001..T-055` from a prior session can see its Phase 9 merge step read a mix of fresh per-component STRIDE outputs and a stale `.threats-merged.json` from the previous session, leading to cross-run ID drift (e.g. `T-003` surviving as a YAML/JSON phantom after the current MD dropped it during consolidation). This is the root cause behind the architect-review findings W-02 / W-03 / W-08 seen on the 2026-04-18 thorough run.

### Skill-layer lock acquisition (M3.2 — heartbeat fix)

Background-dispatched Stage 1 / Stage 2 agents do not always run the orchestrator's "step 2" lock-acquire helper before they begin work — observed during the 2026-04-26 19:55 run, the `.appsec-lock` file was missing for the entire run, which meant the heartbeat mechanic was effectively dead and ``/appsec-advisor:status`` reported "no run" while the assessment was running.

The fix is to acquire the lock **at the skill level** — once, before the first Agent dispatch — so the file always exists for the duration of the run. The orchestrator's own per-phase `--heartbeat` calls then see a present lock and refresh it normally. Failure to acquire is non-fatal: a missing lock is degraded observability, not an aborted run.

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/acquire_lock.py" "$OUTPUT_DIR/.appsec-lock" 2>&1 | head -1 || true
# Initial heartbeat so the lock has a fresh ts before Stage 1 starts.
python3 "$CLAUDE_PLUGIN_ROOT/scripts/acquire_lock.py" "$OUTPUT_DIR/.appsec-lock" \
    --heartbeat --phase=skill --step=stage1-dispatch >/dev/null 2>&1 || true
```

The lock is released with an explicit `rm -f` in the Completion Summary section below — `runtime_cleanup.py --stage post-qa` does **not** include `.appsec-lock` in its whitelist (only `--stage all` and `--stage pre-qa` do).

### Skill-layer heartbeat watchdog (M3.4 — Phase-9-silent-hang fix; M3.6 Python lift)

**Problem this solves.** Lock freshness must not depend on the orchestrator making frequent Bash calls. Phase 9 can spend a long time waiting for background STRIDE analyzers, so the skill owns an independent heartbeat process for the full stage.

**Fix.** Spawn `scripts/skill_watchdog.py` as a background Bash process. The Python script issues `acquire_lock.py --heartbeat` every 60 s, mirrors STRIDE progress to `.agent-run.log`, detects stagnation, fires the Phase-9 canary, and (M3.6 #7) tracks per-component idle time independently. The skill owns this process: started right before the Stage 1 Agent dispatch, killed right after the Agent tool returns.

**Pre-M3.6 implementation note.** This used to be a ~60-line inline Bash blob with three layers of nested quoting. The Python rewrite is unit-testable, has no shell-quoting traps, and is the integration point for the per-component-timeout escalation (M3.6 #7) and (when wired) selective `TaskStop` (#8). Behaviour is byte-identical for the four legacy detectors (heartbeat, STRIDE progress, stagnation, canary); the per-component timeout is additive.

**Mechanism.** Use the `Bash` tool with `run_in_background: true` to spawn the watchdog. The tool returns a `task_id`; capture it in `HEARTBEAT_TASK_ID` so the skill can stop it after the stage Agent returns.

```bash
# Skill-layer heartbeat + stride-progress watchdog. Runs in parallel with
# the foreground Stage 1 / 2 / 3 / 4 Agent dispatches. Five responsibilities
# (see scripts/skill_watchdog.py docstring for the full contract):
#   1. Refresh .appsec-lock every 60 s.
#   2. Mirror STRIDE_PROGRESS lines to .agent-run.log.
#   3. STRIDE_STALE after 15 min of no aggregate progress.
#   4. STRIDE_CANARY_TIMEOUT after 3 min of Phase 9 with zero stride output.
#   5. STRIDE_COMPONENT_TIMEOUT (M3.6 #7) per-component idle > 8 min.
python3 "$CLAUDE_PLUGIN_ROOT/scripts/skill_watchdog.py" "$OUTPUT_DIR" \
    --plugin-root "$CLAUDE_PLUGIN_ROOT" \
    --heartbeat-interval 60 \
    --stride-stale-seconds 900 \
    --stride-canary-seconds 180 \
    --component-timeout-seconds 480
```

The skill MUST issue this Bash call with `run_in_background: true` and capture its returned `task_id` in shell scope:

```
HEARTBEAT_TASK_ID=<task_id from background bash>
```

**Lifecycle.**
- **Start** — right before the Stage 1 Agent dispatch (after the handoff banner, after the task-list bootstrap). Place the start *outside* any conditional branch so it always runs in normal mode (skip when `DRY_RUN=true`, where the run is sub-1-minute and a watchdog is overkill).
- **Stop** — right after the Stage 1 Agent tool returns. Call the `TaskStop` tool with `HEARTBEAT_TASK_ID`. Do this BEFORE the cut-off detection so a still-running watchdog does not interfere with the manual-recovery banner branches.
- **Failure modes** — a missed start is degraded observability, never a hard failure. A missed stop leaves a stale watchdog that exits naturally when `runtime_cleanup.py --stage post-qa` removes `.appsec-lock`.

**Stage 2 / Stage 3 / Stage 4** — re-spawn a fresh watchdog before each subsequent foreground Agent dispatch and stop it after each return. The same Python invocation works for all stages because the loop's exit condition is "the lock file is gone".

**Tuning knobs (env-var compatible — pass via the CLI flags above).**

| Flag | Default | Effect |
|------|---------|--------|
| `--heartbeat-interval` | 60 | Seconds between heartbeat refresh + tick |
| `--stride-stale-seconds` | 900 | Wall-time of zero aggregate progress before STRIDE_STALE |
| `--stride-canary-seconds` | 180 | Wait after Phase 9 start before STRIDE_CANARY_TIMEOUT when no `.stride-*.json` exists |
| `--component-timeout-seconds` | 480 | Per-component idle limit (M3.6 #7); `0` disables |

### Wall-time + cost deadline watchdog (M3.4 / M11 + M9)

When the resolved config carries `max_wall_time_seconds` or `max_cost_usd` (set via `--max-wall-time DURATION` or `--max-cost USD`), the skill spawns a **second** background watchdog dedicated to deadline enforcement. Separate from the heartbeat loop because the action on trigger is destructive (kill the in-flight Agent dispatch via `TaskStop`).

**Behaviour:**
- Polls every 30 s.
- Wall-time: if `(now - ASSESSMENT_START_EPOCH) >= max_wall_time_seconds`, log a `DEADLINE_REACHED` warning and remove `.appsec-lock` (which signals the heartbeat watchdog to exit and triggers Stage cut-off detection on Stage 1 return).
- Cost: scans `.hook-events.log` for `cost=$X` lines, sums them per-session, compares to `max_cost_usd`. Same action on hit.
- The skill captures the deadline-watchdog `task_id` in `DEADLINE_TASK_ID` and stops it after Stage 4 (or last running stage) returns, mirroring the heartbeat lifecycle.

```bash
# Wall-time + cost deadline watchdog. Spawned only when a limit is set.
if [ -n "$MAX_WALL_TIME_SECONDS" ] || [ -n "$MAX_COST_USD" ]; then
  DEADLINE_LOOP_CMD='
    START='$ASSESSMENT_START_EPOCH'
    MAX_WT='${MAX_WALL_TIME_SECONDS:-0}'
    MAX_COST='${MAX_COST_USD:-0}'
    while [ -f "'"$OUTPUT_DIR/.appsec-lock"'" ]; do
      NOW=$(date +%s)
      ELAPSED=$((NOW - START))
      TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
      # Wall-time check
      if [ "$MAX_WT" -gt 0 ] && [ "$ELAPSED" -ge "$MAX_WT" ]; then
        echo "$TS  [--------]  WARN   skill-deadline  DEADLINE_REACHED  wall_time elapsed=${ELAPSED}s limit=${MAX_WT}s — aborting" \
            >> "'"$OUTPUT_DIR/.agent-run.log"'" 2>/dev/null || true
        rm -f "'"$OUTPUT_DIR/.appsec-lock"'" 2>/dev/null
        break
      fi
      # Cost check — use cost_running_total.py for accurate per-session
      # cumulative-snapshot delta math (the previous grep-summing
      # double-counted because SESSION_STOP lines are cumulative per
      # session, not incremental).
      if [ "$(echo "$MAX_COST > 0" | bc -l 2>/dev/null)" = "1" ] 2>/dev/null \
         || [ "${MAX_COST%%.*}" -gt 0 ] 2>/dev/null; then
        TOTAL_COST=$(python3 "'"$CLAUDE_PLUGIN_ROOT/scripts/cost_running_total.py"'" \
            "'"$OUTPUT_DIR"'" --format total-only 2>/dev/null)
        if [ -n "$TOTAL_COST" ] && [ "$(awk -v t=$TOTAL_COST -v m=$MAX_COST "BEGIN{print (t>=m)?1:0}")" = "1" ]; then
          echo "$TS  [--------]  WARN   skill-deadline  DEADLINE_REACHED  cost=$TOTAL_COST limit=$MAX_COST — aborting" \
              >> "'"$OUTPUT_DIR/.agent-run.log"'" 2>/dev/null || true
          rm -f "'"$OUTPUT_DIR/.appsec-lock"'" 2>/dev/null
          break
        fi
      fi
      sleep 30
    done
  '
fi
```

The skill issues this Bash with `run_in_background:true`, captures `DEADLINE_TASK_ID`, and `TaskStop`s it during the same Stage-end cleanup that handles the heartbeat watchdog.

When the deadline-watchdog removes `.appsec-lock`, the heartbeat watchdog's loop exits naturally (its predicate is `[ -f .appsec-lock ]`). The Agent dispatch keeps running until its next tool-use returns, at which point `acquire_lock.py --heartbeat` fails (no lock file) and the orchestrator MAY notice. In practice, the skill's post-dispatch cut-off detection picks this up via `! -f threat-model.md` and prints the deadline banner to the user.

**Configuration summary surfacing.** When `max_wall_time_seconds` or `max_cost_usd` is set, the configuration summary appends one line each:
```
  Deadline     : wall-time 30 min  /  cost $15.00
```

### Stage 1 Handoff Banner

**Compute the duration estimate ONCE** via `scripts/estimate_duration.py`. The helper aggregates every signal already available at this point (depth, mode, reasoning model, repo size, prior-run cache in `.appsec-cache/baseline.json`, resume checkpoint, dirty-set count for incremental) into a single per-stage breakdown plus a total wall-clock figure. Cost: one Bash invocation, one-line JSON output (~80 tokens), ~50–100 ms when `git ls-files` is available. See the script's docstring for the source-priority rules (`last_run_cache` > `resume_checkpoint` > `incremental_dirty_set` > `parametric`).

```bash
EST_JSON=$( python3 "$CLAUDE_PLUGIN_ROOT/scripts/estimate_duration.py" \
  --depth "$ASSESSMENT_DEPTH" \
  --mode "$( [ "$REBUILD" = "true" ] && echo rebuild
            || [ "$RESUME"  = "true" ] && echo resume
            || [ "$INCREMENTAL" = "true" ] && echo incremental
            || echo full )" \
  --reasoning-model "$REASONING_MODEL" \
  $( [ "$ARCHITECT_REVIEW" = "true" ] && echo "--architect-review" ) \
  $( [ "$SKIP_QA" = "true" ] && echo "--skip-qa" ) \
  --output-dir "$OUTPUT_DIR" \
  --repo-root "$REPO_ROOT" \
  --max-stride-components "$MAX_STRIDE_COMPONENTS" \
  --sec-change-count "${SEC_CHANGE_COUNT:-0}" \
  2>/dev/null )

EST_TOTAL=$(echo "$EST_JSON" | jq -r '.total_pretty // "~25 min"' 2>/dev/null)
EST_STAGE1=$(echo "$EST_JSON" | jq -r '.stage1_min // 25' 2>/dev/null)
EST_STAGE2=$(echo "$EST_JSON" | jq -r '.stage2_min // 8'  2>/dev/null)
EST_STAGE3=$(echo "$EST_JSON" | jq -r '.stage3_min // 7'  2>/dev/null)
EST_STAGE4=$(echo "$EST_JSON" | jq -r '.stage4_min // 4'  2>/dev/null)
EST_SOURCE=$(echo "$EST_JSON" | jq -r '.source // "parametric"' 2>/dev/null)
# Cache for use across stage handoffs (later banners read these env vars).
export EST_STAGE1 EST_STAGE2 EST_STAGE3 EST_STAGE4 EST_TOTAL EST_SOURCE

# Capture the run-start epoch so the post-stage-3 completion block can
# write the actual wall-clock back into .appsec-cache/baseline.json
# (last_run_seconds — used by the next run's estimator). This is the
# anchor point for all per-run timing in the skill.
ASSESSMENT_START_EPOCH=$(date +%s)
export ASSESSMENT_START_EPOCH

# Source badge — distinguishes a measured-from-prior-run estimate from
# the formula fallback so the user knows how trustworthy it is.
SOURCE_HINT=""
case "$EST_SOURCE" in
  last_run_cache)        SOURCE_HINT="from last run on this repo" ;;
  resume_checkpoint)     SOURCE_HINT="remaining after checkpoint"  ;;
  incremental_dirty_set) SOURCE_HINT="incremental, $SEC_CHANGE_COUNT/$MAX_STRIDE_COMPONENTS components dirty" ;;
  parametric)            SOURCE_HINT="parametric" ;;
esac
```

Then print a blank line and the Stage 1 handoff banner. When `VERBOSE_REPORT=true` is resolved, append a single hint line so the user knows where the extra output is going to appear:

```
▶ Stage 1/<total_stages> — Threat Model Orchestrator starting  (Stage 1: ~<EST_STAGE1> min, total: ~<EST_TOTAL> — <SOURCE_HINT>)
```

When `VERBOSE_REPORT=true`, add one extra line directly underneath (exactly this text, no other variants):
```
  ℹ Verbose mode ON — STEP_START/END, SCAN_START/END, and AGENT_INVOKE lines mirror live to stderr (~20 s poll cadence during Phase 9).
  ℹ Note: stderr is visible in headless `claude -p` mode and in the agent run log (.agent-run.log). Interactive UI may suppress it; tail the log file in a second terminal for live progress.
```

Where:
- `<total_stages>` is the number of pipeline stages that will actually run: `4` when both `ARCHITECT_REVIEW=true` and `SKIP_QA=false`, `3` when only QA, `2` when QA on and architect off, `1` when both off (rare). Always count Stage 1 (orchestrator) and Stage 2 (composition) as separate entries — composition runs in its own renderer session and is no longer Phase 11 of Stage 1.
- `<EST_STAGE1>` and `<EST_TOTAL>` are the integers extracted above; the helper guarantees a sensible fallback when any input is missing.
- `<SOURCE_HINT>` annotates how the estimate was produced. `parametric` means "first run on this repo, formula-only"; subsequent runs use the cached prior measurement and read `from last run on this repo`.

No other text — no explanatory prose, no duplicated mode description — belongs between these lines. The verbose-mode hints are the single exception, and only when the flag is actually on.

**M3.1 UX limitation:** The `Agent` tool dispatches Stage 1 in foreground and blocks the chat for the full duration (~25 min standard, ~40 min thorough). Phase 9 emits watcher progress; phases with no watcher still surface START/END lines in `.agent-run.log`.

### Stage Task List Bootstrap

Right after the handoff banner and **before** dispatching Stage 1, pre-create one `TaskCreate` task per stage. Stage 1 runs in the foreground (see "Dispatch" below), so its internal phases stream directly to the chat as the orchestrator executes tool calls — no per-phase task entries are needed. The stage tasks give the user a single top-level checklist to follow.

**Ordering invariant.** Task IDs are handed out monotonically by `TaskCreate`, so create the tasks in the exact order below.

```
TaskCreate subject="Pre-flight intermediate wipe"
           description="Cleared stale intermediate artifacts before Stage 1."
           activeForm="Wiping stale intermediate artifacts"
           # mark completed immediately after creation — the wipe already ran
```

| Condition | Task subject | activeForm |
|-----------|--------------|------------|
| always | `Stage 1 — Threat Model Orchestrator (Phases 1–10b)` | `Running threat model orchestrator` |
| always (M2.12) | `Stage 2 — Composition (Phase 11)` | `Rendering threat-model.md from fragments` |
| `SKIP_QA=false` AND `DRY_RUN=false` | `Stage 3 — QA Review` | `Running QA review` |
| `ARCHITECT_REVIEW=true` AND `DRY_RUN=false` | `Stage 4 — Architect Review` | `Running architect review` |
| always | `Completion summary + cleanup` | `Writing completion summary` |

**Stage 2 is now always pre-created (M2.12 — Sprint 3).** Previously only the recovery-dispatch path created it. The skill now splits Phase 11 into a separate `appsec-threat-renderer` session so Stage 1 stops cleanly after Phase 10b (`STAGE1_PHASE_LIMIT=10b`) and render-only work does not carry the full analyst prompt.

Immediately after creation, call `TaskUpdate` to mark `Pre-flight intermediate wipe` as `completed` (it ran before this section).

**Skip bootstrap entirely** when `DRY_RUN=true` — the dry-run summary prints at the end anyway. For any non-dry-run invocation, run the bootstrap regardless of depth / mode.

## Resume from Checkpoint

If `--resume` is passed, check for `$OUTPUT_DIR/.appsec-checkpoint`:

### Resume freshness gate (mandatory)

Before inspecting the checkpoint contents, run the resume-guard helper to refuse-to-proceed when the checkpoint is stale. A `--resume` against a checkpoint that was left behind by a hung or crashed prior run will drop the new orchestrator into the same broken state (the historic 55-minute-hang scenario); we would rather force an explicit `--full` / `--rebuild` / `/appsec-advisor:clean-state` than perpetuate the hang silently.

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/check_state.py" \
    "$OUTPUT_DIR" --resume-guard --max-age-seconds 900
GUARD_EXIT=$?
if [ "$GUARD_EXIT" = "3" ]; then
  # Helper already printed the user-facing reason. Drop the --resume
  # intent and abort before dispatching Stage 1.
  exit 3
fi
```

Behaviour:
- No checkpoint present → exit 0, resume proceeds (same as a fresh run).
- `status=completed` → exit 0, resume proceeds (the orchestrator will no-op and exit cleanly).
- `status=started` or `status=aborted` AND checkpoint mtime ≤ 15 min → exit 0, resume proceeds.
- `status=started` or `status=aborted` AND checkpoint mtime > 15 min → **exit 3**. The helper prints a remediation line pointing at `/appsec-advisor:clean-state` and `--full` / `--rebuild`. The skill does not dispatch Stage 1.

### Checkpoint inspection (only reached when guard passed)

1. Read the checkpoint file. It contains `phase=<N> status=<started|completed|aborted> timestamp=<ISO>`.
2. Inform the user what was found:
   ```
   Checkpoint found: Phase <N> (<status>) at <timestamp>
     Available intermediate files:
       .threat-modeling-context.md : <exists|missing>
       .recon-summary.md          : <exists|missing>
       .dep-scan.json             : <exists|missing>
       .stride-*.json             : <n files>
   ```
3. Ask the user whether to resume from the last completed phase or start fresh.
4. If resuming: pass `RESUME_FROM_PHASE=<N+1>` to the orchestrator (where N is the last completed phase). The orchestrator will skip completed phases and reuse existing intermediate files.
5. If starting fresh: proceed as normal (no `RESUME_FROM_PHASE`).

If no checkpoint exists and `--resume` was passed, inform the user and proceed with a fresh assessment.

## Stage 1 — Threat Model Orchestrator (Phases 1–10b)

**Architecture change in M2.12 / M3.8:** Stage 1 now stops cleanly after Phase 10b. Phase 11 (Finalization) is dispatched as a separate **Stage 2** renderer session so composition has its own budget and a smaller prompt.

Invoke the `appsec-advisor:appsec-threat-analyst` agent using `"Threat Model Orchestrator (Phases 1–10b)"` as the Agent tool `description`. The orchestrator handles Phases 1–10b internally (recon, context, architecture, STRIDE, merge, triage). Phase 11 is handled by Stage 2. Do **not** invoke any other agent from the skill level here.

### Dispatch

Stage 1 runs as a **foreground** Agent call. The orchestrator's tool calls stream directly to the chat so the user sees progress inline (Phase banners, sub-agent dispatches, file writes). No `Monitor` for the foreground Agent itself, no notification choreography — but a **background heartbeat watchdog** runs in parallel (see "Skill-layer heartbeat watchdog" above).

1. **Mark the stage task `in_progress`.** Call `TaskUpdate` on the `Stage 1 — Threat Model Orchestrator (Phases 1–10b)` task to set status `in_progress` (skip if the bootstrap was not run, i.e. `DRY_RUN=true`).

2. **Start the heartbeat watchdog (M3.4).** Issue the heartbeat-loop Bash command with `run_in_background: true` and capture the returned `task_id` in `HEARTBEAT_TASK_ID`. Skip when `DRY_RUN=true`. See the "Skill-layer heartbeat watchdog" section above for the exact command. The watchdog runs in parallel with the foreground Stage 1 dispatch and ensures `.appsec-lock` heartbeats fire every 60 s regardless of orchestrator activity.

3. **Dispatch the orchestrator.** Call the Agent tool with `description: "Threat Model Orchestrator (Phases 1–10b)"`. Do **not** set `run_in_background` — this is a blocking inline call. **Pass `STAGE1_PHASE_LIMIT=10b` in the prompt** (in addition to the normal configuration variables) so the agent stops cleanly after Phase 10b without entering Phase 11. All prompt contents and configuration variables are described in the "Passing configuration" subsection below.

4. **Stop the heartbeat watchdog.** Once the Agent tool returns (success, error, or cut-off), send one final heartbeat before stopping the watchdog so the lock reflects activity right up to the stage boundary:
   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/acquire_lock.py" \
       "$OUTPUT_DIR/.appsec-lock" \
       --heartbeat --phase=skill --step=stage-handoff \
       >/dev/null 2>&1 || true
   ```
   Then immediately call `TaskStop` with `HEARTBEAT_TASK_ID` to terminate the background heartbeat loop. Do this BEFORE the cut-off detection branches below — those branches may exit the skill, and a still-running watchdog would block the next user invocation. If `HEARTBEAT_TASK_ID` is unset (DRY_RUN, or watchdog spawn failed), skip both calls silently.

5. **On return, mark the stage task `completed`.** Call `TaskUpdate` to set the `Stage 1 — Threat Model Orchestrator (Phases 1–10b)` task to `completed`, then proceed to the **Phase-10b precondition gate** below.

6. **Record Stage 1 stats (M3.3).** The Agent tool's return notification carries a `<usage>` block with `total_tokens`, `tool_uses`, and `duration_ms`. Extract those values from the notification text (visible in the chat) and call `scripts/record_stage_stats.py` so they end up in `threat-model.md`'s `### Per-Stage Breakdown` table:

   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/record_stage_stats.py" "$OUTPUT_DIR" \
       --stage 1 \
       --name "Threat Model Orchestrator (Phases 1–10b)" \
       --agent appsec-advisor:appsec-threat-analyst \
       --model "$STRIDE_MODEL" \
       --duration-ms <duration_ms_from_usage> \
       --tool-uses <tool_uses_from_usage> \
       --tokens <total_tokens_from_usage>
   ```

   The helper is idempotent — re-running it for the same `--stage` is a no-op. Failure of this helper must NOT block the run; if extraction fails, skip the call and continue to the precondition gate.

### Phase-10b precondition gate (deterministic, skill-level)

Before dispatching Stage 2, verify that Stage 1 produced the four mandatory Phase-1-10b outputs:

```bash
PHASE10B_OK=true
for required in .recon-summary.md .threats-merged.json .triage-flags.json threat-model.yaml; do
  if [ ! -f "$OUTPUT_DIR/$required" ]; then
    PHASE10B_OK=false
    echo "  ✗ Stage 1 did not produce $required" >&2
  fi
done
```

If `PHASE10B_OK=false`, fall through to the existing cut-off detection (below) — Stage 1 died before completing its scope and Stage 2 cannot proceed. If `PHASE10B_OK=true`, continue to Stage 2 dispatch.

## Stage 2 — Composition (Phase 11) (M2.12 — Sprint 3)

Dispatched **always** after a successful Stage 1 (`PHASE10B_OK=true`), Stage 2 runs Phase 11 (Finalization) with its own renderer budget. This is the architectural fix for Phase-11 budget exhaustion.

### Pre-dispatch — pre-generate structural fragments

Before invoking the Stage 2 agent, run the deterministic pre-generator for the 6 structural fragments. The script is idempotent — fragments already on disk are not touched, so this is safe to run regardless of which path led here (always-dispatch, recovery dispatch, REPAIR_MODE retry).

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/pregenerate_fragments.py" "$OUTPUT_DIR" || true
```

Failure here is **non-fatal** (`|| true`) — the hard gate that runs after Stage 2 will catch any genuine fragment shortage regardless of who was supposed to write it.

**Walkthroughs opt-out (`--no-walkthroughs`).** When `SKIP_ATTACK_WALKTHROUGHS=true` (resolved in `.skill-config.json` as `skip_attack_walkthroughs`), pre-write a stub `.fragments/attack-walkthroughs.md` with chain-overview-only content. The agent's idempotency rule (never overwrite an existing fragment) then makes Stage 2 skip the LLM authoring entirely, saving ~1-2 min:

```bash
SKIP_WALK=$(python3 -c "import json,sys; d=json.load(open('$OUTPUT_DIR/.skill-config.json')); print(str(d.get('skip_attack_walkthroughs', False)).lower())" 2>/dev/null || echo false)
if [ "$SKIP_WALK" = "true" ] && [ ! -f "$OUTPUT_DIR/.fragments/attack-walkthroughs.md" ]; then
  mkdir -p "$OUTPUT_DIR/.fragments"
  cat > "$OUTPUT_DIR/.fragments/attack-walkthroughs.md" <<'WALKEOF'
## 3. Attack Walkthroughs

> ⓘ **Detailed walkthroughs skipped** (`--no-walkthroughs`). Per-finding sequence diagrams are omitted for this run. Re-run without the flag to author them. The chain overview below remains intact for the high-level attack picture.

### 3.1 Attack Chain Overview

_Per-finding sequenceDiagram blocks were not authored at this configuration._
_See §8 Threat Register for individual findings and §9 Mitigation Register for the per-finding remediation steps._
WALKEOF
fi
```

### Dispatch

1. **Mark the stage task `in_progress`.** Call `TaskUpdate` on the `Stage 2 — Composition (Phase 11)` task to set status `in_progress` (skip when `DRY_RUN=true`).

2. **Restart the heartbeat watchdog (M3.4 / M3.6).** Spawn a fresh `python3 scripts/skill_watchdog.py "$OUTPUT_DIR" --plugin-root "$CLAUDE_PLUGIN_ROOT"` invocation with `run_in_background:true` (same flags as Stage 1 — see "Skill-layer heartbeat watchdog" above). Capture the new `task_id` in `HEARTBEAT_TASK_ID` (overwriting the Stage 1 value, which was already stopped). Skip when `DRY_RUN=true`.

3. **Dispatch the agent.** Call the `appsec-advisor:appsec-threat-renderer` Agent tool with `description: "Threat Model Renderer (Stage 2)"`. Pass all original configuration variables verbatim (REPO_ROOT, OUTPUT_DIR, WRITE_YAML, WRITE_SARIF, ASSESSMENT_DEPTH, model selections, VERBOSE_REPORT, INVOCATION_ARGS, etc.) so the renderer has the same context the orchestrator had. The renderer authors the 2 LLM-driven JSON fragments (`ms-verdict.json`, `ms-architecture-assessment.json`) plus optionally `attack-walkthroughs.md` and `security-posture-attack-paths.json`, then invokes `compose_threat_model.py --strict`, `render_completion_summary.py --patch-placeholders --no-print`, and `qa_checks.py all`.

   **Stage-2 dispatch guard (G-9).** The Agent call is synchronous and blocks the skill. In production the deadline-watchdog (see "Wall-time + cost deadline watchdog" above) provides the ultimate ceiling via `.appsec-lock` removal. For runs without a `--max-wall-time` limit, the wall-time upper bound is implicitly the Claude Code harness session timeout. No additional watcher is needed here — Stage 2 returns when complete or exhausted. If Stage 2 does not produce `threat-model.md` by the time the Agent call returns, the existing post-Stage-2 `STAGE11_CUTOFF` detection below handles recovery.

4. **Stop the heartbeat watchdog.** Once the Agent tool returns, send one final heartbeat before stopping the loop:
   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/acquire_lock.py" \
       "$OUTPUT_DIR/.appsec-lock" \
       --heartbeat --phase=skill --step=stage-handoff \
       >/dev/null 2>&1 || true
   ```
   Then call `TaskStop` with `HEARTBEAT_TASK_ID`. Skip both calls silently if `HEARTBEAT_TASK_ID` is unset.

5. **On return, mark the stage task `completed`.** Call `TaskUpdate` to set the `Stage 2 — Composition (Phase 11)` task to `completed`. Then proceed to the post-Stage-2 flow: pre-generation backstop + hard gate + Stage 3.

6. **Record Stage 2 stats (M3.3).** Same mechanism as Stage 1 — extract `<usage>` and call the helper:

   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/record_stage_stats.py" "$OUTPUT_DIR" \
       --stage 2 \
       --name "Composition (Phase 11)" \
      --agent appsec-advisor:appsec-threat-renderer \
       --model "$STRIDE_MODEL" \
       --duration-ms <duration_ms_from_usage> \
       --tool-uses <tool_uses_from_usage> \
       --tokens <total_tokens_from_usage>
   ```

### Handoff banner

Before dispatching Stage 2, print:

```
▶ Stage 2 — Composition (Phase 11) starting  (expect ~<EST_STAGE2> min, model: sonnet, renderer budget)
  ⟶ Authoring 2 LLM fragments + invoking compose_threat_model.py
  ⟶ 7 structural fragments pre-generated deterministically (idempotent)
```

### Post-dispatch — fragment-pipeline audit

After Stage 2 returns, run the deterministic fragment pre-generator one more time as a backstop (idempotent), then immediately run the hard gate. The combination guarantees that:

- If Stage 2 authored the 2 LLM fragments correctly: pre-generator no-ops, hard gate passes.
- If Stage 2 skipped a structural fragment: pre-generator fills it in, hard gate still passes (Sprint-2 safety net).
- If Stage 2 inline-shortcut bypassed the renderer entirely: hard gate trips with exit 2.

This is where the existing `pregenerate_fragments.py || true` + `check_inline_shortcut.py || { exit }` blocks live (Sprint-2 wiring above). They run identically here — the only addition vs. the pre-Sprint-3 flow is that the Stage-2 dispatch sits between Stage 1 and the gates.

### Handling turn-budget cut-offs

Thorough-depth runs with 8 STRIDE analyzers (MAX_STRIDE_COMPONENTS=8) routinely touch the Claude Code agent turn budget (observed at ~90 tool calls per agent session in `claude -p` headless mode). When the budget is hit, the Agent call returns control to the skill *before* Phase 11 finalization runs, typically mid-Phase-9 or mid-Phase-10. Two concrete symptoms:

1. The agent's final text ends with something like `"All 8 STRIDE files ready. Proceeding to merge."` without a closing `ASSESSMENT_END` log entry.
2. `$OUTPUT_DIR/threat-model.md` does NOT exist after the Agent call returns — but `$OUTPUT_DIR/.stride-*.json` and `$OUTPUT_DIR/.recon-summary.md` are present.

**Detection (mandatory).** Immediately after the Stage 1 Agent call returns, the skill MUST check whether `threat-model.md` exists:

```bash
if [ ! -f "$OUTPUT_DIR/threat-model.md" ]; then
  # Stage 1 returned without producing the deliverable. Classify the cut-off
  # by inspecting on-disk state — the three branches below correspond to
  # increasingly-late deaths and have different recovery paths.
  STRIDE_COUNT=$(ls "$OUTPUT_DIR"/.stride-*.json 2>/dev/null | wc -l)
  FRAGMENT_COUNT=$(ls "$OUTPUT_DIR"/.fragments/*.{md,json} 2>/dev/null | wc -l)
  if [ "$FRAGMENT_COUNT" -ge 3 ]; then
    # Late death: Phase 11 wrote some fragments but never reached compose.
    # The 2026-04-25 juice-shop crash was this case — 5/12 fragments, no
    # threat-model.md, no yaml. Resume target is the composition step, not
    # Phase 9. Tracked separately so the recovery path can dispatch Stage 2
    # (composition) instead of re-running STRIDE merge.
    STAGE11_CUTOFF=true
  elif [ "$STRIDE_COUNT" -ge 1 ]; then
    STAGE1_CUTOFF=true
  else
    STAGE1_CUTOFF_NO_STRIDE=true
  fi
fi
```

**Late-phase crash (Phase 11 partial) — Stage 2 auto-dispatch.** The `STAGE11_CUTOFF=true` branch fires when at least three fragments are present in `.fragments/` but `threat-model.md` is missing — meaning the orchestrator entered Phase 11, wrote part of the fragment set, then died before `compose_threat_model.py` ran. This is the 2026-04-25 juice-shop case: 5 of 12 fragments written, no yaml, no composed Markdown. The recovery is **not** the same as `STAGE1_CUTOFF` (which assumes Phase 9 still has merge work to do); here the threats are already merged and the only missing work is composition.

**Stage 2 — Composition (recovery dispatch).** Instead of exiting with a banner and forcing the user to manually re-invoke `--resume`, the skill dispatches `appsec-threat-renderer` with a Phase-11-only scope and a fresh turn budget. This keeps the large Stage-1 analyst prompt out of render-only recovery. Stage 2 runs **once** (no retry counter — if it fails, fall through to the banner-and-exit path so we don't burn tokens recursively).

```bash
if [ "$STAGE11_CUTOFF" = "true" ] && [ "${STAGE1B_DISPATCHED:-false}" = "false" ]; then
  STAGE1B_DISPATCHED=true
  printf '\n' >&2
  printf '▶ Stage 2 — Composition (Phase 11 recovery)  starting…\n' >&2
  printf '  Reason: Stage 1 wrote %s fragments but did not reach compose.\n' "$FRAGMENT_COUNT" >&2
  printf '  This is a fresh-budget Phase-11-only dispatch.\n\n' >&2

  # Dispatch via appsec-advisor:appsec-threat-renderer with description
  # "Threat Model Renderer (Stage 2)"
  # and a prompt that:
  #   1. Sets RESUME_FROM_PHASE=11 so the agent skips Phases 1–10b entirely.
  #   2. Lists the existing fragments under .fragments/ and instructs the agent
  #      to author only the missing ones (cross-reference against the
  #      sections-contract.yaml required-fragments list).
  #   3. Reuses .threats-merged.json + .triage-flags.json verbatim — no merge
  #      or triage re-run.
  #   4. Passes all original configuration vars (REPO_ROOT, OUTPUT_DIR,
  #      WRITE_YAML, WRITE_SARIF, ASSESSMENT_DEPTH, models, etc.) identical
  #      to the Stage 1 call so the rendered output matches.
  # The Agent tool returns when Stage 2 completes (success, error, or
  # cut-off). After it returns, the skill re-runs the same threat-model.md
  # existence check that gated the STAGE11_CUTOFF detection above.

  # After Stage 2 returns:
  if [ -f "$OUTPUT_DIR/threat-model.md" ]; then
    # Stage 2 succeeded — clear the cutoff flag and continue into Stage 3.
    STAGE11_CUTOFF=false
    printf '✓ Stage 2 complete — threat-model.md produced. Continuing to Stage 3.\n\n' >&2
  else
    # Stage 2 also failed — re-enter the banner-and-exit path below by
    # re-evaluating fragment count (it may have advanced).
    FRAGMENT_COUNT=$(ls "$OUTPUT_DIR"/.fragments/*.{md,json} 2>/dev/null | wc -l)
    printf '✗ Stage 2 also did not produce threat-model.md (fragments now: %s).\n' "$FRAGMENT_COUNT" >&2
    printf '  Falling through to manual-recovery banner.\n\n' >&2
    # STAGE11_CUTOFF stays true → banner block below fires.
  fi
fi

if [ "$STAGE11_CUTOFF" = "true" ]; then
  CKPT_PHASE="?"
  CKPT_STATUS="?"
  CKPT_STEP=""
  if [ -f "$OUTPUT_DIR/.appsec-checkpoint" ]; then
    CKPT_LINE=$(head -n1 "$OUTPUT_DIR/.appsec-checkpoint" 2>/dev/null || true)
    CKPT_PHASE=$(printf '%s' "$CKPT_LINE" | sed -n 's/.*phase=\([^ ]*\).*/\1/p')
    CKPT_STATUS=$(printf '%s' "$CKPT_LINE" | sed -n 's/.*status=\([^ ]*\).*/\1/p')
    CKPT_STEP=$(printf '%s' "$CKPT_LINE" | sed -n 's/.*step=\([^ ]*\).*/\1/p')
    [ -z "$CKPT_PHASE" ] && CKPT_PHASE="?"
    [ -z "$CKPT_STATUS" ] && CKPT_STATUS="?"
  fi
  FRAG_LIST=$(ls "$OUTPUT_DIR"/.fragments/ 2>/dev/null | sort | tr '\n' ' ')
  THREATS_MERGED="missing"; [ -f "$OUTPUT_DIR/.threats-merged.json" ] && THREATS_MERGED="present"
  TRIAGE_FLAGS="missing"; [ -f "$OUTPUT_DIR/.triage-flags.json" ] && TRIAGE_FLAGS="present"
  cat <<EOF >&2

══════════════════════════════════════════════════════════════
  ASSESSMENT INCOMPLETE — Phase 11 cut off mid-composition
══════════════════════════════════════════════════════════════

  Last checkpoint:        phase=${CKPT_PHASE} status=${CKPT_STATUS}${CKPT_STEP:+ step=${CKPT_STEP}}
  Fragments on disk:      ${FRAGMENT_COUNT} files in .fragments/
  Merged threats:         ${THREATS_MERGED}
  Triage flags:           ${TRIAGE_FLAGS}
  threat-model.md:        not produced
  threat-model.yaml:      not produced

  Phase 11 (Finalization) entered but did not run compose_threat_model.py.
  Likely cause: orchestrator turn-budget exhausted while writing fragments —
  this happens most often on long --resume runs that have to plough through
  Phases 3–10 again before reaching composition. The threats are merged and
  partially rendered; only the final compose step is missing.

  Recover with:
      /appsec-advisor:create-threat-model --resume
        (reuses .threats-merged.json + existing fragments, completes Phase 11)

  Start over with:
      /appsec-advisor:create-threat-model --full
EOF
  printf '\n  Fragments present: %s\n' "$FRAG_LIST" >&2
  printf '══════════════════════════════════════════════════════════════\n\n' >&2
  rm -f "$OUTPUT_DIR/.appsec-lock"
  exit 2
fi
```

The lock is released so the next `--resume` invocation isn't blocked. `.fragments/`, `.threats-merged.json`, `.triage-flags.json`, and the checkpoint are preserved so the resume run can pick them up.

**Early-phase crash (no STRIDE files).** The `STAGE1_CUTOFF_NO_STRIDE=true` branch fires when the orchestrator died before reaching Phase 9 — typically inside Phase 1, 2, 3, 7, or 8. This is the case the historic 2026-04-25 silent-death bug fell into: the parent Claude Code session ended mid-Phase-3 without a `Stop` hook, leaving `.threat-modeling-context.md` and `.recon-summary.md` on disk but no `.stride-*.json` and no `threat-model.md`. Auto-resume is **not** safe here because the resume path at "Recovery path" below assumes Phase 9 has produced stride files; replaying Phases 3–8 from a partial state has no idempotency guarantee. The skill MUST surface the situation explicitly and exit cleanly so the user can choose `--resume` (continue from the checkpoint) or `--full` / `--rebuild` (start over):

```bash
if [ "$STAGE1_CUTOFF_NO_STRIDE" = "true" ]; then
  CKPT_PHASE="?"
  CKPT_STATUS="?"
  if [ -f "$OUTPUT_DIR/.appsec-checkpoint" ]; then
    CKPT_LINE=$(head -n1 "$OUTPUT_DIR/.appsec-checkpoint" 2>/dev/null || true)
    CKPT_PHASE=$(printf '%s' "$CKPT_LINE" | sed -n 's/.*phase=\([^ ]*\).*/\1/p')
    CKPT_STATUS=$(printf '%s' "$CKPT_LINE" | sed -n 's/.*status=\([^ ]*\).*/\1/p')
    [ -z "$CKPT_PHASE" ] && CKPT_PHASE="?"
    [ -z "$CKPT_STATUS" ] && CKPT_STATUS="?"
  fi
  HB_AGE_LABEL="unknown"
  if [ -f "$OUTPUT_DIR/.appsec-lock" ]; then
    HB_TS=$(awk 'NR==2 {print $1; exit}' "$OUTPUT_DIR/.appsec-lock" 2>/dev/null || true)
    if [ -n "$HB_TS" ]; then
      NOW=$(date +%s)
      HB_AGE_LABEL="$((NOW - HB_TS))s"
    fi
  fi
  CTX_MARK="missing"; [ -f "$OUTPUT_DIR/.threat-modeling-context.md" ] && CTX_MARK="present"
  RECON_MARK="missing"; [ -f "$OUTPUT_DIR/.recon-summary.md" ] && RECON_MARK="present"
  cat <<EOF >&2

══════════════════════════════════════════════════════════════
  ASSESSMENT INCOMPLETE — orchestrator died before Phase 9
══════════════════════════════════════════════════════════════

  Last checkpoint:       phase=${CKPT_PHASE} status=${CKPT_STATUS}
  Heartbeat age:         ${HB_AGE_LABEL}
  Stride files:          0 (Phase 9 never started)
  Recon summary:         ${RECON_MARK}
  Context resolution:    ${CTX_MARK}

  The orchestrator session ended mid-pipeline without producing
  a threat model. No STRIDE analysis ran. This is typically caused
  by the parent Claude Code session being killed (window closed,
  OOM, network drop) before the Stop hook could fire.

  Recover with:
      /appsec-advisor:create-threat-model --resume
        (continues from Phase ${CKPT_PHASE}, reuses recon + context)

  Start over with:
      /appsec-advisor:create-threat-model --full
══════════════════════════════════════════════════════════════
EOF
  # Release the lock so the next --resume invocation isn't blocked by
  # acquire_lock.py's stale-mtime window.
  rm -f "$OUTPUT_DIR/.appsec-lock"
  exit 2
fi
```

The lock file is removed (but `.appsec-checkpoint`, `.threat-modeling-context.md`, and `.recon-summary.md` are preserved) so the user's follow-up `--resume` invocation can read them. Do **not** print the regular Completion Summary in this branch — the run did not produce a deliverable.

**Resume budget (hard cap).** The skill MUST track how many resume dispatches it has already fired for this invocation using a counter file `$OUTPUT_DIR/.stage1-resume-count`:

- Before the **first** Stage 1 dispatch, ensure the file is absent (or contains `0`). Fresh runs (`--full`, `--rebuild`) always start at 0.
- Each time a `STAGE1_CUTOFF=true` path spawns a resume Agent, increment the counter and persist it (`echo "$((count + 1))" > "$OUTPUT_DIR/.stage1-resume-count"`) **before** dispatching the resume.
- The default cap is `MAX_STAGE1_RESUMES=1` (one resume per invocation). Override with the `--max-resumes <N>` flag — the skill reads `MAX_STAGE1_RESUMES` from the resolved config; if unset, default to `1`.
- When the counter has reached the cap and `STAGE1_CUTOFF=true` fires again, do **not** dispatch another resume. Instead, treat this as a hard abort (see "Exhausted resumes" below) — this prevents rare recursive cut-off→resume→cut-off chains from burning tokens indefinitely.
- On successful completion (`threat-model.md` exists), the counter file is cleaned up by `runtime_cleanup.py` along with the other transient artifacts.

**Recovery path.** If `STAGE1_CUTOFF=true` **and** the resume counter is below `MAX_STAGE1_RESUMES`, spawn another `appsec-advisor:appsec-threat-analyst` Agent call (fresh turn budget) with the description `"Threat Model Orchestrator (resume)"` and a prompt that:

1. Tells the agent to skip Phases 1–8 entirely because their outputs are on disk (`.recon-summary.md`, `.threat-modeling-context.md`).
2. Lists every `.stride-<component>.json` file under `$OUTPUT_DIR` and instructs the agent not to re-dispatch STRIDE analyzers.
3. Passes all original configuration variables **identical** to the first call.
4. Sets `RESUME_FROM_PHASE=9-merge` so the agent knows to start from the merge step.

The `SendMessage` tool (which would reuse the prior agent's context) is **not** available in every Claude Code configuration, so the resume path MUST use a fresh Agent call — not `SendMessage`. The duplicate context upload is the cost of being portable across headless/IDE/web clients.

**Exhausted resumes.** When `STAGE1_CUTOFF=true` fires and the counter has already reached `MAX_STAGE1_RESUMES`, the skill MUST abort Stage 1 cleanly:

1. Release the `.appsec-lock` so future `--resume` invocations aren't blocked.
2. Print a non-error banner explaining the situation, including the resume count, the intermediate files that survived on disk (`.stride-*.json`, `.recon-summary.md`, etc.), and the exact command to continue manually (`/appsec-advisor:create-threat-model --resume`).
3. Skip Stage 3 and Stage 4 entirely — there is no `threat-model.md` to review.
4. Exit with code 2 (same as other non-fatal Stage 1 failures). This signals automation that the run did not produce a deliverable without claiming an unrecoverable error.

**Not an error (single cut-off).** A single cut-off that resolves via resume is not a skill-level failure and MUST NOT print an error banner. Cut-and-resume is the expected operational mode for thorough runs until Claude Code's per-agent turn budget is raised.

### Passing configuration

Pass along any arguments the user provided as additional focus areas or scope constraints (e.g., a specific subdirectory, component name, or "focus on auth"). If no arguments were given, analyze the entire repository.

Use the `REPO_ROOT` and `OUTPUT_DIR` values resolved in the Path Resolution section above.

Pass the following variables to the agent prompt:
- `CLAUDE_PLUGIN_ROOT=<absolute plugin path>` (resolved in the "Prerequisites" section above — **always pass this explicitly**; do not rely on the variable being inherited by the sub-session, because some harness/headless configurations drop it)
- `REPO_ROOT=<absolute repo path>`
- `OUTPUT_DIR=<absolute output path>`
- `WRITE_YAML=<true|false>`
- `WRITE_SARIF=<true|false>`
- `WRITE_PENTEST_TASKS=<true|false>`
- `PENTEST_FORMAT=<generic|strix>` (only if `WRITE_PENTEST_TASKS=true`)
- `PENTEST_TARGET_URL=<url>` (only if `--pentest-target` was provided)
- `CHECK_REQUIREMENTS=<true|false>`
- `REQUIREMENTS_URL_OVERRIDE=<url>` (only if `--requirements <url>` was provided)
- `INCREMENTAL=<true|false>`
- `REBUILD=<true|false>` (when `true`, Phase 11 writes a `note: "full rebuild — prior threat model and changelog history were discarded on user request (--rebuild)"` into the fresh `v1` changelog entry — the pre-flight wipe already removed the baseline so the orchestrator itself runs as if first-ever)
- `WITH_SCA=<true|false>`
- `KEEP_RUNTIME_FILES=<true|false>` (default `false`; when `true` Phase 11 skips cleanup of transient artifacts — useful for debugging)
- `SCAN_MANIFEST=<true|false>` (default `false`; when `true` the recon-scanner writes every processed file path to `$OUTPUT_DIR/.scan-manifest.txt`)
- `STRIDE_MODEL=<model>` (from `--reasoning-model` resolution; overridden by `--stride-model` or `$APPSEC_STRIDE_MODEL` when set)
- `TRIAGE_MODEL=<model>` (from `--reasoning-model` resolution; overridden by `$APPSEC_TRIAGE_MODEL` when set)
- `MERGER_MODEL=<model>` (from `--reasoning-model` resolution; overridden by `$APPSEC_MERGER_MODEL` when set)
- `CONTEXT_RESOLVER_MODEL=<model>` (haiku-economy tier; default `claude-sonnet-4-6`. Read by Phase 1 dispatch in `phase-group-recon.md`. Override via `$APPSEC_CONTEXT_RESOLVER_MODEL`.)
- `RECON_SCANNER_MODEL=<model>` (haiku-economy tier; default `claude-sonnet-4-6`. Read by Phase 2 dispatch in `phase-group-recon.md`. Override via `$APPSEC_RECON_SCANNER_MODEL`.)
- `QA_ROUTINE_MODEL=<model>` (haiku-economy tier QA-split; default `claude-sonnet-4-6`. Used at the skill level for routine repair iterations. Override via `$APPSEC_QA_ROUTINE_MODEL`.)
- `QA_CONTENT_MODEL=<model>` (haiku-economy tier QA-split; default `claude-sonnet-4-6`. Used for content-class repair iterations. Override via `$APPSEC_QA_CONTENT_MODEL`.)
- `CONFIG_SCANNER_MODEL=<model>` (haiku-economy tier; default `claude-sonnet-4-6`. Used by Phase 2.5 config-scanner dispatch when wired up. Override via `$APPSEC_CONFIG_SCANNER_MODEL`.)
- `ORCHESTRATOR_MODEL=<model>` (haiku-economy tier; always `claude-sonnet-4-6` per matrix — informational only.)
- `STRIDE_PROFILE_JSON=<inline-json>` (depth-reduction profile; default `{"stride_profile_label":"full"}`. Read by Phase 9 dispatch in `phase-group-threats.md` and forwarded to each STRIDE analyzer in Group A. Quick + haiku-economy contains the A-F reduction flags.)
- `REASONING_LABEL=<resolved summary>`
- `RESUME_FROM_PHASE=<N>` (only if resuming from checkpoint)
- `STAGE1_PHASE_LIMIT=10b` (M2.12 — Sprint 3, only set on Stage 1 dispatch — tells the orchestrator to stop cleanly after Phase 10b without entering Phase 11. **Mutually exclusive with `RENDER_ONLY=true`.**)
- `RENDER_ONLY=true` (legacy compatibility signal for older Stage-2 recovery prompts; normal Stage 2 dispatch now uses `appsec-threat-renderer`. **Mutually exclusive with `STAGE1_PHASE_LIMIT=10b`.**)
- `ENRICH_ARCH_FRAGMENTS=<true|false>` (M3.3 / D2 — only set on Stage 2 dispatch. When `true`, the agent overwrites `architecture-diagrams.md` and `security-architecture.md` with LLM-authored richer versions instead of using the deterministic pre-generator output. On by default at standard/thorough; off by default at quick (since 2026-05); force on at any depth via `--enrich-arch`, force off via `--no-enrich-arch`.)
- `SKIP_ATTACK_PATHS_AUTHORING=<true|false>` (only set on Stage 2 dispatch. When `true`, the agent skips authoring `security-posture-attack-paths.json` and lets the renderer's deterministic CWE→class fallback in `compose_threat_model.py:_derive_attack_paths_fallback` produce the fragment. On at quick depth (since 2026-05) to save ~1-3 min in Stage 2; off at standard/thorough where the LLM-authored architectural-root-causes and attack-chain links justify the authoring cost.)
- `SKIP_ATTACK_WALKTHROUGHS=<true|false>` (only set on Stage 2 dispatch. When `true` (set by `--no-walkthroughs`), the agent skips authoring `attack-walkthroughs.md`; the composer renders §3 with the chain-overview-only fallback (no per-finding sequenceDiagram blocks). Saves ~1-2 min in Stage 2.)
- `ASSESSMENT_DEPTH=<quick|standard|thorough>`
- `MAX_STRIDE_COMPONENTS=<3|5|8>`
- `STRIDE_TURNS_SIMPLE=<10|15|20>`
- `STRIDE_TURNS_MODERATE=<15|22|28>`
- `STRIDE_TURNS_COMPLEX=<20|31|35>`
- `DIAGRAM_DEPTH=<minimal|standard|extended>`
- `QA_DEPTH=<core|full|extended>`
- `VERBOSE_REPORT=<true|false>`
- `INVOCATION_ARGS=<raw user arguments>` (captured before argument parsing — empty string if no arguments were provided)
- `PLUGIN_VERSION=<semver>` (from `plugin_meta.py get plugin_version`)
- `ANALYSIS_VERSION=<int>` (from `plugin_meta.py get analysis_version`)
- `COMPAT_LABEL=<equal|older-compatible|incompatible|legacy|unknown>` (only when `INCREMENTAL=true`; set by the Plugin Version Compatibility Gate — the orchestrator uses this to decide whether to render the baseline-older callout in the report header and to set `meta.recommend_full_rerun` in yaml)
- `APPSEC_TRIAGE_DETERMINISTIC=1` (M3.1 — when set, Phase 10b Step 6 invokes `scripts/triage_compute_ranking.py` instead of running an LLM agent. Default: enabled. Override with `APPSEC_TRIAGE_DETERMINISTIC=0` to fall back to LLM Step 6 for debugging or when the deterministic implementation is suspected of producing bad rankings; the run will still complete but Phase 10b will take ~6 min instead of ~2 s.)

## Incremental Mode

When `INCREMENTAL=true`, the orchestrator performs a **delta analysis** instead of a full scan:

1. Read the **baseline git SHA** in this order: `$APPSEC_BASELINE_REF` env var (CI override) → `meta.git.commit_sha` from `$OUTPUT_DIR/threat-model.yaml`. If neither is available, the orchestrator aborts with exit 2.
2. Before Phase 2, run `git -C "$REPO_ROOT" diff --name-only "$BASELINE_SHA"..HEAD` to identify changed files, plus `git diff --name-only` for uncommitted changes.
3. Map changed files to components identified in the previous threat model's `components[]` (paths globs).
4. **Phase 2 recon** may be skipped entirely if the recon fingerprint in `.appsec-cache/baseline.json` matches the current state (manifests, Dockerfiles, IaC files unchanged).
5. **Phase 9** dispatches STRIDE analyzers **only for components with changed paths**. Unchanged components carry their threats forward from `.stride-<id>.json` with stable T-IDs.
6. The existing threat model is **updated in place** — not overwritten. A new entry is appended to the `changelog[]` block in `threat-model.yaml` and rendered into the `Changelog` section of `threat-model.md`, listing added/changed/resolved threats, re-analyzed components, and carried-forward components. Changes are **not** logged only to the console — they are persisted in the threat model itself.
7. `DRY_RUN` is handled at the skill level by redirecting `OUTPUT_DIR` to a temp directory and forcing `INCREMENTAL=false`. The orchestrator never receives `DRY_RUN` — incremental mode and dry-run are mutually exclusive.

This significantly reduces token consumption for incremental security reviews after small code changes. Baseline detection happens in the skill's Incremental Mode Resolution section above — a hard abort is raised there if `--incremental` is passed without an existing threat model, so by the time this section runs the baseline is guaranteed to exist.

When `CHECK_REQUIREMENTS=true` and no requirements YAML is available, the context-resolver aborts with an error. The error behavior depends on the source:
- **`REQUIREMENTS_URL_OVERRIDE` set** (from `--requirements <url>`) — the override URL must be reachable; no cache fallback (abort immediately on fetch failure)
- **`--requirements` (without URL) or config `enabled: true`** — tries the configured URL, falls back to plugin cache; aborts only if both are unavailable

## Dry-Run Mode

`DRY_RUN=true` runs the **full assessment pipeline** (Phases 1–11) but writes all output to a temporary directory (`/tmp/appsec-dry-run-XXXXXX`) instead of the repository. After the orchestrator completes, the skill extracts the Management Summary and key metrics from the temporary `threat-model.md`, prints them to the console, and cleans up the temp directory. **No files are written to the repository.**

Key behaviors:
- `INCREMENTAL` is forced to `false` — dry-run always performs a full analysis
- `OUTPUT_DIR` is redirected to `/tmp` (see Path Resolution)
- The orchestrator runs all phases normally — it does not know it's a dry-run
- `DRY_RUN` is **not** passed to the orchestrator (it receives the temp `OUTPUT_DIR` and runs as usual)
- Stage 3 (QA reviewer) is skipped — the output is transient and does not need QA
- After the console summary, the temp directory is deleted: `rm -rf "$OUTPUT_DIR"`

## Stage 3 — QA Review

After the orchestrator completes (and `DRY_RUN` is `false`), verify that `$OUTPUT_DIR/threat-model.md` exists. Before dispatching the QA-reviewer agent the skill runs two **deterministic pre-agent gates** so the agent's turn budget is spent on qualitative checks rather than on finding drift that a Python script can detect in 200 ms.

### Post-Stage-1 fragment precondition (deterministic, skill-level)

The first thing the skill does after Stage 1 returns is check whether the orchestrator actually went through the fragment pipeline. This is the mechanical enforcement of the policy "direct `Write` of `threat-model.md` is forbidden" — without it the policy is just a sentence in an agent prompt that the LLM can ignore under turn pressure.

**Pre-generation of structural fragments (M2.11 — Sprint 2).**

Before running the hard gate, run ``pregenerate_fragments.py`` so the 6 deterministic structural fragments (system-overview, architecture-diagrams, assets, attack-surface, security-architecture, out-of-scope) are present even when the orchestrator skipped them. The script is **idempotent** — fragments authored by the LLM during Phase 11 take precedence and are never overwritten. This means the orchestrator only needs to author 2 LLM-driven JSON fragments (ms-verdict.json + ms-architecture-assessment.json) plus the qualitative attack-walkthroughs.md to satisfy REQUIRED_FRAGMENTS, dramatically reducing Phase-11 turn pressure. (`use-cases.md` was retired 2026-05 — §6 numbering gap intentional.)

```bash
# Generate the 7 structural fragments deterministically from threat-model.yaml.
# Idempotent: never overwrites a fragment the LLM already authored.
# Failure here is non-fatal — the hard gate below will catch any genuine
# missing fragment regardless of who was supposed to write it.
python3 "$CLAUDE_PLUGIN_ROOT/scripts/pregenerate_fragments.py" \
    "$OUTPUT_DIR" || true
```

**Hard-gate enforcement (M2.10 — promoted from Bash to standalone script).**

The detection logic lives in ``scripts/check_inline_shortcut.py`` so the gate is mechanical and cannot be "softly" interpreted by the LLM that executes this skill body. Indicators A1, A2, B, C are checked there; ``qa_checks.py fragments`` is OR-merged for its independent REQUIRED_FRAGMENTS list. The script prints the full banner to stderr on trip and exits with code 2.

The script is invoked with ``--write-repair-plan`` so the auto-retry loop (M2.13 — Sprint 4) below has a structured failure description on disk to consume:

```bash
# Hard inline-shortcut gate. On trip:
#  • Indicator banner is printed to stderr
#  • .inline-shortcut-repair-plan.json is written to $OUTPUT_DIR (--write-repair-plan)
#  • Exit code 2 is returned
# The auto-retry loop below catches exit 2, runs the recovery sequence,
# and re-dispatches Stage 2. Hard-fail to skill exit 2 only after all
# retries are exhausted.
python3 "$CLAUDE_PLUGIN_ROOT/scripts/check_inline_shortcut.py" \
    "$OUTPUT_DIR" --depth "${ASSESSMENT_DEPTH:-standard}" \
    --write-repair-plan
GATE_EXIT=$?
```

**Auto-Retry Loop (M2.13 — Sprint 4).** Instead of hard-exiting on first trip, the skill performs up to ``MAX_INLINE_RETRIES=2`` recovery+re-dispatch cycles. Each cycle:

1. **Recovery sequence** — best-effort reconstruction of any missing Phase-9/10b outputs:
   ```bash
   # Phase 9 — merge_threats has two steps: collect (build candidates from
   # .stride-*.json) then finalize (apply decisions, assign T-IDs). On a
   # bypass-driven recovery neither has run, so we run both unconditionally
   # when .threats-merged.json is missing.
   if [ ! -f "$OUTPUT_DIR/.threats-merged.json" ] \
      && ls "$OUTPUT_DIR"/.stride-*.json >/dev/null 2>&1; then
     python3 "$CLAUDE_PLUGIN_ROOT/scripts/merge_threats.py" collect \
         --output-dir "$OUTPUT_DIR" || true
     python3 "$CLAUDE_PLUGIN_ROOT/scripts/merge_threats.py" finalize \
         --output-dir "$OUTPUT_DIR" || true
   fi
   # Phase 10b — triage validator runs deterministically against
   # .threats-merged.json. Append-only; safe to re-run.
   if [ ! -f "$OUTPUT_DIR/.triage-flags.json" ] \
      && [ -f "$OUTPUT_DIR/.threats-merged.json" ]; then
     python3 "$CLAUDE_PLUGIN_ROOT/scripts/triage_validate_ratings.py" \
         "$OUTPUT_DIR" --depth "${ASSESSMENT_DEPTH:-standard}" || true
   fi
   # Phase 11 structural fragments — idempotent, fills any gaps the LLM left.
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/pregenerate_fragments.py" \
       "$OUTPUT_DIR" || true
   ```
2. **Re-dispatch Stage 2** — fresh `appsec-threat-renderer` session with identical prompt + configuration to the original Stage 2 dispatch. The renderer is idempotent: it sees the partial fragment set on disk and authors only what is still missing.
3. **Re-run the hard gate** — same `check_inline_shortcut.py --write-repair-plan` call.
4. **Exit conditions:**
   - Gate passes → break loop, proceed to Stage 3.
   - Gate trips AND retry count < `MAX_INLINE_RETRIES` → increment counter, continue loop.
   - Gate trips AND retry count == `MAX_INLINE_RETRIES` → print exhausted-retries banner (see below), clean up markers, exit 2.

```bash
INLINE_RETRY_COUNT=0
MAX_INLINE_RETRIES=2

while [ "$GATE_EXIT" -ne 0 ] && [ "$INLINE_RETRY_COUNT" -lt "$MAX_INLINE_RETRIES" ]; do
  INLINE_RETRY_COUNT=$((INLINE_RETRY_COUNT + 1))
  echo "$INLINE_RETRY_COUNT" > "$OUTPUT_DIR/.inline-shortcut-retry-count"

  printf '\n↻ Auto-retry %d/%d — recovery sequence + Stage 2 re-dispatch\n' \
      "$INLINE_RETRY_COUNT" "$MAX_INLINE_RETRIES" >&2
  printf '    Repair plan : %s/.inline-shortcut-repair-plan.json\n' "$OUTPUT_DIR" >&2

  # Step 1 — recovery sequence (idempotent)
  # ... merge_threats finalize + triage_validate_ratings + pregenerate_fragments
  #     (full bash above)

  # Step 2 — re-dispatch Stage 2 through appsec-threat-renderer
  # The skill calls the Agent tool exactly the same way as the always-dispatch
  # path above (same description, same prompt, same model). The agent sees the
  # recovery outputs on disk and proceeds.

  # Step 3 — re-run the hard gate
  python3 "$CLAUDE_PLUGIN_ROOT/scripts/check_inline_shortcut.py" \
      "$OUTPUT_DIR" --depth "${ASSESSMENT_DEPTH:-standard}" \
      --write-repair-plan
  GATE_EXIT=$?
done

if [ "$GATE_EXIT" -ne 0 ]; then
  # Exhausted all retries — print the auto-retry-exhausted banner.
  cat <<EOF >&2

══════════════════════════════════════════════════════════════
  ASSESSMENT INCOMPLETE — auto-retry exhausted
══════════════════════════════════════════════════════════════

  Stage 2 ran ${INLINE_RETRY_COUNT}/${MAX_INLINE_RETRIES} retries after the
  hard inline-shortcut gate tripped. The orchestrator could not produce a
  contract-compliant threat-model.md within the budget.

  Inspect the final repair plan:
      ${OUTPUT_DIR}/.inline-shortcut-repair-plan.json

  Re-run the skill manually:
      /appsec-advisor:create-threat-model --rebuild

  If this reproduces, file a plugin bug — a contract-compliant Phase-11
  output is reachable from the on-disk Phase-1-10b artifacts via
  pregenerate_fragments.py + 2 LLM-authored JSON fragments.
══════════════════════════════════════════════════════════════
EOF
  rm -f "${TMPDIR:-/tmp}/.appsec-verbose-$(id -u)"
  rm -f "${TMPDIR:-/tmp}/.appsec-tracing-$(id -u)"
  exit 2
fi

# Reaching here means the gate finally passed (possibly after retries).
# Clean up the retry counter so a future fresh invocation starts at 0.
rm -f "$OUTPUT_DIR/.inline-shortcut-retry-count" "$OUTPUT_DIR/.inline-shortcut-repair-plan.json"
```

Behaviour contract:

- **gate exit 0 on first try** → no retries, no recovery sequence, skill proceeds to Stage 3 immediately. Counter file never written.
- **gate exit 2 on first try, recovers in retry 1** → recovery + re-dispatch ran once, gate passed, skill proceeds. Counter file is unlinked at the end (clean state for next invocation).
- **gate exit 2 throughout all retries** → exhausted-retries banner printed, marker cleanup, exit 2. Counter file and repair plan **preserved** so the user can inspect what failed.
- **gate exit 3 (tool error)** → same handling as exit 2 in this loop — fail closed, the recovery sequence is best-effort safe, retry will surface the underlying tool error again.

The retry counter file (`.inline-shortcut-retry-count`) is a single integer. It is added to `runtime_cleanup.py`'s post-qa whitelist so it is reaped on successful completion alongside the repair plan.

The previous ~50 lines of inline Bash that tried to replicate the gate logic in the skill body have been removed (they were the proximate cause of the 2026-04-25 juice-shop Run 4 incident: the LLM executor read the conditional logic, got an exit-1 from ``qa_checks.py``, but proceeded anyway because the Bash short-circuit was loose enough to interpret as a "soft warning"). The standalone script + auto-retry loop makes the gate impossible to bypass without modifying both the script and the skill body.

### Pre-agent contract gate (deterministic, skill-level)

When the fragment precondition passes, run `qa_checks.py repair_plan` before the agent is dispatched. This builds `.qa-repair-plan.json` from the authoritative Python checker so the agent inherits a clean baseline instead of spending turns rediscovering drift:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/qa_checks.py" repair_plan \
    "$OUTPUT_DIR/threat-model.md" "$OUTPUT_DIR"
GATE_EXIT=$?
```

Also apply the auto-fixing checks in place so the Markdown already has clean links, anchors, MS structure, and `<br/>`-stacked multi-link cells before the agent even looks at it:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/qa_checks.py" all \
    "$OUTPUT_DIR/threat-model.md" "$REPO_ROOT" > /dev/null
```

**Branch logic:**
- `GATE_EXIT == 0` — contract clean, no repair plan on disk. Dispatch the QA agent for the remaining qualitative checks (linkification, prior-finding coverage, semantic cross-refs). The agent's work is additive.
- `GATE_EXIT == 1` — contract drift, `.qa-repair-plan.json` already on disk. Enter the Re-Render Loop below **without** dispatching the QA agent first. The Re-Render Loop calls Stage 1 in REPAIR_MODE, which re-authors the offending fragments and re-renders. The QA agent is dispatched **after** the loop settles (status=pass) so it works on a contract-clean document.
- `GATE_EXIT == 2` — tool error (bad path, malformed contract). Log and fall back to the old flow: dispatch the agent unconditionally and let its Check 14 write the plan instead.

This inverts the pre-M3.2 flow where the agent was the first thing to see the rendered Markdown. Cost win: the agent now has 40 turns free for semantic work instead of burning ~10 of them rediscovering mechanical contract drift.

### Stage 3 handoff banner

When the pre-agent gates are clean (or after the Re-Render Loop has settled), dispatch the QA agent. **First print a blank line and the Stage 3 handoff banner**:

```
▶ Stage 3/<total_stages> — QA Review starting  (expect ~<EST_STAGE3> min, model: sonnet-4-6)
  ⟶ Dispatching qa-reviewer — qualitative checks on a contract-clean Markdown (pre-agent gate already passed); scope: file-path linkification, prior-finding coverage, semantic cross-refs
```

Where `<total_stages>` is `3` when `ARCHITECT_REVIEW=true`, otherwise `2`.

Immediately before dispatching, call `TaskUpdate` on the `Stage 3 — QA Review` task to set status `in_progress` (skip if the task was not created, i.e. `SKIP_QA=true` or `DRY_RUN=true`). After the QA agent returns (and any Re-Render Loop iterations have settled), call `TaskUpdate` to set the same task to `completed`.

**Heartbeat watchdog (M3.4 / M3.6).** Spawn a fresh `python3 scripts/skill_watchdog.py "$OUTPUT_DIR" --plugin-root "$CLAUDE_PLUGIN_ROOT"` background invocation (see "Skill-layer heartbeat watchdog" above) immediately before dispatching the QA agent; capture the new `task_id` in `HEARTBEAT_TASK_ID`. After the QA agent returns, send one final heartbeat (`acquire_lock.py --heartbeat --phase=skill --step=stage-handoff || true`) then call `TaskStop` with `HEARTBEAT_TASK_ID`. Skip when `DRY_RUN=true` or `SKIP_QA=true`.

Then invoke the `appsec-advisor:appsec-qa-reviewer` agent using `"QA review of threat model"` as the Agent tool `description`.

**QA model resolution — split-mode (M3.5).** The QA reviewer is dispatched with one of two model IDs depending on what kind of repairs the prior Stage-2 contract gate flagged:

| Iteration | Repair-plan flag classes present | `model:` field |
|---|---|---|
| First QA call (no `.qa-repair-plan.json` yet on disk) | n/a — initial check | `$QA_ROUTINE_MODEL` from `.skill-config.json` |
| Re-Render-Loop iteration where ALL plan entries are in `{links, xrefs, anchors, repair_plan}` | mechanical repairs only | `$QA_ROUTINE_MODEL` (Haiku under `--reasoning-model haiku-economy quick\|standard`) |
| Re-Render-Loop iteration where ANY plan entry is in `{invariants, ms_structure, contract}` | content reasoning required | `$QA_CONTENT_MODEL` (always Sonnet) |

The split derives from `scripts/qa_checks.py` subcommand classes — the routine flags are mechanical (URL fix, anchor rename, T-NNN cross-reference patching) while the content flags require structural understanding of the document. To compute the model selection before dispatch:

```bash
QA_MODEL="$QA_ROUTINE_MODEL"   # default for the first call
if [ -f "$OUTPUT_DIR/.qa-repair-plan.json" ]; then
  CONTENT_HIT=$(python3 -c "
import json, sys
plan = json.load(open('$OUTPUT_DIR/.qa-repair-plan.json'))
content_classes = {'invariants', 'ms_structure', 'contract'}
flags = {entry.get('check') for entry in plan.get('entries', [])}
print('1' if flags & content_classes else '0')
" 2>/dev/null || echo 0)
  [ "$CONTENT_HIT" = "1" ] && QA_MODEL="$QA_CONTENT_MODEL"
fi
```

**Pass the `model` field explicitly** in the Agent tool dispatch so the frontmatter `model: sonnet` default in `agents/appsec-qa-reviewer.md:5` is overridden — the same explicit-pass pattern as Stage 4 (Architect Review) below. Without explicit pass-through, the frontmatter default silently wins and the haiku-economy routing in `.skill-config.json` has no effect, defeating the entire QA-split mechanism. The 2026-05-04 juice-shop run lost ~3 min and ~3× the planned token cost to this drift (stage-stats reported Haiku, AGENT_SPAWN reported Sonnet).

```
- model: $QA_MODEL  ← MUST appear as a top-level Agent tool parameter
```

Pass the following in the prompt body:
- `REPO_ROOT=<absolute repo path>` (same value resolved above)
- `OUTPUT_DIR=<absolute output path>` (same value resolved above)
- `CONTEXT_FILE=$OUTPUT_DIR/.threat-modeling-context.md`
- `QA_DEPTH=<core|full|extended>`

The QA reviewer runs with its own turn budget (up to 40 turns) and fixes broken VS Code links, linkifies bare file references, verifies cross-references, checks YAML/MD consistency, flags unaddressed prior findings, removes unfilled placeholders, and verifies section completeness. It updates `$OUTPUT_DIR/threat-model.md` in-place.

**Strict contract gate.** The QA reviewer's Check 14 is a **hard gate** — when it detects any `sections-contract.yaml` violation, it writes a structured `.qa-repair-plan.json` under `$OUTPUT_DIR/`. The presence of this file signals the skill to enter the Re-Render Loop below before proceeding to Stage 4 (or to the Completion Summary when Stage 4 is disabled).

**Record Stage 3 stats (M3.3).** After the QA Agent returns (and the Re-Render Loop has settled, if invoked), extract the `<usage>` block from the QA Agent's return notification and append the Stage 3 record:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/record_stage_stats.py" "$OUTPUT_DIR" \
    --stage 3 \
    --name "QA Review" \
    --agent appsec-advisor:appsec-qa-reviewer \
    --model "$QA_MODEL" \
    --duration-ms <duration_ms_from_usage> \
    --tool-uses <tool_uses_from_usage> \
    --tokens <total_tokens_from_usage>
```

**Pass the actual `$QA_MODEL` value** (not a hardcoded `claude-sonnet-4-6`) so the per-stage breakdown table reflects which model was effectively used — Haiku at haiku-economy/quick+standard, Sonnet at haiku-economy/thorough or whenever a content-class repair iteration switches to `$QA_CONTENT_MODEL`.

Stage 4 (Architect Review) records `--stage 4` analogously when `ARCHITECT_REVIEW=true`.

### Re-Render Loop — enforce strict contract compliance

Some QA / architect failures are recoverable by re-rendering `threat-model.md` from the (possibly repaired) fragments instead of abandoning the run. The skill manages this loop at the stage boundary so neither the QA reviewer nor the architect reviewer ever mutate the threat model out of band.

**When the loop runs.** After **every** Stage 3 invocation (and after every Stage 4 invocation when `ARCHITECT_REVIEW=true`), the skill inspects the agent's structured output:

- `$OUTPUT_DIR/.qa-status.json` — always written by Stage 3. Status `pass` means the rendered MD matches the contract; status `repair_required` means the Stage 3 helper also wrote `.qa-repair-plan.json` describing the violations.
- `$OUTPUT_DIR/.architect-status.json` — written by Stage 4 when the architect review encounters technical defects that the orchestrator can fix (broken Mermaid syntax, missing attack-walkthrough per Critical, §7.3 missing per-flow `####` blocks, etc.). Status `pass` means the architect had no structural objections; status `repair_required` is paired with `.architect-repair-plan.json`.

**Loop logic (both stages share the same mechanics):**

```
MAX_REPAIR_ITERATIONS = 3       # hard cap on loop depth
repair_iteration = 0            # counts post-Stage-1 repair passes

# Initial pass
dispatch Stage 1 (threat-analyst)         # MODE = full|incremental (from earlier resolution)

loop:
  dispatch Stage 3 (qa-reviewer)
  # Sprint 3A (M3.5): apply content-repair plan + re-compose BEFORE
  # checking qa-status. The applier writes only under .fragments/ and
  # is fail-isolated — its exit code is logged but does not abort the run.
  if exists $OUTPUT_DIR/.qa-content-repair-plan.json:
      python3 $CLAUDE_PLUGIN_ROOT/scripts/apply_content_repair.py "$OUTPUT_DIR" || true
      python3 $CLAUDE_PLUGIN_ROOT/scripts/compose_threat_model.py \
          --output-dir "$OUTPUT_DIR" --strict || true
  read   $OUTPUT_DIR/.qa-status.json   (qa_status)
  read   $OUTPUT_DIR/.qa-repair-plan.json   (qa_plan, optional)

  # Sprint 1D — short-circuit when the plan is a known dead-end.
  if qa_plan.status == "manual_review" or qa_plan.actionable == false:
      # Sprint 1D-bis — release-blocker gate.  Exit code 2 means the
      # qa_status.manual_review_items contain at least one release-blocker
      # pattern (e.g. "(untitled)" mitigation headings).  See
      # `scripts/qa_release_gate.py` → RELEASE_BLOCKER_PATTERNS for the
      # curated list.  The helper is deterministic (no LLM scan), so the
      # decision is reproducible across runs.
      python3 $CLAUDE_PLUGIN_ROOT/scripts/qa_release_gate.py \
          $OUTPUT_DIR/.qa-status.json
      gate_rc=$?
      if gate_rc == 2:
          print release-blocker banner with the items the gate flagged; exit 2
      print manual-review banner; break the loop

  if   qa_status.status == "pass":           break the QA loop
  elif repair_iteration >= MAX_REPAIR_ITERATIONS:
       print hard-fail banner (see below); exit 2
  else:
       repair_iteration += 1
       dispatch Stage 1 again with REPAIR_MODE=true + REPAIR_PLAN_PATH=$OUTPUT_DIR/.qa-repair-plan.json
       continue  (back to Stage 3)
```

**Sprint 3A (M3.5) — content-repair plan application.** The QA reviewer cannot edit `threat-model.md` directly (PreToolUse hook blocks all `Write/Edit` against the canonical Markdown — AGENTS.md invariant). For pre-Sprint-3A runs this meant the reviewer's most useful checks (linkification, placeholder removal, anchor injection) ran in read-only mode and the findings were never applied — the 2026-04-27 run shipped 18 NARRATIVE_PLACEHOLDER comments and missing Linked Threats columns because of this.

The new flow: the QA reviewer enumerates each blocked fix into `$OUTPUT_DIR/.qa-content-repair-plan.json` (schema: `schemas/qa-content-repair-plan.schema.json`). The skill then calls `scripts/apply_content_repair.py` which:

- Reads the plan
- For each action, edits the named fragment under `.fragments/` (writes are restricted to that subtree — the applier hard-rejects anything else)
- Logs per-action success/failure to stderr
- Exits 0 (clean) or 1 (some actions were skipped — never aborts the run)

The applier is followed by a fresh `compose_threat_model.py --strict` so the fragment edits flow through to `threat-model.md`. Both calls are wrapped in `|| true` so a single-action failure cannot block the rest of the loop. When `.qa-content-repair-plan.json` does not exist (the common case — the QA reviewer only emits it when a check was actually blocked), the applier prints `no plan — nothing to do` and the skill proceeds without re-composing.

**Sprint 1D (M3.5) — manual-review pre-check.** Before entering the loop body for any stage, also peek at `.qa-repair-plan.json` directly: when its top-level `status == "manual_review"` (or `actionable == false`), the loop **must not iterate**. The plan's `actions[].fragments_to_rewrite` are all empty in this case (e.g. all `posture_renderer_bug` / `posture_unknown` checker false-positives), so a re-render Stage-1 dispatch can never converge. The 2026-04-27 run produced exactly this state with 7 B2 violations, where the strict-spec interpretation would have burnt 3 × ~10 min iterations for nothing. With the manual-review short-circuit the skill prints the banner below and proceeds straight to the Completion Summary instead — the rendered MD survives unchanged and the user is pointed at the plan for inspection.

**Sprint 1D-bis (M3.6) — release-blocker scan on `manual_review`.** The manual-review short-circuit is correct *only* when the unfixable items are cosmetic (e.g. checker false-positives). Some `manual_review_items` describe defects that make the rendered model unfit for use — these MUST abort the run rather than silently ship. Before printing the manual-review banner, scan `.qa-status.json → manual_review_items[*].issue` (and any item-level `description`) for **any** release-blocker pattern:

```
RELEASE_BLOCKER_PATTERNS = (
  "untitled",                 # Mitigation Register `(untitled)` headings — Step 1 / 4 fix
  "orphan",                   # orphaned T-NNN / M-NNN cross-references
  "broken anchor",            # broken-anchor / no-anchor diagnostics
  "(untitled)",
  "Mitigation column empty",  # MS Mitigations table empty cells
  "title fields missing",
  "linked but no title",
)
```

When a match is found, do NOT print the manual-review banner — print the **release-blocker banner** (below) and exit 2 with the same hard-fail semantics as iteration-exhaustion. The 2026-05-01 example shipped a model where every M-NNN block read `(untitled)` and the Mitigation column was empty across all four MS tables — exactly the pattern this gate catches. Without this check, manual-review pre-empts iteration even for defects the user must not see.

**Release-blocker banner:**

```
══════════════════════════════════════════════════════════════
  ASSESSMENT INCOMPLETE — release-blocking QA defects detected
══════════════════════════════════════════════════════════════

  Stage             : Stage 3 QA
  Status            : repair_required (manual_review path)
  Blockers          : <N> release-blocking item(s) — see below
  Output            : $OUTPUT_DIR/threat-model.md (NOT released)

  The following manual-review items match the release-blocker
  allowlist and indicate the rendered model has structural defects
  the user must not see (e.g. (untitled) mitigations, missing
  anchors, empty Mitigation columns):

    - <issue 1>
    - <issue 2>
    …

  These typically trace to schema-drift in `threat-model.yaml`
  (e.g. `mitigation_title` instead of `title`, `addresses` instead
  of `threat_ids`). Inspect $OUTPUT_DIR/threat-model.yaml against
  schemas/threat-model.output.schema.yaml and re-run.
══════════════════════════════════════════════════════════════
```

The release-blocker scan deliberately runs **before** the cosmetic manual-review banner so a partial release-blocker match is not masked by a co-occurring cosmetic flag. The pattern list is curated — adding a pattern is a deliberate decision (every entry blocks otherwise-shipping runs).

**Manual-review banner (printed instead of iterating):**

```
══════════════════════════════════════════════════════════════
  CONTRACT GATE — MANUAL REVIEW REQUIRED (no auto-repair attempted)
══════════════════════════════════════════════════════════════

  Stage             : <Stage 3 QA | Stage 4 Architect>
  Final plan        : $OUTPUT_DIR/<.qa-repair-plan.json|.architect-repair-plan.json>
  Violations        : <N> (none have writable fragment targets — auto-repair cannot fix them)
  Output            : $OUTPUT_DIR/threat-model.md (rendered, but the listed contract checker
                      flags need a code/contract change to resolve — typically renderer
                      regex drift vs current template, or a checker false positive)

  The skill skipped the Re-Render Loop because every action's
  `fragments_to_rewrite` field is empty. Iterating would burn budget without
  changing the outcome. Inspect the plan, then either:
    1. Patch the underlying checker / renderer (contributes to plugin code), or
    2. Update `data/sections-contract.yaml` if the rule itself is wrong.
══════════════════════════════════════════════════════════════
```

The analogous loop then runs for Stage 4 when `ARCHITECT_REVIEW=true`, using `.architect-status.json` / `.architect-repair-plan.json`. Each stage has its own `MAX_REPAIR_ITERATIONS` budget (default 3); they are not shared. The same `manual_review` short-circuit applies.

**Between-iteration handoff banner (print before each repair Stage 1):**

```
↻ Repair iteration <k>/<MAX_REPAIR_ITERATIONS> — re-rendering from repair plan
    Source      : <.qa-repair-plan.json | .architect-repair-plan.json>
    Violations  : <N> (<type1>, <type2>, …)
    Orchestrator: Stage 1 (REPAIR_MODE=true)
```

**Repair-mode Stage 1 invocation.** The skill re-spawns the `appsec-advisor:appsec-threat-analyst` agent with:

- `REPAIR_MODE=true`
- `REPAIR_PLAN_PATH=<absolute path to the repair-plan json>`
- all original flags and resolved variables unchanged (REPO_ROOT, OUTPUT_DIR, STRIDE_MODEL, …)

The orchestrator's repair-mode branch must:

1. Skip Phases 1–10 (their outputs are already on disk).
2. Load the repair plan; for each `action`, re-author the listed `fragments_to_rewrite` so the next compose pass emits a contract-clean document. The orchestrator's repair branch is the **only** legal writer of `.fragments/*.{json,md}` — it never touches `threat-model.md` directly.
3. Re-invoke `python3 $CLAUDE_PLUGIN_ROOT/scripts/compose_threat_model.py --output-dir $OUTPUT_DIR --strict` (Phase 11 Substep 5).
4. Re-run the QA contract gate (Phase 11 Substep 6) as before.
5. Log `REPAIR_END` with the iteration number, the fragment paths that were rewritten, and the final `qa_checks.py contract` exit code.

**Hard-fail banner (printed when the loop exhausts its iterations):**

```
══════════════════════════════════════════════════════════════
  ASSESSMENT INCOMPLETE — strict contract gate failed
══════════════════════════════════════════════════════════════

  Stage             : <Stage 3 QA | Stage 4 Architect>
  Max iterations    : <MAX_REPAIR_ITERATIONS>
  Final plan        : $OUTPUT_DIR/<.qa-repair-plan.json|.architect-repair-plan.json>
  Violations        : <N> remaining
  Output            : $OUTPUT_DIR/threat-model.md (rendered but NON-COMPLIANT)

  The skill exhausted its auto-repair budget without reaching a contract-clean
  render. Inspect the final plan file for the list of actions that failed to
  resolve, fix the underlying fragments or the contract itself, then re-run
  the skill. The threat model on disk is NOT guaranteed to match the
  sections-contract.yaml schema.
══════════════════════════════════════════════════════════════
```

Then `rm -f` the verbose marker and exit 2.

**When the loop is suppressed.** The Re-Render Loop is **not** activated when:

- `DRY_RUN=true` — the temp `OUTPUT_DIR` is disposable; a single pass is sufficient. (Stage 3 still writes `.qa-status.json`, but the skill ignores `repair_required` in dry-run mode.)
- `SKIP_QA=true` (flag `--no-qa` or env `APPSEC_SKIP_QA=1`) — Stage 3 itself is skipped, so there is no status file to trigger a loop.

Both cases fall through to the Completion Summary directly.

## Stage 4 — Architect Review (auto-on at thorough, else opt-in)

Stage 4 runs when `ARCHITECT_REVIEW=true` (resolved in the Architect Review Resolution section above — auto-enabled at `ASSESSMENT_DEPTH=thorough`, otherwise requires explicit `--architect-review`) **and** `DRY_RUN=false`. Verify that `$OUTPUT_DIR/threat-model.md` and `$OUTPUT_DIR/threat-model.yaml` both exist. If either is missing, skip Stage 4 silently (the QA reviewer or orchestrator already surfaced the underlying failure).

**First print a blank line and the Stage 4 handoff banner** (extract the model short-name from `ARCHITECT_MODEL` — e.g. `claude-opus-4-7` → `opus-4-7`):

```
▶ Stage 4/3 — Architect Review starting  (expect ~<EST_STAGE4> min, model: <model-short-name>)
  ⟶ Dispatching architect-reviewer — advisory review: architecture coherence, control realism, chain plausibility (6 checks); never rewrites output — emits .architect-review.md
```

Immediately before dispatching, call `TaskUpdate` on the `Stage 4 — Architect Review` task to set status `in_progress`. After the agent returns (success or non-fatal error), call `TaskUpdate` to set it to `completed`. (The task was only created when `ARCHITECT_REVIEW=true` and `DRY_RUN=false` — if absent, skip the update.)

**Heartbeat watchdog (M3.4 / M3.6).** Spawn a fresh `python3 scripts/skill_watchdog.py "$OUTPUT_DIR" --plugin-root "$CLAUDE_PLUGIN_ROOT"` background invocation (see "Skill-layer heartbeat watchdog" above) immediately before dispatching the architect agent; capture the new `task_id` in `HEARTBEAT_TASK_ID`. After the agent returns, send one final heartbeat (`acquire_lock.py --heartbeat --phase=skill --step=stage-handoff || true`) then call `TaskStop` with `HEARTBEAT_TASK_ID`. Skip when `DRY_RUN=true`.

Then invoke the `appsec-advisor:appsec-architect-reviewer` agent using `"Architect review of threat model"` as the Agent tool `description`, and **pass the `model` field explicitly** so the frontmatter default is overridden:

- `model: <ARCHITECT_MODEL>` — resolved from `--architect-model` (default `claude-opus-4-7` when Stage 4 is enabled)

Pass the following variables in the prompt:
- `REPO_ROOT=<absolute repo path>` (same value resolved above)
- `OUTPUT_DIR=<absolute output path>` (same value resolved above)
- `CONTEXT_FILE=$OUTPUT_DIR/.threat-modeling-context.md`
- `ASSESSMENT_DEPTH=<quick|standard|thorough>`
- `MODEL_ID=<ARCHITECT_MODEL>` — so the agent logs the model it is actually running on

The architect reviewer runs with its own turn budget (up to 40 turns) and writes `$OUTPUT_DIR/.architect-review.md` with findings and a single-line verdict. It never modifies the threat model itself.

**Non-fatal.** If Stage 4 errors out or returns without writing `.architect-review.md`, proceed to the Completion Summary as normal — the threat model is still valid. Log the failure to `.agent-run.log` but do not fail the overall skill.

## Completion Summary

After Stage 3 completes (or after Stage 1 if `DRY_RUN=true`), **always** print a final summary. This is the last thing the skill outputs and is critical for headless mode (`claude -p`) where it becomes the entire visible output.

### Dry-Run Completion (DRY_RUN=true)

When `DRY_RUN=true`, call `render_completion_summary.py` in dry-run mode, then clean up the temp directory.

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/render_completion_summary.py" \
    --output-dir "$OUTPUT_DIR" --repo-root "$REPO_ROOT" --mode dry-run
rm -rf "$OUTPUT_DIR"
rm -f "${TMPDIR:-/tmp}/.appsec-verbose-$(id -u)"
rm -f "${TMPDIR:-/tmp}/.appsec-tracing-$(id -u)"
```

The script extracts the Management Summary (from `## Management Summary` to the next `## ` heading), strips HTML blockquotes / `<br/>` / `style="..."` for plain-console readability, extracts threat and control counts from `threat-model.yaml`, and prints the preview banner. Full format spec lives in the script's docstring and tests — no LLM-authored extraction needed.

Exit after the call. Do not print file paths, log files, or run statistics — the temp directory is gone.

### Normal Completion (DRY_RUN=false)

**M2.15 / M3.3 — issue aggregation (run before completion summary).**
Aggregate post-run issues from the logs into `.run-issues.json` for the
`-- Run Issues --` block in the completion summary below and for the
`/appsec-advisor:fix-run-issues` skill. The recommender enrichment step
adds a `fix_recommendation` per issue so the user can act on them
without log-grep.

**M3.3 contract change** — the §Appendix Run Issues section is no longer
rendered into `threat-model.md`. The data still lives in `.run-issues.json`
(observability artefact) and the completion summary still surfaces a
`-- Run Issues --` block (transient terminal output), but the persisted
Markdown stays focused on threat content. Therefore: no second
`compose_threat_model.py` call is needed after aggregation. The
aggregator runs once, writes the JSON, and we move on.

Best-effort — failure does not block completion since the issues are
merely observability data.

```bash
# Aggregate + enrich; non-fatal if the aggregator chokes on a malformed log.
python3 "$CLAUDE_PLUGIN_ROOT/scripts/aggregate_run_issues.py" \
    "$OUTPUT_DIR" --depth "${ASSESSMENT_DEPTH:-standard}" || true
```

**Design intent.** The completion block is the *only* thing the user reliably sees in headless (`claude -p`) mode and the dominant visible artifact in interactive mode. It is rendered by `scripts/render_completion_summary.py` — a single self-contained Python script with full unit tests. **Do not hand-author any part of this block**; invoke the script and print its output verbatim.

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/render_completion_summary.py" \
    --output-dir "$OUTPUT_DIR" \
    --repo-root  "$REPO_ROOT" \
    --mode "$MODE" \
    --reasoning-model "$REASONING_MODEL" \
    $( [ "$WRITE_YAML"         = "true"  ] && echo "--write-yaml"         || echo "--no-write-yaml" ) \
    $( [ "$WRITE_SARIF"        = "true"  ] && echo "--write-sarif"        || echo "--no-write-sarif" ) \
    $( [ "$CHECK_REQUIREMENTS" = "true"  ] && echo "--check-requirements" || echo "--no-check-requirements" ) \
    $( [ "$ARCHITECT_REVIEW"   = "true"  ] && echo "--architect-review"   || echo "--no-architect-review" ) \
    $( [ "$WITH_SCA"           = "true"  ] && echo "--with-sca"           || echo "--no-with-sca" ) \
    --patch-placeholders
```

The `--patch-placeholders` flag rewrites `_pending_` markers in the MD's `## Appendix: Run Statistics` section with the extracted durations and models. Idempotent — a second invocation is a no-op.

**What the script produces (format contract):** the output has exactly this shape, with `-- Section ---` dividers in this fixed order:

1. Header banner (`══` rules + `ASSESSMENT COMPLETE — Summary follows`)
2. `Repository:` / `Mode:` lines (the Mode line appends `(delta: +X / ~Y / -Z)` when `changelog[0]` carries delta data)
3. `-- Files ---` — artifact paths (yaml conditional on `--write-yaml`; sarif conditional on file presence)
4. `-- Change Summary ---` — rendered only when `threat-model.yaml` has a meaningful `changelog[0]` with deltas (so first-run fulls are naturally skipped)
5. `-- Metrics ---` — threats / components / controls (/ requirements when `--check-requirements`)
6. `-- Run Statistics ---` — total + per-phase durations, agent roster, tokens + cost (via `verify_run_costs.py`). Omitted entirely when `.hook-events.log` and `.agent-run.log` have no extractable data.
7. `-- Next Steps ---` — 1–5 conditional action lines (Management Summary always → top severity → architect review → SARIF → requirements → reasoning-model → dep-scan → baseline; capped at 5)
8. `-- Log Files ---`
9. Closing rule (`══`)

The script's rendering logic (file-listing rules, Change Summary conditionals, Next Steps priority, placeholder patching) is covered by `tests/test_render_completion_summary.py`. If the contract needs to change, edit the script and its tests — never the skill layer.

### Persist the wall-clock for next-run replay

Right after `render_completion_summary.py` returns (still **before** the
runtime cleanup wipes intermediate state), write the just-finished run's
total wall-clock + mode + depth into `.appsec-cache/baseline.json` so
the next invocation's `estimate_duration.py` can use it as the
highest-priority data source. This single integer is what flips future
banners from "parametric" to "from last run on this repo" and pins the
estimate to within ±5 % of reality.

```bash
RUN_START_EPOCH="${ASSESSMENT_START_EPOCH:-0}"
if [ "$RUN_START_EPOCH" -gt 0 ]; then
  RUN_END_EPOCH=$(date +%s)
  RUN_SECONDS=$(( RUN_END_EPOCH - RUN_START_EPOCH ))
  RUN_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  CACHE_DIR="$OUTPUT_DIR/.appsec-cache"
  CACHE_FILE="$CACHE_DIR/baseline.json"
  mkdir -p "$CACHE_DIR" 2>/dev/null
  if [ -f "$CACHE_FILE" ]; then
    # Merge with existing baseline.json (don't clobber other fields).
    jq --argjson s "$RUN_SECONDS" \
       --arg     m "$MODE" \
       --arg     d "${ASSESSMENT_DEPTH:-standard}" \
       --arg     i "$RUN_ISO" \
       '. + {last_run_seconds: $s, last_run_mode: $m, last_run_depth: $d, last_run_iso: $i}' \
       "$CACHE_FILE" > "$CACHE_FILE.tmp" 2>/dev/null \
       && mv "$CACHE_FILE.tmp" "$CACHE_FILE"
  else
    # No baseline yet (first-ever run) — minimal seed file. Other
    # fields (manifest hashes, ID counters) get filled in by
    # baseline_state.py on the next assessment.
    cat > "$CACHE_FILE" <<EOF
{
  "last_run_seconds": $RUN_SECONDS,
  "last_run_mode":    "$MODE",
  "last_run_depth":   "${ASSESSMENT_DEPTH:-standard}",
  "last_run_iso":     "$RUN_ISO"
}
EOF
  fi
fi
```

`ASSESSMENT_START_EPOCH` is captured at the very top of the skill (before stage 1 dispatch) — see "Stage 1 Handoff Banner" above. Best-effort: if `jq` is unavailable or the write fails, the next-run estimator simply falls back to the parametric formula. Cleanup later runs whether this step succeeded or not.

### Persist per-component durations for next-run Phase-9 estimate (M5)

Right after writing `last_run_seconds`, also record per-component STRIDE durations so the next run's `estimate_duration.py` can produce a Phase-9-aware estimate. The helper script reads `.stride-*.json` mtimes against the most-recent Phase-9 PHASE_START in `.agent-run.log` and merges the result into `.appsec-cache/baseline.json.component_durations`.

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/record_component_durations.py" \
    "$OUTPUT_DIR" 2>/dev/null || true
```

Best-effort: failure here is non-fatal — the next run falls through to `last_run_cache` or `parametric` source.

### Post-summary cleanup

After the script returns, call `TaskUpdate` on the `Completion summary + cleanup` task to set status `completed`. (This is the final task on the list, so once it flips the whole Stage-1→cleanup sequence shows ✔ across the board.)

Then run the deterministic post-pipeline transient-file cleanup (whitelist pinned in `scripts/runtime_cleanup.py`) and remove the verbose / tracing marker files:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/runtime_cleanup.py" "$OUTPUT_DIR" --stage post-qa >/dev/null 2>&1 || true
if [ "$ARCHITECT_REVIEW" = "true" ]; then
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/runtime_cleanup.py" "$OUTPUT_DIR" --stage post-architect >/dev/null 2>&1 || true
fi
rm -f "$OUTPUT_DIR/.appsec-lock"
rm -f "${TMPDIR:-/tmp}/.appsec-verbose-$(id -u)"
rm -f "${TMPDIR:-/tmp}/.appsec-tracing-$(id -u)"
```

`post-qa` runs the Phase 11 whitelist plus QA-specific artifacts (`.qa-status.json`, empty `.qa-repair-plan.json`, `.fragments/`). `post-architect` additively removes architect-review status files. Exit code 1 (safety-gate block) is silenced with `|| true` — the summary has already been printed.

### PDF Export (only when `WRITE_PDF=true`)

The PDF export runs **after** all four stages, the Completion Summary, and `runtime_cleanup`. Placing it last is intentional: at this point `threat-model.md` is final (no more QA / architect re-render passes), so the PDF can never go stale. The export script is the same one that backs `/appsec-advisor:export-pdf` — see `skills/export-pdf/SKILL.md` for the standalone form.

**Non-fatal.** PDF export failures must not fail the assessment. The threat model itself was successfully written before this step runs; a missing system dependency (pandoc, weasyprint) or a conversion error are warnings, not errors. Log the issue and continue.

```bash
if [ "$WRITE_PDF" = "true" ]; then
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/export_pdf.py" \
        --input  "$OUTPUT_DIR/threat-model.md" \
        --output "$OUTPUT_DIR/threat-model.pdf" \
        2>&1 | tee -a "$OUTPUT_DIR/.agent-run.log" >&2
    PDF_RC=${PIPESTATUS[0]}
    if [ "$PDF_RC" -eq 0 ]; then
        printf '\n  PDF: %s/threat-model.pdf\n' "$OUTPUT_DIR" >&2
    else
        printf '\n  PDF export skipped (exit %s — see preflight output above)\n' "$PDF_RC" >&2
        printf '  Run `/appsec-advisor:export-pdf --check-only` for the install hints.\n' >&2
    fi
fi
```

The exporter's own preflight handles missing dependencies with a clear message; the skill simply prints a one-line pointer to `--check-only` so the user knows where to look. The `tee` to `.agent-run.log` ensures the preflight diagnostics are captured for post-mortem even when the user runs in non-interactive mode.

`scripts/runtime_cleanup.py` already lists `threat-model.pdf` in its NEVER-touch set — so this output survives all subsequent cleanup invocations the same way `threat-model.md` and `threat-model.sarif.json` do.

**Explicit success exit.** After the PDF block (or after the cleanup block when `WRITE_PDF=false`) emit an unambiguous success exit so that no subsequent code path can accidentally run:

```bash
exit 0
```

## Error Handling

If `$OUTPUT_DIR/threat-model.md` does not exist after Stage 1 (orchestrator failed before writing output):
1. Check for `$OUTPUT_DIR/.appsec-checkpoint` to determine which phase failed.
2. Inform the user:
   ```
   Error: assessment did not complete successfully.
     Last checkpoint: Phase <N> (<status>)
     Available intermediate files can be inspected in <OUTPUT_DIR>/
     Run with --resume to continue from the last completed phase.
   ```
3. Remove the verbose and tracing marker files so the next run is not accidentally verbose or tracing:
   ```bash
   rm -f "${TMPDIR:-/tmp}/.appsec-verbose-$(id -u)"
   rm -f "${TMPDIR:-/tmp}/.appsec-tracing-$(id -u)"
   ```
4. Skip Stage 3.

Every other abort path (conflicting flags, missing baseline for `--incremental`, incompatible plugin version, failed `CLAUDE_PLUGIN_ROOT` discovery) must also run the `rm -f` cleanup before exiting non-zero. This keeps the verbose and tracing markers strictly scoped to the single run that asked for them.
