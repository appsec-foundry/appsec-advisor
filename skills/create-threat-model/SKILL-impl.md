# create-threat-model — full implementation

This file is loaded on demand by SKILL.md for non-help invocations. Do not modify the frontmatter routing logic; edit this file for implementation changes.

> **Reading protocol — suppress meta-narration.** This file is large; read it
> as needed, but do **not** narrate that fact to the user. No "this is a large
> orchestration file", no "let me map its structure before continuing", no
> running commentary on how you are scanning or chunking it. The same silence
> applies to **executing** the pipeline: do **not** announce the Bash you are
> about to run — no "let me execute the pipeline preamble", no "I'll run the
> combined pre-flight sequence in one shell", no "first I'll resolve config",
> no narration of which commands you are bundling into a shell. Just call the
> tool. Suppress all of it **silently** (same rule as the TaskList contract
> below) — do not announce that you are suppressing it either. The user's first
> visible output should be pipeline progress (the Pre-flight summary render),
> not remarks about reading this file or running its commands.

## Pipeline Overview (Stage-D, post-M2.13)

> **TaskList contract — read before tracking progress.** The boxes in the
> diagram below describe the **runtime pipeline**, not the user-facing
> `TaskList`. Do **not** call `TaskCreate` while reading this section. The
> canonical `TaskList` is created later, in **`Stage Task List Bootstrap`**
> (after config resolution + the handoff banner — search for that heading).
> Until then, **suppress** any `TaskCreate` reflex even if Claude Code emits
> a "task tools haven't been used recently" reminder during the long Bash
> preamble — that reminder is generic and does not override this contract.
> Suppress it **silently**: do **not** narrate that you are ignoring the
> reminder or the contract (no "I'll ignore the TaskCreate reminder…" lines).
> Just no-op and proceed to the next step.
>
> In particular, do **not** create separate `TaskCreate` entries for any of:
>   - `Resolve config` / `emit .skill-config.json` (preamble Bash)
>   - `Render Pre-flight summary` (preamble LLM render)
>   - `Pre-generate structural fragments` (intra-Stage-1 since M2.12;
>     `pregenerate_fragments.py` runs inside Stage 1 Phase 11 Substeps 1–3
>     and again inside Stage 2 recovery — never as a user-visible stage)
>   - Any per-phase entry inside Stage 1 (phases stream inline as the
>     foreground Agent runs)
>
> The only `TaskCreate` calls allowed are the eight rows defined in
> `Stage Task List Bootstrap` (`Preparing workspace`, `Stage 1a - Threat
> Analysis`, `Stage 1b - Triage`, `Stage 1c - Abuse Case Verification`
> (when `DRY_RUN=false`), `Stage 2 - Report Rendering`, conditional
> `Stage 3 - QA Review`, conditional `Stage 4 - Architect Review`,
> `Final summary + cleanup`).
> Subjects must match **verbatim** — later `TaskUpdate` calls match by
> subject and silently no-op on drift.

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
│  Stage 1 — Threat Analysis & Triage                                 │
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
│  Stage 2 - Report Rendering (M2.12 — fresh renderer budget)         │
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
                   │  Stage 3 - QA Review (sonnet, 120)  │
                   │  + Re-Render Loop (max 3 iter.)     │
                   └────────────────┬────────────────────┘
                                    │
                                    ▼
                   ┌─────────────────────────────────────┐
                   │  Stage 4 - Architect Review         │
                   │  (only at depth=thorough or         │
                   │   --architect-review)               │
                   └────────────────┬────────────────────┘
                                    │
                                    ▼
                   ┌─────────────────────────────────────┐
                   │  Final summary + cleanup            │
                   │  render_completion_summary.py       │
                   │  runtime_cleanup.py post-qa         │
                   └─────────────────────────────────────┘
```

**Compliance contract.** No malformed `threat-model.md` is ever persisted to `$OUTPUT_DIR/`. Every path either produces a contract-clean document (composed by `compose_threat_model.py --strict` from schema-validated fragments) or aborts with exit 2 and a structured repair plan (`.inline-shortcut-repair-plan.json`) for inspection. The skill exits 0 only when Stage 3 has signed off on a compose-rendered MD, either through the deterministic QA gate (`.qa-status.json` with `source: deterministic-pre-agent`) or through an explicit `appsec-qa-reviewer` invocation.

**Composition transparency (M2.14 — Sprint 6).** Every successful compose writes `$OUTPUT_DIR/.compose-stats.json` with structured warnings + per-section retry counts. When that file shows non-clean status (or the `.inline-shortcut-retry-count` is > 0), the renderer adds a `## Appendix: Composition Notes` section to `threat-model.md` and the completion summary emits a `-- Composition Health --` block. On clean runs both are silently omitted. The MD-embedded form is the canonical persistence — it survives `runtime_cleanup`, git commits, and PR reviews.

## Prerequisites — Environment & Allow-Listed Commands

### `CLAUDE_PLUGIN_ROOT` discovery

Several downstream scripts (`plugin_meta.py`, `baseline_state.py`, `agent_logger.py`) expect `$CLAUDE_PLUGIN_ROOT` to point at the plugin directory. Claude Code sets this when a plugin command runs, but in some harness configurations (e.g. headless `claude -p`, older claude-code releases) the variable is **not** propagated into Bash sub-processes. Resolve it explicitly at the start of the skill and pass it through to every agent invocation.

> **CRITICAL — single Bash call:** The Claude Code `Bash` tool starts a **fresh shell for every tool call** — variables set in one call are not visible in the next. The discovery block and the early flag validation below **must be combined into one single `Bash` tool call** (not two separate calls). If you split them, `$CLAUDE_PLUGIN_ROOT` will be empty when `resolve_config.py` runs and the path expands to `/scripts/resolve_config.py`, causing an immediate "No such file or directory" error.

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

# Early flag validation — must run in the same Bash call as the discovery above.
python3 "$CLAUDE_PLUGIN_ROOT/scripts/resolve_config.py" --validate-only "$@"
VALIDATE_EXIT=$?
if [ "$VALIDATE_EXIT" -ne 0 ]; then
  exit "$VALIDATE_EXIT"
fi
```

The resolved value must also be passed verbatim in the Stage 1 and Stage 3 agent prompts (see "Stage 1 — Threat Analysis & Triage" below).

### Early flag validation (fail-fast)

Before any preflight steps run (state cleanup, cache validation, session-bloat detection), validate the user's flags. Invalid flags must produce an immediate error — never silent inference, never preflight side-effects against an unrecognised invocation. The validator is `resolve_config.py --validate-only`: argparse rejects unknown flags with exit 2, the conflict detector rejects mutually-exclusive pairs with exit 1, and the script produces no output / writes no files on success.

The validation is already embedded in the discovery block above — **do not issue a second separate `Bash` tool call for it**. The combined snippet above is the canonical implementation; this section documents the behaviour contract only:

- Unknown flag (e.g. `--qiuck` typo) → argparse prints `usage: …` and `error: unrecognized arguments: --qiuck` to stderr, exits 2. Skill exits 2 immediately.
- Conflicting flags (e.g. `--rebuild --incremental`) → resolver prints the conflict reason, exits 1. Skill exits 1 immediately.
- Skill-only flags (currently just `--force`) are stripped by the script before parsing, so they don't trigger false-positive failures here.
- Clean parse → exit 0, no output, skill proceeds to the preflight steps below.

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

Users who need explicit control have `/appsec-advisor:clean-run-state` — same helper, same semantics, plus a `--force` escape hatch and a `--dry-run` reporting mode.

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

### Optional QA-validator dependency check

The Stage-3 `qa_checks.py mermaid_syntax` check is two-tier: a permissive regex pre-pass plus an authoritative Mermaid parser (Node `jsdom` polyfill + `@mermaid-js/mermaid-cli`). When the authoritative parser is missing, the regex fallback silently accepts patterns Mermaid then rejects at render time — the 2026-05-24 juice-shop run shipped 24 broken Mermaid blocks because of this gap (`participant X as "..."` quoted aliases × 14; truncated `(path…)` labels × 10). Detecting the missing dependency at run-start surfaces the gap before ~45 min of work end with a silently-degraded QA gate.

Non-blocking: Node / npm are legitimately absent on slim Docker images and barebones WSL, and the threat model still renders; only the mermaid validator coverage drops. Skip with `APPSEC_SKIP_VALIDATOR_CHECK=1` for known-good CI environments.

```bash
if [ "${APPSEC_SKIP_VALIDATOR_CHECK:-}" != "1" ]; then
  # The preflight MUST mirror the exact probe logic of the Layer-B validator
  # (scripts/mermaid_validate.mjs), otherwise it false-positives. Two rules:
  #   * jsdom — findJsdom() tries the scripts/ scope first, then the global
  #     /usr/lib/node_modules path. A global jsdom DOES satisfy the validator,
  #     so the preflight must accept it too.
  #   * mermaid core — findMermaidCore() does NOT require.resolve('mermaid');
  #     it existsSync()-probes for mermaid.core.mjs bundled inside
  #     @mermaid-js/mermaid-cli's node_modules (global mmdc install) plus two
  #     scripts/-local fallbacks. A bare require.resolve('mermaid', {paths:
  #     [scripts]}) never sees the mmdc-bundled copy and wrongly reports it
  #     missing — that was the false-positive this block previously had.
  JSDOM_OK="no"
  MERMAID_CORE_OK="no"
  if command -v node >/dev/null 2>&1; then
    eval "$(node --input-type=module -e "
      import { createRequire } from 'node:module';
      import { existsSync } from 'node:fs';
      import { join } from 'node:path';
      const scripts = '${CLAUDE_PLUGIN_ROOT}/scripts';
      const r = createRequire(scripts + '/package.json');
      let j='no', m='no';
      // jsdom: scripts/ scope, then global /usr/lib (same as findJsdom()).
      try { r.resolve('jsdom', { paths: [scripts] });                j='yes'; } catch {}
      if (j==='no') { try { r.resolve('jsdom', { paths: ['/usr/lib/node_modules'] }); j='yes'; } catch {} }
      // mermaid core: existsSync probe list identical to findMermaidCore().
      const cands = [
        '/usr/lib/node_modules/@mermaid-js/mermaid-cli/node_modules/mermaid/dist/mermaid.core.mjs',
        '/usr/local/lib/node_modules/@mermaid-js/mermaid-cli/node_modules/mermaid/dist/mermaid.core.mjs',
        join(scripts, 'node_modules/@mermaid-js/mermaid-cli/node_modules/mermaid/dist/mermaid.core.mjs'),
        join(scripts, 'node_modules/mermaid/dist/mermaid.core.mjs'),
      ];
      for (const p of cands) if (existsSync(p)) { m='yes'; break; }
      console.log('JSDOM_OK=' + j + ' MERMAID_CORE_OK=' + m);
    " 2>/dev/null)"
  fi
  MMDC_OK="no"
  command -v mmdc >/dev/null 2>&1 && MMDC_OK="yes"
  if [ "$JSDOM_OK" = "no" ] || [ "$MERMAID_CORE_OK" = "no" ] || [ "$MMDC_OK" = "no" ]; then
    MISSING=""
    NPM_PKGS=""
    [ "$JSDOM_OK" = "no" ]         && { MISSING="$MISSING jsdom";   NPM_PKGS="$NPM_PKGS jsdom"; }
    [ "$MERMAID_CORE_OK" = "no" ]  && { MISSING="$MISSING mermaid"; NPM_PKGS="$NPM_PKGS mermaid"; }
    [ "$MMDC_OK" = "no" ]          && MISSING="$MISSING @mermaid-js/mermaid-cli"
    printf '\n⚠ Optional QA validators missing:%s\n' "$MISSING" >&2
    printf '  To install (worth it — these caught 24 Mermaid breakages a regex-only run shipped on 2026-05-24):\n' >&2
    # Only print install line(s) for what is actually missing. mermaid core is
    # normally satisfied by the mmdc-bundled copy, so NPM_PKGS usually reduces
    # to just `jsdom`; a global mmdc install is irrelevant noise when present.
    [ -n "$NPM_PKGS" ] && printf '    npm install --prefix %s/scripts%s\n' "$CLAUDE_PLUGIN_ROOT" "$NPM_PKGS" >&2
    [ "$MMDC_OK" = "no" ] && printf '    npm install -g @mermaid-js/mermaid-cli\n' >&2
    printf '  Without these, qa_checks.py mermaid_syntax falls back to a regex-only check that has\n' >&2
    printf '  documented false-negatives (sequenceDiagram quoted aliases, unbalanced parens in graph\n' >&2
    printf '  labels). The threat model still renders, but mermaid bugs may ship to the final report.\n' >&2
    printf '  Suppress this warning: export APPSEC_SKIP_VALIDATOR_CHECK=1\n\n' >&2
  fi
fi
```

Behaviour contract:
- Both dependencies present → silent, run proceeds normally.
- One or both missing → single stderr block listing what's missing plus copy-pasteable install commands, then the run proceeds (non-blocking).
- **Console relay (do not summarize away):** when the banner fires, your console message to the user MUST include the exact `npm install …` command(s) printed for what's missing — not just "validators missing, non-blocking". The whole ask is a one-liner with real value (the Layer-B jsdom+mermaid parser catches grammar breakages the regex pass misses), so surface it verbatim rather than condensing it out.
- `node` itself absent → the `command -v node` guard short-circuits and `JSDOM_OK=no` is reported; the user sees that the runtime is needed before either npm package can be installed.
- `APPSEC_SKIP_VALIDATOR_CHECK=1` → the entire block is skipped, no stderr output. Intended for CI pipelines where the maintainer has accepted the regex-only fallback as the run's QA contract.

This is the cheapest possible signal: ~50 ms when both deps are present (two `command -v` plus one `node -e`), zero output. The fully-detailed install / verification flow lives in the planned `/appsec-advisor:check-validators` skill (see roadmap); this block intentionally does NOT duplicate that work — it just surfaces the gap.

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
| `--html` | `WRITE_HTML=true` (calls `scripts/export_html.py` after all stages — see HTML Export below) | `false` |
| `--requirements` | `CHECK_REQUIREMENTS=true` | from config `enabled` |
| `--requirements <url>` | `CHECK_REQUIREMENTS=true`, `REQUIREMENTS_URL_OVERRIDE=<url>` | from config `enabled` |
| `--no-requirements` | `CHECK_REQUIREMENTS=false` | from config `enabled` |
| `--dry-run` | `DRY_RUN=true` | `false` |
| `--no-confirm` / `--yes` | `NO_CONFIRM=true` — skip confirmation prompts for destructive cleanup modes. | `false` |
| `--resume` | Resume from last checkpoint | n/a |
| `--incremental` | `INCREMENTAL=true` — assertion that a baseline exists (hard abort otherwise) | auto-detected from baseline |
| `--full` | `INCREMENTAL=false` — force full scan even when prior output exists. Conflicts with `--incremental`. Preserves prior `changelog[]` history and surfaces a delta against the previous baseline in the completion summary. | `false` |
| `--rebuild` | `REBUILD=true` — superset of `--full`: wipes prior model (md/yaml/sarif), cache (`.appsec-cache/`), and all intermediate files before running, then performs a fresh full assessment with no history carry-over. No delta computation, no T-ID stability. Conflicts with `--incremental` and `--resume`. Redundant with `--full` (implicitly forces full). | `false` |
| `--rerender` | `RERENDER=true` (`MODE=rerender`) — re-render Stage 2 + re-run Stage 3 QA from the EXISTING Stage-1 fragments; skips Stage 1 and the incremental no-op gate. Requires a structured baseline (hard abort otherwise). For fragment / renderer / QA / contract changes — NOT for source-code changes (use `--incremental`/`--full`). Conflicts with `--full`, `--incremental`, `--rebuild`, `--resume`. | `false` |
| `--keep-runtime-files` | `KEEP_RUNTIME_FILES=true` (suppresses Phase 11 cleanup of transient artifacts — useful for debugging) | `false` |
| `--max-resumes <N>` | `MAX_STAGE1_RESUMES=<N>` — hard cap on automatic Stage 1 resume dispatches after turn-budget cut-offs. `0` disables resume entirely (single-shot run). See "Handling turn-budget cut-offs" below. | `1` |
| `--max-wall-time <duration>` | `MAX_WALL_TIME_SECONDS=<seconds>` — hard wall-time deadline for the watchdog (for example `3600`, `60m`, `1h`). | (none) |
| `--max-cost <usd>` | `MAX_COST_USD=<float>` — hard cumulative cost deadline for the watchdog. | (none) |
| `--repo <path>` | `REPO_ROOT=<abs-path>` | current working directory |
| `--output <path>` | `OUTPUT_DIR=<abs-path>` | `$REPO_ROOT/docs/security` |
| `--reasoning-model <mode>` | `REASONING_MODEL=<sonnet\|opus-cheap\|opus\|sonnet-economy>` → resolves to `STRIDE_MODEL`, `TRIAGE_MODEL`, `MERGER_MODEL` plus the extended-agent matrix | `sonnet-economy` at quick (since 2026-05); `opus-cheap` at standard/thorough (see Reasoning Model Resolution) |
| `--stride-model <model>` | `STRIDE_MODEL=<model>` (punctual override, applied **after** `--reasoning-model` resolution) | (none — inherits from `--reasoning-model`) |
| `--no-opus` | Forbid Opus anywhere; downgrades every Opus selection (incl. the `opus`/`opus-cheap` tier merger and the architect default) to Sonnet. Applied **last** in `resolve_config.py`, so it overrides `--reasoning-model opus`, `--stride-model`, and any `APPSEC_*_MODEL` env override. Also settable org-wide via org-profile `policy.disable_opus`, or via env `APPSEC_DISABLE_OPUS=1`. The three sources OR together — any can enable, none can disable. | off (Opus allowed) |
| `--assessment-depth <level>` | `ASSESSMENT_DEPTH=<quick\|standard\|thorough>` | `standard` |
| `--quick` | shortcut for `--assessment-depth quick`; also sets `SKIP_QA=true` and `SKIP_ATTACK_WALKTHROUGHS=true` (mutually exclusive with `--thorough`) | n/a |
| `--thorough` | shortcut for `--assessment-depth thorough` (mutually exclusive with `--quick`) | n/a |
| `--architect-review` | `ARCHITECT_REVIEW=true` — enables Stage 4 (advisory architect-level review) | auto-on at `--assessment-depth thorough`, off otherwise |
| `--no-architect-review` | `ARCHITECT_REVIEW=false` — escape hatch to disable Stage 4 even at `--assessment-depth thorough` | n/a |
| `--architect-model <sonnet\|opus>` | `ARCHITECT_MODEL=<model>` — model for Stage 4 (ignored when `ARCHITECT_REVIEW=false`) | `opus` when Stage 4 is enabled |
| `--no-enrich-arch` | `ENRICH_ARCH_FRAGMENTS=false` — force deterministic architecture fragments at any depth. | depth-based |
| `--enrich-arch` | `ENRICH_ARCH_FRAGMENTS=true` — force LLM-enriched architecture fragments at any depth. | depth-based |
| `--verbose` | `VERBOSE_REPORT=true` — also writes a per-user marker file that flips `agent_logger.py` into stderr-mirroring mode for the duration of this run (see "Verbose Mode — Marker File Lifecycle" below) | `false` |
| `--tracing` / `--no-tracing` | `TRACING=true` (default since M3.6) — writes a per-user marker file that activates per-agent token/turn/cost/wall-time tracking in `.appsec-trace.log`. At session end, `agent_logger.py` appends an ASSESSMENT_TRACE Markdown table to `.appsec-trace.log` (see "Tracing Mode — Marker File Lifecycle" below). Pass `--no-tracing` to disable. | `true` |
| `--base <ref>` | `BASE_REF=<ref>` — git ref to diff HEAD against for incremental mode (default: `commit_sha` recorded in the prior `threat-model.yaml`). Used in MR/PR mode to target the base branch. | (baseline commit) |
| `--pr-mode` | `PR_MODE=true` — produce a focused delta report limited to components affected by the `--base ... HEAD` diff. Implies `--incremental` and skips Stage 3 QA. | `false` |
| `--no-qa` | `SKIP_QA=true` — skip the Stage 3 QA reviewer (faster CI runs where the report is machine-consumed). Also honoured via `APPSEC_SKIP_QA=1` and implied by `--assessment-depth quick`. | `false` at standard/thorough; `true` at quick |
| `--qa-scan-repo` | `QA_SCAN_REPO=true` — compatibility flag for historical deep repo-scan behaviour. The expensive QA Pass 2c remains retired in the QA prompt; the flag is retained only so configuration summaries and older CI invocations stay stable. | `false` |
| `--no-walkthroughs` | `SKIP_ATTACK_WALKTHROUGHS=true` — skip authoring `attack-walkthroughs.md` in Stage 2; the composer renders §3 with chain-overview-only fallback (no per-finding sequenceDiagram blocks). Saves ~1-2 min in Stage 2. Also implied by `--assessment-depth quick`. | `false` at standard/thorough; `true` at quick |
| `--abuse-cases` | `skip_abuse_case_verification=false` — force the Stage 1c abuse-case verifier fan-out ON at any depth (overrides the quick-depth default-off). Conflicts with `--no-abuse-cases`. | on at standard/thorough; off at quick |
| `--no-abuse-cases` | `skip_abuse_case_verification=true` — force the Stage 1c abuse-case verifier fan-out OFF at any depth (skips matcher + verifiers + chain fold even at standard/thorough; §9 renders the not-applicable catalog and no finding is chain-elevated). Conflicts with `--abuse-cases`. | on at standard/thorough; off at quick |
| `--scan-manifest` | `SCAN_MANIFEST=true` — write a sorted, newline-separated list of every file the recon-scanner processed to `$OUTPUT_DIR/.scan-manifest.txt`. Useful for auditing which files were and weren't included in the assessment. | `false` |
| _(no CLI flag)_ | `APPSEC_PLUGIN_DEV=1` — show auto-fix suggestions and `/appsec-advisor:fix-run-issues` hints in the completion summary's Run Issues block. Off by default; intended for plugin developers working on appsec-advisor itself. Set in `.claude/settings.json → env` in the plugin repo. | `false` |

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
# Resolve cfg silently. We deliberately do NOT call --config-summary here —
# the canonical user-visible "what is about to happen" surface is the
# consolidated Run Plan box rendered AFTER the pre-check + dirty-set + compat
# gates have refined the verdict. Showing the user-argv-resolution box here
# would just describe the inputs, then the Run Plan box would describe the
# actual pipeline a few Bash calls later — two boxes for one decision is
# the exact "summary multiple times" complaint we are fixing.
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

**The user-visible run plan is rendered later** (after the incremental pre-check, dirty-set check, and analysis-version compat gate have all completed) by ``resolve_config.py --run-plan``. That box reflects the FINAL verdict — what the pipeline will actually run, not the raw argv resolution — and is the one the LLM emits as response text. See the "Run Plan box" section right before "## Full-Scan Recommendation Prompt" below.

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
| ``stride_model`` / ``triage_model`` / ``merger_model`` | str | ``"claude-sonnet-4-6"`` / ``"claude-sonnet-4-6"`` / ``"claude-opus-4-7"`` (at default ``opus-cheap``) |
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
RERENDER=$(echo "$RESOLVED_JSON" | python3 -c "import json,sys;print(str(json.load(sys.stdin).get('rerender',False)).lower())")
# Auto-upgraded-full recon reuse: set by resolve_config on the depth-increase /
# requirements-added overrides (NOT on explicit --full or first run). Tells the
# recon gate it may skip Phase 2 when the tree is git-provably clean. See
# phase-group-recon.md "Incremental fingerprint skip".
RECON_REUSE_ELIGIBLE=$(echo "$RESOLVED_JSON" | python3 -c "import json,sys;print(str(json.load(sys.stdin).get('reuse_recon_eligible',False)).lower())")
# Full-M1: parallel STRIDE fan-out at the skill (Level-0) instead of serial
# inline STRIDE inside a single Level-1 analyst. DEFAULT-ON for from-scratch
# runs (full/rebuild) — no env var needed. Opt-OUT with APPSEC_PARALLEL_STRIDE=0
# (falls back to the serial inline analyst). Incremental/rerender runs use
# STRIDE-delta, not the fan-out, so they are never parallelised here. The
# graceful fallback in dispatch step 3b still catches a manifest defect at
# runtime, so default-on degrades to serial rather than hard-failing.
PARALLEL_STRIDE=false
if { [ "$MODE" = "full" ] || [ "$MODE" = "rebuild" ]; } && [ "${APPSEC_PARALLEL_STRIDE:-1}" != "0" ]; then
  PARALLEL_STRIDE=true
fi
# Capture the RAW env value ONCE for the forensic PARALLEL_STRIDE_RESOLVED line
# below (the `-` form, not `:-`, shows `unset` distinctly from empty). Reuse this
# named variable in the log line — do NOT re-inline `${APPSEC_PARALLEL_STRIDE:-N}`
# there. The resolution above defaults to 1 (`:-1`); a display that re-applies a
# default drifts from the truth (the 2026-06-04 pstride-e2e run logged `=1` while
# the var was genuinely unset). The whole point of this diagnostic is to tell
# "env set" from "default applied" — so it must show the raw env, not the default.
PARALLEL_STRIDE_ENV="${APPSEC_PARALLEL_STRIDE-unset}"
# Live-phase console surfacing (opt-in, experimental). When on, Stage 1 (and
# Stage 2) are dispatched run_in_background so the Level-0 orchestrator stays
# unblocked and can drive a per-phase TaskUpdate from a Monitor on the phase
# log — the only way to render the live phase on the MAIN console (a blocking
# foreground Agent call queues all async output until it returns; verified by
# spike 2026-06-04). Env-gated so the default (foreground) flow is byte-
# unchanged. Mutually exclusive with PARALLEL_STRIDE for v1 (that path already
# surfaces per-component STRIDE rows and has its own A/B split); PARALLEL_STRIDE
# wins when both are set.
LIVE_PHASE=false
if [ "${APPSEC_LIVE_PHASE:-0}" = "1" ] && [ "$PARALLEL_STRIDE" = "false" ]; then
  LIVE_PHASE=true
fi
DRY_RUN=$(echo "$RESOLVED_JSON" | python3 -c "import json,sys;print(str(json.load(sys.stdin)['dry_run']).lower())")
OUTPUT_DIR=$(echo "$RESOLVED_JSON" | python3 -c "import json,sys;print(json.load(sys.stdin)['output_dir'])")
REPO_ROOT=$(echo "$RESOLVED_JSON"  | python3 -c "import json,sys;print(json.load(sys.stdin)['repo_root'])")
# …etc. for ARCHITECT_REVIEW, WRITE_YAML, etc.

# Reasoning core models (existing)
STRIDE_MODEL=$(echo "$RESOLVED_JSON" | python3 -c "import json,sys;print(json.load(sys.stdin)['stride_model'])")
TRIAGE_MODEL=$(echo "$RESOLVED_JSON" | python3 -c "import json,sys;print(json.load(sys.stdin)['triage_model'])")
MERGER_MODEL=$(echo "$RESOLVED_JSON" | python3 -c "import json,sys;print(json.load(sys.stdin)['merger_model'])")

# Extended-model routing (sonnet-economy tier — see AGENTS.md).
# These default to claude-sonnet-4-6 when --reasoning-model is not sonnet-economy
# (preserves backward-compat). When sonnet-economy is active, individual fields
# resolve to claude-haiku-4-5 according to the per-depth routing matrix.
CONTEXT_RESOLVER_MODEL=$(echo "$RESOLVED_JSON" | python3 -c "import json,sys;print(json.load(sys.stdin).get('context_resolver_model','claude-sonnet-4-6'))")
RECON_SCANNER_MODEL=$(echo   "$RESOLVED_JSON" | python3 -c "import json,sys;print(json.load(sys.stdin).get('recon_scanner_model','claude-sonnet-4-6'))")
QA_ROUTINE_MODEL=$(echo      "$RESOLVED_JSON" | python3 -c "import json,sys;print(json.load(sys.stdin).get('qa_routine_model','claude-sonnet-4-6'))")
QA_CONTENT_MODEL=$(echo      "$RESOLVED_JSON" | python3 -c "import json,sys;print(json.load(sys.stdin).get('qa_content_model','claude-sonnet-4-6'))")
CONFIG_SCANNER_MODEL=$(echo  "$RESOLVED_JSON" | python3 -c "import json,sys;print(json.load(sys.stdin).get('config_scanner_model','claude-sonnet-4-6'))")
ORCHESTRATOR_MODEL=$(echo    "$RESOLVED_JSON" | python3 -c "import json,sys;print(json.load(sys.stdin).get('orchestrator_model','claude-sonnet-4-6'))")

# STRIDE depth profile (Quick-mode A-F reductions, only when
# --reasoning-model sonnet-economy AND --assessment-depth quick).
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

## Re-Render Mode (`--rerender`) — skip Stage 1, re-render + re-QA from existing fragments

**When `RERENDER=true` (`MODE=rerender`), take this branch and SKIP everything between here and "## Stage 2 — Report Rendering"** — the Incremental Pre-Check, the Incremental Fast-Path (null-change abort), the Resume-from-Checkpoint section, **Stage 1**, and **Stage 1c**. Re-render mode trusts the on-disk Stage-1 artifacts as canonical, re-runs only the LLM-cheap render + the full Stage-3 QA gate (incl. the Re-Render Loop), and never re-analyzes source. It is the right tool when a fragment was hand-edited or the renderer/QA/contract logic changed; it is the **wrong** tool when source code changed (use `--incremental`/`--full` then).

**Why this branch exists / what it bypasses:** the Incremental Fast-Path below runs "before anything else" and would null-change-abort an unchanged repo, and a `--full` run would re-run Stage 1 and regenerate every fragment. Re-render needs neither — it explicitly re-renders the existing fragments. This branch is therefore evaluated **before** the fast-path.

**Step R1 — precondition gate (hard).** Re-render needs a complete Stage-1 artifact set on disk. Verify all of the following exist; if any is missing, print the banner and exit 2 (do not fall through to Stage 1):

```bash
MISSING=""
for f in threat-model.yaml .threats-merged.json .triage-flags.json; do
  [ -f "$OUTPUT_DIR/$f" ] || MISSING="$MISSING $f"
done
FRAG_COUNT=$(find "$OUTPUT_DIR/.fragments" -maxdepth 1 -type f 2>/dev/null | wc -l)
[ "$FRAG_COUNT" -ge 3 ] || MISSING="$MISSING .fragments/(>=3)"
if [ -n "$MISSING" ]; then
  printf '\n✗ --rerender needs an existing assessment to re-render.\n' >&2
  printf '  Missing under %s:%s\n' "$OUTPUT_DIR" "$MISSING" >&2
  printf '  Run a full/standard assessment first; --rerender then re-renders\n' >&2
  printf '  its fragments. For source-code changes use --incremental or --full.\n\n' >&2
  exit 2
fi
```

**Step R2 — acquire the lock** exactly as a normal run does (the skill owns the lock across Stage 2 + Stage 3; same `acquire_lock.py` call + skill_watchdog spawn used before the Stage-2 dispatch below).

**Step R3 — proceed directly to "## Stage 2 — Report Rendering".** Dispatch `appsec-advisor:appsec-threat-renderer` with the **identical** prompt/config the normal post-Stage-1 flow uses (REPO_ROOT, OUTPUT_DIR, WRITE_SARIF, ASSESSMENT_DEPTH, models, etc.). The renderer reuses the existing `.fragments/`, `.threats-merged.json`, `.triage-flags.json`, `threat-model.yaml`, and `.abuse-case-verdicts.json` (it authors only the 2 MS JSON fragments + walkthroughs/posture and never regenerates analyst-authored fragments such as `security-architecture.md`). Then continue **unchanged** into the post-Stage-2 flow: pre-generation backstop + inline-shortcut hard gate + **Stage 3 QA + Re-Render Loop** (where a contract-drift triggers the `appsec-fragment-fixer`), then the Completion Summary.

**Do NOT** re-run the deterministic emitters (Phase 10 SCA etc.) — their outputs are already baked into the fragments/yaml (same rule as the Re-Render Loop, see §"AFTER the Stage-2 no-op gate"). **Do NOT** re-dispatch Stage 1c abuse-case verifiers — reuse the existing `.abuse-case-verdicts.json`.

---

## Incremental Pre-Check: reject incomplete baseline

> **Skip this entire section (and the Fast-Path + Resume + Stage 1/1c below) when `RERENDER=true`** — see "## Re-Render Mode" above.

When `MODE=incremental`, **before** anything else (fast-path, dirty-set, compat gate), refuse the run if the baseline `threat-model.yaml` was written during a budget-critical wrap-up — i.e. carries `meta.incomplete: true`. An incomplete baseline has unknown coverage (some components were skipped, some STRIDE categories never ran); building deltas on top of it would compound the gap silently, making it look like everything is fine when in fact whole vulnerability classes have never been analyzed.

```bash
if [ "$MODE" = "incremental" ] && [ -f "$OUTPUT_DIR/threat-model.yaml" ]; then
  # Match the line `  incomplete: true` (two-space indent under `meta:`).
  # We only check this single sentinel — the absence of the key on a clean
  # baseline returns no match (grep exits 1) and the run continues normally.
  if grep -qE '^  incomplete:\s*true\s*$' "$OUTPUT_DIR/threat-model.yaml" 2>/dev/null; then
    echo "" >&2
    printf '\033[31m✗ Incremental baseline is marked incomplete — refusing to continue\033[0m\n' >&2
    echo "" >&2
    echo "  The previous run did not finish normally (turn-budget exhausted, or" >&2
    echo "  a sub-agent triggered wrap-up). The resulting threat-model.yaml carries" >&2
    echo "  meta.incomplete: true and is not safe to use as an incremental baseline" >&2
    echo "  — coverage gaps in the baseline would propagate silently into the delta." >&2
    echo "" >&2
    SKIPPED_LINE=$(grep -E '^  wrap_up_skipped:' "$OUTPUT_DIR/threat-model.yaml" -A 10 2>/dev/null | head -6)
    if [ -n "$SKIPPED_LINE" ]; then
      echo "  Skipped in the prior run:" >&2
      echo "$SKIPPED_LINE" | sed 's/^/    /' >&2
      echo "" >&2
    fi
    echo "  Fix: re-run with --full to refresh the baseline. The next incremental" >&2
    echo "        run will then have a complete baseline to delta against." >&2
    echo "" >&2
    rm -f "${TMPDIR:-/tmp}/.appsec-verbose-$(id -u)" "${TMPDIR:-/tmp}/.appsec-tracing-$(id -u)"
    exit 2
  fi
fi
```

The check is intentionally placed before the fast-path null-change abort: even a no-op delta is wrong when built on an incomplete baseline (it would print "nothing changed" while masking the prior run's coverage gaps).

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
  set +e
  FAST_PATH_OUTPUT=$(python3 "$CLAUDE_PLUGIN_ROOT/scripts/baseline_state.py" $FAST_PATH_ARGS 2>/dev/null)
  FAST_PATH_EXIT=$?
  set -e

  # Classify the result into shell vars the LLM uses to render the banner
  # as response text (NOT via Bash echo — see "Pre-Check Banner" section
  # below). Claude Code's UI folds Bash output into "+N lines (ctrl+o
  # to expand)" once it crosses a few lines, which would bury the banner
  # at the exact moment the user needs to see it. Surfacing through the
  # response stream sidesteps the fold.
  case "$FAST_PATH_EXIT" in
    0)  PRE_CHECK_DECISION=noop ;;
    2)  PRE_CHECK_DECISION=noise ;;
    10) PRE_CHECK_DECISION=plugin-drift ;;
    1)  PRE_CHECK_DECISION=changes ;;
    *)  PRE_CHECK_DECISION=skip ;;   # exit 3 or unrecognised — fall through to full flow
  esac
  export PRE_CHECK_DECISION FAST_PATH_OUTPUT FAST_PATH_EXIT

  # CI mode honours the drift signal silently for plugin-drift only —
  # interactive sessions get the full banner + I/F/A prompt below.
  if [ "$PRE_CHECK_DECISION" = "plugin-drift" ] && [ "${APPSEC_CI_MODE:-}" = "1" ]; then
    echo "  CI mode: plugin-drift detected; aborting (trigger a dedicated --full refresh job)."
    rm -f "${TMPDIR:-/tmp}/.appsec-verbose-$(id -u)" "${TMPDIR:-/tmp}/.appsec-tracing-$(id -u)"
    exit 0
  fi
fi
```

### Component Dirty-Set Pre-Check (refines the verdict for `changes`)

When ``PRE_CHECK_DECISION=changes`` we still need to know **which components**
the relevant files actually touch. A relevant file may be a top-level global
manifest (``package.json``, ``Dockerfile`` at repo root) — adding a dependency
there shifts the threat surface in principle but maps to no specific component
path glob in ``threat-model.yaml``. The threat-analyst would take its internal
No-Op Delta fast-path on that input, but only after spending ~2-3 minutes
warming up Phase 1. We beat it to that decision at the skill level by mapping
the relevant files against ``components[].paths`` in pure Python — no agent,
no token spend.

```bash
DIRTY_SET_OUTPUT=""
DIRTY_SET_EXIT=""
DIRTY_SET_DECISION="skip"
if [ "$PRE_CHECK_DECISION" = "changes" ]; then
  REL_FILES=$(echo "$FAST_PATH_OUTPUT" | python3 -c '
import json, sys
d = json.load(sys.stdin)
for f in d.get("security_relevant_changes", []) or []:
    print(f)
')
  DIRTY_SET_OUTPUT=$(printf '%s\n' "$REL_FILES" \
    | python3 "$CLAUDE_PLUGIN_ROOT/scripts/baseline_state.py" dirty-set \
        --output-dir "$OUTPUT_DIR" 2>/dev/null || true)
  DIRTY_SET_EXIT=$?
  case "$DIRTY_SET_EXIT" in
    0)  DIRTY_SET_DECISION=dirty ;;
    2)  DIRTY_SET_DECISION=noop_global_only ;;
    3)  DIRTY_SET_DECISION=ambiguous ;;
    *)  DIRTY_SET_DECISION=skip ;;
  esac
fi
export DIRTY_SET_OUTPUT DIRTY_SET_EXIT DIRTY_SET_DECISION
```

When ``DIRTY_SET_DECISION=noop_global_only`` the skill must fast-abort exactly
like ``PRE_CHECK_DECISION=noop`` / ``noise`` — every relevant file is a
top-level global manifest, no component glob matches, the threat-analyst
would have produced an empty changelog after burning Phase 1's budget. The
final verdict and the user-visible reasoning land in the consolidated
**Run Plan box** rendered below.

The same pre-check is performed by ``scripts/run-headless.sh`` at shell
level, so CI runners can fast-abort *before* even spawning Claude Code. The
in-skill version is a safety net for interactive invocations.

### Pre-flight summary — render in your response (LLM-side, no extra Bash)

**Render trigger — mandatory in every mode.** The LLM emits the consolidated
``Threat Model — Pre-flight`` summary **directly as response text** as soon as
`RESOLVED_JSON` is set AND the analysis-version compat gate has set
`COMPAT_LABEL` (see the next section). This is the user's only "what is
about to happen" surface before Stage 1 dispatch — never skip it.

`PRE_CHECK_DECISION` and `DIRTY_SET_DECISION` are populated **only when
`MODE=incremental`** (see the §"Fast-Path Pre-Check" block above — both are
wrapped in `if [ "$MODE" = "incremental" ]`). In full / rebuild / first-run
mode both variables are intentionally empty — that absence is itself the
signal that the verdict is `RUN — full assessment` (the explicit Full-Run
row in the verdict mapping below). Empty pre-check vars are NOT a reason
to skip the render.

| Mode at this point | PRE_CHECK_DECISION | DIRTY_SET_DECISION | Action |
|---|---|---|---|
| `incremental` | set (noop / noise / changes / plugin-drift / skip) | set when `changes` | render summary using verdict-mapping table |
| `full` / `rebuild` / first run | (empty) | (empty) | render summary using the "RUN — full assessment" row |

**Why no separate Bash call to render the summary:** every Bash tool result
gets folded by the Claude Code UI into a `+N lines (ctrl+o to expand)`
widget. If the summary is computed by Bash, the user sees it twice
(once folded, once visible in the response). Computing the summary on the
LLM side from the JSONs the LLM already has — `FAST_PATH_OUTPUT`,
`DIRTY_SET_OUTPUT`, `COMPAT_LABEL` — gives a single visible copy.

The Python helper `resolve_config.py --run-plan` (see source for the
field-substitution rules and verdict logic) is still the canonical
formatter and is exercised by the `/appsec-advisor:status` and
`/appsec-advisor:threat-model-health` skills. The create-threat-model
skill bypasses the Bash call and follows the same template inline.

#### Verdict mapping (read off `PRE_CHECK_DECISION:DIRTY_SET_DECISION`)

| Pre-check | Dirty-set | Verdict line | Pipeline line | Will run? |
|---|---|---|---|---|
| `noop`        | (n/a)              | `NO-OP — no source changes; pipeline skipped` | `SKIPPED (no agents will run)` | no |
| `noise`       | (n/a)              | `NOISE-ONLY — pipeline skipped`               | `SKIPPED (no agents will run)` | no |
| `plugin-drift`| (n/a)              | `PLUGIN-DRIFT — plugin upgraded (B → C, tier=T)` | `PROMPT (interactive) / ABORT (CI)` | no (interactive prompt below) |
| `changes`     | `noop_global_only` | `NO-OP — relevant changes touch no component` | `SKIPPED (no agents will run)` | no |
| `changes`     | `noop_empty_input` | `NO-OP — relevant list empty after mapping`   | `SKIPPED (no agents will run)` | no |
| `changes`     | `dirty`            | `RUN — N component(s) dirty`                  | `change check -> recon -> STRIDE delta (<ids>) -> triage -> render -> QA` | yes |
| `changes`     | `ambiguous`        | `AMBIGUOUS — possible new component`          | `change check -> recon -> STRIDE delta -> triage -> render -> QA` | yes |
| `changes`     | `skip` (error)     | `RUN — incremental (delta scope unresolved)`  | (incremental pipeline)                                                   | yes |

For `--full` / `--rebuild` / first-run paths the verdict is `RUN — full
assessment` and the pipeline is `recon -> architecture -> STRIDE -> triage
-> render -> QA` (plus QA / architect review when those flags are on).

**Full scan over an existing model — the `Reason` line is MANDATORY.** When a
complete prior `threat-model.yaml` exists (`baseline_state` ∈ {`structured`,
`legacy`}) and the run is nonetheless full, the verdict line is `RUN — full
assessment (existing model)` and the `Reason` MUST name *why* the incremental
fast-path was not taken — never leave it implicit. Apply this precedence (the
same logic as `resolve_config.py:_full_over_existing_reason`):

| Trigger | Reason text |
|---|---|
| assessment depth increased vs baseline | `existing model was built at '<base>' depth; --assessment-depth <cur> requested — incremental cannot deepen carried-forward components, so a full re-assessment runs` (auto-incremental → full; set by `resolve_incremental_mode`, highest precedence) |
| security requirements newly requested vs baseline | `existing model was built WITHOUT a security-requirements check; --requirements now requested — incremental cannot add requirement coverage to carried-forward components, so a full re-assessment runs` (auto-incremental → full; set by `resolve_incremental_mode` as `mode_upgraded_reason`. The reverse — dropping `--requirements` on a requirements-built baseline — is a **hard abort**, not an auto-upgrade; see Incremental Mode) |
| `COMPAT_LABEL=incompatible` | `existing model present, but its analysis_version is incompatible with this plugin — full rebuild required` |
| `COMPAT_LABEL=older-compatible` | `existing model present; analysis schema drifted (older but compatible) — full refresh applies new categories to all findings` |
| plugin tier ∈ {minor, major} | `existing model present; plugin upgraded (<tier>) — full refresh re-applies updated analysis to all components` |
| mode upgraded by the Full-Scan Recommendation Prompt | the upgrade trigger that fired (`MODE_UPGRADED_REASON` — e.g. broad delta / plugin drift / schema drift) |
| `--rebuild` | `wipes prior model + cache, no T-ID stability` |
| explicit `--full` (no other trigger) | `existing model present; --full requested — complete re-assessment (changelog history preserved)` |

(First-run / `baseline_state=empty` keeps `RUN — full assessment` with reason
`no prior threat-model.yaml in output dir — first full assessment`; no
"existing model" suffix.)

#### Summary template

Substitute the bracketed `<...>` fields from `RESOLVED_JSON`,
`FAST_PATH_OUTPUT`, `DIRTY_SET_OUTPUT`, and the verdict mapping. Skip a
section entirely when its precondition is false (per the conditional
comments). Section headers stand alone; key/value rows are indented with
two spaces. Section blocks are separated by a single blank line.

```
Threat Model — Pre-flight

Target
  Repository: <repo_root>
  Output    : <output_dir>

Plugin
  Version   : appsec-advisor <plugin_version> (analysis v<analysis_version>)
  <if plugin tier ∈ {minor, major}:>Baseline  : <baseline> (tier=<tier>)  ⚠ DRIFT
  <if compat ∉ {equal, None}:>Schema    : analysis_version drift: <compat_label>
  Mode      : <mode_line>

Decision
  Verdict   : <verdict>
  Pipeline  : <pipeline>
  Reason    : <reason>

<if pre-check has files (sec_count + noise_count + excluded > 0):>
Files
  Total seen: <sec + noise + excluded>
  Excluded  : <excluded_pre_filter_count> (plugin output / scan-excludes)
  Noise     : <noise_count> (docs / format-only / non-security)
  Relevant  : <security_relevant_change_count>
  <if dirty_set:>Components: <K> known, <D> dirty (<ids>), <K-D> carried forward

<if security_relevant_changes is non-empty:>
<if will_run:>Why this run is going to launch
<else:>Why this run will NOT execute Stage 1+2+3
  • <file>  [<comma-joined first 3 reasons from relevance_reasons[file]>]
  ... (cap at 6; if more, "  • … and M more")

<if will_run:>Configuration
  Depth     : <depth_summary — see _format_depth_summary>
  Reasoning : <reasoning_summary>
  <if PARALLEL_STRIDE=true:>STRIDE disp: parallel (per-component fan-out, Level-0; default)
  <elif mode∈{full,rebuild} AND APPSEC_PARALLEL_STRIDE=0:>STRIDE disp: serial inline (disabled via APPSEC_PARALLEL_STRIDE=0)
  <if LIVE_PHASE=true:>Live phase : on (background dispatch + console phase)
  <elif env APPSEC_LIVE_PHASE=1 (set but PARALLEL_STRIDE active):>Live phase : requested — inactive (PARALLEL_STRIDE wins)
  <active options if any (Outputs / Extras / Skips / Run flags / STRIDE / Limits)>

Notes
  • <note 1>
  • <note 2>
  ...
```

**Notes** content (concatenate, in this order, those whose precondition is true):

  • `will_run=True` → `"Ctrl-C now to abort before any tokens are spent."`
  • `will_run=True ∧ mode != full/rebuild` → `"Pass --full to widen the scope to a complete re-assessment."`
  • `will_run=False` → `"threat-model.md preserved as-is."`
  • `will_run=False` → `"Pass --full to force a complete re-assessment regardless."`
  • `plugin tier=major` → `"STRONGLY consider --full — major plugin bump may contain breaking analysis changes that incremental cannot retro-apply."`
  • `plugin tier=minor` → `"Consider --full — minor plugin bumps usually ship analysis improvements that only affect newly-scanned code in incremental."`
  • `compat=older-compatible` → `"Analysis schema drifted (baseline analysis_version older but compatible) — full rebuild applies new categories to ALL findings."`
  • `cfg.repo_size_capped=True` → `"STRIDE component count capped at <N> (would have been 5) due to large repo (<S> source files)."`

The rendered summary goes verbatim into the response text — no
``` code fence around it. Section headers (`Target`, `Plugin`, `Decision`, ...)
are the visible structure; the leading `Threat Model — Pre-flight` heading
identifies the block to the user.

#### Per-decision next step after rendering the summary

```bash
case "$PRE_CHECK_DECISION:$DIRTY_SET_DECISION" in
  noop:* | noise:* | changes:noop_global_only | changes:noop_empty_input)
    # Missing-export backstop. The repo is unchanged so the pipeline is
    # skipped — but the user may have added an export flag (--pdf / --html)
    # whose artifact does not exist yet from a prior run. The existing
    # threat-model.md is final and canonical, so we can produce the missing
    # export directly (deterministic, no LLM, no stages) instead of forcing a
    # pointless full re-scan. Only generate artifacts that are REQUESTED AND
    # ABSENT; an already-present export is left untouched.
    #   • PDF / HTML derive purely from threat-model.md → produced here.
    #   • SARIF (--sarif) is a Stage-2 RENDER product, not a post-stage export;
    #     if it is requested-but-missing, re-rendering is required — tell the
    #     user to re-run with --rerender rather than silently doing nothing.
    if [ "${WRITE_PDF:-false}" = "true" ] && [ ! -f "$OUTPUT_DIR/threat-model.pdf" ]; then
      printf '\n  No source changes — reusing existing threat model; requested PDF is missing, generating it now.\n' >&2
      # UNSANDBOXED: mermaid → headless Chrome needs socket() (see PDF Export §). Non-fatal.
      python3 "$CLAUDE_PLUGIN_ROOT/scripts/export_pdf.py" \
        --input "$OUTPUT_DIR/threat-model.md" --output "$OUTPUT_DIR/threat-model.pdf" \
        2>&1 | tee -a "$OUTPUT_DIR/.agent-run.log" >&2 || true
    fi
    if [ "${WRITE_HTML:-false}" = "true" ] && [ ! -f "$OUTPUT_DIR/threat-model.html" ]; then
      printf '\n  No source changes — reusing existing threat model; requested HTML is missing, generating it now.\n' >&2
      python3 "$CLAUDE_PLUGIN_ROOT/scripts/export_html.py" \
        --input "$OUTPUT_DIR/threat-model.md" --output "$OUTPUT_DIR/threat-model.html" \
        2>&1 | tee -a "$OUTPUT_DIR/.agent-run.log" >&2 || true
    fi
    if [ "${WRITE_SARIF:-false}" = "true" ] && [ ! -f "$OUTPUT_DIR/threat-model.sarif.json" ]; then
      printf '\n  Note: --sarif requested but threat-model.sarif.json is absent. SARIF is a render product;\n  re-run with --rerender to regenerate it from the existing Stage-1 artifacts.\n' >&2
    fi
    rm -f "${TMPDIR:-/tmp}/.appsec-verbose-$(id -u)" "${TMPDIR:-/tmp}/.appsec-tracing-$(id -u)"
    exit 0
    ;;
  *)
    : # fall through to compat gate / recommendation prompt / Stage 1
    ;;
esac
```

`plugin-drift` falls into the `*)` branch on purpose — interactive runs
continue to the Full-Scan Recommendation Prompt below; CI runs already
exited in the pre-check Bash (see "Skill-level dirty-set Pre-Check"
section above).

## Full-Scan Recommendation Prompt (auto-incremental only)

After the fast-path and the Plugin Version Compatibility Gate, and **before** the Stage 1 Handoff Banner, evaluate whether the user should be offered a chance to switch to a full scan. This prompt fires **only** when all of the following are true:

1. `INCREMENTAL_IS_AUTO=true` — mode was auto-detected, not explicitly requested via `--incremental`
2. At least one recommendation trigger is present (see table below)
3. `NO_CONFIRM=false` — `--no-confirm` / `--yes` was not passed
4. `APPSEC_CI_MODE` is not `1`
5. stdin is a TTY (`[ -t 0 ]`)

| Trigger | Variable | Condition |
|---------|----------|-----------|
| Analysis-version drifted | `COMPAT_LABEL` | `older-compatible` (baseline yaml's `analysis_version` is older but compatible with the current plugin) |
| Plugin-version drifted | `PLUGIN_TIER` | `minor` \| `major` (semver bump even if `analysis_version` did not move — the runtime prompts / heuristics may still be different) |
| Broad source delta | `SEC_CHANGE_COUNT` vs `MAX_STRIDE_COMPONENTS` | security-relevant file count is large relative to the operational component ceiling: `SEC_CHANGE_COUNT / MAX_STRIDE_COMPONENTS >= 0.8` (integer: `SEC_CHANGE_COUNT * 10 / MAX_STRIDE_COMPONENTS >= 8`) — a broad delta where a full scan gives better T-ID stability |
| Critical / attack-surface change | `CRITICAL_CHANGE_COUNT` | one or more changed files are high-blast-radius: **security primitives** (auth / crypto / session / validation / CORS / CSP) **or** **trust-boundary & I/O surface** (new/changed routes, endpoints, controllers, interfaces, GraphQL/gRPC/OpenAPI, serializers, schemas) **or** **architecture / data model** (middleware, gateways, adapters, ORM/entities, model files, migrations); `security_critical_change_count > 0` from the fast-path. The incremental dirty-set maps such a file to a single component and carries every other component forward — but a new route or a shared-code change expands or shifts the attack surface in ways a delta scope never re-models. Fires **regardless of count** (a single such file is enough). |

```bash
# Only evaluate when mode was auto-detected incremental.
if [ "$MODE" = "incremental" ] && [ "$INCREMENTAL_IS_AUTO" = "true" ] \
    && [ "$NO_CONFIRM" = "false" ] \
    && [ "${APPSEC_CI_MODE:-}" != "1" ] \
    && [ -t 0 ]; then

  # Collect trigger reasons.
  PROMPT_REASONS=""
  BASELINE_PLUGIN=$(echo "$FAST_PATH_OUTPUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("plugin_version",{}).get("baseline","?"))' 2>/dev/null || echo '?')
  CURRENT_PLUGIN=$(echo  "$FAST_PATH_OUTPUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("plugin_version",{}).get("current","?"))' 2>/dev/null || echo '?')
  PLUGIN_TIER=$(echo     "$FAST_PATH_OUTPUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("plugin_version",{}).get("tier","?"))' 2>/dev/null || echo '?')

  if [ "$COMPAT_LABEL" = "older-compatible" ]; then
    PROMPT_REASONS="${PROMPT_REASONS}    • Analysis schema drifted (baseline analysis_version is older but compatible) — full rebuild ensures new categories / CWE remappings apply to ALL findings, not just newly-scanned code\n"
  elif [ "$PLUGIN_TIER" = "major" ]; then
    PROMPT_REASONS="${PROMPT_REASONS}    • Plugin upgraded ${BASELINE_PLUGIN} → ${CURRENT_PLUGIN} (MAJOR) — STRIDE prompts / heuristics likely changed; carried-forward threats use the old reasoning\n"
  elif [ "$PLUGIN_TIER" = "minor" ]; then
    PROMPT_REASONS="${PROMPT_REASONS}    • Plugin upgraded ${BASELINE_PLUGIN} → ${CURRENT_PLUGIN} (minor) — analysis improvements ship in minors and only apply to newly-scanned code in incremental mode\n"
  fi

  SEC_CHANGE_COUNT=$(echo "$FAST_PATH_OUTPUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("security_relevant_change_count",0))' 2>/dev/null || echo 0)
  # Integer arithmetic: count*10/max >= 8  ⟺  count/max >= 0.8
  if [ "$(( SEC_CHANGE_COUNT * 10 / MAX_STRIDE_COMPONENTS ))" -ge 8 ] && [ "$SEC_CHANGE_COUNT" -gt 0 ]; then
    PROMPT_REASONS="${PROMPT_REASONS}    • ${SEC_CHANGE_COUNT} security-relevant files changed (broad delta vs the ${MAX_STRIDE_COMPONENTS}-component operational ceiling) — full scan gives better T-ID stability at similar cost\n"
  fi

  # Critical / attack-surface change — fires on a SINGLE file. Security
  # primitives (auth/crypto/session/validation) OR trust-boundary & I/O surface
  # (new/changed routes, endpoints, interfaces, schemas) OR architecture/data
  # model (middleware, gateway, adapter, ORM, model, migration). A delta scope
  # re-examines just the one component the file's path-glob matched.
  CRITICAL_CHANGE_COUNT=$(echo "$FAST_PATH_OUTPUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("security_critical_change_count",0))' 2>/dev/null || echo 0)
  CRITICAL_SAMPLE=$(echo "$FAST_PATH_OUTPUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(", ".join(d.get("security_critical_changes",[])[:3]))' 2>/dev/null || echo '')
  if [ "$CRITICAL_CHANGE_COUNT" -gt 0 ]; then
    PROMPT_REASONS="${PROMPT_REASONS}    • ${CRITICAL_CHANGE_COUNT} critical / attack-surface file(s) changed (${CRITICAL_SAMPLE}) — security primitive, route/interface, or architecture/model change with system-wide blast radius; incremental only re-scans the one matching component and carries dependents forward\n"
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
        # Carry the trigger that justified the upgrade into the re-rendered
        # Pre-flight Reason line (§"Full scan over an existing model"). Collapse
        # the first PROMPT_REASONS bullet to a one-liner; fall back to a generic
        # phrase. The post-upgrade summary surfaces this so a full scan over an
        # existing model is never unexplained.
        MODE_UPGRADED_REASON=$(printf '%b' "$PROMPT_REASONS" | sed -n 's/^[[:space:]]*•[[:space:]]*//p' | head -1)
        [ -z "$MODE_UPGRADED_REASON" ] && MODE_UPGRADED_REASON="auto-incremental upgraded to full at user request"
        MODE_UPGRADED_REASON="existing model present; switched to full — ${MODE_UPGRADED_REASON}"
        ;;
    esac
  fi
fi

# Non-interactive backstop for the critical / attack-surface trigger. The
# prompt above is interactive-only (CI / --no-confirm / non-TTY all skip it),
# but a security-primitive, route/interface, or architecture/model change is a
# CORRECTNESS concern, not a preference — so even when we cannot prompt we
# still (a) print a visible advisory and (b) set
# RECOMMEND_FULL=true so Phase 11 renders the "consider --full" callout in the
# report and sets meta.recommend_full_rerun. We do NOT silently force a full
# scan in CI: that could 10× an automated run's cost/time on a 1-line change.
if [ "$MODE" = "incremental" ] && [ "$INCREMENTAL_IS_AUTO" = "true" ] \
    && { [ "$NO_CONFIRM" = "true" ] || [ "${APPSEC_CI_MODE:-}" = "1" ] || [ ! -t 0 ]; }; then
  CRITICAL_CHANGE_COUNT=$(echo "$FAST_PATH_OUTPUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("security_critical_change_count",0))' 2>/dev/null || echo 0)
  if [ "$CRITICAL_CHANGE_COUNT" -gt 0 ]; then
    CRITICAL_SAMPLE=$(echo "$FAST_PATH_OUTPUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(", ".join(d.get("security_critical_changes",[])[:3]))' 2>/dev/null || echo '')
    printf '\n⚠ %s critical / attack-surface file(s) changed (%s) — security primitive, route/interface, or architecture/model change; incremental re-scans only the matching component and carries dependents forward.\n  Consider re-running with --full. (Set meta.recommend_full_rerun in this run.)\n' "$CRITICAL_CHANGE_COUNT" "$CRITICAL_SAMPLE" >&2
    RECOMMEND_FULL=true
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

**Replaced by the Pre-flight summary** rendered at the §"Pre-flight summary — render in your response (LLM-side, no extra Bash)" section above. The legacy `resolve_config.py --config-summary` Python renderer still exists (covered by `tests/test_resolve_config.py`) and is invoked by the `/appsec-advisor:status` and `/appsec-advisor:threat-model-health` skills — but the create-threat-model skill no longer prints it. Showing both would render the same configuration twice (once via `--config-summary`, once via the Pre-flight summary that follows a few Bash calls later — the "summary multiple times" complaint that drove the 2026-05-09 consolidation).

The `resolve_config.py --emit-file` call at the Configuration Resolution section above writes `.skill-config.json` silently — it does NOT print a Configuration Summary box (see the explicit comment at that call site: *"We deliberately do NOT call --config-summary here"*).

**Mode upgrade re-render.** If the Full-Scan Recommendation Prompt above mutated `MODE` from incremental → full, the user has already seen the Pre-flight summary with the pre-upgrade verdict. The skill MUST re-render the Pre-flight summary (NOT a separate Configuration Summary) so the post-upgrade state is visible:

```bash
if [ "$MODE_UPGRADED_BY_PROMPT" = "true" ]; then
  # Re-derive RESOLVED_JSON / FAST_PATH_OUTPUT for the upgraded mode so the
  # re-render reflects the actual --full pipeline that will run.
  RESOLVED_JSON=$(python3 "$CLAUDE_PLUGIN_ROOT/scripts/resolve_config.py" --emit-file $RESOLVE_ARGS --full)
fi
```

Then re-emit the Pre-flight summary per the §"Summary template" rules above, prefixed with the line `Pre-flight (post mode-upgrade)`. The verdict is now `RUN — full assessment (existing model)`, and its `Reason` line MUST be the `MODE_UPGRADED_REASON` captured at the switch (per the §"Full scan over an existing model" precedence table) — so the user sees exactly why the existing model is being fully re-scanned. Do **not** call `--config-summary` here — it would print the legacy Configuration Summary on top of the new Pre-flight summary, recreating the exact duplication this consolidation removed.

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
    .architect-review.md, .threat-modeling-context.md, .recon-summary.md
    .sca-practice-findings.json, .known-bad-libs-findings.json
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
     -o -name ".threat-modeling-context.md" -o -name ".recon-summary.md" \
     -o -name ".sca-practice-findings.json" -o -name ".known-bad-libs-findings.json" \
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

The fix is to acquire the lock **at the skill level** — once, before the first Agent dispatch — so the file always exists for the duration of the run. The orchestrator's own per-phase `--heartbeat` calls then see a present lock and refresh it normally. A blocked lock is fatal for this invocation: starting the heartbeat after `LOCK_BLOCKED` refreshes a lock this run does not own and makes headless `--resume` look idle instead of failed.

```bash
set +e
LOCK_OUTPUT=$(python3 "$CLAUDE_PLUGIN_ROOT/scripts/acquire_lock.py" "$OUTPUT_DIR/.appsec-lock" 2>&1)
LOCK_EXIT=$?
set -e
printf '%s\n' "$LOCK_OUTPUT" | head -1
if [ "$LOCK_EXIT" != "0" ]; then
  printf '%s\n' "$LOCK_OUTPUT" >&2
  printf 'Refusing to start because another assessment appears active for OUTPUT_DIR=%s\n' "$OUTPUT_DIR" >&2
  printf 'If no assessment is running, inspect or clean with: python3 "%s/scripts/check_state.py" "%s" --clean\n' \
      "$CLAUDE_PLUGIN_ROOT" "$OUTPUT_DIR" >&2
  exit 3
fi
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

### Live-phase Monitor (opt-in, experimental — `APPSEC_LIVE_PHASE=1`)

A second background helper, distinct from the watchdog, that surfaces the **live phase on the main console**. The watchdog writes progress to files only; the Monitor turns each phase-log line into a console notification that wakes the (now-unblocked) orchestrator so it can mirror the phase name via `TaskUpdate`.

- **Why it requires background dispatch.** A blocking foreground `Agent` call queues ALL async console output (Monitor events, text) until it returns — so the live phase would only appear *after* Stage 1 finished (verified by the 2026-06-04 spike). The `LIVE_PHASE` variant therefore dispatches Stage 1 with `run_in_background: true` (see Stage-1 dispatch step 3 → "Live-phase variant") and the orchestrator stays free to react to Monitor events.
- **Command / start / stop:** see Stage-1 dispatch **step 2b** (start, captures `LIVE_PHASE_MONITOR_ID`) and **step 4** (stop, beside the watchdog `TaskStop`). The grep alternation deliberately covers progress markers (`PHASE_START/END`, `STRIDE_PROGRESS`) AND every failure/terminal marker (`STRIDE_STALE`, `STRIDE_CANARY_TIMEOUT`, `STRIDE_COMPONENT_TIMEOUT`, `WRAP_UP_TRIGGERED`, `AGENT_ERROR`, `TOOL_ERROR`) so a stalled/crashed run is never silent.
- **Failure modes** — same posture as the watchdog: a missed start is degraded observability; a missed stop is backstopped by the Monitor's `timeout_ms` (1 h) and self-ends when the log's directory is cleaned.
- **v1 scope: Stage 1 only.** The same pattern is applicable to Stage 2 (renderer) and Stage 3/4, but is intentionally NOT wired there yet — the background dispatch + resume-on-notification control flow is new and unproven; Stage 1 (~25 min) carries almost all the payoff. Promote to Stage 2+ only after a real run confirms the Stage-1 path is reliable. PARALLEL_STRIDE runs ignore `LIVE_PHASE` (that path already shows per-component STRIDE rows and has its own A/B split; combining the two is deferred). **The parallel path is NOT label-less, though:** it sets three coarse phase-group labels via `TaskUpdate` at its existing dispatch seams (Stage-1 dispatch steps 3a/3c/3d — "Phases 1–8", "Phase 9 — STRIDE (N)", "Phases 9–10b") with no background dispatch or Monitor. That is the cheap, zero-risk middle ground between "Stage 1" opacity and full per-phase live ticking; the latter still needs the background rewrite gated behind `LIVE_PHASE` and remains serial-only.

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
  # Fix #2b — deadline START is initially ASSESSMENT_START_EPOCH (set just
  # before Stage 1 dispatch) but gets RE-DERIVED from the orchestrator's
  # first ASSESSMENT_START log line as soon as that line appears. The
  # initial value includes any wait time on the user's permission prompt
  # before the Agent tool actually launches — without the re-derivation a
  # --max-wall-time deadline would fire prematurely after a slow approve.
  DEADLINE_LOOP_CMD='
    START='$ASSESSMENT_START_EPOCH'
    MAX_WT='${MAX_WALL_TIME_SECONDS:-0}'
    MAX_COST='${MAX_COST_USD:-0}'
    LOG="'"$OUTPUT_DIR/.agent-run.log"'"
    REFINED_START=false
    while [ -f "'"$OUTPUT_DIR/.appsec-lock"'" ]; do
      if [ "$REFINED_START" = false ] && [ -f "$LOG" ]; then
        # Replace the bash-captured START with the actual orchestrator
        # ASSESSMENT_START timestamp the first time the log is non-empty.
        REAL_START=$(python3 -c "
import re, datetime
ts_re = re.compile(r\"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s.*ASSESSMENT_START\b\")
try:
    with open(\"$LOG\", encoding=\"utf-8\", errors=\"replace\") as fh:
        for line in fh:
            m = ts_re.match(line)
            if m:
                dt = datetime.datetime.strptime(m.group(1), \"%Y-%m-%dT%H:%M:%SZ\").replace(tzinfo=datetime.timezone.utc)
                print(int(dt.timestamp()))
                break
except OSError:
    pass
" 2>/dev/null)
        if [ -n "$REAL_START" ] && [ "$REAL_START" -gt 0 ]; then
          START=$REAL_START
          REFINED_START=true
        fi
      fi
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

### Deterministic route-inventory + architecture-coverage pre-pass (skill-level enforcement)

`phase-group-recon.md` §2.6 instructs the Stage 1 analyst to run `route_inventory.py` and `architecture_coverage_checks.py` "unconditionally" — but that is an LLM prompt, and under the `STAGE1_PHASE_LIMIT=8` parallel-STRIDE split (and under turn pressure generally) the analyst sometimes skips them. When `.route-inventory.json` is absent, `build_threat_model_yaml.py:build_attack_surface` gets an **empty baseline** and falls back to whatever finding-relevant entry points the analyst hand-authored into `.attack-surface-overrides.json` — typically a dozen vuln-focused, mostly-unauthenticated routes. The symptom is a report whose §5 Attack Surface lists only a handful of authenticated endpoints even though the app exposes dozens (2026-06-04 juice-shop: 4 authenticated rendered vs. 52 detected across 112 real routes).

These three scripts are pure deterministic pattern extraction (~1 s, no LLM, no tokens), so the skill owns them as a hard pre-pass rather than trusting the analyst. Run them **before the Stage 1 dispatch** so `.route-inventory.json` exists when the analyst's Phase 6 reads it AND when Analyst-B's Phase 11 yaml-write composes `attack_surface[]`. Idempotent — a later analyst re-run is a harmless overwrite. Skip only in `--rerender` mode (Stage 1 is bypassed, the inventory from the prior run is reused) and `--dry-run` (sub-1-minute synthetic run). In incremental mode it still runs (the baseline route set is cheap to recompute and a route added/removed since baseline is exactly what an incremental delta wants to see).

`source_auth_scanner.py` is the deterministic broken-access-control scanner (`data/source-auth-checks.yaml` → AUTHZ-001..008: BOLA / IDOR / mass assignment / JWT algorithm-confusion / missing route auth). Its output `.source-auth-findings.json` is ingested by `merge_threats.py:_load_source_auth_findings` into the same `.threats-merged.json` candidate pool the STRIDE analyzer feeds, so the findings flow through triage, evidence verification, and rendering like any other threat. The ingest is file-presence-gated and was already wired end-to-end; this pre-pass is what produces the file (without it the scanner never runs and the eight high-precision authz checks are dead). Run it here — beside the route inventory and under the same guards — for the same reason: an LLM-prompt instruction is unreliable under turn pressure.

```bash
if [ "$DRY_RUN" != "true" ] && [ "$RERENDER" != "true" ]; then
  python3 "$CLAUDE_PLUGIN_ROOT/scripts/route_inventory.py" \
      --repo-root "$REPO_ROOT" --output-dir "$OUTPUT_DIR" >/dev/null 2>&1 || true
  python3 "$CLAUDE_PLUGIN_ROOT/scripts/architecture_coverage_checks.py" \
      --repo-root "$REPO_ROOT" --output-dir "$OUTPUT_DIR" >/dev/null 2>&1 || true
  python3 "$CLAUDE_PLUGIN_ROOT/scripts/source_auth_scanner.py" \
      --repo-root "$REPO_ROOT" --output-dir "$OUTPUT_DIR" --quiet >/dev/null 2>&1 || true
  if [ -f "$OUTPUT_DIR/.route-inventory.json" ]; then
    RI_COUNT=$(python3 -c "import json;print(len((json.load(open('$OUTPUT_DIR/.route-inventory.json')) or {}).get('routes') or []))" 2>/dev/null || echo 0)
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   skill  ROUTE_INVENTORY_PREPASS  .route-inventory.json ready (${RI_COUNT} routes)" \
        >> "$OUTPUT_DIR/.agent-run.log"
  else
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  WARN   skill  ROUTE_INVENTORY_PREPASS  route_inventory.py produced no .route-inventory.json — Phase 6 will fall back to the sidecar additions only" \
        >> "$OUTPUT_DIR/.agent-run.log"
  fi
  if [ -f "$OUTPUT_DIR/.source-auth-findings.json" ]; then
    SAF_COUNT=$(python3 -c "import json;print((json.load(open('$OUTPUT_DIR/.source-auth-findings.json')) or {}).get('violations') or 0)" 2>/dev/null || echo 0)
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   skill  SOURCE_AUTH_PREPASS  .source-auth-findings.json ready (${SAF_COUNT} authz finding(s))" \
        >> "$OUTPUT_DIR/.agent-run.log"
  fi
fi
```

Behaviour contract:
- **`.route-inventory.json` produced** → Phase 6 / yaml-write use it as the deterministic `attack_surface[]` baseline (full route set with per-route `authn_signal`); the analyst's sidecar `additions[]` only add finding-specific entry points on top.
- **Extractor finds no routes** (non-web repo, unsupported framework) → empty inventory, the sidecar-only fallback applies exactly as before; non-fatal.
- **Script error** (`|| true`) → non-fatal; the analyst's own Phase 2.6 attempt is the second line of defence, and a genuinely empty baseline still renders via the sidecar additions.
- **`.source-auth-findings.json` produced** → `merge_threats.py` ingests every AUTHZ-NNN finding into the threat-merge candidate pool; absent file → non-fatal, STRIDE-only authz coverage as before.

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
  $( [ "$(python3 -c "import json;print(json.load(open('$OUTPUT_DIR/.skill-config.json')).get('skip_abuse_case_verification',False))" 2>/dev/null)" = "True" ] && echo "--skip-abuse-cases" ) \
  --output-dir "$OUTPUT_DIR" \
  --repo-root "$REPO_ROOT" \
  --max-stride-components "$MAX_STRIDE_COMPONENTS" \
  --sec-change-count "${SEC_CHANGE_COUNT:-0}" \
  2>/dev/null )

# Pure-Python JSON extraction — `jq` is not a hard dependency of the skill,
# and the previous `jq -r '.field // "fallback"'` form failed silently on
# Alpine / slim Docker / vanilla WSL images, leaving the variables empty
# strings instead of falling back. The handoff banner then rendered as
# ``Stage 1: ~ min, total: ~ — `` which is the exact symptom this guards
# against. See Fix #1 (root cause).
_est_get() { python3 -c "import json,sys; raw=sys.stdin.read().strip() or '{}'
try: d=json.loads(raw)
except Exception: d={}
print(d.get('$1', '$2'))" <<< "$EST_JSON" 2>/dev/null; }
EST_TOTAL=$(_est_get total_pretty "~25 min")
EST_STAGE1=$(_est_get stage1_min 25)
EST_STAGE2=$(_est_get stage2_min 8)
EST_STAGE3=$(_est_get stage3_min 7)
EST_STAGE4=$(_est_get stage4_min 4)
EST_SOURCE=$(_est_get source parametric)
# Cache for use across stage handoffs (later banners read these env vars).
export EST_STAGE1 EST_STAGE2 EST_STAGE3 EST_STAGE4 EST_TOTAL EST_SOURCE

# Capture the run-start epoch so the post-stage-3 completion block can
# write the actual wall-clock back into .appsec-cache/baseline.json
# (last_run_seconds — used by the next run's estimator). This is the
# anchor point for all per-run timing in the skill.
ASSESSMENT_START_EPOCH=$(date +%s)
export ASSESSMENT_START_EPOCH

# Persist the same epoch to a marker file that survives the whole run, so the
# Completion Summary can compute the TRUE end-to-end wall-clock (now - start).
# A file is required because shell state does not persist across the skill's
# separate Bash calls, and .agent-run.log's ASSESSMENT_START line is unreliable
# for this — it gets overwritten by each analyst dispatch under the
# parallel-STRIDE split, so a log-derived start under-counts the scan. Written
# unconditionally at every real-run start (overwrites any stale prior value, so
# the next run never inherits a wrong baseline). Early no-op/abort paths never
# reach this line and render no completion summary, so they need no marker.
printf '%s' "$ASSESSMENT_START_EPOCH" > "$OUTPUT_DIR/.scan-start-epoch" 2>/dev/null || true

# Source badge — distinguishes a measured-from-prior-run estimate from
# the formula fallback so the user knows how trustworthy it is.
SOURCE_HINT=""
case "$EST_SOURCE" in
  last_run_cache)        SOURCE_HINT="from last run on this repo" ;;
  resume_checkpoint)     SOURCE_HINT="remaining after checkpoint"  ;;
  incremental_dirty_set) SOURCE_HINT="incremental, $SEC_CHANGE_COUNT relevant file(s), ceiling $MAX_STRIDE_COMPONENTS components" ;;
  parametric)            SOURCE_HINT="parametric" ;;
esac
```

Then print a blank line and the Stage 1 handoff banner. When `VERBOSE_REPORT=true` is resolved, append a single hint line so the user knows where the extra output is going to appear:

```
▶ Stage 1/<total_stages> — Threat Analysis & Triage starting  (Stage 1: ~<EST_STAGE1> min, total: ~<EST_TOTAL> — <SOURCE_HINT>)
```

When `VERBOSE_REPORT=true`, add one extra line directly underneath (exactly this text, no other variants):
```
  ℹ Verbose mode ON — STEP_START/END, SCAN_START/END, and AGENT_INVOKE lines mirror live to stderr (~20 s poll cadence during Phase 9).
  ℹ Note: stderr is visible in headless `claude -p` mode and in the agent run log (.agent-run.log). Interactive UI may suppress it; use /appsec-advisor:status --live or tail .appsec-progress.json/.agent-run.log in a second terminal for live progress.
```

Where:
- `<total_stages>` is the number of pipeline stages that will actually run: start with `2` for Stage 1 (orchestrator) + Stage 2 (composition), add `1` when `SKIP_QA=false` and `DRY_RUN=false`, and add `1` when `ARCHITECT_REVIEW=true` and `DRY_RUN=false`. Therefore normal quick runs without architect review show `2`; standard runs with QA and no architect review show `3`; thorough runs with QA + architect review show `4`; `--no-qa` without architect review shows `2`.
- `<EST_STAGE1>` and `<EST_TOTAL>` are the integers extracted above; the helper guarantees a sensible fallback when any input is missing.
- `<SOURCE_HINT>` annotates how the estimate was produced. `parametric` means "first run on this repo, formula-only"; subsequent runs use the cached prior measurement and read `from last run on this repo`.

No other text — no explanatory prose, no duplicated mode description — belongs between these lines. The verbose-mode hints are the single exception, and only when the flag is actually on.

**M3.1 UX limitation:** The `Agent` tool dispatches Stage 1 in foreground and blocks the chat for the full duration (~25 min standard, ~40 min thorough). Phase and step events update `.appsec-progress.json`; Phase 9 also emits watcher progress. **Opt-in mitigation:** `APPSEC_LIVE_PHASE=1` switches Stage 1 to a background dispatch + live-phase Monitor that renders the current phase on the main console (experimental — see §"Live-phase Monitor" and the Stage-1 "Live-phase variant"). For runs without it, live phase is still observable in a second terminal via `/appsec-advisor:status --live` or by tailing `.agent-run.log`.

### Stage Task List Bootstrap

Right after the handoff banner and **before** dispatching Stage 1, pre-create one `TaskCreate` task per stage. Stage 1 runs in the foreground (see "Dispatch" below), so its internal phases stream directly to the chat as the orchestrator executes tool calls — no per-phase task entries are needed. The stage tasks give the user a single top-level checklist to follow.

**This is the ONLY place `TaskCreate` is allowed in the skill.** No earlier `TaskCreate` call is permitted — not for `Resolve config`, not for `Render Pre-flight summary`, not for `Pre-generate structural fragments` (intra-Stage-1 since M2.12), not for per-phase Stage 1 entries. If you have already created tasks earlier in the run (e.g. nudged by a Claude Code "task tools haven't been used recently" reminder during the preamble), **delete them via `TaskUpdate` before continuing** so the TaskList reflects exactly the eight spec'd rows below (`Preparing workspace`, `Stage 1a …`, `Stage 1b …`, `Stage 1c …`, `Stage 2 …`, conditional `Stage 3 …`, conditional `Stage 4 …`, `Final summary + cleanup`) — later `TaskUpdate` calls (stage lifecycle, completion-summary spinner clear at the end of the skill) match by subject and will silently no-op on drift, leaving the spinner hung.

**Subjects must match verbatim.** The condition table below is the source of truth — do not paraphrase ("Stage 1 — dispatch appsec-threat-analyst" is wrong; the correct subject is "Stage 1a - Threat Analysis"). The exact strings are referenced by downstream `TaskUpdate` calls.

**Ordering invariant.** Task IDs are handed out monotonically by `TaskCreate`, so create the tasks in the exact order below.

```
TaskCreate subject="Preparing workspace"
           description="Cleared stale intermediate artifacts before Stage 1."
           activeForm="Preparing workspace"
           # mark completed immediately after creation — the wipe already ran
```

| Condition | Task subject | activeForm |
|-----------|--------------|------------|
| always | `Stage 1a - Threat Analysis` | `Running threat analysis` |
| always | `Stage 1b - Triage` | `Running triage` |
| `DRY_RUN=false` AND `skip_abuse_case_verification=false` | `Stage 1c - Abuse Case Verification` | `Verifying abuse-case chains` |
| always (M2.12) | `Stage 2 - Report Rendering` | `Rendering threat model report` |
| `SKIP_QA=false` AND `DRY_RUN=false` | `Stage 3 - QA Review` | `Running QA review` |
| `ARCHITECT_REVIEW=true` AND `DRY_RUN=false` | `Stage 4 - Architect Review` | `Running architect review` |
| `KEEP_RUNTIME_FILES=false` | `Final summary + cleanup` | `Writing final summary` |
| `KEEP_RUNTIME_FILES=true` | `Final summary` | `Writing final summary` |

**Final-row label is conditional on `KEEP_RUNTIME_FILES` (the `--keep-runtime-files` flag).** When runtime files are kept the post-pipeline transient-file cleanup is skipped (see "Post-summary cleanup" below), so the row must NOT advertise a cleanup step it will not perform — create it as `Final summary`. Otherwise create it as `Final summary + cleanup`. **Whichever subject you create, the closing `TaskUpdate` in "Post-summary cleanup" MUST use the SAME subject verbatim** (it matches by subject and silently no-ops on drift, which would hang the spinner). All other downstream references to this row resolve through that same `KEEP_RUNTIME_FILES` branch.

**Stage 1 is exposed as three `Stage 1a/1b/1c` sub-rows (2026-06).** Threat analysis and triage formally belong to one work family, so they share the Stage-1 number with a letter suffix rather than consuming integer stages 2–4. The split is honest about what can show *live* progress:

- `Stage 1a - Threat Analysis` and `Stage 1b - Triage` both run **inside the single `appsec-threat-analyst` dispatch** (`STAGE1_PHASE_LIMIT=10b`). The skill blocks on that one `Agent()` call and cannot drive a mid-dispatch transition, so both rows are marked `in_progress` together at dispatch and `completed` together on return — `1b` has no independent live phase (it is the analyst's Phase 10b). This is accepted: two static-but-truthful rows beat one opaque "Stage 1" row.
- `Stage 1c - Abuse Case Verification` is the one Stage-1 sub-step with a **separate skill-level dispatch** (sonnet verifier fan-out), so it earns a real `in_progress → completed` lifecycle, driven by the §"Stage 1c — Abuse Case Verification" section. Created only when `DRY_RUN=false`. It is already recorded as `--stage 1 --variant abuse-verification` in `.stage-stats.jsonl`, so the `1c` label matches the existing stats model. Subjects must match verbatim and use hyphen-minus, not em-dash (same TUI-width precedent as the other rows).

**Stage 2 is now always pre-created (M2.12 — Sprint 3).** Previously only the recovery-dispatch path created it. The skill now splits Phase 11 at the Substep-3 / Substep-4 boundary: `STAGE1_PHASE_LIMIT=10b` keeps the deterministic Substeps 1–3 (counts, yaml write, baseline cache) in Stage 1, while the LLM compose work (Substeps 4–N) goes into a separate `appsec-threat-renderer` session so render-only work does not carry the full analyst prompt.

Immediately after creation, call `TaskUpdate` to mark `Preparing workspace` as `completed` (it ran before this section).

**Skip bootstrap entirely** when `DRY_RUN=true` — the dry-run summary prints at the end anyway. For any non-dry-run invocation, run the bootstrap regardless of depth / mode.

## Resume from Checkpoint

If `--resume` is passed, check for `$OUTPUT_DIR/.appsec-checkpoint`:

### Resume freshness gate (mandatory)

Before inspecting the checkpoint contents, run the resume-guard helper to refuse-to-proceed when the checkpoint is stale. A `--resume` against a checkpoint that was left behind by a hung or crashed prior run will drop the new orchestrator into the same broken state (the historic 55-minute-hang scenario); we would rather force an explicit `--full` / `--rebuild` / `/appsec-advisor:clean-run-state` than perpetuate the hang silently.

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
- `status=started` or `status=aborted` AND checkpoint mtime > 15 min → **exit 3**. The helper prints a remediation line pointing at `/appsec-advisor:clean-run-state` and `--full` / `--rebuild`. The skill does not dispatch Stage 1.

### Checkpoint inspection (only reached when guard passed)

1. Read the checkpoint file. It contains `phase=<N> status=<started|completed|aborted> timestamp=<ISO>`.
2. Inform the user what was found:
   ```
   Checkpoint found: Phase <N> (<status>) at <timestamp>
     Available intermediate files:
       .threat-modeling-context.md : <exists|missing>
       .recon-summary.md          : <exists|missing>
       .sca-practice-findings.json : <exists|missing>
       .known-bad-libs-findings.json : <exists|missing>
       .stride-*.json             : <n files>
   ```
3. Ask the user whether to resume from the last completed phase or start fresh.
4. If resuming: pass `RESUME_FROM_PHASE=<N+1>` to the orchestrator (where N is the last completed phase). The orchestrator will skip completed phases and reuse existing intermediate files.
5. If starting fresh: proceed as normal (no `RESUME_FROM_PHASE`).

If no checkpoint exists and `--resume` was passed, inform the user and proceed with a fresh assessment.

### Requirements pre-fetch gate (deterministic, skill-level)

**Closes the requirements fail-open gap.** When a run asks to be checked against requirements (`CHECK_REQUIREMENTS=true`) the source must load or the run must abort — previously this was only soft prose in `appsec-context-resolver.md` ("stop immediately … the orchestrator will detect the missing context file"), and under turn pressure the agent sometimes wrote the context file anyway, so an unreachable URL slipped through and the run silently produced a report claiming a requirements check that never happened. This gate makes the fetch-or-abort mechanical: it resolves the active source (honouring the `fail_mode` contract — `fail_closed` for an explicit `--requirements <url>`, `cache_fallback` for org-profile/config) and writes `$OUTPUT_DIR/.requirements.yaml` for the context-resolver to reuse. On an unreachable explicit URL (or no remote + no cache) it **fail-closes** with exit 2. Skipped in `--rerender` (Stage 1 does not run).

```bash
if [ "$RERENDER" != "true" ]; then
  # Read the already-resolved decision from RESOLVED_JSON directly (these are
  # passed into the agent prompt, not necessarily exported as shell vars here),
  # and pass it through with --require so the fetcher never re-derives `enabled`
  # differently than the skill did (quick-depth defaults can diverge).
  REQ_CHECK=$(echo "$RESOLVED_JSON" | python3 -c "import json,sys;print(str(json.load(sys.stdin).get('check_requirements',False)).lower())")
  REQ_URL=$(echo "$RESOLVED_JSON" | python3 -c "import json,sys;print(json.load(sys.stdin).get('requirements_url_override') or '')")
  if [ "$REQ_CHECK" = "true" ]; then
    REQ_ARGS="--require"
    [ -n "$REQ_URL" ] && REQ_ARGS="--requirements $REQ_URL"
  else
    REQ_ARGS="--no-requirements"
  fi
  python3 "$CLAUDE_PLUGIN_ROOT/scripts/fetch_requirements.py" \
      --output-dir "$OUTPUT_DIR" \
      --plugin-root "$CLAUDE_PLUGIN_ROOT" \
      $REQ_ARGS
  REQ_FETCH_EXIT=$?
  if [ "$REQ_FETCH_EXIT" = "2" ]; then
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  ERROR  skill  REQUIREMENTS_UNAVAILABLE  CHECK_REQUIREMENTS=true but requirements could not be loaded — aborting" \
        >> "$OUTPUT_DIR/.agent-run.log"
    rm -f "$OUTPUT_DIR/.appsec-lock"
    rm -f "${TMPDIR:-/tmp}/.appsec-verbose-$(id -u)" "${TMPDIR:-/tmp}/.appsec-tracing-$(id -u)"
    exit 2
  fi
fi
```

The script prints a full diagnostic to stderr on abort (the unreachable URL, the `fail_mode`, and the remediation). On success `$OUTPUT_DIR/.requirements.yaml` is on disk and Step 2b of the context-resolver reuses it instead of fetching again.

## Stage 1 — Threat Analysis & Triage

> **⚠ ROUTING — read FIRST. `PARALLEL_STRIDE` was resolved during Configuration Resolution (default-ON for `MODE` ∈ {full, rebuild}; opt-OUT via `APPSEC_PARALLEL_STRIDE=0`).**
> - **If `PARALLEL_STRIDE=true`** → you MUST take the **Parallel-STRIDE split** (Full-M1): dispatch Analyst-A with `STAGE1_PHASE_LIMIT=8`, then run `build_stride_dispatch_manifest.py` → `validate_dispatch_manifest.py` → **fan out one `appsec-stride-analyzer` per component IN PARALLEL** → dispatch Analyst-B with `RESUME_FROM_PHASE=9-merge`. The full procedure is **step 3 → "Parallel-STRIDE variant"** below. Do **NOT** do the default single `STAGE1_PHASE_LIMIT=10b` dispatch in this case.
> - **If `PARALLEL_STRIDE=false` AND `LIVE_PHASE=false`** (opt-out `APPSEC_PARALLEL_STRIDE=0`, or incremental/rerender mode) → use the single-analyst foreground dispatch (step 3 → "Serial variant").
> - **If `PARALLEL_STRIDE=false` AND `LIVE_PHASE=true`** (opt-in `APPSEC_LIVE_PHASE=1`) → use the **background dispatch + live-phase Monitor** (step 3 → "Live-phase variant"); also start the Monitor in step 2b. `LIVE_PHASE` is never true when `PARALLEL_STRIDE=true` (mutually exclusive, resolved at Configuration Resolution).
> Verify the values before dispatching AND persist them for forensics (writes a canonical `PARALLEL_STRIDE_RESOLVED` line to `.agent-run.log`, updates `.appsec-progress.json`, and mirrors to stderr — so a post-mortem can tell at a glance which dispatch path was eligible to fire, without re-deriving it from spawn counts). **The `env APPSEC_PARALLEL_STRIDE=` field MUST be the raw `$PARALLEL_STRIDE_ENV` captured in the resolution block (value or `unset`) — never re-inline a `${APPSEC_PARALLEL_STRIDE:-N}` default here, or the line lies about whether a var was actually set:**
> ```bash
> python3 "$CLAUDE_PLUGIN_ROOT/scripts/log_event.py" "$OUTPUT_DIR" info \
>     PARALLEL_STRIDE_RESOLVED \
>     "PARALLEL_STRIDE=$PARALLEL_STRIDE LIVE_PHASE=$LIVE_PHASE (mode=$MODE, env APPSEC_PARALLEL_STRIDE=$PARALLEL_STRIDE_ENV)" \
>     --agent skill 2>/dev/null || true
> ```

**Architecture change in M2.12 / M3.8:** Stage 1 runs Phases 1–10b **plus the deterministic Phase 11 Substeps 1–3** (counts pre-compute, canonical `threat-model.yaml` write, baseline-cache update). The LLM-heavy Phase 11 Substeps 4–N (fragment authoring, `compose_threat_model.py`, QA, SARIF/pentest exports) are dispatched as a separate **Stage 2** renderer session so the budget-cheap deterministic prep work stays in Stage 1's natural flow while the expensive compose work gets its own fresh budget and a smaller prompt. The full contract lives in `agents/appsec-threat-analyst.md` → "STAGE1_PHASE_LIMIT — early-exit branch".

Invoke the `appsec-advisor:appsec-threat-analyst` agent using `"Threat Analysis & Triage"` as the Agent tool `description`. The orchestrator handles Phases 1–10b and Phase 11 Substeps 1–3 internally (recon, context, architecture, STRIDE, merge, triage, yaml write, baseline-cache update). The LLM compose work (Phase 11 Substeps 4–N) is handled by Stage 2. Do **not** invoke any other agent from the skill level here.

### Dispatch

By default Stage 1 runs as a **foreground** Agent call. The orchestrator's tool calls stream directly to the chat so the user sees progress inline (Phase banners, sub-agent dispatches, file writes). No `Monitor` for the foreground Agent itself, no notification choreography — but a **background heartbeat watchdog** runs in parallel (see "Skill-layer heartbeat watchdog" above). **Exception:** when `LIVE_PHASE=true` (opt-in `APPSEC_LIVE_PHASE=1`) the dispatch is instead `run_in_background` + a live-phase Monitor so the current phase renders on the main console — see step 3 → "Live-phase variant" and §"Live-phase Monitor" above.

0. **Snapshot prior artifact stats (all modes).** Capture `mtime + size` of `threat-model.yaml` and (if it exists) `threat-model.md` so the post-Stage-1 / post-Stage-2 gates can (a) detect a true no-op on incremental runs and (b) tell a freshly-rendered deliverable from a **stale prior** one. A full/rebuild re-run over an existing OUTPUT_DIR still has the previous `threat-model.md` on disk, so a bare `-f` existence check would misread a mid-Stage-1 death as success (DG-1). Capture in every mode; the cut-off detection below compares against this snapshot.
   ```bash
   YAML_PRE_STAGE1="missing"
   MD_PRE_STAGE1="missing"
   if [ -f "$OUTPUT_DIR/threat-model.yaml" ]; then
     YAML_PRE_STAGE1=$(stat -c '%Y:%s' "$OUTPUT_DIR/threat-model.yaml" 2>/dev/null \
                     || stat -f '%m:%z' "$OUTPUT_DIR/threat-model.yaml" 2>/dev/null \
                     || echo "missing")
   fi
   if [ -f "$OUTPUT_DIR/threat-model.md" ]; then
     MD_PRE_STAGE1=$(stat -c '%Y:%s' "$OUTPUT_DIR/threat-model.md" 2>/dev/null \
                   || stat -f '%m:%z' "$OUTPUT_DIR/threat-model.md" 2>/dev/null \
                   || echo "missing")
   fi
   export YAML_PRE_STAGE1 MD_PRE_STAGE1
   ```

1. **Mark the Stage-1 tasks `in_progress`.** Call `TaskUpdate` on **both** the `Stage 1a - Threat Analysis` and `Stage 1b - Triage` tasks to set status `in_progress` (skip if the bootstrap was not run, i.e. `DRY_RUN=true`). Both run inside this one analyst dispatch, so both go `in_progress` here and both go `completed` together on return (step 5) — `1b` has no separate live phase. Note: the TaskCreate subjects use hyphen-minus (`-`), not em-dash (`—`), because the TodoWrite TUI renderer mis-handles the em-dash's UTF-8 width (1 column / 3 bytes) on partial redraws — adjacent task labels visibly bleed into the em-dash position (e.g. `Final summary` + `Stage 3 — QA Review` rendered as `Final 3ummQA Review`). Same precedent: do not "fix" `-` → `—` in any of the eight stage subjects.

2. **Start the heartbeat watchdog (M3.4).** Issue the heartbeat-loop Bash command with `run_in_background: true` and capture the returned `task_id` in `HEARTBEAT_TASK_ID`. Skip when `DRY_RUN=true`. See the "Skill-layer heartbeat watchdog" section above for the exact command. The watchdog runs in parallel with the foreground Stage 1 dispatch and ensures `.appsec-lock` heartbeats fire every 60 s regardless of orchestrator activity.

2b. **Start the live-phase Monitor (only when `LIVE_PHASE=true` and `DRY_RUN=false`).** This drives the live-phase console display in the §"Live-phase variant" below. `Monitor` is a **deferred tool** — call `ToolSearch` with query `select:Monitor` before first use. Then start it and capture the returned `task_id` in `LIVE_PHASE_MONITOR_ID`:
   - command: `tail -n0 -F "$OUTPUT_DIR/.agent-run.log" 2>/dev/null | grep --line-buffered -E "PHASE_START|PHASE_END|STRIDE_PROGRESS|STRIDE_STALE|STRIDE_CANARY_TIMEOUT|STRIDE_COMPONENT_TIMEOUT|WRAP_UP_TRIGGERED|AGENT_ERROR|TOOL_ERROR"`
   - description: `"appsec Stage 1 — live phase"` (this is what the console renders per event; keep it meaningful because the per-line payload is NOT shown inline — the orchestrator reads the payload from the event notification and mirrors it via `TaskUpdate`, see §"Live-phase variant")
   - `timeout_ms: 3600000` (1 h backstop), `persistent: false`
   - `tail -n0` avoids replaying prior-run log history; `-F` (capital) survives the analyst's `>`-overwrite of `.agent-run.log` at `ASSESSMENT_START` and follows the file by name. Skip this step entirely when `LIVE_PHASE=false` (the default).

3. **Dispatch the orchestrator.**

   **— Parallel-STRIDE variant (`PARALLEL_STRIDE=true` — Full-M1, the DEFAULT for full/rebuild; opt-OUT via `APPSEC_PARALLEL_STRIDE=0`).** Instead of one monolithic analyst that inlines STRIDE serially, split Stage 1 so the skill (Level-0, can fan out) dispatches the per-component STRIDE analyzers in parallel:

   3a. **Analyst-A** — **Coarse phase-group label (C-lite, skip when `DRY_RUN=true`):** before dispatching, call `TaskUpdate` on the `Stage 1a - Threat Analysis` task to set `activeForm: "Phases 1–8 — recon → architecture → controls"`. This is the only console signal the user gets while Analyst-A is blocking (its internal per-phase `PHASE_START` lines go to `.agent-run.log`, NOT the parent console — a blocking foreground sub-agent's interior never streams). The three coarse labels in 3a/3c/3d are inserted at the natural dispatch seams the orchestrator already controls — no background dispatch, no Monitor, no `LIVE_PHASE`. (Per-phase live ticking would require backgrounding Analyst-A/B; intentionally out of scope here.) Then: Agent call `description: "Threat Analysis & Triage"`, prompt sets **`STAGE1_PHASE_LIMIT=8`** (+ normal config). It runs Phases 1–8 + the Phase-9 dispatch-prep, writes `.stride-analyst-context.json` + `.dispatch-context/<id>/`, then stops (see `agents/appsec-threat-analyst.md` → "STAGE1_PHASE_LIMIT=8 — Analyst-A branch"). Foreground/blocking.

   3b. **Build + validate the dispatch manifest** (deterministic, ~1 s):
   ```bash
   PS_FAIL=0
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/build_stride_dispatch_manifest.py" "$OUTPUT_DIR" \
       --depth "$ASSESSMENT_DEPTH" \
       --ceiling "$MAX_STRIDE_COMPONENTS" \
       --analyst-context "$OUTPUT_DIR/.stride-analyst-context.json" || PS_FAIL=1
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/validate_dispatch_manifest.py" \
       "$OUTPUT_DIR/.stride-dispatch-manifest.json" "$OUTPUT_DIR" || PS_FAIL=1
   ```
   **On `PS_FAIL=1` → graceful fallback (never hard-fail):** log `PARALLEL_STRIDE_FALLBACK` and dispatch a normal single `STAGE1_PHASE_LIMIT=10b` analyst with `RESUME_FROM_PHASE=9` (it re-runs STRIDE inline per the M1-lite escape clause + the rest of Stage 1). Skip 3c/3d. The default flow is unchanged, so a manifest defect degrades to today's behaviour — no regression.

   3c. **Fan out STRIDE analyzers in parallel.** **Coarse phase-group label (C-lite, skip when `DRY_RUN=true`):** after the manifest validates, call `TaskUpdate` on `Stage 1a - Threat Analysis` to set `activeForm: "Phase 9 — STRIDE (<N> components)"` where `<N>` is the manifest's `components[]` count. (The per-component `"STRIDE: <NAME>"` Agent rows below render natively in the subagent panel — this label just names the phase group above them.)

   **⚠ HARD CONSTRAINT — ONE MESSAGE, ALL COMPONENTS, NO EXCEPTIONS.** Read `.stride-dispatch-manifest.json`; collect ALL `components[]` entries; issue ALL `Agent` calls to `appsec-advisor:appsec-stride-analyzer` **in a SINGLE message turn** (multiple tool-use blocks in one response). This is NOT optional and NOT sequential: every component must be in the SAME message so Claude Code dispatches them concurrently. **DO NOT send one Agent call, wait for it to finish, then send the next.** That sequential pattern collapses the fan-out to a serial chain, multiplying wall-clock by N (observed in production: 6 components × ~4 min each = 27 min instead of 5 min parallel). Concrete check: if you are about to call Agent for component 2 AFTER component 1 returned, you have already violated this constraint — stop and re-read. The proven model is the Stage-1c abuse-verifier dispatch (SKILL-impl.md §"Stage 1c"): all verifiers dispatched in one message, all run concurrently.

   **Set each Agent call's `description` to `"STRIDE: <NAME>"`** (the component's `name` from the manifest entry — e.g. `"STRIDE: express-api"`) so the Claude Code subagent panel shows one labelled row per component being analyzed. The component name leads the string because the panel truncates. Map each manifest entry to the analyzer's prompt params (`COMPONENT_ID`/`NAME`/`DESCRIPTION`/`PATHS`/`COMPLEXITY`, `MAX_TURNS`, `INTERFACES`, `TRUST_BOUNDARIES`, `CONTROLS`, `KNOWN_*`, `TAXONOMY_SLICE_DIR`, and `*_INDEX_PATH` from `index_paths.*`). **Each dispatch prompt MUST also pass `REPO_ROOT`, `OUTPUT_DIR`, `CLAUDE_PLUGIN_ROOT`, and instruct the analyzer to `export OUTPUT_DIR=<value>` as its FIRST Bash call** — `agent_progress.sh` silently no-ops unless `OUTPUT_DIR` is a shell env var, so without the export the analyzer writes `.stride-<id>.json` but skips `.progress/<id>.json`, blinding the watchdog and (pre-fix) false-positiving `check_stride_dispatch.py`. Model = `STRIDE_MODEL`. Wait for all to return — each writes `.stride-<id>.json` + `.progress/<id>.json`. **Issuing the real per-component `Agent` calls here is what makes the run pass the post-Stage-1 gate.** `check_stride_dispatch.py` requires *count-based* dispatch evidence: at least as many `AGENT_SPAWN appsec-stride-analyzer` lines in `.hook-events.log` as the manifest has components (each `Agent` call emits exactly one). **The manifest's existence alone is NOT proof** — it is built in step 3b *before* this fan-out, so it survives a collapse where you build it and then inline STRIDE instead of dispatching; that is the precise failure the gate now catches (it would silently pass pre-2026-06-05). If the spawn count falls short, the gate falls through to the per-component `.progress/` check — so a genuinely-parallel run whose hooks under-logged is still saved by the `.progress/` files the `export OUTPUT_DIR` above guarantees, while a true inline-collapse (no spawns AND no `.progress/`) trips and aborts the run.

   **3c-retry — Stub detection and immediate re-dispatch (before Analyst-B).** After all STRIDE agents return, inspect every `.stride-<id>.json` for stub output BEFORE dispatching Analyst-B:

   ```bash
   STUB_COMPONENTS=""
   for f in "$OUTPUT_DIR"/.stride-*.json; do
     [ -f "$f" ] || continue
     cid=$(basename "$f" .json | sed 's/^\.stride-//')
     # A stub has threats=[] OR partial=true — both indicate turn-budget exhaustion.
     IS_STUB=$(python3 -c "
   import json, sys
   try:
     d = json.load(open('$f'))
     threats = d.get('threats', [])
     partial = d.get('partial', False)
     print('yes' if (not threats or partial) else 'no')
   except Exception:
     print('no')
   " 2>/dev/null)
     if [ "$IS_STUB" = "yes" ]; then
       STUB_COMPONENTS="$STUB_COMPONENTS $cid"
       echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [$cid]  WARN   skill  STRIDE_STUB   component=$cid threats=0 — queuing for re-dispatch" >> "$OUTPUT_DIR/.agent-run.log"
     fi
   done
   ```

   For each `$cid` in `$STUB_COMPONENTS`, re-dispatch the single `appsec-stride-analyzer` **once** (foreground, `run_in_background: false`) with the same prompt as the original dispatch. If the retry still produces a stub or fails validation, log `STRIDE_STUB_RETRY_FAILED` and proceed without that component (`merge_threats.py` tolerates missing components). Do NOT re-dispatch more than once per component — a second exhaustion signals the component is too large for the current turn budget, and Analyst-B's merge step will carry forward an empty threat set rather than blocking. Dispatch all stub re-runs **simultaneously in one message** when there are multiple stubs.

   3d. **Analyst-B** — **Coarse phase-group label (C-lite, skip when `DRY_RUN=true`):** before dispatching, call `TaskUpdate` on `Stage 1a - Threat Analysis` to set `activeForm: "Phases 9–10b — merge → triage"`. Then: Agent call `description: "Threat Analysis & Triage (merge+triage)"`, prompt sets **`RESUME_FROM_PHASE=9-merge`** (+ normal config + `STAGE1_PHASE_LIMIT=10b`). It skips Phases 1–8 + STRIDE, reuses the `.stride-*.json`, and runs Phase 9 merge → Phase 10/10b → Phase-11 Substeps 1–3. Same post-conditions + checkpoint (`phase=10b status=completed need_render=true`) as the default branch. Then continue to step 4.

   **— Serial variant (`PARALLEL_STRIDE=false` AND `LIVE_PHASE=false` — opt-out / incremental fallback).** Reached when `APPSEC_PARALLEL_STRIDE=0` is set, or in non-full/rebuild modes where the parallel split does not apply. Call the Agent tool with `description: "Threat Analysis & Triage"`. Do **not** set `run_in_background` — this is a blocking inline call. **Pass `STAGE1_PHASE_LIMIT=10b` in the prompt** (in addition to the normal configuration variables) so the agent stops cleanly after Phase 10b plus Phase 11 Substeps 1–3 (deterministic yaml write + baseline cache), without entering the LLM-heavy Substeps 4–N. All prompt contents and configuration variables are described in the "Passing configuration" subsection below.

   **— Live-phase variant (`LIVE_PHASE=true` — opt-in via `APPSEC_LIVE_PHASE=1`, experimental).** Same agent, same `description: "Threat Analysis & Triage"`, same `STAGE1_PHASE_LIMIT=10b` prompt and config as the Default variant — the ONLY differences are the dispatch mode and the control flow that follows. Set **`run_in_background: true`** on the Agent call so the Level-0 orchestrator is NOT blocked (a blocking foreground call would queue all async console output until it returns — verified by the 2026-06-04 spike). Capture the returned background agent id in `STAGE1_AGENT_ID`. Then drive the live-phase display:

   - **End your turn immediately after dispatching.** Do NOT proceed to step 4. Do NOT make any blocking tool call (Bash, foreground Agent) while waiting — any blocking call re-blocks the main loop and re-queues the Monitor events, defeating the whole mechanism. You will be re-invoked by notifications.
   - **On each live-phase Monitor event** (task id `LIVE_PHASE_MONITOR_ID`): parse the phase/step text out of the event payload (e.g. `… PHASE_START   [Phase 3/11] ▶ Architecture Modeling…` → `Phase 3/11 — Architecture Modeling`; `STRIDE_PROGRESS stride_files=2 …` → `Phase 9/11 — STRIDE 2/5 components`) and call `TaskUpdate` on the `Stage 1a - Threat Analysis` task to set its `activeForm` to that text. This is what surfaces the live phase NAME on the console (the raw Monitor line shows only the static description). Do nothing else; end your turn again. If the payload has no parseable phase, skip the update.
   - **On a `STRIDE_STALE` / `STRIDE_CANARY_TIMEOUT` / `STRIDE_COMPONENT_TIMEOUT` / `AGENT_ERROR` / `TOOL_ERROR` event:** surface it once as a short console line (these are the failure/terminal markers — do not stay silent), then keep waiting.
   - **On the `STAGE1_AGENT_ID` completion notification** (carries the `<usage>` block — same shape the Default variant reads inline): the dispatch is done. Proceed to **step 4** below and continue the normal flow (stop watchdog, stop Monitor, gates, stats). The `<usage>` from this completion notification is what step 6 records.

   This is the one place in the skill that uses background dispatch + resume-on-notification. It is gated behind `LIVE_PHASE` precisely so the proven foreground flow stays the default. The cut-off detection (step 4+), resume, and stats logic are all UNCHANGED — they run at the same point (after the dispatch completes), the only difference being that "completes" now means "the completion notification arrived" rather than "the blocking call returned".

4. **Stop the heartbeat watchdog.** Once the Agent tool returns (success, error, or cut-off), send one final heartbeat before stopping the watchdog so the lock reflects activity right up to the stage boundary:
   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/acquire_lock.py" \
       "$OUTPUT_DIR/.appsec-lock" \
       --heartbeat --phase=skill --step=stage-handoff \
       >/dev/null 2>&1 || true
   ```
   Then immediately call `TaskStop` to terminate the background heartbeat loop. Do this BEFORE the cut-off detection branches below — those branches may exit the skill, and a still-running watchdog would block the next user invocation. If `HEARTBEAT_TASK_ID` is unset (DRY_RUN, or watchdog spawn failed), skip both calls silently.

   **Also stop the live-phase Monitor (when `LIVE_PHASE=true`).** If `LIVE_PHASE_MONITOR_ID` is set, call `TaskStop` on it here too — same place, same `task_id` param, schema already loaded. Stopping it in the SAME step as the watchdog guarantees a skill early-exit (cut-off branch) never leaks the Monitor. Skip silently when unset.

   > **`TaskStop` is a deferred tool — load its schema first.** Unlike `TaskCreate`/`TaskUpdate`, `TaskStop` is frequently NOT in the pre-loaded tool set, so calling it directly fails with `InputValidationError: unexpected parameter`. Before the first `TaskStop` of the run, call `ToolSearch` with query `select:TaskStop` to load its schema. Its parameter is **`task_id`** (snake_case) — **not** `taskId`; passing `taskId` is the exact "Invalid tool parameters" failure observed on the 2026-06-01 juice-shop run. This applies to every `TaskStop` site below (Stage 2 / Stage 3 / Stage 4) — load the schema once, then reuse `task_id` each time.

5. **On return, mark the Stage-1 tasks `completed`.** Call `TaskUpdate` to set **both** the `Stage 1a - Threat Analysis` and `Stage 1b - Triage` tasks to `completed`, then proceed to the **Phase-10b precondition gate** below.

6. **Record Stage 1 stats (M3.3).** The Agent tool's return notification carries a `<usage>` block with `total_tokens`, `tool_uses`, and `duration_ms`. Extract those values from the notification text (visible in the chat) and call `scripts/record_stage_stats.py` so they end up in `threat-model.md`'s `### Per-Stage Breakdown` table. (In the `LIVE_PHASE=true` variant the same `<usage>` block arrives in the background agent's **completion notification** — identical fields, identical extraction.)

   **`STAGE1_START_ISO` capture (multi-dispatch wall-time, 2026-05-23 juice-shop forensics).** Before dispatching the Stage 1 agent above, capture the dispatch-start timestamp into `STAGE1_START_ISO` (`STAGE1_START_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)` immediately before the Agent tool call). This is the lower bound the recorder uses to derive `dispatch_count` + `wall_secs_observed` from `.hook-events.log` — without it the recorder cannot tell apart this stage's `AGENT_SPAWN` events from earlier-run residue in incremental mode. The variable is plumbed through to the recorder via `--since-iso` below. When `STAGE1_START_ISO` is empty (e.g. the capture line was skipped), pass nothing and the recorder degrades to the legacy single-dispatch field set (back-compat).

   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/record_stage_stats.py" "$OUTPUT_DIR" \
       --stage 1 \
       --name "Threat Analysis & Triage" \
       --agent appsec-advisor:appsec-threat-analyst \
       --model "$STRIDE_MODEL" \
       --duration-ms <duration_ms_from_usage> \
       --tool-uses <tool_uses_from_usage> \
       --tokens <total_tokens_from_usage> \
       ${STAGE1_START_ISO:+--subagent-type appsec-advisor:appsec-threat-analyst --since-iso "$STAGE1_START_ISO"}
   ```

   The helper is idempotent — re-running it for the same `--stage` is a no-op. Failure of this helper must NOT block the run; if extraction fails, skip the call and continue to the precondition gate. The optional `--subagent-type` / `--since-iso` pair enriches the JSONL record with `dispatch_count` and `wall_secs_observed`; both are derived from `.hook-events.log` and are robust to multi-spawn auto-retry from the Re-Render / inline-shortcut loops below (`SKILL-impl.md` §"Re-Render Loop" + §"Auto-retry"). `duration_ms` continues to reflect only the final successful Agent return (API-billed); the new fields capture the full wall span including aborted spawns.

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

If `PHASE10B_OK=false`, fall through to the existing cut-off detection (below) — Stage 1 died before completing its scope and Stage 2 cannot proceed. If `PHASE10B_OK=true`, continue to the STRIDE-dispatch gate below.

### STRIDE-dispatch gate (deterministic, skill-level)

**This closes the Phase-9 inline-shortcut gap.** `phase-group-threats.md` instructs the orchestrator to dispatch one parallel `appsec-stride-analyzer` sub-agent per component, but that is an LLM prompt — under turn-budget pressure the orchestrator sometimes analyzes components **inline** instead, hand-writing `.stride-<id>.json` with zero `Agent` calls. Inlining collapses every component into one ~182k-token serial context where a single standard-tier API stall freezes the whole phase (2026-06-02 juice-shop: 23 min lost, 5 components inlined). The detection logic lives in `scripts/check_stride_dispatch.py` so the gate is mechanical: a real `.stride-<id>.json` (non-stub, non-empty) with no matching `.progress/<id>.json` — the latter written only by a dispatched analyzer — trips it. Skipped in incremental mode (carry-forward makes progress-file absence ambiguous) and in dry-run (the sub-1-minute synthetic run may legitimately inline, same rationale as the watchdog skip). Runs here because `.progress/` is reaped only at `runtime_cleanup.py --stage pre-qa`, which is later than this gate.

```bash
STRIDE_DISPATCH_EXIT=0
if [ "$DRY_RUN" != "true" ]; then
  python3 "$CLAUDE_PLUGIN_ROOT/scripts/check_stride_dispatch.py" \
      "$OUTPUT_DIR" \
      $([ "$INCREMENTAL" = "true" ] && echo --incremental)
  STRIDE_DISPATCH_EXIT=$?
fi
if [ "$STRIDE_DISPATCH_EXIT" = "2" ]; then
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  ERROR  skill  STRIDE_INLINED  Phase 9 inlined — real .stride-*.json with no .progress/ dispatch evidence" \
      >> "$OUTPUT_DIR/.agent-run.log"
  rm -f "$OUTPUT_DIR/.appsec-lock"
  rm -f "${TMPDIR:-/tmp}/.appsec-verbose-$(id -u)" "${TMPDIR:-/tmp}/.appsec-tracing-$(id -u)"
  exit 2
fi
```

On exit 2 the script prints a full banner to stderr naming the inlined components and the remediation (re-run; the orchestrator must dispatch). Then continue to the YAML integrity gate below.

### YAML integrity gate (deterministic, skill-level)

**This is the critical enforcement point.** The finalization agent is instructed to run `validate_intermediate.py` internally, but under turn-budget pressure it may skip or incompletely execute that step — the instruction is an LLM prompt, not a hard technical barrier. This skill-level gate closes that gap: it runs `validate_intermediate.py` directly in the skill's Bash context, outside any agent, and **blocks Stage 2 dispatch if the YAML is structurally invalid**.

The most common failure mode observed in production: `attack_surface`, `trust_boundaries`, and `security_controls` are held in the orchestrator's working memory but never written to the YAML. The schema requires all three as non-empty arrays; their absence causes `(0)` empty tables across §2.4, §5, §7, and §9 regardless of how correct Stage 2's rendering is. No amount of LLM instruction in Stage 2 can recover content that was never persisted to the YAML.

**Bootstrap-stub special case.** `triage_compute_ranking.py --bootstrap-yaml` (invoked by `appsec-triage-validator`) writes a minimal stub when Phase 11 Substep 2's full yaml-write never ran — it carries `meta._bootstrap: true` as a marker and uses the merged-threats shape (`t_id`/`component_id`) rather than the output shape (`id`/`component`). The stub is, by design, NOT output-schema-valid; it exists only so the deterministic triage script has something to read. When the gate detects the stub, it MUST NOT block — the actual production failure here is "Stage 1 never reached Phase 11 Substeps 1–3", and the user-facing remediation is the same as `--rebuild` regardless. The gate prints a distinct diagnostic and exits 2; it does NOT treat the stub as a normal schema failure.

```bash
# Bootstrap-stub detection — see "Bootstrap-stub special case" above.
IS_BOOTSTRAP_STUB=$(python3 -c "
import sys, yaml
try:
    with open('$OUTPUT_DIR/threat-model.yaml', encoding='utf-8') as fh:
        m = (yaml.safe_load(fh) or {}).get('meta') or {}
    print('yes' if m.get('_bootstrap') else 'no')
except Exception:
    print('no')
" 2>/dev/null)

if [ "$IS_BOOTSTRAP_STUB" = "yes" ]; then
  cat >&2 <<EOF

══════════════════════════════════════════════════════════════
  STAGE 2 BLOCKED — threat-model.yaml is a bootstrap stub
══════════════════════════════════════════════════════════════

  Stage 1 produced only the bootstrap stub written by
  triage_compute_ranking.py --bootstrap-yaml. The canonical
  yaml-write (Phase 11 Substep 2 — with assets, attack_surface,
  trust_boundaries, security_controls, mitigations) never ran.

  Likely cause: Stage 1 agent ran out of turns before reaching
  Phase 11 Substeps 1–3. The architectural data accumulated in
  agent working memory across Phases 3–8 was lost when the agent
  session ended.

  Recover with:
      /appsec-advisor:create-threat-model --rebuild
        (fresh full assessment; the stub cannot be salvaged
         because Phase 3–8 data only existed in agent memory)

  Inspect (do not edit by hand):
      $OUTPUT_DIR/threat-model.yaml          (stub, _bootstrap:true)
      $OUTPUT_DIR/.threats-merged.json       (preserved)
      $OUTPUT_DIR/.recon-summary.md          (preserved)
══════════════════════════════════════════════════════════════
EOF
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  ERROR  skill  YAML_GATE_BOOTSTRAP_STUB  threat-model.yaml is meta._bootstrap=true — Stage 1 never reached Phase 11 Substep 2" \
      >> "$OUTPUT_DIR/.agent-run.log"
  rm -f "$OUTPUT_DIR/.appsec-lock"
  rm -f "${TMPDIR:-/tmp}/.appsec-verbose-$(id -u)" "${TMPDIR:-/tmp}/.appsec-tracing-$(id -u)"
  exit 2
fi

# Hard gate: validate threat-model.yaml schema before dispatching Stage 2.
# An invalid YAML here means Stage 1 did not fully persist Phase 3-8 data.
# Stage 2 rendering from an invalid YAML produces silently broken output
# (empty §5 Attack Surface, empty §7 Operational Strengths, empty §9
# Mitigation Register, empty §2.4 layer tables) — abort now, not after render.
YAML_VALIDATE_OUTPUT=$(python3 "$CLAUDE_PLUGIN_ROOT/scripts/validate_intermediate.py" \
    threat_model_output "$OUTPUT_DIR/threat-model.yaml" 2>&1)
YAML_VALIDATE_RC=$?
if [ "$YAML_VALIDATE_RC" -ne 0 ]; then
  INVALID_COUNT=$(echo "$YAML_VALIDATE_OUTPUT" | grep -c "^INVALID:" || echo "?")
  cat >&2 <<EOF

══════════════════════════════════════════════════════════════
  STAGE 2 BLOCKED — threat-model.yaml failed schema validation
══════════════════════════════════════════════════════════════

  ${INVALID_COUNT} schema violation(s) found. Most common cause:
    attack_surface / trust_boundaries / security_controls were
    NOT written to threat-model.yaml by Stage 1 (Phase 3–8 data
    held in agent working memory but never persisted to YAML).

  First violations:
$(echo "$YAML_VALIDATE_OUTPUT" | grep "^INVALID:" | head -8 | sed 's/^/    /')

  Fix options:
    1. Re-run with --rebuild (complete fresh assessment)
    2. Re-run with --resume (Stage 1 re-runs Phase 11 only)

  threat-model.yaml is preserved at: $OUTPUT_DIR/threat-model.yaml
══════════════════════════════════════════════════════════════
EOF
  echo "$YAML_VALIDATE_OUTPUT" >> "$OUTPUT_DIR/.agent-run.log"
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  ERROR  skill  YAML_GATE_BLOCKED  ${INVALID_COUNT} INVALID lines — Stage 2 not dispatched" \
      >> "$OUTPUT_DIR/.agent-run.log"
  rm -f "$OUTPUT_DIR/.appsec-lock"
  rm -f "${TMPDIR:-/tmp}/.appsec-verbose-$(id -u)" "${TMPDIR:-/tmp}/.appsec-tracing-$(id -u)"
  exit 2
fi
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   skill  YAML_GATE_PASSED  threat-model.yaml passed schema validation" \
    >> "$OUTPUT_DIR/.agent-run.log"
```

If either branch trips, the run exits 2 without dispatching Stage 2. The YAML and all Stage 1 intermediate files are preserved so `--resume` can re-run Phase 11 with a corrected write, or `--rebuild` starts fresh. If both branches pass, continue to the YAML invariant gate.

### YAML invariant gate (RC.G.3 / RC.K — Phase-11 Substep-2 drift detector)

Phase-11 Substep-2 is LLM-driven: it assembles `threat-model.yaml` from `.threats-merged.json` plus working-memory Phases-5-8 context. In practice the LLM silently rewrites threat fields it is supposed to copy verbatim. The 2026-05 juice-shop run mutated 3 of 36 STRIDE categories (T-005 Tampering→Elevation of Privilege, T-024 Information Disclosure→Tampering, T-030 Information Disclosure→Tampering) between merge and yaml, and 29 of 36 titles. Downstream §8 grouping, attack-walkthroughs and mitigation references treated the post-mutation values as authoritative.

`scripts/enforce_yaml_invariants.py` compares `stride` and `cwe` (the fields with semantic downstream impact) between yaml and merged, restores the merged value when they diverge, appends `yaml_invariant_drift` to `evidence_flags`, and writes a `YAML_INVARIANT_DRIFT` audit line to `.agent-run.log`. Idempotent.

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/enforce_yaml_invariants.py" "$OUTPUT_DIR" 2>&1 | tail -10 || true
```

Runs **before** the auto-emitter pass so that any post-yaml mutation by reclassify_components, sanitize_perimeter_claims etc. operates on a stride/cwe-canonical yaml. `--report-only` is available for CI inspection without rewrite.

### Stage 2 no-op gate (incremental only — skip render when YAML unchanged)

Compare the current `threat-model.yaml` `mtime+size` against the snapshot taken at Stage 1 step 0. **If the YAML is byte-identical to the prior run, Stage 1 took its no-op fast-path — Stage 2 (renderer) and Stage 3 (QA) have nothing to do** and would only burn ~15 min of agent time re-rendering an identical report. Skip both stages and emit a concise summary instead.

```bash
SKIP_STAGE2_NOOP=false
if [ "$MODE" = "incremental" ] && [ "$DRY_RUN" = "false" ] \
     && [ "${YAML_PRE_STAGE1:-missing}" != "missing" ] \
     && [ -f "$OUTPUT_DIR/threat-model.yaml" ] \
     && [ -f "$OUTPUT_DIR/threat-model.md" ]; then
  YAML_POST_STAGE1=$(stat -c '%Y:%s' "$OUTPUT_DIR/threat-model.yaml" 2>/dev/null \
                  || stat -f '%m:%z' "$OUTPUT_DIR/threat-model.yaml" 2>/dev/null \
                  || echo "missing")
  if [ "$YAML_POST_STAGE1" = "$YAML_PRE_STAGE1" ]; then
    SKIP_STAGE2_NOOP=true
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   skill  STAGE2_NOOP_SKIP  yaml unchanged (mtime:size=$YAML_POST_STAGE1) — skipping renderer + QA" \
        >> "$OUTPUT_DIR/.agent-run.log"
  fi
fi

if [ "$SKIP_STAGE2_NOOP" = "true" ]; then
  printf '\n══════════════════════════════════════════════════════════════\n'
  printf '  Incremental no-op — threat-model.yaml unchanged after Stage 1\n'
  printf '══════════════════════════════════════════════════════════════\n\n'
  printf '  Stage 1 took its fast-path; the YAML was not rewritten.\n'
  printf '  Renderer (Stage 2) and QA (Stage 3) would re-produce the\n'
  printf '  identical threat-model.md — both skipped to save ~15 min\n'
  printf '  of agent time on every "nothing changed" run.\n\n'
  printf '  Existing report:    %s/threat-model.md (preserved)\n' "$OUTPUT_DIR"
  printf '  To force re-render: /appsec-advisor:create-threat-model --full\n\n'
  # Still mark the stage tasks completed so the Task spinner clears.
  # TaskUpdate Stage 2 → completed
  # TaskUpdate Stage 3 → completed (only if it was created — depends on SKIP_QA / DRY_RUN)
  rm -f "${TMPDIR:-/tmp}/.appsec-verbose-$(id -u)" "${TMPDIR:-/tmp}/.appsec-tracing-$(id -u)"
  exit 0
fi
```

This gate complements the SKILL-level fast-abort (exit codes 0/2 from `baseline_state.py check-changes`): the pre-check abort handles "no changes detected before Stage 1 even ran"; this gate handles "Stage 1 ran but its internal no-op / low-risk fast-path produced no YAML mutation". Together they cover every code path where re-rendering is provably wasted work.

`mtime+size` is sufficient — Stage 1 always rewrites the YAML via atomic `os.replace` when it produces real output, which updates both fields. A meta-only sed-patch (e.g. `meta.generated` timestamp bump) does the same, so an unchanged tuple is a strong signal of "Stage 1 returned without writing anything new". When in doubt the gate stays closed and the run proceeds normally.

### Auto-emitter pass — Meta-Findings + Review-Mitigations (M-RCA-2026-05)

Runs **after** the Stage-2 no-op gate has decided to proceed AND **before** the Stage-2 fragment pre-generator. Two deterministic Python helpers append derived content to `threat-model.yaml` so the Stage-2 renderer agent sees an enriched canonical YAML on its first read:

1. **`emit_meta_findings.py`** — aggregates `threats[]` by `source` and emits cross-cutting `meta_findings[]`. Today it surfaces `Insufficient Secret Management` when ≥2 `configuration-defect` threats land. The `Insufficient Patch Management` MF used to fire on ≥2 `dep-scan` threats, but the `dep-scan` source was removed in 2026-05; patch-management posture is now produced directly by `emit_sca_practice.py` (Phase 10) and merged here via the `.sca-practice-findings.json` + `.known-bad-libs-findings.json` sidecars. MF-NNN IDs allocated in their own namespace, no T-ID-contiguity impact.
2. **`emit_review_mitigations.py`** — synthesises `kind: review` mitigations for findings with `evidence_check ∈ {ambiguous, refuted}` (M-15/M-16), clustered `kind: investigate` mitigations for `source ∈ {architectural-anti-pattern, coverage-gap}` (M-17 — one card per `architectural_theme` to control §9 volume), and `poc_hint` annotations on threats with `affected_parameter` in injection-class CWEs (M-20).
3. **`emit_threat_vektors.py`** — assigns `threats[].vektor` deterministically from CWE class (798/321/312/540 → `repo-read`; 79/352/601/1021 → `victim-required`) plus the evidence file's auth_required (matched against `attack_surface[]` by camelCase-token overlap). Closes the bug where the composer renders `"internet-user"` for every threat in §8 because Stage 1 never populates the field. Idempotent — hand-set values preserved.
4. **`detect_open_registration.py`** — scans `attack_surface[]` for an unauthenticated registration route (POST /register, /signup, /api/Users, etc.). Writes `meta.open_user_registration: true | false`. Read by the §6 heatmap renderer to collapse `internet-user` / `internet-priv-user` actor cards into `internet-anon` (the three-tier attacker spectrum is misleading when registration is one POST away). The §8 Vektor column keeps its granularity.

Both scripts are **idempotent** — they strip prior auto-emitted entries before re-computing. M-NNN ID allocation uses `_scan_max_m_id` semantics that align with `baseline_state.py:_scan_max_id` (line 255-256) so the next run's baseline counter picks up the synthesized IDs naturally without collision.

**Placement contract.** The pass MUST run:
- **AFTER the YAML integrity gate** (above) — emitters call `yaml.safe_load` on the YAML; a structurally-broken YAML would produce confusing emitter errors that mask the real gate failure.
- **AFTER the Stage-2 no-op gate** — emitters always rewrite the YAML (mtime+size bump). Running them before the no-op gate would permanently break incremental no-op detection and burn ~15 min Stage 2 + Stage 3 on every truly-unchanged run.
- **BEFORE the Stage-2 fragment pre-generator** — pre-generator reads `meta_findings[]` (when present) and the Stage-2 renderer agent reads `threats[].poc_hint` for §8 rendering. Running emitters after pre-generate would leave the fragments stale.
- **NOT re-run inside the Re-Render Loop** — the loop dispatches `appsec-fragment-fixer` in REPAIR_MODE which never re-writes Stage-1 YAML (it only touches `.fragments/` + recompose). Re-running emitters per repair iteration would reshuffle M-NNN IDs because `_scan_max_m_id` returns a different ceiling after partial repair-write.

```bash
# Auto-emitter pass — Meta-Findings + Review-Mitigations (M-RCA-2026-05) +
# deterministic YAML hygiene (M-RCA-2026-05b: sanitize_perimeter_claims,
# validate_evidence_lines, reclassify_components). Order matters:
#   1. emit_meta_findings   — derives MF-NNN from threats[] by source.
#   2. emit_review_mitigations — synthesises kind:review/investigate mitigations.
#   3. sanitize_perimeter_claims — strips speculative WAF/DDoS/firewall
#      absence phrasing from trust_boundaries[].enforcement and
#      security_controls[].notes. Runs BEFORE pre-gen so the deterministic
#      architecture-diagrams.md fragment inherits clean text.
#   4. validate_evidence_lines — deterministic floor for the
#      appsec-evidence-verifier agent. Sets evidence_check + evidence_flags
#      on every threat where the LLM verifier did not already write a
#      verified/refuted/verified-prior verdict.
#   5. reclassify_components — fixes attack-target-tier vs control-location-
#      tier drift. Reassigns threats whose evidence.file matches exactly
#      one other component's paths globs.
#   6. enforce_control_taxonomy — RC-1 + RC-6 (2026-05): canonicalises
#      security_controls[].control names (e.g. "JWT RS256 Authentication"
#      → "JWT Bearer Authentication") and re-routes mis-classified
#      security_controls[].domain entries (e.g. auth-flow rate limiting
#      parked in §7.12 Real-time → §7.2 IAM). Must run BEFORE
#      pregenerate_fragments so the mechanical §7.1 overview table +
#      `**Controls covered:**` lines are built from a taxonomy-clean yaml.
# All scripts are idempotent + best-effort: failures fall back to the
# pre-script YAML rather than aborting the run after 25+ minutes of Stage 1.
if [ "$DRY_RUN" = "false" ]; then
  {
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   skill  AUTO_EMITTER_START  meta-findings + review-mitigations + config-scan-mitigations + yaml-hygiene + vektors + open-registration + asset-links + control-taxonomy"
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/emit_meta_findings.py" "$OUTPUT_DIR" 2>&1 || true
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/emit_review_mitigations.py" "$OUTPUT_DIR" 2>&1 || true
    # M-RCA-2026-05 — `kind: fix` mitigations for config-scan threats.
    # Stage 1's appsec-config-scanner emits findings without remediation
    # prose (the agent's actual output schema is leaner than its docs imply)
    # and merge_threats._config_finding_to_threat does not populate
    # `mitigation_ids[]` or `remediation`. As a result, build_mitigations
    # never produced an M-NNN card for them and the §8 Threat Register
    # shipped with empty **Fix:** cells on every config-scan row. This
    # emitter looks up canonical remediation prose (config-iac-checks.yaml
    # by `config_check_id` → built-in slug map for scanner-synthesised
    # checks → generic fallback), allocates a new M-NNN per threat, and
    # links it back via threats[].mitigation_ids. Idempotent: prior
    # auto_source="config-scan" cards are cleared before re-computing.
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/emit_config_scan_mitigations.py" "$OUTPUT_DIR" 2>&1 || true
    # M-RCA-2026-06 — `kind: fix` mitigations for CODE findings the LLM left
    # uncovered. build_mitigations only emits an M-NNN card when the threat
    # already carries mitigation_ids[]; when Phase-11's LLM yaml-write
    # under-produces (2026-06-02 juice-shop: all 13 Critical findings came
    # back with mitigation_ids=[]), the Mitigation Register ships
    # "_No P1 mitigations._" despite every threat carrying a full remediation
    # block. This emitter backfills a fix card (priority from severity+effort)
    # for any non-config-scan threat with remediation content but no link, and
    # back-references it via threats[].mitigation_ids. Idempotent; runs AFTER
    # emit_config_scan_mitigations so config-scan threats are already linked
    # and skipped.
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/emit_finding_fix_mitigations.py" "$OUTPUT_DIR" 2>&1 || true
    # Clean finding TITLES (2026-06-12) — normalize threats[].title to
    # `<weakness class> — <file:line>` (strip `via <impl>`, parens, params,
    # embedded files). The verbose code-laden titles otherwise render into every
    # xref cell (§2/§4/§2.3/§8). Idempotent (_title_source). Runs before the
    # mitigation-title pass (independent; that keys on CWE, not title).
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/emit_clean_finding_titles.py" "$OUTPUT_DIR" 2>&1 || true
    # General mitigation TITLES (2026-06-12) — runs AFTER all mitigation
    # emitters so it generalizes the full set. Stage 1 authors detailed
    # remediation instructions as mitigation_title ("Replace `.decode(token)`
    # with `.verify(...)`…", "Add HEALTHCHECK CMD curl -f http://…"); this
    # rewrites the §10 register/index TITLE to a clear class-level label keyed
    # on the addressed CWE (the actionable detail stays in the block body's
    # How/steps/code). Idempotent (stashes _title_source).
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/emit_general_mitigation_titles.py" "$OUTPUT_DIR" 2>&1 || true
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/sanitize_perimeter_claims.py" "$OUTPUT_DIR" 2>&1 || true
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/validate_evidence_lines.py" "$OUTPUT_DIR" --repo-root "$REPO_ROOT" 2>&1 || true
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/reclassify_components.py" "$OUTPUT_DIR" 2>&1 || true
    # RC-1 + RC-6 (2026-05): canonicalise security_controls[].control names
    # against forbidden_heading_patterns + alias rewrites, and re-route
    # security_controls[].domain when token-match against a §7 method_whitelist
    # contradicts the Stage-1 assignment (specifically: auth controls parked
    # in §7.12 Real-time and Not Applicable Controls). Closes the cascade
    # of §7.2.1 heading-rename / §7.1 overview-table inconsistencies that
    # surfaced in the 2026-05-23 juice-shop run. Idempotent.
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/enforce_control_taxonomy.py" "$OUTPUT_DIR" 2>&1 || true
    # Auth-coverage completeness (2026-06-06): §7.2 must ALWAYS identify,
    # describe and rate every authentication variant the app exposes — password
    # login, MFA, social/OAuth login — plus the password-credential lifecycle
    # (user registration, password reset). The Phase-8 analyst routinely omits
    # variants that exist in code (juice-shop: OAuth, registration, reset all
    # present, two anchoring Critical findings, none cataloged → §7.2 listed
    # only Password + MFA). This emitter backfills any DETECTED-but-uncataloged
    # canonical auth mechanism into security_controls[] with kind:mechanism (so
    # §7 renders a flow sub-block + sequenceDiagram) rated from its linked
    # finding(s), and records a lifecycle-required aspect (registration / reset)
    # that is genuinely absent under password auth as effectiveness:Missing.
    # Runs AFTER enforce_control_taxonomy (so the coverage check sees canonical
    # control names) and BEFORE pregenerate_fragments. Idempotent.
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/emit_auth_coverage.py" "$OUTPUT_DIR" --repo-root "$REPO_ROOT" 2>&1 || true
    # Issue-1: deterministic vektor field per threat (CWE + attack_surface
    # auth_required → repo-read / victim-required / internet-anon /
    # internet-user) so §8 Vektor column reflects real reachability rather
    # than the renderer's `"internet-user"` default. Idempotent — preserves
    # any hand-set values.
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/emit_threat_vektors.py" "$OUTPUT_DIR" 2>&1 || true
    # Surface WHY a rating sits above its class baseline (public-repo secret,
    # unauth privileged endpoint, attack-chain keystone) as a short inline
    # severity_rationale the §8 card renders. Runs AFTER emit_threat_vektors
    # because the rationale keys on threats[].vektor. Idempotent.
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/emit_severity_rationale.py" "$OUTPUT_DIR" 2>&1 || true
    # Issue-1: detect open user self-registration; sets
    # meta.open_user_registration which the §6 heatmap renderer reads to
    # collapse internet-user / internet-priv-user actor cards into
    # internet-anon (registration is one POST away, the spectrum is
    # misleading on the at-a-glance view).
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/detect_open_registration.py" "$OUTPUT_DIR" 2>&1 || true
    # Public-repo detection (2026-06): sets meta.public_source_repo only on
    # high-confidence LOCAL signals (OSI license file + public-host github/
    # gitlab/bitbucket source URL). When true, compose collapses the repo-read
    # actor "Internal Developer" into "Anonymous Internet Attacker" (a public
    # repo's committed secrets are readable by anyone). When the evidence is
    # insufficient the flag is left UNSET and the Internal Developer actor is
    # kept — never guess public on a repo we cannot confirm. Honors the operator
    # override meta.public_source_repo_pinned. Needs --repo-root.
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/detect_public_repo.py" "$OUTPUT_DIR" --repo-root "$REPO_ROOT" 2>&1 || true
    # R-3 (2026-05): rebuild assets[].linked_threats from CWE-class affinity +
    # keyword overlap. Stage 1 Phase 5 is LLM-authored and routinely produces
    # links that have nothing to do with the asset (e.g. session-tokens linked
    # to YAML bomb / CORS / mass assignment instead of XSS + JWT storage).
    # Idempotent. Hand-set entries preserved via assets[].linked_threats_manual.
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/enrich_asset_links.py" "$OUTPUT_DIR" 2>&1 || true
    # Mask committed secrets in Stage-1 evidence excerpts (e.g. raw
    # `password: 'admin123'`, PEM private-key markers) so the Stage-3
    # unmasked_secrets gate — which scans threat-model.yaml as well as the
    # rendered markdown — cannot trip on author-supplied excerpts. Uses the
    # SAME secret_scan.py pattern set as the gate, so detector⇔masker symmetry
    # guarantees the yaml passes. The composer applies the identical mask to the
    # rendered markdown (it re-reads real source files for §8 evidence), so both
    # artifacts are clean by construction. Idempotent and best-effort.
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/secret_scan.py" --mask "$OUTPUT_DIR/threat-model.yaml" 2>&1 || true
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  INFO   skill  AUTO_EMITTER_END"
  } | tee -a "$OUTPUT_DIR/.agent-run.log" >&2
fi
```

Behaviour contract:

- **Empty `threats[]`** — both emitters no-op (zero auto-cards added, no `meta_findings` block emitted). The composer sees the YAML untouched.
- **`DRY_RUN=true`** — skipped entirely. Auto-emission is value-add for persistent reports; transient dry-run output does not benefit from it.
- **Stage 1 cut-off (`STAGE1_CUTOFF*`)** — the Phase-10b gate and YAML integrity gate above already exit non-zero on these paths, so emitters never see partial state.
- **`STAGE11_CUTOFF` Stage-2 recovery dispatch** — after the recovery dispatch produces `threat-model.yaml`, the next return to this section re-enters the auto-emitter pass with the freshly-written YAML. Idempotency makes the re-entry safe.
- **`--resume`** — emitters are idempotent. Prior `auto_emitted: true` entries in `mitigations[]` are stripped before re-computing; T-NNN ↔ M-NNN back-links are cleaned up symmetrically. `meta_findings[]` is rebuilt from scratch (preserving any `manual: true` operator-pinned entries at the head).

**Schema compatibility.** All emitter outputs are within the existing `threat-model.output.schema.yaml` envelope:
- `meta_findings[]` — defined at schema:670+ with the exact category enum the emitter writes.
- `mitigations[].kind` — `[fix, review, investigate, accept_risk]` enum (schema:619); emitters write `review` and `investigate`.
- `mitigations[].review_target` / `review_reason` — explicit optional string fields (schema:630+).
- `mitigations[].auto_emitted` / `auto_source` — accepted via `additionalProperties: true` on the mitigations item (schema:576).
- `threats[].poc_hint` — accepted via `additionalProperties: true` on the threats item.

The YAML integrity gate that runs before this section will still pass after the emitter writes; the schema permits every field the emitters touch.

## Stage 1c — Abuse Case Verification (visible skill-level stage)

**This is a first-class, user-visible stage** (formerly the invisible "Phase 10c"). It runs between Stage 1 and Stage 2, has its own `TaskList` row (`Stage 1c - Abuse Case Verification`), a handoff banner, a heartbeat watchdog, and a `.stage-stats.jsonl` record — so the verifier fan-out's cost, duration, and verdict reliability are visible in the completion summary and the §Run-Statistics breakdown (RC-2026-06: the 2026-06 juice-shop run lost 3/6 verifiers with no visibility because this work was unstaged).

**Why this lives at the skill level.** Abuse-case discovery → verifier fan-out → `.abuse-case-verdicts.json` is documented in `phase-group-threats.md` as running "after Phase 10b and before Phase 11". But Stage 1 is dispatched with `STAGE1_PHASE_LIMIT=10b`, whose analyst branch stops *after* Phase 10b plus the deterministic Phase-11 substeps 1–3 — it never reaches it. Running it here — after the YAML is final, before Stage 2 renders — closes the gap deterministically and keeps it out of Stage 1's turn budget.

Runs only when `DRY_RUN=false` **and** `skip_abuse_case_verification=false` (resolved in `.skill-config.json` from the `--abuse-cases` / `--no-abuse-cases` flags — default on at standard/thorough, off at quick; see the Argument Parsing table). Entirely non-fatal — any failure leaves §9 to render its catalog/placeholder.

**Skip the whole stage** (no matcher, no verifier fan-out, no escalation, no chain fold, no §9 render-from-verdicts, and no TaskList row — it was not created in the bootstrap) when **either** `DRY_RUN=true` **or** `skip_abuse_case_verification=true`. In the skip case the §9 fragment is still produced by the deterministic `render_abuse_cases.py` backstop in the Stage-3 pre-generation block, which no-ops to the not-applicable catalog/placeholder because no `.abuse-case-verdicts.json` exists — so §8 → §10 numbering stays contiguous and no finding is chain-elevated. Read the flag at stage entry:

```bash
SKIP_ABUSE=$(python3 -c "import json;print(str(json.load(open('$OUTPUT_DIR/.skill-config.json')).get('skip_abuse_case_verification',False)).lower())" 2>/dev/null || echo false)
if [ "$DRY_RUN" = "true" ] || [ "$SKIP_ABUSE" = "true" ]; then
  : # Stage 1c skipped — proceed directly to Stage 2. No TaskList row to update.
else
  : # run the full Stage 1c sequence below (steps 0–4).
fi
```

0. **Stage open.** Capture the start timestamp, mark the task in progress, print the banner, and start the heartbeat watchdog (same `skill_watchdog.py` invocation as the other stages — see "Skill-layer heartbeat watchdog"; capture its `task_id` in `HEARTBEAT_TASK_ID`). Skip all of this when `DRY_RUN=true`.
   ```bash
   STAGE_ABUSE_START_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)
   ABUSE_PIPELINE_FAILED=0
   ```
   - `TaskUpdate` `Stage 1c - Abuse Case Verification` → `in_progress`.
   - Banner:
     ```
     ▶ Stage 1c - Abuse Case Verification starting  (deterministic match + per-candidate sonnet verifier fan-out)
       ⟶ Chains each derived from §8 findings; verified step-by-step, then folded into §9
     ```

1. **Deterministic match** (no LLM): build candidates from the standard library + org profile + repo-local cases against `.threats-merged.json`. `--repo-root` loads `<repo>/.appsec/abuse-cases/*.yaml` (zero-config repo-local layer).
   ```bash
   if ! python3 "$CLAUDE_PLUGIN_ROOT/scripts/match_abuse_cases.py" match \
       --output-dir "$OUTPUT_DIR" \
       --repo-root "$REPO_ROOT" \
       ${ORG_PROFILE_PATH:+--org-profile "$ORG_PROFILE_PATH"}; then
     ABUSE_PIPELINE_FAILED=1
     printf '\n\033[1;31m✗ Abuse-case match failed (match_abuse_cases.py match exited nonzero)\033[0m\n' >&2
   fi
   CANDIDATES=$(python3 "$CLAUDE_PLUGIN_ROOT/scripts/match_abuse_cases.py" \
       list-candidates --output-dir "$OUTPUT_DIR" 2>/dev/null)
   ```
2. **Verifier fan-out** — for each AC-ID in `$CANDIDATES`, dispatch the `appsec-advisor:appsec-abuse-case-verifier` Agent (`model: sonnet`, foreground) with the prompt body `ABUSE_CASE_ID=<AC-ID>`, `MATCH_RESULT_PATH=$OUTPUT_DIR/.abuse-case-matches.json`, `REPO_ROOT`, `OUTPUT_DIR`, `CLAUDE_PLUGIN_ROOT`, `MODEL_ID=sonnet`. **Single-pass sonnet** (perf 2026-06-02): the former haiku-first + bounded-sonnet-escalation two-tier ran its waves *sequentially* (haiku → finalize barrier → sonnet re-verify), and on complex repos most candidates escalated anyway (juice-shop: 5/6) — so the haiku wave was near-pure wasted wall-time for the same final verdicts (sonnet is what produced them). Dispatching sonnet directly collapses it to one wave. Dispatch all candidates together in ONE message (wall-clock ≈ slowest single case). Each writes one `.abuse-case-verdict-<AC-ID>.json` — and per the agent's write-first contract it pre-seeds that file (finding ids from the matcher) before investigating, so a cut-off verifier still leaves a valid file. **Budget guard:** if `$OUTPUT_DIR/.budget-critical` exists, SKIP the fan-out (the merge below records every candidate `inconclusive`). When `$CANDIDATES` is empty, skip straight to step 3 (the not-applicable catalog still renders). **Collect each agent's `<usage>`** (sum `duration_ms` / `tool_uses` / `total_tokens` across all verifiers) for the stage-stats record in step 4.
3. **Merge + finalize** (deterministic) — produces the final chain verdicts directly from the single sonnet wave:
   ```bash
   if ! python3 "$CLAUDE_PLUGIN_ROOT/scripts/verify_abuse_cases.py" merge --output-dir "$OUTPUT_DIR"; then
     ABUSE_PIPELINE_FAILED=1
     printf '\n\033[1;31m✗ Abuse-case merge failed (verify_abuse_cases.py merge exited nonzero)\033[0m\n' >&2
   fi
   if ! python3 "$CLAUDE_PLUGIN_ROOT/scripts/match_abuse_cases.py" finalize --output-dir "$OUTPUT_DIR"; then
     ABUSE_PIPELINE_FAILED=1
     printf '\n\033[1;31m✗ Abuse-case finalize failed (match_abuse_cases.py finalize exited nonzero)\033[0m\n' >&2
   fi
   # DG-2: a pipeline crash must NOT masquerade as "no abuse cases apply". When
   # ABUSE_PIPELINE_FAILED=1 the §9 not-applicable catalog below is rendering
   # over INCOMPLETE data — surface it loudly. stderr is mirrored into
   # .agent-run.log in headless mode, so this is recorded for forensics.
   if [ "$ABUSE_PIPELINE_FAILED" = "1" ]; then
     printf '  §9 Abuse Cases reflect an INCOMPLETE verification pass (a script failed above).\n' >&2
   fi
   ```

3b2. **Fold verified chains into severity** (deterministic, no LLM). Now that the abuse verdicts are final, re-run the deterministic triage ranking so a **code-verified `fully_viable` chain bubbles its constituent findings up** — not only in §9, but in §8 `effective_severity` AND the §1 `top_findings` / Management-Summary ranking. This re-reads `.abuse-case-verdicts.json` + `.abuse-case-matches.json` (the sidecars did not exist when Stage 1 ran Phase 10b) and re-applies the elevation + ranking onto the already-final `threat-model.yaml` + `.triage-flags.json`. The script **self-gates** via `--if-deterministic-owner` on the artifact marker `ranking.computed_by` in `.triage-flags.json` — written only by the deterministic Step 6 run — and exits cleanly otherwise. So this only acts in deterministic-triage mode, where `triage_compute_ranking.py` is the **sole owner** of `effective_severity` and there is no LLM refinement to clobber (`appsec-triage-validator.md` fast-path). Do NOT gate this on the `APPSEC_TRIAGE_DETERMINISTIC` env var: env vars do not reach skill-level Bash, so an env-gated call silently no-ops on every default run. Non-fatal and idempotent — the elevation is upward-only (`_detect_verified_abuse_chains`), so a second pass on identical inputs is a no-op. Under `.budget-critical` every chain is `inconclusive`, so there is nothing to fold and this is a harmless no-op.
   ```bash
   if [ -f "$OUTPUT_DIR/.abuse-case-verdicts.json" ]; then
     python3 "$CLAUDE_PLUGIN_ROOT/scripts/triage_compute_ranking.py" "$OUTPUT_DIR" \
         --if-deterministic-owner || true
   fi
   ```

3c. **Render §9** (deterministic):
   ```bash
   # Render the §9 fragment HERE — BEFORE the Stage-2 renderer's first
   # compose. The verdicts are final at this point; rendering now means the
   # abuse-cases.md fragment already exists when Stage 2 runs
   # compose_threat_model.py, so §9 ships populated on the first compose.
   # (Earlier this only ran in the Stage-3 pre-gen block, AFTER Stage 2's
   # compose, so the first composed report carried the "No abuse cases"
   # placeholder until a Re-Render Loop happened to recompose — §9 could ship
   # empty on any clean run with no other repair. RC-2026-06.)
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/render_abuse_cases.py" \
       --output-dir "$OUTPUT_DIR" \
       --repo-root "$REPO_ROOT" \
       ${ORG_PROFILE_PATH:+--org-profile "$ORG_PROFILE_PATH"} || true
   ```
4. **Stage close.** Send a final heartbeat, stop the watchdog (`TaskStop` with `HEARTBEAT_TASK_ID`), record the aggregated stage-stats, and mark the task complete. The stage is recorded under `--stage 1 --variant abuse-verification` so it sorts immediately after Stage 1 in the Per-Stage Breakdown without renumbering Stages 2–4 (mirrors the Stage-3 `repair-<k>` variant pattern). When `$CANDIDATES` was empty (no agents ran) record a deterministic zero-token row instead (`--agent deterministic:match_abuse_cases.py --model none --tokens 0 --tool-uses 0`).
   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/record_stage_stats.py" "$OUTPUT_DIR" \
       --stage 1 --variant "abuse-verification" \
       --name "Abuse Case Verification" \
       --agent appsec-advisor:appsec-abuse-case-verifier \
       --model sonnet \
       --duration-ms <sum_duration_ms> \
       --tool-uses <sum_tool_uses> \
       --tokens <sum_tokens> \
       ${STAGE_ABUSE_START_ISO:+--subagent-type appsec-advisor:appsec-abuse-case-verifier --since-iso "$STAGE_ABUSE_START_ISO"}
   ```
   - `TaskUpdate` `Stage 1c - Abuse Case Verification` → `completed`.

The §9 fragment is **also** re-rendered idempotently in the Stage-3 pre-generation block (a backstop that picks up any late verdict change); rendering it here as well guarantees the FIRST Stage-2 compose already includes §9. Both calls read `.abuse-case-verdicts.json` (viable chains) **and** `.abuse-case-matches.json` (the generic catalog evaluated-but-not-applicable table) and are byte-identical given identical inputs.

## Stage 2 - Report Rendering (M2.12 — Sprint 3)

Dispatched **always** after a successful Stage 1 (`PHASE10B_OK=true`) **and** when the no-op gate above did not skip it. Stage 2 runs Phase 11 (Finalization) with its own renderer budget. This is the architectural fix for Phase-11 budget exhaustion.

### Pre-dispatch — pre-generate structural fragments

Before invoking the Stage 2 agent, run the deterministic pre-generator. The
6 structural fragments split into two classes (**P2 — A4**):

1. **Mechanical fragments** — `system-overview.md`, `architecture-diagrams.md`,
   `assets.md`, `attack-surface.md`, `out-of-scope.md`. These are derived
   100 % from `threat-model.yaml` with no narrative input from the LLM. They
   are **force-regenerated** here so any LLM drift from Phase 11 substep 4
   (drift modes seen in 2026-05 runs: `assets.md` losing the ID column,
   `attack-surface.md` inventing extra rows, `architecture-diagrams.md`
   embedded with `\n` literal node labels) is overwritten with the
   yaml-aligned canonical version.
2. **Scaffold-fill fragment** — `security-architecture.md`. The pre-generator
   writes a scaffold with `<!-- NARRATIVE_PLACEHOLDER -->` comments that
   the Stage 2 LLM expands. We run this idempotently (no `--force`) so a
   completed fragment survives a second pre-generate invocation.

```bash
# Class 1 — force-regenerate the mechanical fragments. The LLM is no
# longer trusted to author these (yaml is single source of truth).
#
# attack-walkthroughs.md is now in this class: §3 is rendered
# deterministically by scripts/walkthrough_renderer.py from yaml +
# data/walkthrough-templates/. The renderer agent does NOT touch it.
python3 "$CLAUDE_PLUGIN_ROOT/scripts/pregenerate_fragments.py" "$OUTPUT_DIR" \
    --force \
    --only system-overview.md,architecture-diagrams.md,assets.md,attack-surface.md,out-of-scope.md,attack-walkthroughs.md \
    || true

# Class 2 — idempotent scaffold for security-architecture.md. The depth
# is read from .skill-config.json (or defaults to standard); at quick depth
# §7.4-§7.12 NARRATIVE_PLACEHOLDERs are stripped so the LLM has no
# expansion bait there.
python3 "$CLAUDE_PLUGIN_ROOT/scripts/pregenerate_fragments.py" "$OUTPUT_DIR" \
    --only security-architecture.md \
    || true
```

Failure here is **non-fatal** (`|| true`) — the hard gate that runs after Stage 2 will catch any genuine fragment shortage regardless of who was supposed to write it.

**Walkthroughs opt-out (`--no-walkthroughs` or quick depth).** When `SKIP_ATTACK_WALKTHROUGHS=true` (resolved in `.skill-config.json` as `skip_attack_walkthroughs`), the §3 section is dropped entirely from the rendered document via the conditional `condition: "not skip_attack_walkthroughs"` gate in `data/sections-contract.yaml` (`document.order` and both `document_sets`). The composer also suppresses the related cross-references:

- §3 heading, body, and TOC entry are removed by the contract gate.
- The quick-mode notice replaces the "No per-finding sequence diagrams in §3" bullet with "No §3 Attack Walkthroughs (entirely skipped at `--quick`)" so the omission is acknowledged but no broken §3 link is left in the callout.
- The §8 Threat Register intro element list omits the "Attack Walkthrough — back-link into [§3]" bullet entirely (no orphan reference to a missing section).
- Per-finding Story Cards never render the `**Attack Walkthrough:**` field (gated on `fid_to_walkthrough` being non-empty — and the map is empty because §3 produces no anchors).

**No stub fragment is written.** Pre-Sprint-N versions of this skill pre-wrote a chain-overview-only stub `.fragments/attack-walkthroughs.md` to defeat the renderer agent's idempotency rule. With the §3 section now conditional, the stub is unnecessary — the composer no-ops on the missing fragment because the section is skipped from the pipeline before fragment loading. Removing the stub also avoids leaving a `.fragments/attack-walkthroughs.md` file on disk that confuses post-mortem inspection.

### Dispatch

1. **Mark the stage task `in_progress`.** Call `TaskUpdate` on the `Stage 2 - Report Rendering` task to set status `in_progress` (skip when `DRY_RUN=true`).

2. **Restart the heartbeat watchdog (M3.4 / M3.6).** Spawn a fresh `python3 scripts/skill_watchdog.py "$OUTPUT_DIR" --plugin-root "$CLAUDE_PLUGIN_ROOT"` invocation with `run_in_background:true` (same flags as Stage 1 — see "Skill-layer heartbeat watchdog" above). Capture the new `task_id` in `HEARTBEAT_TASK_ID` (overwriting the Stage 1 value, which was already stopped). Skip when `DRY_RUN=true`.

   **Fresh-budget clear (G-BC).** Immediately before dispatch, clear any stale turn-budget flags so the renderer — which has its own `maxTurns` and polls `.budget-critical` by existence — is not forced into a premature wrap-up by a flag raised earlier in the run (Stage 1, STRIDE, or the abuse fan-out). The PostToolUse watchdog also resets per dispatch, but this skill-layer clear is the deterministic guarantee that does not depend on the hook firing:
   ```bash
   rm -f "$OUTPUT_DIR/.budget-critical" "$OUTPUT_DIR/.budget-warning"
   ```

3. **Dispatch the renderer.** Two paths — a **parallel split** (default when §7 enrichment is on) and the **single full dispatch** (back-compat). Resolve which:

   ```bash
   # Parallel render (perf 2026-06-05): §7 prose and the management-summary
   # fragments are independent, so author them in TWO concurrent renderer
   # agents (wall ≈ max(§7, MS) ≈ 6 min instead of ~11 min serial). Only
   # meaningful when §7 is actually LLM-filled (ENRICH on) — at quick depth /
   # --no-enrich the §7 work is deterministic and there is nothing to split,
   # so fall through to the single full dispatch. Default-on; opt-OUT via
   # APPSEC_PARALLEL_RENDER=0 (then the byte-unchanged single dispatch runs).
   ENRICH_ARCH_FRAGMENTS=$(python3 -c "import json;print(str(json.load(open('$OUTPUT_DIR/.skill-config.json')).get('enrich_arch_fragments',False)).lower())" 2>/dev/null || echo false)
   PARALLEL_RENDER=false
   if [ "${APPSEC_PARALLEL_RENDER:-1}" != "0" ] && [ "$ENRICH_ARCH_FRAGMENTS" = "true" ] && [ "$DRY_RUN" = "false" ]; then
     PARALLEL_RENDER=true
   fi
   ```

   **— Parallel-render variant (`PARALLEL_RENDER=true`).** Dispatch **two** `appsec-advisor:appsec-threat-renderer` Agent calls **in a single message** so they run concurrently (same proven Level-0 fan-out as the STRIDE / abuse-verifier pattern). Pass all original configuration variables verbatim to **both** (REPO_ROOT, OUTPUT_DIR, WRITE_YAML, WRITE_SARIF, ASSESSMENT_DEPTH, model selections, ENRICH_ARCH_FRAGMENTS, SKIP_ATTACK_PATHS_AUTHORING, SKIP_ATTACK_WALKTHROUGHS, VERBOSE_REPORT, INVOCATION_ARGS, etc.), adding exactly one differing key:
   - Agent **S** — `description: "Render: §7 Security Architecture"`, prompt adds `RENDER_ROLE=secarch`. Authors only `security-architecture.md` (+ `architecture-diagrams.md`); does NOT compose.
   - Agent **M** — `description: "Render: Management Summary"`, prompt adds `RENDER_ROLE=ms`. Authors only `ms-verdict.json` (+ `ms-critical-attack-tree.json` when ≥2 Critical, + `security-posture-attack-paths.json` unless skipped), runs the MS compactness gate; does NOT compose.

   Wait for **both** to return, then compose + QA **at skill level** (the work the split agents deliberately skip):

   ```bash
   # Capture compose's EXIT CODE — not file presence. On a --strict failure
   # (e.g. one split agent emitted an off-schema fragment) the on-disk
   # threat-model.md is the STALE prior render, so `[ -f … ]` would falsely
   # read as success and the downstream inline-shortcut gate would pass a stale
   # doc (2026-06-05 parallel-render gotcha). Exit code is the only honest
   # signal. Retry compose once (mirrors the single-dispatch renderer's
   # Postcondition recovery) before handing off to the recovery path.
   COMPOSE_RC=0
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/compose_threat_model.py" \
       --output-dir "$OUTPUT_DIR" --strict || COMPOSE_RC=$?
   if [ "$COMPOSE_RC" -ne 0 ]; then
       echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  [--------]  WARN   threat-renderer  COMPOSE_FAILED  rc=$COMPOSE_RC (parallel render) — retrying once" >> "$OUTPUT_DIR/.agent-run.log"
       COMPOSE_RC=0
       python3 "$CLAUDE_PLUGIN_ROOT/scripts/compose_threat_model.py" \
           --output-dir "$OUTPUT_DIR" --strict || COMPOSE_RC=$?
   fi
   if [ "$COMPOSE_RC" -eq 0 ]; then
       # Compose succeeded → run QA (on a stale MD it would be noise) and write
       # the completed checkpoint the split agents deliberately skipped, so
       # STAGE11_CUTOFF detection sees the same clean signal the single-dispatch
       # renderer would have written.
       if [ "$SKIP_QA" = "true" ] || [ "$DRY_RUN" = "true" ] || [ "$PR_MODE" = "true" ]; then
           python3 "$CLAUDE_PLUGIN_ROOT/scripts/qa_checks.py" all \
               "$OUTPUT_DIR/threat-model.md" "$REPO_ROOT" > /dev/null || true
       else
           python3 "$CLAUDE_PLUGIN_ROOT/scripts/qa_checks.py" contract \
               "$OUTPUT_DIR/threat-model.md" > /dev/null || true
       fi
       python3 "$CLAUDE_PLUGIN_ROOT/scripts/log_event.py" "$OUTPUT_DIR" phase-end "[Phase 11/11] Finalization (parallel renderer)" --agent threat-renderer 2>/dev/null || true
       echo "phase=11 status=completed timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$OUTPUT_DIR/.appsec-checkpoint"
   else
       # Both compose attempts failed → do NOT mark completed (that would ship a
       # stale doc). Record an incomplete checkpoint and fall through to the
       # post-dispatch backstop + hard gate + Stage-3 re-render loop, which own
       # fragment-repair recovery exactly as for a single-dispatch compose miss.
       echo "phase=11 status=incomplete reason=compose_failed_parallel timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$OUTPUT_DIR/.appsec-checkpoint"
   fi
   ```

   On a persistent compose failure the incomplete checkpoint routes into the existing post-dispatch backstop + hard gate and the §"Post-dispatch — fragment-pipeline audit" recovery — the same path the single-dispatch flow uses when a renderer returns without producing `threat-model.md`.

   **— Single full dispatch (`PARALLEL_RENDER=false`).** Call the `appsec-advisor:appsec-threat-renderer` Agent tool with `description: "Threat Model Renderer (Stage 2)"` and `RENDER_ROLE=full` (or simply omit it — `full` is the default). Pass all original configuration variables verbatim (REPO_ROOT, OUTPUT_DIR, WRITE_YAML, WRITE_SARIF, ASSESSMENT_DEPTH, model selections, VERBOSE_REPORT, INVOCATION_ARGS, etc.) so the renderer has the same context the orchestrator had. The renderer authors the LLM-driven JSON fragment (`ms-verdict.json`) plus optionally `attack-walkthroughs.md` and `security-posture-attack-paths.json` and (when `ENRICH_ARCH_FRAGMENTS=true`) the §7 enrichment, then invokes `compose_threat_model.py --strict --output-dir "$OUTPUT_DIR"` and conditional QA: full `qa_checks.py all` when Stage 3 is skipped (`SKIP_QA=true`, `DRY_RUN=true`, or `PR_MODE=true`), otherwise only the fast contract check because the skill-level `repair_plan` gate and QA reviewer own the full QA pass.

   **RC.B — neither path calls `render_completion_summary.py --patch-placeholders` here.** The renderer cannot observe its own duration / tokens (those are only available post-Agent-return). The skill-final `--patch-placeholders` invocation in the §Completion Summary section below — after every stage has written to `.stage-stats.jsonl` — is the only authoritative patch point.

   **Stage-2 dispatch guard (G-9).** The Agent call is synchronous and blocks the skill. In production the deadline-watchdog (see "Wall-time + cost deadline watchdog" above) provides the ultimate ceiling via `.appsec-lock` removal. For runs without a `--max-wall-time` limit, the wall-time upper bound is implicitly the Claude Code harness session timeout. No additional watcher is needed here — Stage 2 returns when complete or exhausted. If Stage 2 does not produce `threat-model.md` by the time the Agent call returns, the existing post-Stage-2 `STAGE11_CUTOFF` detection below handles recovery.

4. **Stop the heartbeat watchdog.** Once the Agent tool returns, send one final heartbeat before stopping the loop:
   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/acquire_lock.py" \
       "$OUTPUT_DIR/.appsec-lock" \
       --heartbeat --phase=skill --step=stage-handoff \
       >/dev/null 2>&1 || true
   ```
   Then call `TaskStop` with `HEARTBEAT_TASK_ID`. Skip both calls silently if `HEARTBEAT_TASK_ID` is unset.

5. **On return, mark the stage task `completed`.** Call `TaskUpdate` to set the `Stage 2 - Report Rendering` task to `completed`. Then proceed to the post-Stage-2 flow: pre-generation backstop + hard gate + Stage 3.

6. **Record Stage 2 stats (M3.3).** Same mechanism as Stage 1 — extract `<usage>` and call the helper. **In the parallel-render variant two `<usage>` blocks return (Agent S + Agent M)** — sum their `total_tokens` and `tool_uses`, and use the **larger** `duration_ms` (they ran concurrently, so wall-time is the max, not the sum). The `--since-iso "$STAGE2_START_ISO"` enrichment already derives the true `dispatch_count` (=2) and `wall_secs_observed` from `.hook-events.log`, so the recorded wall-time stays honest regardless.

   **`STAGE2_START_ISO` capture (mandatory for multi-dispatch wall-time).** Capture the dispatch-start timestamp into `STAGE2_START_ISO` (`STAGE2_START_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)` immediately before the Agent tool call in step 3). Stage 2 is the stage most likely to re-dispatch (auto-retry via `check_inline_shortcut.py` → `MAX_INLINE_RETRIES=2`, see §"Auto-retry — inline shortcut" below, and `STAGE11_CUTOFF` recovery dispatch from the §"Handling turn-budget cut-offs" path). Without this capture, the recorder cannot derive `dispatch_count` / `wall_secs_observed` and Stage 2 wall-time silently under-reports by 50% on multi-spawn runs (observed on 2026-05-23 juice-shop: reported 8m06s, actual 15m58s).

   ```bash
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/record_stage_stats.py" "$OUTPUT_DIR" \
       --stage 2 \
       --name "Report Rendering" \
       --agent appsec-advisor:appsec-threat-renderer \
       --model "$STRIDE_MODEL" \
       --duration-ms <duration_ms_from_usage> \
       --tool-uses <tool_uses_from_usage> \
       --tokens <total_tokens_from_usage> \
       ${STAGE2_START_ISO:+--subagent-type appsec-advisor:appsec-threat-renderer --since-iso "$STAGE2_START_ISO"}
   ```

### Handoff banner

Before dispatching Stage 2, print:

```
▶ Stage 2 - Report Rendering starting  (expect ~<EST_STAGE2> min, model: sonnet, renderer budget)
  ⟶ Authoring 2 LLM fragments + invoking compose_threat_model.py
  ⟶ Structural fragments prepared from YAML before rendering
```

### Post-dispatch — fragment-pipeline audit

After Stage 2 returns, run the deterministic fragment pre-generator one more time as a backstop (idempotent), then immediately run the hard gate. The combination guarantees that:

- If Stage 2 authored the 2 LLM fragments correctly: pre-generator no-ops, hard gate passes.
- If Stage 2 skipped a structural fragment: pre-generator fills it in, hard gate still passes (Sprint-2 safety net).
- If Stage 2 inline-shortcut bypassed the renderer entirely: hard gate trips with exit 2.

This is where the existing `pregenerate_fragments.py || true` + `check_inline_shortcut.py || { exit }` blocks live (Sprint-2 wiring above). They run identically here — the only addition vs. the pre-Sprint-3 flow is that the Stage-2 dispatch sits between Stage 1 and the gates.

### Handling turn-budget cut-offs

Thorough-depth runs whose criteria selection yields the full inventory (commonly ~8 STRIDE analyzers; bounded by the `MAX_STRIDE_COMPONENTS` operational ceiling) routinely touch the Claude Code agent turn budget (observed at ~90 tool calls per agent session in `claude -p` headless mode). When the budget is hit, the Agent call returns control to the skill *before* Phase 11 finalization runs, typically mid-Phase-9 or mid-Phase-10. Two concrete symptoms:

1. The agent's final text ends with something like `"All 8 STRIDE files ready. Proceeding to merge."` without a closing `ASSESSMENT_END` log entry.
2. `$OUTPUT_DIR/threat-model.md` does NOT exist after the Agent call returns — but `$OUTPUT_DIR/.stride-*.json` and `$OUTPUT_DIR/.recon-summary.md` are present.

**Detection (mandatory).** Immediately after the Stage 1 Agent call returns, the skill MUST check whether `threat-model.md` was **freshly produced** — not merely present. A `-f` test alone is unsafe: a full/rebuild re-run leaves the previous run's `threat-model.md` on disk, so it must also be NEWER than the pre-Stage-1 snapshot (DG-1).

```bash
MD_POST_STAGE1="missing"
if [ -f "$OUTPUT_DIR/threat-model.md" ]; then
  MD_POST_STAGE1=$(stat -c '%Y:%s' "$OUTPUT_DIR/threat-model.md" 2>/dev/null \
                || stat -f '%m:%z' "$OUTPUT_DIR/threat-model.md" 2>/dev/null \
                || echo "missing")
fi
# Cut-off if the deliverable is missing OR unchanged since before Stage 1.
if [ ! -f "$OUTPUT_DIR/threat-model.md" ] || [ "$MD_POST_STAGE1" = "$MD_PRE_STAGE1" ]; then
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

  # MAX_TURNS surfacing (RC.B — 2026-05-24). The budget watchdog mirrors
  # MAX_TURNS to hook-stderr via _HIGH_SIGNAL_EVENTS in agent_logger.py,
  # but Claude Code's interactive TUI does NOT surface hook stderr; the
  # orchestrator's own wrap-up Bash call (cat .budget-critical) is
  # collapsed past ~20 lines so the headline fact is invisible. Print a
  # short, prominent banner here whenever a cut-off fires AND a
  # .budget-critical flag is on disk — the user reliably sees this
  # because it comes from the skill's own stderr (not a hook, not a
  # collapsed bash output). Fires once, before the recovery dispatch.
  if [ -f "$OUTPUT_DIR/.budget-critical" ]; then
    BUDGET_LINE=$(python3 -c "
import json
try:
    with open('$OUTPUT_DIR/.budget-critical') as f:
        d = json.load(f)
    if d:
        e = d[0]
        print(f\"agent={e.get('agent','?')}  turns={e.get('turns','?')}/{e.get('max','?')}  ({int(e.get('pct',0)*100)}%)\")
except Exception:
    pass
" 2>/dev/null)
    LAST_PHASE=$(grep 'PHASE_END' "$OUTPUT_DIR/.agent-run.log" 2>/dev/null \
                 | tail -1 \
                 | sed -nE 's/.*\[(Phase [0-9a-z]+\/[0-9]+)\].*/\1/p' || true)
    printf '\n\033[1;31m✗ MAX_TURNS reached — Stage 1 turn budget exhausted\033[0m\n' >&2
    printf '  %s\n' "${BUDGET_LINE:-(see .budget-critical for details)}" >&2
    [ -n "$LAST_PHASE" ] && printf '  Last completed: %s\n' "$LAST_PHASE" >&2
    printf '  Recovery path follows below.\n\n' >&2
  fi
fi
```

**Late-phase crash (Phase 11 partial) — Stage 2 auto-dispatch.** The `STAGE11_CUTOFF=true` branch fires when at least three fragments are present in `.fragments/` but `threat-model.md` is missing — meaning the orchestrator entered Phase 11, wrote part of the fragment set, then died before `compose_threat_model.py` ran. This is the 2026-04-25 juice-shop case: 5 of 12 fragments written, no yaml, no composed Markdown. The recovery is **not** the same as `STAGE1_CUTOFF` (which assumes Phase 9 still has merge work to do); here the threats are already merged and the only missing work is composition.

**Stage 2 - Report Rendering (recovery dispatch).** Instead of exiting with a banner and forcing the user to manually re-invoke `--resume`, the skill dispatches `appsec-threat-renderer` with a Phase-11-only scope and a fresh turn budget. This keeps the large Stage-1 analyst prompt out of render-only recovery. Stage 2 runs **once** (no retry counter — if it fails, fall through to the banner-and-exit path so we don't burn tokens recursively).

```bash
if [ "$STAGE11_CUTOFF" = "true" ] && [ "${STAGE1B_DISPATCHED:-false}" = "false" ]; then
  STAGE1B_DISPATCHED=true
  printf '\n' >&2
  printf '▶ Stage 2 - Report Rendering recovery starting…\n' >&2
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
  MD_POST_STAGE2="missing"
  if [ -f "$OUTPUT_DIR/threat-model.md" ]; then
    MD_POST_STAGE2=$(stat -c '%Y:%s' "$OUTPUT_DIR/threat-model.md" 2>/dev/null \
                  || stat -f '%m:%z' "$OUTPUT_DIR/threat-model.md" 2>/dev/null \
                  || echo "missing")
  fi
  if [ -f "$OUTPUT_DIR/threat-model.md" ] && [ "$MD_POST_STAGE2" != "$MD_PRE_STAGE1" ]; then
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

**Recovery path.** If `STAGE1_CUTOFF=true` **and** the resume counter is below `MAX_STAGE1_RESUMES`, spawn another `appsec-advisor:appsec-threat-analyst` Agent call (fresh turn budget) with the description `"Threat Analysis & Triage (resume)"` and a prompt that:

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
- `RECON_REUSE_ELIGIBLE=<true|false>` (default `false`; set `true` by `resolve_config` only on an **auto-upgraded** full run — depth increased or `--requirements` newly added against an unchanged baseline, never on explicit `--full` or a first run. When `true`, Phase 2's recon gate in `phase-group-recon.md` may skip recon and reuse the prior `.recon-summary.md` **iff** the tree is git-provably clean (`check-fingerprint --require-clean-tree`). Lets a depth/requirements re-run on an unchanged repo avoid the ~6 min recon while still re-running STRIDE/triage at the new depth.)
- `REBUILD=<true|false>` (when `true`, Phase 11 writes a `note: "full rebuild — prior threat model and changelog history were discarded on user request (--rebuild)"` into the fresh `v1` changelog entry — the pre-flight wipe already removed the baseline so the orchestrator itself runs as if first-ever)
- `KEEP_RUNTIME_FILES=<true|false>` (default `false`; when `true` Phase 11 skips cleanup of transient artifacts — useful for debugging)
- `SCAN_MANIFEST=<true|false>` (default `false`; when `true` the recon-scanner writes every processed file path to `$OUTPUT_DIR/.scan-manifest.txt`)
- `STRIDE_MODEL=<model>` (from `--reasoning-model` resolution; overridden by `--stride-model` or `$APPSEC_STRIDE_MODEL` when set)
- `TRIAGE_MODEL=<model>` (from `--reasoning-model` resolution; overridden by `$APPSEC_TRIAGE_MODEL` when set)
- `MERGER_MODEL=<model>` (from `--reasoning-model` resolution; overridden by `$APPSEC_MERGER_MODEL` when set)
- `CONTEXT_RESOLVER_MODEL=<model>` (sonnet-economy tier; default `claude-sonnet-4-6`. Read by Phase 1 dispatch in `phase-group-recon.md`. Override via `$APPSEC_CONTEXT_RESOLVER_MODEL`.)
- `RECON_SCANNER_MODEL=<model>` (sonnet-economy tier; default `claude-sonnet-4-6`. Read by Phase 2 dispatch in `phase-group-recon.md`. Override via `$APPSEC_RECON_SCANNER_MODEL`.)
- `QA_ROUTINE_MODEL=<model>` (sonnet-economy tier QA-split; default `claude-sonnet-4-6`. Used at the skill level for routine repair iterations. Override via `$APPSEC_QA_ROUTINE_MODEL`.)
- `QA_CONTENT_MODEL=<model>` (sonnet-economy tier QA-split; default `claude-sonnet-4-6`. Used for content-class repair iterations. Override via `$APPSEC_QA_CONTENT_MODEL`.)
- `CONFIG_SCANNER_MODEL=<model>` (defaults to `claude-haiku-4-5` at all reasoning tiers. Read by Phase 2.5 dispatch in `phase-group-recon.md`. Override via `$APPSEC_CONFIG_SCANNER_MODEL`.)
- `ACTOR_DISCOVERY_MODEL=<model>` (defaults to `claude-sonnet-4-6`. Read by Phase 2.7 dispatch. Override via `$APPSEC_ACTOR_DISCOVERY_MODEL`.)
- `REFRESH_ACTOR_DISCOVERY=<true|false>` (when `true`, Phase 2.7 passes `--refresh-discovery` to resolve_actors.py and forces a new LLM discovery run even when the cache key is unchanged. Set by `--refresh-discovery` flag.)
- `ORCHESTRATOR_MODEL=<model>` (sonnet-economy tier; always `claude-sonnet-4-6` per matrix — informational only.)
- `STRIDE_PROFILE_JSON=<inline-json>` (depth-reduction profile; default `{"stride_profile_label":"full"}`. Read by Phase 9 dispatch in `phase-group-threats.md` and forwarded to each STRIDE analyzer in Group A. Quick + sonnet-economy contains the A-F reduction flags.)
- `REASONING_LABEL=<resolved summary>`
- `RESUME_FROM_PHASE=<N>` (only if resuming from checkpoint)
- `STAGE1_PHASE_LIMIT=10b` (M2.12 — Sprint 3, only set on Stage 1 dispatch — tells the orchestrator to run Phases 1–10b plus the deterministic Phase 11 Substeps 1–3 (counts, yaml write, baseline cache) and then stop cleanly without entering the LLM-heavy Substeps 4–N. See `agents/appsec-threat-analyst.md` → "STAGE1_PHASE_LIMIT — early-exit branch" for the full contract. **Mutually exclusive with `RENDER_ONLY=true`.**)
- `RENDER_ONLY=true` (legacy compatibility signal for older Stage-2 recovery prompts; normal Stage 2 dispatch now uses `appsec-threat-renderer`. **Mutually exclusive with `STAGE1_PHASE_LIMIT=10b`.**)
- `ENRICH_ARCH_FRAGMENTS=<true|false>` (M3.3 / D2 — only set on Stage 2 dispatch. When `true`, the agent fills `security-architecture.md` (§7) with LLM-authored narrative instead of leaving the deterministic scaffold's placeholders. Off by default at quick; **on by default at standard and thorough** (the deterministic scaffold ships unfilled `NARRATIVE_PLACEHOLDER` comments for §7.3–§7.12 at standard/thorough, so enrichment is required for a non-empty §7 — see `resolve_config.py:resolve_enrich_arch_fragments`); force on at any depth via `--enrich-arch`, force off via `--no-enrich-arch`. **Note (2026-06):** `architecture-diagrams.md` (§2) is NOT enriched — it is deterministic and force-regenerated before AND after Stage 2, so §2 incl. its per-diagram `**Key takeaway:**` lines is owned solely by `pregenerate_fragments.py:gen_architecture_diagrams`. This flag gates §7 only.)
- `SKIP_ATTACK_PATHS_AUTHORING=<true|false>` (only set on Stage 2 dispatch. When `true`, the agent skips authoring `security-posture-attack-paths.json` and lets the renderer's deterministic CWE→class fallback in `compose_threat_model.py:_derive_attack_paths_fallback` produce the fragment. On at quick depth (since 2026-05) to save ~1-3 min in Stage 2; off at standard/thorough where the LLM-authored architectural-root-causes and attack-chain links justify the authoring cost.)
- `SKIP_ATTACK_WALKTHROUGHS=<true|false>` (only set on Stage 2 dispatch. When `true` (set by `--no-walkthroughs` or quick depth), the agent skips authoring `attack-walkthroughs.md`; the composer renders §3 with the chain-overview-only fallback (no per-finding sequenceDiagram blocks). Saves ~1-2 min in Stage 2.)
- `RENDER_ROLE=<full|secarch|ms>` (perf 2026-06-05 — only set on Stage 2 dispatch. `full` (default / omit) = single-agent path: author MS + §7 + compose. `secarch` / `ms` = the two parallel split roles (`PARALLEL_RENDER=true`): each authors only its half and does NOT compose; the skill composes after both return. See `agents/appsec-threat-renderer.md` → "Render role — READ FIRST".)
- `ASSESSMENT_DEPTH=<quick|standard|thorough>`
- `MAX_STRIDE_COMPONENTS=<operational ceiling, default 10>` (safety valve passed to the manifest builder as `--ceiling`; NOT the selection count — components are criteria-selected by `select_stride_components()`)
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

**Requirements-toggle invalidation.** `resolve_incremental_mode` compares the FINAL resolved `check_requirements` against the baseline's `meta.check_requirements` (asymmetric, auto-path only — explicit `--incremental` is honored as-is). Adding requirements (baseline off → run on, via `--requirements`) auto-upgrades the auto-incremental run to a full re-assessment (incremental cannot tag carried-forward components). Dropping requirements (baseline on → run off, including the quick-depth auto-disable) is **destructive** — it would overwrite the requirements-enriched model and silently strip the §7b/§10 Requirements Compliance traceability — so it is a **hard abort** at config-resolution time (exit 1), instructing the user to re-run with `--full` (overwrite without requirements; changelog preserved) or `--requirements` (keep coverage). A pre-feature baseline with no `meta.check_requirements` field is treated as unknown and never gates.

When `CHECK_REQUIREMENTS=true` and no requirements YAML is available, the context-resolver aborts with an error. The error behavior depends on the source:
- **`REQUIREMENTS_URL_OVERRIDE` set** (from `--requirements <src>`) — the explicit source must load; no cache fallback (abort immediately on load failure). An `http(s)://` value is fetched remotely; anything else is read as a local file path (no `file://` scheme).
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

## Stage 3 - QA Review

After the orchestrator completes (and `DRY_RUN` is `false`), verify that `$OUTPUT_DIR/threat-model.md` exists. Before dispatching the QA-reviewer agent the skill runs two **deterministic pre-agent gates** so the agent's turn budget is spent on qualitative checks rather than on finding drift that a Python script can detect in 200 ms.

### Post-Stage-1 fragment precondition (deterministic, skill-level)

The first thing the skill does after Stage 1 returns is check whether the orchestrator actually went through the fragment pipeline. This is the mechanical enforcement of the policy "direct `Write` of `threat-model.md` is forbidden" — without it the policy is just a sentence in an agent prompt that the LLM can ignore under turn pressure.

**Pre-generation of structural fragments (M2.11 — Sprint 2).**

Before running the hard gate, run ``pregenerate_fragments.py`` so the 6 deterministic structural fragments (system-overview, architecture-diagrams, assets, attack-surface, security-architecture, out-of-scope) are present even when the orchestrator skipped them. **Mechanical fragments are force-regenerated (P2 — A4)** so any LLM drift from Phase 11 substep 4 is overwritten with the yaml-aligned canonical version. **`security-architecture.md` is regenerated idempotently** because its scaffold contains `<!-- NARRATIVE_PLACEHOLDER -->` comments that the Stage 2 LLM legitimately fills in.

```bash
# Generate the 7 structural fragments deterministically from threat-model.yaml.
# P2 (A4) — mechanical fragments use --force so LLM drift is overwritten;
# security-architecture.md keeps its scaffold-fill semantics (idempotent).
# Failure is non-fatal — the hard gate below catches any genuine missing
# fragment regardless of who was supposed to write it.
#
# attack-walkthroughs.md joined the --force set: §3 is now rendered
# deterministically by scripts/walkthrough_renderer.py from yaml + per-CWE
# templates under data/walkthrough-templates/. The walkthrough_depth,
# walkthrough_coverage, and chain_compactness contract checks pass by
# construction, so no LLM repair loop runs for §3.
python3 "$CLAUDE_PLUGIN_ROOT/scripts/pregenerate_fragments.py" "$OUTPUT_DIR" \
    --force \
    --only system-overview.md,architecture-diagrams.md,assets.md,attack-surface.md,out-of-scope.md,attack-walkthroughs.md \
    || true
python3 "$CLAUDE_PLUGIN_ROOT/scripts/pregenerate_fragments.py" "$OUTPUT_DIR" \
    --only security-architecture.md,_chain-skeleton.md \
    || true
# §9 Abuse Cases — deterministic render from the Phase-10b verdicts. No-ops
# (and removes any stale fragment) when no abuse case applied, so compose then
# emits its placeholder line and §8 → §10 numbering stays contiguous.
python3 "$CLAUDE_PLUGIN_ROOT/scripts/render_abuse_cases.py" \
    --output-dir "$OUTPUT_DIR" \
    --repo-root "$REPO_ROOT" \
    ${ORG_PROFILE_PATH:+--org-profile "$ORG_PROFILE_PATH"} \
    || true
```

`_chain-skeleton.md` is kept for one release as a deprecated transitional
artifact (the legacy renderer fallback path still reads it). It is no
longer the source of truth for `attack-walkthroughs.md` — `walkthrough_renderer.py`
is. Idempotent on purpose: when the agent has already filled it in, the
scaffold is preserved.

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
   # Phase 11 structural fragments — P2 (A4): mechanical fragments are
   # force-regenerated so LLM drift gets overwritten; security-architecture.md
   # keeps its scaffold-fill semantics so a partially-completed Stage 2
   # narrative survives the recovery dispatch.
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/pregenerate_fragments.py" "$OUTPUT_DIR" \
       --force \
       --only system-overview.md,architecture-diagrams.md,assets.md,attack-surface.md,out-of-scope.md,attack-walkthroughs.md \
       || true
   python3 "$CLAUDE_PLUGIN_ROOT/scripts/pregenerate_fragments.py" "$OUTPUT_DIR" \
       --only security-architecture.md,_chain-skeleton.md \
       || true
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

Before invoking `qa_checks.py`, run the deterministic prose-fix pass — currently this wraps unbacked path-shaped tokens (`lib/insecurity.ts`, `routes/login.ts:42`) in backticks per `prose-style.md → Rule 6`. The renderer prompt asks for this but LLM compliance is patchy; the script is idempotent and shaves a dozen `inline_code_format` warnings off `.qa-prepass.json` for free:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/apply_prose_fixes.py" \
    "$OUTPUT_DIR/threat-model.md" 2>&1 | tee -a "$OUTPUT_DIR/.agent-run.log" >&2 || true
```

**Hard secret-leak gate (always, fail-closed).** The full `qa_checks.py all` detector battery is deferred off the clean path, so the secret check must run on its own to actually block a release. Scan the persisted `threat-model.md` *and* `threat-model.yaml`; a hit exits non-zero and the skill aborts with exit 2. The detector excludes already-masked values (`AIza****`, `**** (12 chars)`, `[REDACTED]`) and unquoted code-identifier references (`secret: publicKey`, `password: security.hash`), so it fires only on genuine unmasked literals / typed tokens / private-key markers — which the masking policy (`agents/shared/secret-handling.md`) requires the author to redact. A correctly-masked document passes; a doc carrying a raw value is blocked until it is masked at authoring time.

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/qa_checks.py" unmasked_secrets \
    "$OUTPUT_DIR/threat-model.md" "$OUTPUT_DIR" > "$OUTPUT_DIR/.qa-secret-scan.json"
SECRET_GATE_EXIT=$?
if [ "$SECRET_GATE_EXIT" -eq 1 ]; then
    printf '✖ Unmasked secret detected in the rendered threat model — refusing to release.\n' >&2
    printf '  See %s/.qa-secret-scan.json. Mask the value at authoring time\n' "$OUTPUT_DIR" >&2
    printf '  (agents/shared/secret-handling.md): typed tokens → first 4 chars + ****; passwords → **** plus length only.\n' >&2
    exit 2
fi
```

When the fragment precondition passes, run `qa_checks.py repair_plan` before the agent is dispatched. This builds `.qa-repair-plan.json` from the authoritative Python checker so the agent inherits a clean baseline instead of spending turns rediscovering drift:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/qa_checks.py" repair_plan \
    "$OUTPUT_DIR/threat-model.md" "$OUTPUT_DIR"
GATE_EXIT=$?
```

Also apply the auto-fixing checks in place so the Markdown already has clean links, anchors, MS structure, and `<br/>`-stacked multi-link cells before the agent even looks at it. The `autofix` subcommand runs **only** the five in-place mutating passes (links, anchors, MS structure, cell-format, heading-attribute strip); it does **not** run the ~45-check detector battery. That battery (`qa_checks.py all` → `.qa-prepass.json`) is deferred to the agent-dispatch path below, because on the clean fast path the QA agent is skipped and nothing consumes the pre-pass JSON:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/qa_checks.py" autofix \
    "$OUTPUT_DIR/threat-model.md" "$REPO_ROOT"
```

**Branch logic:**
- `GATE_EXIT == 0` — contract clean, no repair plan on disk. The `autofix` pass above already applied the in-place fixes; write a compact `$OUTPUT_DIR/.qa-status.json` with `status: "pass"` and `source: "deterministic-pre-agent"`, then skip the QA agent unless `QA_DEPTH=extended` or `APPSEC_FORCE_QA_AGENT=1`. This is the normal fast path: the in-place auto-fixers own links, anchors, MS structure, cell-format; the `repair_plan` **gate** owns contract validation, Mermaid syntax, unfilled placeholders, and YAML↔MD consistency (count + asset cross-reference drift) — each trips the gate (exit 1/3) rather than the deferred `all` battery. No LLM session — and no detector pre-pass — is needed when they are clean. (Pre-2026-06-05 `placeholders` and `yaml_md_consistency` lived only in the deferred `all` battery, which never runs on the clean path because the QA agent that consumed it is skipped — so a residual placeholder or a yaml/md count drift could ship silently. They are now folded into `build_repair_plan`.)
- `GATE_EXIT == 1` — contract drift, `.qa-repair-plan.json` already on disk. Enter the Re-Render Loop below **without** dispatching the QA agent first. The Re-Render Loop dispatches `appsec-fragment-fixer` in REPAIR_MODE, which re-authors the offending fragments and re-renders. The QA agent is dispatched **after** the loop settles (status=pass) so it works on a contract-clean document.
- `GATE_EXIT == 2` — tool error (bad path, malformed contract). Log and fall back to the old flow: dispatch the agent unconditionally and let its Check 14 write the plan instead.
- `GATE_EXIT == 3` — `manual_review`: a real defect exists but **no** action carries a writable fragment target, so re-rendering cannot converge (e.g. a deterministic yaml↔md count drift, which means a composer/fragment bug, not LLM drift). Do **not** enter the Re-Render Loop (it would burn iterations on an unfixable plan). Instead dispatch the QA agent **once** for semantic triage — it inherits the on-disk `.qa-repair-plan.json` and decides between a soft edit, a release-blocker, or a `manual_review_items` escalation. Treat it like the `== 2` fallback for dispatch purposes (set `QA_AGENT_DISPATCHED=true`).

**Mandatory dispatch guard.** Set a local `QA_AGENT_DISPATCHED=false` flag before this gate. Only set it to `true` in the explicit agent-dispatch branch below. On the clean deterministic path (`GATE_EXIT == 0`, `QA_DEPTH != extended`, and `APPSEC_FORCE_QA_AGENT != 1`), do **not** execute any later instruction that invokes `appsec-qa-reviewer`, starts the Stage-3 heartbeat watchdog, extracts QA-agent usage, or waits for a QA-agent result. Continue directly to Stage 4 (if enabled) or the completion summary. Record Stage 3 stats as a zero-token deterministic gate (`agent=deterministic:qa_checks.py`, model=`none`) when the stats helper is available.

This inverts the pre-M3.2 flow where the agent was the first thing to see the rendered Markdown. Cost win: clean runs avoid the 90 KB Markdown read entirely; non-clean runs give the QA agent a repair-plan-sized input instead of making it rediscover mechanical drift.

### Stage 3 handoff banner

Run this subsection **only when `QA_AGENT_DISPATCHED=true` is required**:

- `GATE_EXIT == 2` fallback
- `GATE_EXIT == 3` (`manual_review` — re-render cannot fix; agent triages the on-disk plan)
- `QA_DEPTH=extended`
- `APPSEC_FORCE_QA_AGENT=1`
- the Re-Render Loop settled with a remaining non-empty repair/content-repair plan that requires semantic triage

When one of those conditions holds, set `QA_AGENT_DISPATCHED=true`, dispatch the QA agent, and **first print a blank line and the Stage 3 handoff banner**:

```
▶ Stage 3/<total_stages> — QA Review starting  (expect ~<EST_STAGE3> min, model: sonnet-4-6)
  ⟶ Dispatching qa-reviewer — repair-plan triage and semantic review only; deterministic qa_checks.py already handled mechanical gates
```

Where `<total_stages>` is `4` when `ARCHITECT_REVIEW=true`, otherwise `3`.

Immediately before dispatching, call `TaskUpdate` on the `Stage 3 - QA Review` task to set status `in_progress` (skip if the task was not created, i.e. `SKIP_QA=true` or `DRY_RUN=true`). After the QA agent returns (and any Re-Render Loop iterations have settled), call `TaskUpdate` to set the same task to `completed`. If `QA_AGENT_DISPATCHED=false`, mark the task completed after writing the deterministic `.qa-status.json` and skip this handoff.

**Heartbeat watchdog (M3.4 / M3.6).** Spawn a fresh `python3 scripts/skill_watchdog.py "$OUTPUT_DIR" --plugin-root "$CLAUDE_PLUGIN_ROOT"` background invocation (see "Skill-layer heartbeat watchdog" above) immediately before dispatching the QA agent; capture the new `task_id` in `HEARTBEAT_TASK_ID`. After the QA agent returns, send one final heartbeat (`acquire_lock.py --heartbeat --phase=skill --step=stage-handoff || true`) then call `TaskStop` with `HEARTBEAT_TASK_ID`. Skip when `DRY_RUN=true` or `SKIP_QA=true`.

**Produce the detector pre-pass the agent consumes (dispatch path only).** The `autofix` pass at the gate already cleaned the Markdown in place; now — and only now, because the agent is actually being dispatched — run the full detector battery to write the `.qa-prepass.json` the reviewer loads as `PRE_PASS_JSON`:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/qa_checks.py" all \
    "$OUTPUT_DIR/threat-model.md" "$REPO_ROOT" > "$OUTPUT_DIR/.qa-prepass.json"
```

(If this step is ever skipped, the reviewer's own fallback re-runs `qa_checks.py all` once — see `appsec-qa-reviewer.md` "Pre-pass handoff". The skill-level run is preferred so the agent inherits a clean baseline without spending a turn.)

Inside this guarded branch, invoke the `appsec-advisor:appsec-qa-reviewer` agent using `"QA review of threat model"` as the Agent tool `description`. If `QA_AGENT_DISPATCHED=false`, this invocation is skipped entirely.

**QA model resolution — split-mode (M3.5).** The QA reviewer is dispatched with one of two model IDs depending on what kind of repairs the prior Stage-2 contract gate flagged:

| Iteration | Repair-plan flag classes present | `model:` field |
|---|---|---|
| First QA call (no `.qa-repair-plan.json` yet on disk) | n/a — initial check | `$QA_ROUTINE_MODEL` from `.skill-config.json` |
| Re-Render-Loop iteration where ALL plan entries are in `{links, xrefs, anchors, repair_plan}` | mechanical repairs only | `$QA_ROUTINE_MODEL` (Haiku under `--reasoning-model sonnet-economy quick\|standard`) |
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

**Pass the `model` field explicitly** in the Agent tool dispatch so the frontmatter `model: sonnet` default in `agents/appsec-qa-reviewer.md:5` is overridden — the same explicit-pass pattern as Stage 4 (Architect Review) below. Without explicit pass-through, the frontmatter default silently wins and the sonnet-economy routing in `.skill-config.json` has no effect, defeating the entire QA-split mechanism. The 2026-05-04 juice-shop run lost ~3 min and ~3× the planned token cost to this drift (stage-stats reported Haiku, AGENT_SPAWN reported Sonnet).

```
- model: $QA_MODEL  ← MUST appear as a top-level Agent tool parameter
```

Pass the following in the prompt body:
- `REPO_ROOT=<absolute repo path>` (same value resolved above)
- `OUTPUT_DIR=<absolute output path>` (same value resolved above)
- `CONTEXT_FILE=$OUTPUT_DIR/.threat-modeling-context.md`
- `QA_DEPTH=<core|full|extended>`
- `PRE_PASS_JSON_PATH=$OUTPUT_DIR/.qa-prepass.json` when the deterministic pre-pass wrote one
- `REPAIR_PLAN_PATH=$OUTPUT_DIR/.qa-repair-plan.json` when a plan exists, otherwise `none`

The QA reviewer runs with its own turn budget and **does not repeat deterministic checks**. It reads the pre-pass summary and any repair plans, classifies structural vs. manual-review vs. content-repair work, performs only semantic checks that Python cannot reliably decide, and writes `$OUTPUT_DIR/.qa-status.json`. It may apply permitted soft edits, but it must not re-read the full Markdown unless the pre-pass or repair plan names a specific semantic ambiguity requiring source context.

**Strict contract gate.** The QA reviewer's Check 14 is a **hard gate** — when it detects any `sections-contract.yaml` violation, it writes a structured `.qa-repair-plan.json` under `$OUTPUT_DIR/`. The presence of this file signals the skill to enter the Re-Render Loop below before proceeding to Stage 4 (or to the Completion Summary when Stage 4 is disabled).

**Record Stage 3 stats (M3.3).** If `QA_AGENT_DISPATCHED=true`, after the QA Agent returns (and the Re-Render Loop has settled, if invoked), extract the `<usage>` block from the QA Agent's return notification and append the Stage 3 record.

**`STAGE3_START_ISO` capture.** Capture `STAGE3_START_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)` immediately before the QA Agent dispatch. The Re-Render Loop may re-dispatch the QA reviewer per iteration; without the lower-bound capture the recorder treats every prior renderer/analyst spawn in `.hook-events.log` as in-scope (`dispatch_count` over-counts).

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/record_stage_stats.py" "$OUTPUT_DIR" \
    --stage 3 \
    --name "QA Review" \
    --agent appsec-advisor:appsec-qa-reviewer \
    --model "$QA_MODEL" \
    --duration-ms <duration_ms_from_usage> \
    --tool-uses <tool_uses_from_usage> \
    --tokens <total_tokens_from_usage> \
    ${STAGE3_START_ISO:+--subagent-type appsec-advisor:appsec-qa-reviewer --since-iso "$STAGE3_START_ISO"}
```

**Pass the actual `$QA_MODEL` value** (not a hardcoded `claude-sonnet-4-6`) so the per-stage breakdown table reflects which model was effectively used — Haiku at sonnet-economy/quick+standard, Sonnet at sonnet-economy/thorough or whenever a content-class repair iteration switches to `$QA_CONTENT_MODEL`.

Stage 4 (Architect Review) records `--stage 4` analogously when `ARCHITECT_REVIEW=true`, with `STAGE4_START_ISO` captured the same way and `--subagent-type appsec-advisor:appsec-architect-reviewer`.

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
  run Stage 3 QA gate
  # The Stage 3 gate may be deterministic-only. Do not dispatch
  # qa-reviewer unless QA_AGENT_DISPATCHED=true is required by the
  # Stage 3 dispatch guard above.
  # Sprint 3A (M3.5): apply content-repair plan + re-compose BEFORE
  # checking qa-status. The applier writes only under .fragments/ and
  # is fail-isolated — its exit code is logged but does not abort the run.
  if exists $OUTPUT_DIR/.qa-content-repair-plan.json:
      python3 $CLAUDE_PLUGIN_ROOT/scripts/apply_content_repair.py "$OUTPUT_DIR" || true
      python3 $CLAUDE_PLUGIN_ROOT/scripts/compose_threat_model.py \
          --output-dir "$OUTPUT_DIR" --strict || true
      # Canonical finalization tail — the --strict recompose above discards the
      # autofix-applied §4/§5 GFM→HTML fixed-layout tables + path-backticking
      # (autofix-exclusive; see AGENTS.md "Critical ordering rule"). Re-apply so
      # the repaired document does not regress to plain wide-column GFM tables.
      python3 $CLAUDE_PLUGIN_ROOT/scripts/apply_prose_fixes.py "$OUTPUT_DIR/threat-model.md" || true
      python3 $CLAUDE_PLUGIN_ROOT/scripts/qa_checks.py autofix "$OUTPUT_DIR/threat-model.md" "$REPO_ROOT" || true
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
      if gate_rc == 1:
          # `.qa-status.json` missing/unreadable → the release-blocker gate could
          # not run, so we cannot prove the report is clean. Fail closed (abort)
          # rather than shipping an unverified report. (qa_release_gate.py: 0=ok,
          # 1=missing/unreadable, 2=blocker.)
          print ".qa-status.json missing/unreadable — release-blocker gate could not run; aborting (fail-closed)"; exit 2
      print manual-review banner; break the loop

  if   qa_status.status == "pass":           break the QA loop
  elif repair_iteration >= MAX_REPAIR_ITERATIONS:
       print hard-fail banner (see below); exit 2
  else:
       # Sprint 3B (M3.7) — mechanical applier short-circuit. Before
       # dispatching the lean fragment-fixer REPAIR pass (~3–4 min,
       # sonnet), try the deterministic applier first. It handles
       # composer-output defects like `toc_nested_link` with a regex
       # substitution on threat-model.md (the source fragment contains
       # no nested link — the pattern is produced by the Composer's
       # double-linkification, so a Stage-1 fragment-edit cannot fix it
       # but a post-compose regex can).
       #
       #   exit 0 → every action in the plan was mechanical and applied.
       #            Skip the REPAIR_MODE dispatch this iteration; just
       #            refresh .qa-repair-plan.json so the next loop turn
       #            sees the cleaned document.
       #   exit 1 → at least one action requires semantic reasoning
       #            (e.g. control_subsection_coverage). Mechanical
       #            actions in the plan were still applied; the
       #            REPAIR_MODE dispatch then only needs to address the
       #            semantic residue.
       #   exit 2 → tool error (missing threat-model.md, unreadable
       #            plan). Log and fall through to the existing path so
       #            the heavy agent can still try.
       python3 $CLAUDE_PLUGIN_ROOT/scripts/apply_repair_plan.py "$OUTPUT_DIR"
       APPLIER_RC=$?
       if APPLIER_RC == 0:
           # Refresh the gate so the next loop turn observes the fix.
           python3 $CLAUDE_PLUGIN_ROOT/scripts/qa_checks.py repair_plan \
               "$OUTPUT_DIR/threat-model.md" "$OUTPUT_DIR" >/dev/null || true
           repair_iteration += 1
           continue  (back to Stage 3 — no heavy LLM dispatch this turn)
       repair_iteration += 1
       rm -f $OUTPUT_DIR/.budget-critical $OUTPUT_DIR/.budget-warning   # fresh-budget clear (G-BC): the REPAIR pass has its own maxTurns; never inherit an earlier stage's wrap-up flag
       dispatch appsec-fragment-fixer (REPAIR_MODE=true) + REPAIR_PLAN_PATH=$OUTPUT_DIR/.qa-repair-plan.json
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
# Mirrors scripts/qa_release_gate.py RELEASE_BLOCKER_PATTERNS (case-insensitive
# match). That script is the single source of truth — keep this copy in sync.
RELEASE_BLOCKER_PATTERNS = (
  "untitled",                 # Mitigation Register `(untitled)` headings — Step 1 / 4 fix
  "(untitled)",
  "orphan",                   # orphaned T-NNN / M-NNN cross-references
  "broken anchor",            # broken-anchor / no-anchor diagnostics
  "mitigation column empty",  # MS Mitigations table empty cells
  "title fields missing",
  "linked but no title",
  "no title",                 # generic "no title" / "missing title"
  "missing title",
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
    Repair agent: appsec-fragment-fixer (REPAIR_MODE=true)
```

**Repair-mode invocation.** The skill spawns the lean `appsec-advisor:appsec-fragment-fixer` agent (maxTurns 30, no Phase 1–10 prompt) with:

- `REPAIR_MODE=true`
- `REPAIR_PLAN_PATH=<absolute path to the repair-plan json>`
- all original flags and resolved variables unchanged (REPO_ROOT, OUTPUT_DIR, STRIDE_MODEL, …)

This replaces the former heavy `appsec-threat-analyst` REPAIR_MODE dispatch: a contract-drift repair is a small fragment-scoped edit + recompose, not a re-analysis, so it must not pay for the 1440-line analyst prompt / 300-turn budget. The fragment-fixer's repair-mode branch must:

1. Skip Phases 1–10 (their outputs are already on disk).
2. Load the repair plan; for each `action`, re-author the listed `fragments_to_rewrite` so the next compose pass emits a contract-clean document. The orchestrator's repair branch is the **only** legal writer of `.fragments/*.{json,md}` — it never touches `threat-model.md` directly.
3. Re-invoke `python3 $CLAUDE_PLUGIN_ROOT/scripts/compose_threat_model.py --output-dir $OUTPUT_DIR --strict` (Phase 11 Substep 5).
3b. **Re-run `apply_prose_fixes.py` on the freshly composed `threat-model.md`** (`python3 $CLAUDE_PLUGIN_ROOT/scripts/apply_prose_fixes.py $OUTPUT_DIR/threat-model.md`). A `compose_threat_model.py --strict` rebuild regenerates the Markdown from fragments and therefore **discards** the deterministic prose-fix pass that the pre-agent gate (§"Pre-agent contract gate") applied before the repair — without this re-run the final document ships with unbackticked code tokens (function calls like `eval()`, file paths like `lib/insecurity.ts:23`, weak-hash names like `MD5`) in tables, §2 Top-Threats cells, and §3 Attack-Walkthrough steps. Idempotent; safe to run after every recompose. (Mirrors the call at the §"Pre-agent contract gate" so the post-repair document matches the pre-repair contract.)
3c. **Re-run `qa_checks.py autofix` as the LAST mutation** (`python3 $CLAUDE_PLUGIN_ROOT/scripts/qa_checks.py autofix $OUTPUT_DIR/threat-model.md $REPO_ROOT`). The recompose at step 3 also discards the autofix-exclusive **§4/§5 GFM→HTML fixed-layout table conversion + `A-NN`/`C-NN` nowrap** (and the links/anchors/MS-structure/cell-format passes) — these live ONLY in `qa_checks.py:cmd_autofix`, never in `compose`, so a bare recompose ships them as plain wide-column GFM tables. This is the canonical final sequence `compose --strict → apply_prose_fixes → qa_checks autofix` (AGENTS.md → "Critical ordering rule"); skipping it is the root cause of repeated §4/§5 table + code-format regressions on repaired runs.
4. Re-run the QA contract gate (Phase 11 Substep 6) as before.
5. Log `REPAIR_END` with the iteration number, the fragment paths that were rewritten, and the final `qa_checks.py contract` exit code.

**Record the repair-mode dispatch as a SEPARATE stage-stats entry** so the
9-min sonnet REPAIR cost is not conflated with the deterministic Stage-3
QA fast-path record. The QA fast-path runs first (deterministic, 5s,
`tokens=0`, `model=none`); when the gate trips and REPAIR_MODE fires,
the repair dispatch is its OWN stat with an iteration-distinct variant
`repair-<k>` (k = `repair_iteration`, 1-based). Without `--variant`,
the second `record_stage_stats.py --stage 3 …` call silently no-ops via
the (stage, variant) idempotency key. **A CONSTANT `--variant repair`
has the same failure when the Re-Render Loop runs more than one
REPAIR_MODE iteration** (observed juice-shop 2026-05-30 `--thorough`:
two repair dispatches, only the first recorded — the second iteration's
~10 min / ~120k tokens were lost from the per-stage breakdown). Using
`repair-<k>` keeps crash-safety idempotency (re-running the SAME
iteration after a crash → same key → no-op) AND captures every distinct
repair pass. `render_completion_summary.py` sums `duration_ms` across
all JSONL lines regardless of variant value, so the distinct variants
all roll into the total correctly.

Capture `STAGE3_REPAIR_START_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)` right
before each repair-mode Agent dispatch (per iteration — capture freshly
each pass). After the Agent returns (substitute `<k>` with the 1-based
repair iteration number):

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/record_stage_stats.py" "$OUTPUT_DIR" \
    --stage 3 --variant "repair-<k>" \
    --name "Re-Render Loop (REPAIR_MODE)" \
    --agent appsec-advisor:appsec-fragment-fixer \
    --model "$STRIDE_MODEL" \
    --duration-ms <duration_ms_from_usage> \
    --tool-uses <tool_uses_from_usage> \
    --tokens <total_tokens_from_usage> \
    ${STAGE3_REPAIR_START_ISO:+--subagent-type appsec-advisor:appsec-fragment-fixer --since-iso "$STAGE3_REPAIR_START_ISO"}
```

The recorder's hybrid-record sanity gate (Fix B, 2026-05-25) will warn
on stderr if a future skill change accidentally passes
`--agent deterministic:* --model none` together with non-zero tokens,
catching the regression that produced the juice-shop 2026-05-25
Stage-3 record with `model=none` + `tokens=119662`.

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
- `SKIP_QA=true` (flag `--no-qa`, env `APPSEC_SKIP_QA=1`, or quick depth) — Stage 3 itself is skipped, so there is no status file to trigger a loop.

Both cases fall through to the Completion Summary directly.

## Stage 4 - Architect Review (auto-on at thorough, else opt-in)

Stage 4 runs when `ARCHITECT_REVIEW=true` (resolved in the Architect Review Resolution section above — auto-enabled at `ASSESSMENT_DEPTH=thorough`, otherwise requires explicit `--architect-review`) **and** `DRY_RUN=false`. Verify that `$OUTPUT_DIR/threat-model.md` and `$OUTPUT_DIR/threat-model.yaml` both exist. If either is missing, skip Stage 4 silently (the QA reviewer or orchestrator already surfaced the underlying failure).

**First print a blank line and the Stage 4 handoff banner** (extract the model short-name from `ARCHITECT_MODEL` — e.g. `claude-opus-4-7` → `opus-4-7`):

```
▶ Stage 4/<total_stages> — Architect Review starting  (expect ~<EST_STAGE4> min, model: <model-short-name>)
  ⟶ Dispatching architect-reviewer — advisory review: architecture coherence, control realism, chain plausibility (13 checks); never rewrites output — emits .architect-review.md
```

Immediately before dispatching, call `TaskUpdate` on the `Stage 4 - Architect Review` task to set status `in_progress`. After the agent returns (success or non-fatal error), call `TaskUpdate` to set it to `completed`. (The task was only created when `ARCHITECT_REVIEW=true` and `DRY_RUN=false` — if absent, skip the update.)

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

After the last enabled review stage completes (Stage 3 when QA is enabled, Stage 4 when architect review is enabled, or Stage 2 when QA is skipped), **always** print a final summary. For `DRY_RUN=true`, print the dry-run summary after Stage 2 and skip Stage 3/4. This is the last thing the skill outputs and is critical for headless mode (`claude -p`) where it becomes the entire visible output.

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

**Budget warning banner (turn-budget exhaustion / wrap-up).**

Before rendering the completion summary, surface any agent that hit its
turn-budget ceiling or triggered a wrap-up. Without this banner the user
would have to grep `.agent-run.log` to discover that a sub-agent
terminated early — the `threat-model.md` would still exist, but with
`meta.incomplete: true` and skipped components.

The watchdog (`scripts/budget_watchdog.py`, called from the PostToolUse
hook in `agent_logger.py`) emits `BUDGET_WARN` (75%), `BUDGET_CRITICAL`
(90%), and `MAX_TURNS` (100%) per session, plus the agent-emitted
`WRAP_UP_TRIGGERED` when an agent gracefully wound down on a critical
flag. This block surfaces all of those events.

```bash
# Sub-agent vs orchestrator distinction (RC.B — 2026-05-24). The existing
# INCOMPLETE banner below conflates orchestrator MAX_TURNS (= run did not
# produce a usable deliverable) with sub-agent MAX_TURNS (= deliverable is
# fine, only that sub-agent's output is reduced-depth). When md exists AND
# .budget-critical is on disk, surface a less alarming INFO note and
# suppress the louder INCOMPLETE banner. The threat-model.yaml meta.incomplete
# check below still fires for the truly-incomplete case.
SUPPRESS_INCOMPLETE_BANNER=false
if [ -f "$OUTPUT_DIR/threat-model.md" ] && [ -f "$OUTPUT_DIR/.budget-critical" ]; then
  AGENTS_AFFECTED=$(python3 -c "
import json
try:
    with open('$OUTPUT_DIR/.budget-critical') as f:
        d = json.load(f)
    print(', '.join(sorted({e.get('agent','?') for e in d if e.get('agent')})))
except Exception:
    pass
" 2>/dev/null)
  if [ -n "$AGENTS_AFFECTED" ]; then
    printf '\n\033[33mℹ Budget critical during run — deliverable complete\033[0m\n' >&2
    printf '  Agents affected: %s\n' "$AGENTS_AFFECTED" >&2
    printf '  threat-model.md was produced; per-agent output may be reduced-depth.\n' >&2
    printf '  Details: %s/.budget-critical\n\n' "$OUTPUT_DIR" >&2
    SUPPRESS_INCOMPLETE_BANNER=true
  fi
  # Clean up stale flag so the next run's banner reflects only that run's events.
  rm -f "$OUTPUT_DIR/.budget-critical"
fi

if [ "$SUPPRESS_INCOMPLETE_BANNER" = "false" ] && \
   grep -qE "BUDGET_CRITICAL|MAX_TURNS|WRAP_UP_TRIGGERED" \
       "$OUTPUT_DIR/.agent-run.log" 2>/dev/null; then
  printf '\n\033[31m⚠ INCOMPLETE — turn-budget exhausted for one or more agents\033[0m\n' >&2
  grep -E "BUDGET_CRITICAL|MAX_TURNS|WRAP_UP_TRIGGERED" \
       "$OUTPUT_DIR/.agent-run.log" | sed 's/^/  /' >&2
  echo "" >&2
  echo "  Details: $OUTPUT_DIR/.budget-critical (JSON list of affected sessions)" >&2
  if [ -f "$OUTPUT_DIR/threat-model.yaml" ] && \
     grep -q "^  incomplete: true" "$OUTPUT_DIR/threat-model.yaml" 2>/dev/null; then
    echo "  threat-model.yaml is marked meta.incomplete:true — incremental runs will refuse this baseline." >&2
    echo "  Re-run with --full once the workload is reduced (smaller scope, --quick, or bumped maxTurns)." >&2
  fi
  echo "" >&2
elif grep -q "BUDGET_WARN" "$OUTPUT_DIR/.agent-run.log" 2>/dev/null; then
  printf '\n\033[33m⚠ Budget warning — an agent reached 75%% of its turn ceiling\033[0m\n' >&2
  grep "BUDGET_WARN" "$OUTPUT_DIR/.agent-run.log" | sed 's/^/  /' >&2
  echo "  Output is complete; consider monitoring future runs for budget drift." >&2
  echo "" >&2
fi
```

The banner is **stderr-only and best-effort** — a missing log or unreadable file silently skips the banner; the run never blocks on the warning emission itself. The same events are also already mirrored to stderr in real-time during the run (via `_HIGH_SIGNAL_EVENTS` in `agent_logger.py`); this banner is the consolidated end-of-run reminder.

**Design intent.** The completion block is the *only* thing the user reliably sees in headless (`claude -p`) mode and the dominant visible artifact in interactive mode. It is rendered by `scripts/render_completion_summary.py` — a single self-contained Python script with full unit tests. **Do not hand-author any part of this block**; invoke the script and print its output verbatim.

**Compute the true end-to-end wall-clock first.** Read the `.scan-start-epoch`
marker written at run start (see the "anchor point for all per-run timing"
block above) and write the elapsed seconds to `.scan-wall-seconds`, which
`render_completion_summary.py` reads to render the `Total scan (wall)` line
**alongside** the `Total stage compute` total. The two figures differ by the
orchestration overhead (between-dispatch turns, preamble, permission waits) —
showing both is what makes "how long did the scan take" unambiguous. The stage
total is the sum of per-stage agent compute from `.stage-stats.jsonl`; the
wall-clock is real elapsed time. Best-effort — a missing marker just omits the
wall line:

```bash
SCAN_START=$(cat "$OUTPUT_DIR/.scan-start-epoch" 2>/dev/null || echo 0)
if [ "${SCAN_START:-0}" -gt 0 ]; then
  printf '%s' "$(( $(date +%s) - SCAN_START ))" > "$OUTPUT_DIR/.scan-wall-seconds" 2>/dev/null || true
fi
```

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/render_completion_summary.py" \
    --output-dir "$OUTPUT_DIR" \
    --repo-root  "$REPO_ROOT" \
    --mode "$MODE" \
    --reasoning-model "$REASONING_MODEL" \
    --assessment-depth "$ASSESSMENT_DEPTH" \
    $( [ "$WRITE_YAML"         = "true"  ] && echo "--write-yaml"         || echo "--no-write-yaml" ) \
    $( [ "$WRITE_SARIF"        = "true"  ] && echo "--write-sarif"        || echo "--no-write-sarif" ) \
    $( [ "$WRITE_PENTEST_TASKS" = "true"  ] && echo "--write-pentest-tasks" || echo "--no-write-pentest-tasks" ) \
    $( [ "$CHECK_REQUIREMENTS" = "true"  ] && echo "--check-requirements" || echo "--no-check-requirements" ) \
    $( [ "$ARCHITECT_REVIEW"   = "true"  ] && echo "--architect-review"   || echo "--no-architect-review" ) \
    $( [ "${APPSEC_PLUGIN_DEV:-}" = "1"  ] && echo "--plugin-dev" ) \
    --patch-placeholders
```

The `--patch-placeholders` flag rewrites `_pending_` markers in the MD's `## Appendix: Run Statistics` section with the extracted durations and models. Idempotent — a second invocation is a no-op.

**What the script produces (format contract):** the output is an unboxed,
scan-friendly summary in this fixed order:

1. `Assessment complete: Create Threat Model`
2. `Repository`
3. `Run` — mode, scope, depth, duration, cost, QA, architect review
4. `Results` — threats by severity, components, controls, mitigations
5. `Change Summary` — rendered only when `threat-model.yaml` has a meaningful `changelog[0]` with deltas
6. `Threat Delta` — top 3 new, resolved, and changed threats when available
7. `Outputs` — artifact paths (yaml conditional on `--write-yaml`; sarif conditional on file presence)
8. Conditional health / run-issues / security notice blocks
9. `Next Steps` — 1–5 conditional action lines
10. `Run Statistics` — total + per-phase durations, agent roster, tokens + cost when extractable
11. `Logs`

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
# Prefer the first ASSESSMENT_START timestamp in .agent-run.log (the actual
# orchestrator-Phase-1 start) over ASSESSMENT_START_EPOCH. The shell variable
# is captured before the Stage 1 Agent dispatch and therefore includes any
# user-confirm wait time on the permission prompt — which would inflate
# last_run_seconds and corrupt the next run's estimate. The log timestamp is
# only written once the orchestrator is actually running. Fallback chain:
# log -> ASSESSMENT_START_EPOCH -> skip.
RUN_START_EPOCH=$(python3 - "$OUTPUT_DIR/.agent-run.log" "${ASSESSMENT_START_EPOCH:-0}" <<'PYEOF'
import sys, re, datetime
log_path, fallback = sys.argv[1], sys.argv[2]
ts_re = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s.*ASSESSMENT_START\b')
try:
    with open(log_path, encoding='utf-8', errors='replace') as fh:
        for line in fh:
            m = ts_re.match(line)
            if m:
                dt = datetime.datetime.strptime(m.group(1), '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)
                print(int(dt.timestamp()))
                sys.exit(0)
except OSError:
    pass
print(fallback)
PYEOF
)
if [ "$RUN_START_EPOCH" -gt 0 ]; then
  RUN_END_EPOCH=$(date +%s)
  RUN_SECONDS=$(( RUN_END_EPOCH - RUN_START_EPOCH ))
  RUN_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  CACHE_DIR="$OUTPUT_DIR/.appsec-cache"
  CACHE_FILE="$CACHE_DIR/baseline.json"
  mkdir -p "$CACHE_DIR" 2>/dev/null
  if [ -f "$CACHE_FILE" ]; then
    # Merge with existing baseline.json (don't clobber other fields).
    # Pure-Python implementation — `jq` is not a hard dependency of the skill
    # (Alpine, slim Docker images, vanilla WSL all ship without it). The
    # earlier `jq` form failed silently on those systems and the field never
    # made it to disk, defeating the entire estimation cache.
    python3 - "$CACHE_FILE" "$RUN_SECONDS" "$MODE" "${ASSESSMENT_DEPTH:-standard}" "$RUN_ISO" <<'PYEOF'
import json, sys, os
path, secs, mode, depth, iso = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
try:
    with open(path, encoding='utf-8') as fh:
        data = json.load(fh)
except Exception:
    data = {}
data['last_run_seconds'] = secs
data['last_run_mode']    = mode
data['last_run_depth']   = depth
data['last_run_iso']     = iso
tmp = path + '.tmp'
with open(tmp, 'w', encoding='utf-8') as fh:
    json.dump(data, fh, indent=2)
os.replace(tmp, path)
PYEOF
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

`RUN_START_EPOCH` is derived from the first `ASSESSMENT_START` line in `.agent-run.log` so that pre-dispatch user-confirm wait time is excluded from `last_run_seconds`. `ASSESSMENT_START_EPOCH` is captured at the top of the skill as a fallback (and is still used by the deadline watchdog at §"Wall-time + cost deadline watchdog"). Best-effort: if both signals are missing the cache write is skipped and the next-run estimator falls back to the parametric formula. The cache write itself uses `python3` rather than `jq`, so the field is persisted on systems without `jq` installed.

### Persist per-component durations for next-run Phase-9 estimate (M5)

Right after writing `last_run_seconds`, also record per-component STRIDE durations so the next run's `estimate_duration.py` can produce a Phase-9-aware estimate. The helper script reads `.stride-*.json` mtimes against the most-recent Phase-9 PHASE_START in `.agent-run.log` and merges the result into `.appsec-cache/baseline.json.component_durations`.

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/record_component_durations.py" \
    "$OUTPUT_DIR" 2>/dev/null || true
```

Best-effort: failure here is non-fatal — the next run falls through to `last_run_cache` or `parametric` source.

### Post-summary cleanup

After the script returns, call `TaskUpdate` on the final task to set status `completed`. **Use the same subject you created in Stage Task List Bootstrap** — `Final summary` when `KEEP_RUNTIME_FILES=true`, otherwise `Final summary + cleanup`. (This is the final task on the list, so once it flips the whole Stage-1→cleanup sequence shows completed across the board.)

Then run the deterministic post-pipeline transient-file cleanup (whitelist pinned in `scripts/runtime_cleanup.py`) and remove the verbose / tracing marker files. **When `KEEP_RUNTIME_FILES=true` (the `--keep-runtime-files` flag), SKIP the `runtime_cleanup.py` calls entirely** — the whole point of the flag is to leave the transient artifacts (`.stride-*.json`, `.threats-merged.json`, `.fragments/`, `.qa-*.json`, etc.) on disk for debugging. The lock release and marker cleanup still run regardless (they are run-state, not debug artifacts):

```bash
if [ "$KEEP_RUNTIME_FILES" != "true" ]; then
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/runtime_cleanup.py" "$OUTPUT_DIR" --stage post-qa >/dev/null 2>&1 || true
    if [ "$ARCHITECT_REVIEW" = "true" ]; then
        python3 "$CLAUDE_PLUGIN_ROOT/scripts/runtime_cleanup.py" "$OUTPUT_DIR" --stage post-architect >/dev/null 2>&1 || true
    fi
else
    printf '  Runtime files kept (--keep-runtime-files) — transient artifacts NOT cleaned.\n' >&2
fi
rm -f "$OUTPUT_DIR/.appsec-lock"
rm -f "${TMPDIR:-/tmp}/.appsec-verbose-$(id -u)"
rm -f "${TMPDIR:-/tmp}/.appsec-tracing-$(id -u)"
```

`post-qa` runs the Phase 11 whitelist plus QA-specific artifacts (`.qa-status.json`, empty `.qa-repair-plan.json`, `.fragments/`). `post-architect` additively removes architect-review status files. Exit code 1 (safety-gate block) is silenced with `|| true` — the summary has already been printed. Both `runtime_cleanup.py` invocations are skipped under `--keep-runtime-files` so the kept artifacts survive, matching the conditional `Final summary` task label (no "+ cleanup" advertised when no cleanup runs).

### PDF Export (only when `WRITE_PDF=true`)

The PDF export runs **after** all four stages, the Completion Summary, and `runtime_cleanup`. Placing it last is intentional: at this point `threat-model.md` is final (no more QA / architect re-render passes), so the PDF can never go stale. The export script is the same one used by `/appsec-advisor:export-threat-model --formats pdf`.

**Non-fatal.** PDF export failures must not fail the assessment. The threat model itself was successfully written before this step runs; a missing system dependency (pandoc, weasyprint) or a conversion error are warnings, not errors. Log the issue and continue.

**Run this step UNSANDBOXED.** Mermaid rendering shells out to a headless Chrome (via mmdc/Puppeteer), and Chrome's `process_singleton` calls `socket()` at launch — a syscall the Bash sandbox blocks (`Operation not permitted`, EPERM, path-independent). Under the sandbox the export aborts with a "Mermaid renderer cannot run …" message and writes **no** PDF (by design: a diagram-less PDF is a broken deliverable, not a silent fallback). Dispatch the `export_pdf.py` invocation below with the **sandbox disabled** so Chrome can launch and all diagrams render. If you see that abort message, the cause is the sandbox — re-run the exact command unsandboxed; do **not** "fix" it by adding `--no-mermaid` (that ships a diagram-less PDF). `--no-mermaid` is only for a deliberate, user-requested diagram-less export.

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
        printf '  Run `/appsec-advisor:export-threat-model --formats pdf --check-only` for the install hints.\n' >&2
    fi
fi
```

The exporter's own preflight handles missing dependencies with a clear message; the skill simply prints a one-line pointer to `--check-only` so the user knows where to look. The `tee` to `.agent-run.log` ensures the preflight diagnostics are captured for post-mortem even when the user runs in non-interactive mode.

`scripts/runtime_cleanup.py` already lists `threat-model.pdf` in its NEVER-touch set — so this output survives all subsequent cleanup invocations the same way `threat-model.md` and `threat-model.sarif.json` do.

### HTML Export (only when `WRITE_HTML=true`)

The HTML export runs **after** the PDF block, under the same rationale: `threat-model.md` is final, so the standalone `threat-model.html` can never go stale. The export script is the same one used by `/appsec-advisor:export-threat-model --formats html`. `--pdf` and `--html` are independent and may both be set in one run.

**Non-fatal.** HTML export failures must not fail the assessment, identically to PDF. The threat model itself was already written; a conversion error or a missing optional `mmdc` (Mermaid pre-render) is a warning, not an error. Log and continue.

```bash
if [ "$WRITE_HTML" = "true" ]; then
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/export_html.py" \
        --input  "$OUTPUT_DIR/threat-model.md" \
        --output "$OUTPUT_DIR/threat-model.html" \
        2>&1 | tee -a "$OUTPUT_DIR/.agent-run.log" >&2
    HTML_RC=${PIPESTATUS[0]}
    if [ "$HTML_RC" -eq 0 ]; then
        printf '\n  HTML: %s/threat-model.html\n' "$OUTPUT_DIR" >&2
    else
        printf '\n  HTML export skipped (exit %s — see preflight output above)\n' "$HTML_RC" >&2
        printf '  Run `/appsec-advisor:export-threat-model --formats html --check-only` for the install hints.\n' >&2
    fi
fi
```

`scripts/runtime_cleanup.py` already lists `threat-model.html` in its NEVER-touch set, so this output survives subsequent cleanup the same way `threat-model.pdf` does.

**Explicit success exit.** After the HTML block (or after the cleanup block when both `WRITE_PDF=false` and `WRITE_HTML=false`) emit an unambiguous success exit so that no subsequent code path can accidentally run:

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
