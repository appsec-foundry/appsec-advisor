---
name: create-threat-model
description: Perform a threat assessment of a repository and produce a threat-model.md. Supports --repo to analyze external repos and --output to set the output directory. Optionally also writes threat-model.yaml with --yaml flag.
---

This skill runs in up to three stages: first the threat analyst orchestrator (Phases 1–10), then the QA reviewer (Phase 11), and — at `--assessment-depth thorough` (auto) or whenever `--architect-review` is passed — an advisory architect review (Stage 3). Each stage is a separate Agent invocation with its own turn budget. Pass `--no-architect-review` to suppress Stage 3 even at thorough depth.

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

The resolved value must also be passed verbatim in the Stage 1 and Stage 2 agent prompts (see "Stage 1 — Threat Model Orchestrator" below).

### Bash commands the skill relies on

If you run Claude Code with a restrictive `permissions.allow` list in `settings.json`, the following command prefixes must be allow-listed for the skill to work end-to-end. Each one is invoked by the orchestrator, the sub-agents, or one of the plugin scripts:

| Command | Who runs it | Purpose |
|---------|-------------|---------|
| `git rev-parse`, `git log`, `git diff --name-only`, `git status`, `git show` | orchestrator, context-resolver | baseline SHA, changed-file delta, commit metadata |
| `git -C <repo> …` | all agents | when `--repo <path>` points outside the current working directory |
| `python3 <plugin>/scripts/*.py` | orchestrator, skill, qa-reviewer | `plugin_meta.py`, `baseline_state.py`, `stride_progress.py`, `validate_intermediate.py`, `verify_run_costs.py` |
| `find /root /home /opt -maxdepth 6 …` | skill fallback | `CLAUDE_PLUGIN_ROOT` discovery when env is empty |
| `date -u +%Y-%m-%dT%H:%M:%SZ` / `date +%s` | all agents | log timestamps and phase-epoch tracking |
| `grep -c`, `wc -l`, `wc -c`, `awk`, `sed`, `stat`, `ls`, `basename` | all agents | count aggregation for PHASE_END/STEP_END lines |
| `mkdir -p`, `rm -f`, `cat`, `echo`, `printf`, `cp`, `mv` | all agents | intermediate file handling, checkpoints, lock |
| `sha256sum` / `shasum -a 256` | `baseline_state.py` | stride file fingerprinting |

**None** of the above are destructive against `$REPO_ROOT` — every write targets `$OUTPUT_DIR` (default `$REPO_ROOT/docs/security`) or a temp file under it. If you want a minimally-scoped allow-list, permit `Bash(git:*)`, `Bash(python3:*)`, `Bash(grep:*)`, `Bash(find:*)`, and `Bash(date:*)` plus the file-handling basics.

## `--help` — inline help (early exit)

If the user's arguments contain the token `--help` or `-h` (anywhere, case-sensitive), **do not run the assessment**. Print the contents of `HELP.txt` verbatim and exit 0. Detection happens before any other parsing so broken flag combinations don't block access to help.

```bash
cat "$CLAUDE_PLUGIN_ROOT/skills/create-threat-model/HELP.txt"
```

If the `cat` fails (missing file or unresolved `$CLAUDE_PLUGIN_ROOT`), fall back to a one-line message pointing at `docs/threat-model-skill.md`. After printing, exit. Do not read any further files, dispatch agents, or perform any other action.

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
| `--repo <path>` | `REPO_ROOT=<abs-path>` | current working directory |
| `--output <path>` | `OUTPUT_DIR=<abs-path>` | `$REPO_ROOT/docs/security` |
| `--reasoning-model <mode>` | `REASONING_MODEL=<sonnet\|opus-cheap\|opus>` → resolves to `STRIDE_MODEL`, `TRIAGE_MODEL`, `MERGER_MODEL` | `opus-cheap` at standard/thorough; `sonnet` at quick (see Reasoning Model Resolution) |
| `--stride-model <model>` | `STRIDE_MODEL=<model>` (punctual override, applied **after** `--reasoning-model` resolution) | (none — inherits from `--reasoning-model`) |
| `--assessment-depth <level>` | `ASSESSMENT_DEPTH=<quick\|standard\|thorough>` | `standard` |
| `--architect-review` | `ARCHITECT_REVIEW=true` — enables Stage 3 (advisory architect-level review) | auto-on at `--assessment-depth thorough`, off otherwise |
| `--no-architect-review` | `ARCHITECT_REVIEW=false` — escape hatch to disable Stage 3 even at `--assessment-depth thorough` | n/a |
| `--architect-model <sonnet\|opus>` | `ARCHITECT_MODEL=<model>` — model for Stage 3 (ignored when `ARCHITECT_REVIEW=false`) | `opus` when Stage 3 is enabled |
| `--verbose` | `VERBOSE_REPORT=true` — also writes a per-user marker file that flips `agent_logger.py` into stderr-mirroring mode for the duration of this run (see "Verbose Mode — Marker File Lifecycle" below) | `false` |
| `--tracing` | `TRACING=true` — writes a per-user marker file that activates per-agent token/turn/cost/wall-time tracking in `.appsec-trace.log`. At session end, `agent_logger.py` appends an ASSESSMENT_TRACE Markdown table to `.appsec-trace.log` (see "Tracing Mode — Marker File Lifecycle" below) | `false` |
| `--base <ref>` | `BASE_REF=<ref>` — git ref to diff HEAD against for incremental mode (default: `commit_sha` recorded in the prior `threat-model.yaml`). Used in MR/PR mode to target the base branch. | (baseline commit) |
| `--pr-mode` | `PR_MODE=true` — produce a focused delta report limited to components affected by the `--base ... HEAD` diff. Implies `--incremental` and skips Stage 2 QA. | `false` |
| `--no-qa` | `SKIP_QA=true` — skip the Stage 2 QA reviewer (faster CI runs where the report is machine-consumed). Also honoured via `APPSEC_SKIP_QA=1`. | `false` |
| `--qa-scan-repo` | `QA_SCAN_REPO=true` — enable QA Check 2 Pass 2c (proactive repo-wide `find` for unlinked basenames). Off by default because it is expensive on large repos and only marginally useful (cosmetic linkification). | `false` |

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
RESOLVED_JSON=$(python3 "$CLAUDE_PLUGIN_ROOT/scripts/resolve_config.py" --emit-file $INVOCATION_ARGS)
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

## Incremental Fast-Path (null-change abort)

When `MODE=incremental` and a baseline exists, run a **unified pre-check** *before* entering Stage 1. If nothing has changed since the last run and the plugin hasn't drifted, exit immediately with a friendly message — no agents dispatched, no tokens burned.

```bash
if [ "$MODE" = "incremental" ]; then
  FAST_PATH_ARGS="check-changes --output-dir \"$OUTPUT_DIR\" --repo-root \"$REPO_ROOT\""
  [ -n "$BASE_REF" ] && FAST_PATH_ARGS="$FAST_PATH_ARGS --base-ref \"$BASE_REF\""
  FAST_PATH_OUTPUT=$(python3 "$CLAUDE_PLUGIN_ROOT/scripts/baseline_state.py" $FAST_PATH_ARGS 2>/dev/null || true)
  FAST_PATH_EXIT=$?

  case "$FAST_PATH_EXIT" in
    0)
      echo "No changes detected since the last scan — threat model is up to date."
      echo "  Baseline : $(echo "$FAST_PATH_OUTPUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("baseline_sha","?")[:12])')"
      echo "  Current  : $(echo "$FAST_PATH_OUTPUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("head_sha","?")[:12])')"
      exit 0
      ;;
    10)
      echo "Source unchanged, but plugin version has drifted since the last run."
      echo "$FAST_PATH_OUTPUT" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(" ",d["plugin_version"].get("message",""))'
      if [ "${APPSEC_CI_MODE:-}" = "1" ]; then
        # In CI we honour the drift signal and still abort — dedicated
        # full-refresh jobs should handle plugin upgrades.
        exit 0
      else
        # Interactive: user may want to carry on; fall through to the normal run
        # (the compat gate below may still hard-abort on analysis_version drift).
        echo "  Continuing with incremental run; pass --full to force a rebuild."
      fi
      ;;
    *)
      : # status=changed or error — fall through
      ;;
  esac
fi
```

The same pre-check is performed by `scripts/run-headless.sh` at shell level, so CI runners can fast-abort *before* even spawning Claude Code. The in-skill version is a safety net for interactive invocations.

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

Print the consolidated configuration block by calling ``resolve_config.py`` in summary mode:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/resolve_config.py" --config-summary $INVOCATION_ARGS
```

The script emits the fixed-format block (Repository / Output / Plugin / Mode / Baseline / Depth / Requirements / Architect) plus the conditional post-summary lines (output-outside-repo note, rebuild-overwrite warning, incremental-tip, requirements-disabled tip). The exact format contract is pinned in ``scripts/resolve_config.py → render_configuration_summary`` and covered by ``tests/test_resolve_config.py``. No handwriting of the summary — if the format needs to change, edit the script.

The ``Baseline`` line is printed only when ``MODE=incremental``; the ``Architect`` line only when ``ARCHITECT_REVIEW=true``. Both are handled inside the script.

### Rebuild Pre-flight Wipe (only when `REBUILD=true`)

When `REBUILD=true` and `DRY_RUN=false`, wipe prior model and cached state **before** the Stage 1 handoff banner but **after** the Configuration Summary (so the user has already seen `Mode: rebuild (...)` and the `POST_SUMMARY_NOTE` warning).

Print the wipe header:

```

Rebuild: discarding prior threat model and all cached state.
  Removing from <OUTPUT_DIR>:
    threat-model.md / threat-model.yaml / threat-model.sarif.json / pentest-tasks.yaml (if present)
    .architect-review.md, .threat-modeling-context.md, .recon-summary.md, .dep-scan.json
    .stride-*.json, .threats-merged.json, .triage-flags.json, .merge-*.json
    .appsec-cache/ (baseline cache directory)
    .appsec-checkpoint (if present)
  Preserved:
    .agent-run.log, .hook-events.log (audit trail — overwritten by next run's ASSESSMENT_START)
```

Then perform the wipe in a single Bash call:

```bash
cd "$OUTPUT_DIR" 2>/dev/null || true
WIPED_COUNT=$(find . -maxdepth 1 \
  \( -name "threat-model.md" -o -name "threat-model.yaml" -o -name "threat-model.sarif.json" \
     -o -name "pentest-tasks.yaml" -o -name ".architect-review.md" \
     -o -name ".threat-modeling-context.md" -o -name ".recon-summary.md" -o -name ".dep-scan.json" \
     -o -name ".stride-*.json" -o -name ".threats-merged.json" -o -name ".triage-flags.json" \
     -o -name ".merge-*.json" -o -name ".appsec-checkpoint" \) \
  -print -delete 2>/dev/null | wc -l)
rm -rf .appsec-cache 2>/dev/null
echo "  Removed $WIPED_COUNT files + .appsec-cache/"
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
    .architect-review.md (will be regenerated by Stage 3 if enabled)
    .recon-summary.md (will be regenerated by Phase 2)
    .appsec-checkpoint (will be recreated from Phase 1)
    .progress/ (per-agent progress tracker — will be recreated)
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
     -o -name ".session-agent-map" -o -name ".prior-findings-index.json" \) \
  -print -delete 2>/dev/null | wc -l)
rm -rf .progress 2>/dev/null
echo "  Removed $WIPED_COUNT stale intermediate files + .progress/"
```

If `$OUTPUT_DIR` does not exist or `find` fails, treat as no-op.

**Why this matters.** Without this step, a `--full` run against a directory that held, say, `T-001..T-055` from a prior session can see its Phase 9 merge step read a mix of fresh per-component STRIDE outputs and a stale `.threats-merged.json` from the previous session, leading to cross-run ID drift (e.g. `T-003` surviving as a YAML/JSON phantom after the current MD dropped it during consolidation). This is the root cause behind the architect-review findings W-02 / W-03 / W-08 seen on the 2026-04-18 thorough run.

### Stage 1 Handoff Banner

Then print a blank line and the Stage 1 handoff banner. When `VERBOSE_REPORT=true` is resolved, append a single hint line so the user knows where the extra output is going to appear:

```
▶ Stage 1/<total_stages> — Threat Model Orchestrator starting  (expect ~<duration>)
```

When `VERBOSE_REPORT=true`, add one extra line directly underneath (exactly this text, no other variants):
```
  ℹ Verbose mode ON — STEP_START/END, SCAN_START/END, and AGENT_INVOKE lines mirror live to stderr (~20 s poll cadence during Phase 9).
```

Where:
- `<total_stages>` is `3` when `ARCHITECT_REVIEW=true`, otherwise `2`
- `<duration>` depends on `ASSESSMENT_DEPTH`: `~15 min` (quick), `~25 min` (standard), `~40 min` (thorough)

No other text — no explanatory prose, no duplicated mode description — belongs between these lines. The verbose-mode hint is the single exception, and only when the flag is actually on.

## Resume from Checkpoint

If `--resume` is passed, check for `$OUTPUT_DIR/.appsec-checkpoint`:

1. Read the checkpoint file. It contains `phase=<N> status=<started|completed> timestamp=<ISO>`.
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

## Stage 1 — Threat Model Orchestrator

Invoke the `appsec-advisor:appsec-threat-analyst` agent **exactly once** using `"Threat Model Orchestrator"` as the Agent tool `description`. The orchestrator handles all phases internally (including context resolution in Phase 1) — do **not** invoke `appsec-context-resolver` or any other agent from the skill level. Only invoke the orchestrator here.

### Handling turn-budget cut-offs

Thorough-depth runs with 8 STRIDE analyzers (MAX_STRIDE_COMPONENTS=8) routinely touch the Claude Code agent turn budget (observed at ~90 tool calls per agent session in `claude -p` headless mode). When the budget is hit, the Agent call returns control to the skill *before* Phase 11 finalization runs, typically mid-Phase-9 or mid-Phase-10. Two concrete symptoms:

1. The agent's final text ends with something like `"All 8 STRIDE files ready. Proceeding to merge."` without a closing `ASSESSMENT_END` log entry.
2. `$OUTPUT_DIR/threat-model.md` does NOT exist after the Agent call returns — but `$OUTPUT_DIR/.stride-*.json` and `$OUTPUT_DIR/.recon-summary.md` are present.

**Detection (mandatory).** Immediately after the Stage 1 Agent call returns, the skill MUST check whether `threat-model.md` exists:

```bash
if [ ! -f "$OUTPUT_DIR/threat-model.md" ]; then
  # Stage 1 cut off before Phase 11. Check for resumable state.
  STRIDE_COUNT=$(ls "$OUTPUT_DIR"/.stride-*.json 2>/dev/null | wc -l)
  if [ "$STRIDE_COUNT" -ge 1 ]; then
    STAGE1_CUTOFF=true
  else
    STAGE1_CUTOFF_NO_STRIDE=true
  fi
fi
```

**Recovery path.** If `STAGE1_CUTOFF=true`, spawn a **second** `appsec-advisor:appsec-threat-analyst` Agent call (fresh turn budget) with the description `"Threat Model Orchestrator (resume)"` and a prompt that:

1. Tells the agent to skip Phases 1–8 entirely because their outputs are on disk (`.recon-summary.md`, `.threat-modeling-context.md`).
2. Lists every `.stride-<component>.json` file under `$OUTPUT_DIR` and instructs the agent not to re-dispatch STRIDE analyzers.
3. Passes all original configuration variables **identical** to the first call.
4. Sets `RESUME_FROM_PHASE=9-merge` so the agent knows to start from the merge step.

The `SendMessage` tool (which would reuse the prior agent's context) is **not** available in every Claude Code configuration, so the resume path MUST use a fresh Agent call — not `SendMessage`. The duplicate context upload is the cost of being portable across headless/IDE/web clients.

**Not an error.** Cut-offs are not skill-level failures and MUST NOT print an error banner. Cut-and-resume is the expected operational mode for thorough runs until Claude Code's per-agent turn budget is raised.

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
- `STRIDE_MODEL=<model>` (from `--reasoning-model` resolution; overridden by `--stride-model` or `$APPSEC_STRIDE_MODEL` when set)
- `TRIAGE_MODEL=<model>` (from `--reasoning-model` resolution; overridden by `$APPSEC_TRIAGE_MODEL` when set)
- `MERGER_MODEL=<model>` (from `--reasoning-model` resolution; overridden by `$APPSEC_MERGER_MODEL` when set)
- `REASONING_LABEL=<resolved summary>`
- `RESUME_FROM_PHASE=<N>` (only if resuming from checkpoint)
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
- Stage 2 (QA reviewer) is skipped — the output is transient and does not need QA
- After the console summary, the temp directory is deleted: `rm -rf "$OUTPUT_DIR"`

## Stage 2 — QA Review

After the orchestrator completes (and `DRY_RUN` is `false`), verify that `$OUTPUT_DIR/threat-model.md` exists. Before dispatching the QA-reviewer agent the skill runs two **deterministic pre-agent gates** so the agent's turn budget is spent on qualitative checks rather than on finding drift that a Python script can detect in 200 ms.

### Post-Stage-1 fragment precondition (deterministic, skill-level)

The first thing the skill does after Stage 1 returns is check whether the orchestrator actually went through the fragment pipeline. This is the mechanical enforcement of the policy "direct `Write` of `threat-model.md` is forbidden" — without it the policy is just a sentence in an agent prompt that the LLM can ignore under turn pressure.

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/qa_checks.py" fragments "$OUTPUT_DIR"
FRAG_EXIT=$?
if [ "$FRAG_EXIT" -ne 0 ]; then
  # The orchestrator took the inline-shortcut. Classify and act.
  if [ ! -d "$OUTPUT_DIR/.fragments" ]; then
    # Hard failure — no fragments at all means Re-Render Loop cannot run.
    # Print the "inline-shortcut detected" banner (see below) and exit 2.
    INLINE_SHORTCUT=true
  else
    # Partial fragment set — extremely unusual, but repair-loop-eligible.
    # Surface as a contract violation so the regular loop fires.
    INLINE_SHORTCUT=false
  fi
fi
```

**Inline-shortcut banner (printed when `.fragments/` is missing entirely):**

```
══════════════════════════════════════════════════════════════
  ASSESSMENT INCOMPLETE — inline-shortcut detected
══════════════════════════════════════════════════════════════

  Stage 1 wrote $OUTPUT_DIR/threat-model.md directly without going
  through the fragment pipeline (.fragments/ is missing).

  Root cause: the orchestrator skipped Phase 11 Substeps 4–5 and
  hand-authored the Markdown. The contract-mandated renderers
  (finding_list, bullet_list, computed tables) never ran, which
  means the rendered report is structurally non-compliant AND the
  Re-Render Loop cannot repair it (it has no fragments to rewrite).

  Fix: re-run the skill. If this failure reproduces on a second
  attempt, file a plugin bug — the orchestrator prompt should have
  prevented the shortcut.
══════════════════════════════════════════════════════════════
```

Then `rm -f` the verbose and tracing markers, skip Stage 2 and Stage 3, and exit 2. Do not print a partial completion summary — the report on disk is known non-compliant and the skill must not legitimize it.

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

### Stage 2 handoff banner

When the pre-agent gates are clean (or after the Re-Render Loop has settled), dispatch the QA agent. **First print a blank line and the Stage 2 handoff banner**:

```
▶ Stage 2/<total_stages> — QA Review starting  (expect ~5 min, model: sonnet-4-6)
  ⟶ Dispatching qa-reviewer — qualitative checks on a contract-clean Markdown (pre-agent gate already passed); scope: file-path linkification, prior-finding coverage, semantic cross-refs
```

Where `<total_stages>` is `3` when `ARCHITECT_REVIEW=true`, otherwise `2`.

Then invoke the `appsec-advisor:appsec-qa-reviewer` agent using `"QA review of threat model"` as the Agent tool `description`.

Pass the following in the prompt:
- `REPO_ROOT=<absolute repo path>` (same value resolved above)
- `OUTPUT_DIR=<absolute output path>` (same value resolved above)
- `CONTEXT_FILE=$OUTPUT_DIR/.threat-modeling-context.md`
- `QA_DEPTH=<core|full|extended>`

The QA reviewer runs with its own turn budget (up to 40 turns) and fixes broken VS Code links, linkifies bare file references, verifies cross-references, checks YAML/MD consistency, flags unaddressed prior findings, removes unfilled placeholders, and verifies section completeness. It updates `$OUTPUT_DIR/threat-model.md` in-place.

**Strict contract gate.** The QA reviewer's Check 14 is a **hard gate** — when it detects any `sections-contract.yaml` violation, it writes a structured `.qa-repair-plan.json` under `$OUTPUT_DIR/`. The presence of this file signals the skill to enter the Re-Render Loop below before proceeding to Stage 3 (or to the Completion Summary when Stage 3 is disabled).

### Re-Render Loop — enforce strict contract compliance

Some QA / architect failures are recoverable by re-rendering `threat-model.md` from the (possibly repaired) fragments instead of abandoning the run. The skill manages this loop at the stage boundary so neither the QA reviewer nor the architect reviewer ever mutate the threat model out of band.

**When the loop runs.** After **every** Stage 2 invocation (and after every Stage 3 invocation when `ARCHITECT_REVIEW=true`), the skill inspects the agent's structured output:

- `$OUTPUT_DIR/.qa-status.json` — always written by Stage 2. Status `pass` means the rendered MD matches the contract; status `repair_required` means the Stage 2 helper also wrote `.qa-repair-plan.json` describing the violations.
- `$OUTPUT_DIR/.architect-status.json` — written by Stage 3 when the architect review encounters technical defects that the orchestrator can fix (broken Mermaid syntax, missing attack-walkthrough per Critical, §7.3 missing per-flow `####` blocks, etc.). Status `pass` means the architect had no structural objections; status `repair_required` is paired with `.architect-repair-plan.json`.

**Loop logic (both stages share the same mechanics):**

```
MAX_REPAIR_ITERATIONS = 3       # hard cap on loop depth
repair_iteration = 0            # counts post-Stage-1 repair passes

# Initial pass
dispatch Stage 1 (threat-analyst)         # MODE = full|incremental (from earlier resolution)

loop:
  dispatch Stage 2 (qa-reviewer)
  read   $OUTPUT_DIR/.qa-status.json
  if   .status == "pass":           break the QA loop
  elif repair_iteration >= MAX_REPAIR_ITERATIONS:
       print hard-fail banner (see below); exit 2
  else:
       repair_iteration += 1
       dispatch Stage 1 again with REPAIR_MODE=true + REPAIR_PLAN_PATH=$OUTPUT_DIR/.qa-repair-plan.json
       continue  (back to Stage 2)
```

The analogous loop then runs for Stage 3 when `ARCHITECT_REVIEW=true`, using `.architect-status.json` / `.architect-repair-plan.json`. Each stage has its own `MAX_REPAIR_ITERATIONS` budget (default 3); they are not shared.

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

  Stage             : <Stage 2 QA | Stage 3 Architect>
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

- `DRY_RUN=true` — the temp `OUTPUT_DIR` is disposable; a single pass is sufficient. (Stage 2 still writes `.qa-status.json`, but the skill ignores `repair_required` in dry-run mode.)
- `SKIP_QA=true` (flag `--no-qa` or env `APPSEC_SKIP_QA=1`) — Stage 2 itself is skipped, so there is no status file to trigger a loop.

Both cases fall through to the Completion Summary directly.

## Stage 3 — Architect Review (auto-on at thorough, else opt-in)

Stage 3 runs when `ARCHITECT_REVIEW=true` (resolved in the Architect Review Resolution section above — auto-enabled at `ASSESSMENT_DEPTH=thorough`, otherwise requires explicit `--architect-review`) **and** `DRY_RUN=false`. Verify that `$OUTPUT_DIR/threat-model.md` and `$OUTPUT_DIR/threat-model.yaml` both exist. If either is missing, skip Stage 3 silently (the QA reviewer or orchestrator already surfaced the underlying failure).

**First print a blank line and the Stage 3 handoff banner** (extract the model short-name from `ARCHITECT_MODEL` — e.g. `claude-opus-4-7` → `opus-4-7`):

```
▶ Stage 3/3 — Architect Review starting  (expect ~4 min, model: <model-short-name>)
  ⟶ Dispatching architect-reviewer — advisory review: architecture coherence, control realism, chain plausibility (6 checks); never rewrites output — emits .architect-review.md
```

Then invoke the `appsec-advisor:appsec-architect-reviewer` agent using `"Architect review of threat model"` as the Agent tool `description`, and **pass the `model` field explicitly** so the frontmatter default is overridden:

- `model: <ARCHITECT_MODEL>` — resolved from `--architect-model` (default `claude-opus-4-7` when Stage 3 is enabled)

Pass the following variables in the prompt:
- `REPO_ROOT=<absolute repo path>` (same value resolved above)
- `OUTPUT_DIR=<absolute output path>` (same value resolved above)
- `CONTEXT_FILE=$OUTPUT_DIR/.threat-modeling-context.md`
- `ASSESSMENT_DEPTH=<quick|standard|thorough>`
- `MODEL_ID=<ARCHITECT_MODEL>` — so the agent logs the model it is actually running on

The architect reviewer runs with its own turn budget (up to 40 turns) and writes `$OUTPUT_DIR/.architect-review.md` with findings and a single-line verdict. It never modifies the threat model itself.

**Non-fatal.** If Stage 3 errors out or returns without writing `.architect-review.md`, proceed to the Completion Summary as normal — the threat model is still valid. Log the failure to `.agent-run.log` but do not fail the overall skill.

## Completion Summary

After Stage 2 completes (or after Stage 1 if `DRY_RUN=true`), **always** print a final summary. This is the last thing the skill outputs and is critical for headless mode (`claude -p`) where it becomes the entire visible output.

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

### Post-summary cleanup

After the script returns, run the deterministic post-pipeline transient-file cleanup (whitelist pinned in `scripts/runtime_cleanup.py`) and remove the verbose / tracing marker files:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/runtime_cleanup.py" "$OUTPUT_DIR" --stage post-qa >/dev/null 2>&1 || true
if [ "$ARCHITECT_REVIEW" = "true" ]; then
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/runtime_cleanup.py" "$OUTPUT_DIR" --stage post-architect >/dev/null 2>&1 || true
fi
rm -f "${TMPDIR:-/tmp}/.appsec-verbose-$(id -u)"
rm -f "${TMPDIR:-/tmp}/.appsec-tracing-$(id -u)"
```

`post-qa` runs the Phase 11 whitelist plus QA-specific artifacts (`.qa-status.json`, empty `.qa-repair-plan.json`, `.fragments/`). `post-architect` additively removes architect-review status files. Exit code 1 (safety-gate block) is silenced with `|| true` — the summary has already been printed.

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
4. Skip Stage 2.

Every other abort path (conflicting flags, missing baseline for `--incremental`, incompatible plugin version, failed `CLAUDE_PLUGIN_ROOT` discovery) must also run the `rm -f` cleanup before exiting non-zero. This keeps the verbose and tracing markers strictly scoped to the single run that asked for them.
