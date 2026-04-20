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
    -path "*/appsec-plugin/claude-plugin/skills/create-threat-model/SKILL.md" \
    2>/dev/null | head -1 | xargs -r dirname | xargs -r dirname | xargs -r dirname)
fi
export CLAUDE_PLUGIN_ROOT
if [ -z "$CLAUDE_PLUGIN_ROOT" ] || [ ! -d "$CLAUDE_PLUGIN_ROOT" ]; then
  echo "Error: CLAUDE_PLUGIN_ROOT could not be resolved — install the appsec-plugin or set the variable manually." >&2
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

If the user's arguments contain the token `--help` or `-h` (anywhere, case-sensitive), **do not run the assessment**. Print the block below verbatim to the conversation and exit with status 0. Detection happens before any other parsing so broken flag combinations don't block access to help.

```
/appsec-plugin:create-threat-model — Architectural STRIDE threat modeling.

USAGE
  /appsec-plugin:create-threat-model [SCOPE] [FLAGS]

  SCOPE is free-text that narrows the analysis to a component or area,
  e.g.  "focus on the authentication service".

COMMON FLAGS
  --yaml / --no-yaml           Emit threat-model.yaml (default: on)
  --sarif                      Emit threat-model.sarif.json
  --requirements [<url>]       Enable requirements compliance check (Phase 8b)
  --no-requirements            Skip requirements check even when enabled
  --with-sca                   Run dependency CVE scan
  --dry-run                    Preview the pipeline without writing any files
  --repo <path>                Repository to analyze (default: cwd)
  --output <path>              Output directory (default: <repo>/docs/security)

INCREMENTAL / CI
  --incremental                Delta re-analysis based on git diff
  --full                       Force complete re-assessment (preserves history)
  --rebuild                    Wipe state and start fresh (no T-ID stability)
  --resume                     Continue from the last checkpoint
  --base <ref>                 Diff base for incremental (default: prior commit)
  --pr-mode                    MR/PR delta (implies --incremental)
  --no-qa                      Skip the Stage-2 QA reviewer (faster CI)

CLEANUP
  --clean-cache                Delete caches & transient files; exits
  --clean-all                  Delete everything in output dir; exits
  --force                      Skip confirmation for --clean-all

MODEL / DEPTH
  --assessment-depth <level>   quick | standard (default) | thorough
  --reasoning-model <mode>     sonnet | opus-cheap | opus
  --stride-model <model>       Punctual STRIDE-analyzer override
  --architect-review           Force Stage-3 architect review on
  --no-architect-review        Disable Stage-3 even at depth=thorough
  --architect-model <m>        sonnet | opus (default: opus at thorough)

OUTPUT
  --pentest-tasks              Emit pentest-tasks.yaml for DAST/pentest agents
  --pentest-format <fmt>       generic (default) | strix
  --pentest-target <url>       base URL for pentest-tasks meta.target
  --verbose                    Metadata table + Run Statistics appendix

ADVANCED
  --keep-runtime-files         Preserve transient files after success

See `/appsec-plugin:status` for claude-plugin/configuration/last-run information, and
`docs/threat-model-skill.md` for the full flag reference.
```

After printing, exit. Do not read any files, dispatch agents, or perform any other action.

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
| `--reasoning-model <mode>` | `REASONING_MODEL=<sonnet\|opus-cheap\|opus>` → resolves to `STRIDE_MODEL`, `TRIAGE_MODEL`, `MERGER_MODEL` | follows `--assessment-depth` (see Reasoning Model Resolution) |
| `--stride-model <model>` | `STRIDE_MODEL=<model>` (punctual override, applied **after** `--reasoning-model` resolution) | (none — inherits from `--reasoning-model`) |
| `--assessment-depth <level>` | `ASSESSMENT_DEPTH=<quick\|standard\|thorough>` | `standard` |
| `--architect-review` | `ARCHITECT_REVIEW=true` — enables Stage 3 (advisory architect-level review) | auto-on at `--assessment-depth thorough`, off otherwise |
| `--no-architect-review` | `ARCHITECT_REVIEW=false` — escape hatch to disable Stage 3 even at `--assessment-depth thorough` | n/a |
| `--architect-model <sonnet\|opus>` | `ARCHITECT_MODEL=<model>` — model for Stage 3 (ignored when `ARCHITECT_REVIEW=false`) | `opus` when Stage 3 is enabled |
| `--verbose` | `VERBOSE_REPORT=true` — also writes a per-user marker file that flips `agent_logger.py` into stderr-mirroring mode for the duration of this run (see "Verbose Mode — Marker File Lifecycle" below) | `false` |
| `--base <ref>` | `BASE_REF=<ref>` — git ref to diff HEAD against for incremental mode (default: `commit_sha` recorded in the prior `threat-model.yaml`). Used in MR/PR mode to target the base branch. | (baseline commit) |
| `--pr-mode` | `PR_MODE=true` — produce a focused delta report limited to components affected by the `--base ... HEAD` diff. Implies `--incremental` and skips Stage 2 QA. | `false` |
| `--no-qa` | `SKIP_QA=true` — skip the Stage 2 QA reviewer (faster CI runs where the report is machine-consumed). Also honoured via `APPSEC_SKIP_QA=1`. | `false` |

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

## Requirements Resolution

After parsing flags, resolve `CHECK_REQUIREMENTS` before invoking any agent.

### Conflict detection

If both `--requirements` and `--no-requirements` are present, abort immediately:

- `--requirements` + `--no-requirements` → `Error: conflicting flags --requirements and --no-requirements cannot be used together.`

### Resolve CHECK_REQUIREMENTS

Read the requirements config to determine the default:

```bash
SKILL_CONFIG=""
if [ -n "$CLAUDE_PLUGIN_ROOT" ]; then
  SKILL_CONFIG="$CLAUDE_PLUGIN_ROOT/skills/check-appsec-requirements/config.json"
else
  SKILL_CONFIG=$(find /root /home /opt -maxdepth 6 \
    -path "*/appsec-plugin/claude-plugin/skills/check-appsec-requirements/config.json" \
    2>/dev/null | head -1)
fi
```

Read `requirements_source.enabled` from the config. If not found, treat as `false`.

Apply the following resolution order — first match wins:

1. `--no-requirements` is set → `CHECK_REQUIREMENTS=false`
2. `--requirements` is set (with or without URL) → `CHECK_REQUIREMENTS=true` (+ `REQUIREMENTS_URL_OVERRIDE=<url>` if URL provided)
3. Config `enabled` is `true` → `CHECK_REQUIREMENTS=true`
4. None of the above → `CHECK_REQUIREMENTS=false`

Store the resolved state as `REQUIREMENTS_LABEL` (one of: `enabled (config)`, `enabled (--requirements)`, `enabled (--requirements <url>)`, `disabled (config)`, `disabled (--no-requirements)`) — it is printed later in the Configuration Summary block, not here.

## YAML Output Resolution

`threat-model.yaml` is the **canonical structured baseline** — it is what incremental runs read to find the last commit SHA, the components, and the changelog. It MUST be written on every successful run unless the user explicitly opts out. The resolution is therefore:

### Conflict detection

If both `--yaml` and `--no-yaml` are present, abort immediately:

- `--yaml` + `--no-yaml` → `Error: conflicting flags --yaml and --no-yaml cannot be used together.`

### Resolve WRITE_YAML

Apply the following resolution order — first match wins:

1. `--no-yaml` is set → `WRITE_YAML=false` (user explicitly opts out — incremental mode will break for any future run against this output dir)
2. `--yaml` is set → `WRITE_YAML=true` (redundant — same as default — kept for backwards compatibility)
3. **Default** → `WRITE_YAML=true`

**This is an inversion from the pre-M2 default.** Previously `--yaml` was opt-in; now yaml is always-on because it is the only machine-readable baseline an incremental run can use. `--no-yaml` remains as an escape hatch for cases where the user wants an MD-only report (e.g. quick ad-hoc reviews of a throwaway repo).

If a user passes `--no-yaml` and also uses `--incremental` on a *subsequent* run, the incremental run will have no `meta.git.commit_sha` to diff against and will abort with the same error as if no baseline existed — that is the intended behaviour, not a bug.

Store the resolved state as `WRITE_YAML_LABEL` (one of: `enabled (default)`, `enabled (--yaml)`, `disabled (--no-yaml)`) — printed in the Configuration Summary block.

## Assessment Depth Resolution

Resolve `ASSESSMENT_DEPTH` and derive concrete parameters. If `--assessment-depth` was not provided, default to `standard`.

| Variable | `quick` | `standard` | `thorough` |
|----------|---------|-----------|------------|
| `MAX_STRIDE_COMPONENTS` | 3 | 5 | 8 |
| `STRIDE_TURNS_SIMPLE` | 10 | 15 | 20 |
| `STRIDE_TURNS_MODERATE` | 15 | 22 | 28 |
| `STRIDE_TURNS_COMPLEX` | 20 | 31 | 35 |
| `DIAGRAM_DEPTH` | `minimal` | `standard` | `extended` |
| `QA_DEPTH` | `core` | `full` | `extended` |

Store the resolved depth as `DEPTH_LABEL` in the form `<quick|standard|thorough> (components: <N>, STRIDE turns: <S>/<M>/<C>, diagrams: <depth>, QA: <depth>)` — it is printed later in the Configuration Summary block, not here.

## Reasoning Model Resolution

Resolve `REASONING_MODEL` and derive `STRIDE_MODEL`, `TRIAGE_MODEL`, and `MERGER_MODEL` before invoking the orchestrator. These three variables are passed to the orchestrator and used as the `model` parameter when the orchestrator dispatches the corresponding sub-agents via the Agent tool — overriding each agent's `model: sonnet` frontmatter default.

### Mode matrix

| `REASONING_MODEL` | `STRIDE_MODEL` | `TRIAGE_MODEL` | `MERGER_MODEL` | Added cost (typical) |
|---|---|---|---|---|
| `sonnet` | `claude-sonnet-4-6` | `claude-sonnet-4-6` | `claude-sonnet-4-6` | baseline |
| `opus-cheap` | `claude-sonnet-4-6` | `claude-opus-4-7` | `claude-opus-4-7` | +~$0.07 |
| `opus` | `claude-opus-4-7` | `claude-opus-4-7` | `claude-opus-4-7` | +~$2–5 |

Other sub-agents (`context-resolver`, `recon-scanner`, `dep-scanner`, `qa-reviewer`) remain on Sonnet regardless — their tasks (I/O, pattern matching, mechanical checking) do not benefit enough from Opus to justify the cost.

### Resolution order (first match wins)

1. `--reasoning-model <mode>` explicitly set → use that mode
2. `ASSESSMENT_DEPTH=thorough` → `opus-cheap`
3. `ASSESSMENT_DEPTH=quick` or `standard` → `sonnet`

### Punctual override — `--stride-model`

`--stride-model` is retained as a deprecated alias for backward compatibility. If the user passes it, apply it **after** the matrix resolution — i.e. it overrides only `STRIDE_MODEL`, leaving `TRIAGE_MODEL` and `MERGER_MODEL` as resolved from `--reasoning-model`.

If `--stride-model` is present, print this deprecation notice once to the user before Stage 1:

```
Note: --stride-model is deprecated — prefer --reasoning-model for coordinated overrides across STRIDE, triage-validator, and threat-merger.
```

### Env-var escape hatch (advanced)

For fine-grained control beyond the modes, the env vars `APPSEC_STRIDE_MODEL`, `APPSEC_TRIAGE_MODEL`, and `APPSEC_MERGER_MODEL` take highest precedence, overriding both `--reasoning-model` and `--stride-model`. Not prominently documented — meant for power-user escape hatches (e.g. "everything Opus except STRIDE for cost cap").

Store the resolved state as `REASONING_LABEL` in the form `<mode> (STRIDE: <model-id>, triage: <model-id>, merger: <model-id>)` — printed later in the Configuration Summary block.

## Architect Review Resolution

Resolve `ARCHITECT_REVIEW` and `ARCHITECT_MODEL` before any agent is invoked. Stage 3 is **auto-enabled at `--assessment-depth thorough`** and disabled at `quick`/`standard`. Both sides are explicitly overridable — `--architect-review` forces it on, `--no-architect-review` forces it off.

This runs **after** Assessment Depth Resolution, so `ASSESSMENT_DEPTH` is already set.

### Conflict detection

If both `--architect-review` and `--no-architect-review` are present, abort immediately:

- `--architect-review` + `--no-architect-review` → `Error: conflicting flags --architect-review and --no-architect-review cannot be used together.` (exit 2)

### Resolve ARCHITECT_REVIEW (first match wins)

1. `--no-architect-review` is set → `ARCHITECT_REVIEW=false`.
2. `--architect-review` is set → `ARCHITECT_REVIEW=true`.
3. `ASSESSMENT_DEPTH=thorough` → `ARCHITECT_REVIEW=true` (**auto-on default for thorough**).
4. Otherwise (`quick` or `standard`) → `ARCHITECT_REVIEW=false`.

### Resolve ARCHITECT_MODEL (only when `ARCHITECT_REVIEW=true`)

1. `--architect-model sonnet` → `ARCHITECT_MODEL=claude-sonnet-4-6`.
2. `--architect-model opus` → `ARCHITECT_MODEL=claude-opus-4-7`.
3. Otherwise (flag not set) → `ARCHITECT_MODEL=claude-opus-4-7` (**default when Stage 3 is enabled**).

When `ARCHITECT_REVIEW=false`, leave `ARCHITECT_MODEL` empty. If `--architect-model` is set **while** `ARCHITECT_REVIEW=false` (e.g. user passed `--no-architect-review --architect-model opus`, or `--architect-model` alone without thorough depth and without `--architect-review`), print a warning and treat `--architect-model` as a no-op:

```
Note: --architect-model is ignored because architect review is disabled (depth != thorough and --architect-review not set, or --no-architect-review was passed).
```

### Dry-run interaction

When `DRY_RUN=true`, Stage 3 is skipped regardless of `ARCHITECT_REVIEW` — the threat model is written to a temp directory and deleted after the console summary, so an architect review of transient output has no consumer. Force `ARCHITECT_REVIEW=false` in this case and skip the rest of this resolution.

### Env-var escape hatch

`APPSEC_ARCHITECT_MODEL` overrides `ARCHITECT_MODEL` when set (highest precedence). Intended for CI pipelines that cap model choice.

Store the resolved state as `ARCHITECT_LABEL`: one of `disabled`, `enabled (opus, auto-thorough)`, `enabled (sonnet, auto-thorough)`, `enabled (opus, --architect-review)`, `enabled (sonnet, --architect-review)`, `disabled (--no-architect-review)` — printed later in the Configuration Summary block.

## Path Resolution

Resolve `REPO_ROOT` and `OUTPUT_DIR` before invoking any agent:

1. **REPO_ROOT** — if `--repo <path>` was provided, use that path. Otherwise use the current working directory. In both cases, resolve the git root:
   ```bash
   git -C "<path>" rev-parse --show-toplevel 2>/dev/null || echo "<path>"
   ```
   Store the result as `REPO_ROOT`. If the path does not exist or is not a directory, print an error and abort:
   ```
   Error: repository path does not exist: <path>
   ```

2. **OUTPUT_DIR** — if `DRY_RUN=true`, always redirect output to a temporary directory so that **no files are written to the repository**:
   ```bash
   if [ "$DRY_RUN" = "true" ]; then
     OUTPUT_DIR=$(mktemp -d /tmp/appsec-dry-run-XXXXXX)
   elif [ -n "$USER_OUTPUT_DIR" ]; then
     OUTPUT_DIR="$USER_OUTPUT_DIR"
   else
     OUTPUT_DIR="$REPO_ROOT/docs/security"
   fi
   mkdir -p "$OUTPUT_DIR"
   ```
   When `DRY_RUN=true`, the temp directory is cleaned up after the console summary is printed (see Completion Summary). The user-provided `--output` flag is ignored in dry-run mode.

3. `REPO_ROOT` and `OUTPUT_DIR` are printed later in the Configuration Summary block — do not print them here. If `OUTPUT_DIR` is not under `REPO_ROOT`, set `OUTPUT_OUTSIDE_REPO=true` so the summary block can append the gitignore note.

## Incremental Mode Resolution

After paths are resolved, determine whether to run a full or incremental assessment.

### Baseline detection — two distinct states

Incremental mode needs a **structured baseline** — specifically `meta.git.commit_sha` from `threat-model.yaml` — to compute the delta. A `threat-model.md` alone is **not** a usable baseline because it has no machine-readable commit anchor. There are therefore three possible output-dir states, not two:

| State | What's on disk | Can incremental work? |
|---|---|---|
| **empty** | no `threat-model.*` at all | no — first run, must be full |
| **legacy** | `threat-model.md` only (no yaml) | no — yaml was opt-in before M2, so this is a pre-M2 report. Needs one bootstrap full run to produce the yaml; from then on incremental works. |
| **structured** | `threat-model.yaml` present (with `meta.git.commit_sha`) | yes — auto-incremental |

Compute this once at the start of resolution:

```bash
if [ -f "$OUTPUT_DIR/threat-model.yaml" ]; then
  # Quick presence check — the orchestrator will do the rigorous
  # commit_sha parse later. If the yaml exists but is malformed, the
  # orchestrator's own baseline-resolution step will fall through to a
  # full scan (see "Graceful fallback" in appsec-threat-analyst.md).
  BASELINE_STATE="structured"
elif [ -f "$OUTPUT_DIR/threat-model.md" ]; then
  BASELINE_STATE="legacy"
else
  BASELINE_STATE="empty"
fi
```

### Dry-run forces full scan

When `DRY_RUN=true`, the skill forces `INCREMENTAL=false` regardless of baseline state or user flags. A dry-run is a complete preview — incremental mode would produce partial results (only changed components) which cannot generate a meaningful Management Summary. If `--incremental --dry-run` is passed, print:
```
Note: --dry-run forces a full analysis. --incremental is ignored.
```

### Conflict detection (runs first)

- `--full` + `--incremental` → abort immediately with `Error: conflicting flags --full and --incremental cannot be used together.` (exit 2)
- `--rebuild` + `--incremental` → abort with `Error: --rebuild discards all prior state; --incremental requires it. Pick one.` (exit 2)
- `--rebuild` + `--resume` → abort with `Error: --rebuild wipes the checkpoint file; --resume needs it. Pick one.` (exit 2)
- `--rebuild` + `--full` → accept (redundant); print once before Stage 1: `Note: --full is implied by --rebuild.`

### Resolution order — first match wins

For each case, set `MODE`, `MODE_LABEL`, and (if listed) `POST_SUMMARY_NOTE`. Nothing is printed here — everything is emitted later in the Configuration Summary block.

0. **`--rebuild` is set** → `REBUILD=true`, `MODE=rebuild`, `INCREMENTAL=false`, `MODE_LABEL="rebuild (fresh — prior model and history discarded)"`. If `BASELINE_STATE` is `structured` or `legacy`, set `POST_SUMMARY_NOTE="Warning: existing threat model, cache, and changelog history at <OUTPUT_DIR> will be deleted before the run. Audit logs (.agent-run.log, .hook-events.log) are preserved."`. Otherwise (`BASELINE_STATE=empty`), treat identically to a first-run full — the rebuild semantics just mean "no baseline is used even if one shows up". The wipe step (see "Rebuild Pre-flight Wipe" below) still runs defensively to handle stray intermediate files.

1. **`--full` is set** → `MODE=full`, `MODE_LABEL="full (--full)"`. If `BASELINE_STATE` is `structured` or `legacy`, set `POST_SUMMARY_NOTE="Warning: existing threat model at <OUTPUT_DIR> will be overwritten. Changelog history is preserved; a Change Summary will be printed after the run."`.

2. **`--incremental` is set** and `BASELINE_STATE=empty` → **hard abort, exit 2**:
   ```
   Error: --incremental requires an existing threat model at <OUTPUT_DIR>.
     No threat-model.yaml or threat-model.md found.
     Run without flags (or with --full) to create an initial threat model first.
   ```

3. **`--incremental` is set** and `BASELINE_STATE=legacy` → **hard abort, exit 2**. This is the case where the user asserted they want a delta, but the output dir only has a pre-M2 legacy report with no structured baseline. Print an actionable message:
   ```
   Error: --incremental requires a structured baseline (threat-model.yaml), but
          only a legacy threat-model.md was found at <OUTPUT_DIR>.
          This report was generated before incremental mode was supported.
     Fix: run once without --incremental to bootstrap threat-model.yaml, then
          subsequent runs will automatically use incremental mode.
   ```

4. **`--incremental` is set** and `BASELINE_STATE=structured` → `MODE=incremental`, `MODE_LABEL="incremental (--incremental)"`, no note.

5. **No flag**, `BASELINE_STATE=structured` → `MODE=incremental` (**auto-detected default**), `MODE_LABEL="incremental (auto)"`, `POST_SUMMARY_NOTE="Tip: pass --full to force a complete re-assessment."`.

6. **No flag**, `BASELINE_STATE=legacy` → `MODE=full` (**bootstrap run**), `MODE_LABEL="full (bootstrap — legacy threat-model.md detected)"`, `POST_SUMMARY_NOTE="Legacy threat-model.md found but no structured baseline (threat-model.yaml). Bootstrapping yaml now — the next run will automatically be incremental."`. **This is the critical path for users upgrading from pre-M2 plugin versions** — they keep their existing .md report, get a structured baseline written alongside it, and from then on get auto-incremental for free.

7. **No flag**, `BASELINE_STATE=empty` → `MODE=full` (first run), `MODE_LABEL="full (first run)"`, no note.

Set `INCREMENTAL=true` when `MODE=incremental`, otherwise `INCREMENTAL=false`.

### Dry-run interaction

When `DRY_RUN=true`, the incremental mode resolution is skipped entirely — `INCREMENTAL` is forced to `false`, `MODE=full`, `MODE_LABEL="full (dry-run)"`. The baseline state detection still runs (for informational purposes in the Configuration Summary) but does not influence mode selection.

### Why auto-incremental is the default

Repeated runs against the same output directory should not re-analyze unchanged components. This avoids unnecessary token consumption. The baseline is `meta.git.commit_sha` from the previously written `threat-model.yaml`. A user upgrading from pre-M2 plugin versions automatically hits the bootstrap path (rule 6) on their first run after the upgrade and then gets auto-incremental on every subsequent run — no manual intervention required.

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

Once Requirements, Depth, Paths, and Incremental Mode have all been resolved, emit the configuration as a single consolidated block. This is the **only** place any of these values are printed — the individual resolution sections above only store variables. Format must match exactly; labels are padded to 12 characters so all colons align. Use plain ASCII only — no bullet glyphs, arrows, or emoji.

```
Configuration resolved.

  Repository   : <REPO_ROOT>
  Output       : <OUTPUT_DIR>
  Plugin       : appsec-plugin <PLUGIN_VERSION> (analysis v<ANALYSIS_VERSION>)
  Mode         : <MODE_LABEL>
  Baseline     : <COMPAT_LABEL>               ← only printed when MODE=incremental
  Depth        : <DEPTH_LABEL>
  Requirements : <REQUIREMENTS_LABEL>
  Architect    : <ARCHITECT_LABEL>            ← only printed when ARCHITECT_REVIEW=true
```

Read `PLUGIN_VERSION` and `ANALYSIS_VERSION` from `plugin_meta.py`:

```bash
PLUGIN_VERSION=$(python3 "$CLAUDE_PLUGIN_ROOT/scripts/plugin_meta.py" get plugin_version)
ANALYSIS_VERSION=$(python3 "$CLAUDE_PLUGIN_ROOT/scripts/plugin_meta.py" get analysis_version)
```

The `Baseline` line is emitted only when `MODE=incremental`; for full runs it is omitted entirely. `COMPAT_LABEL` is the value set by the Plugin Version Compatibility Gate above (one of `equal`, `older-compatible`, `incompatible`, `legacy`, `unknown`).

After the block, append these additional lines **only when the listed condition holds**, in this order:
1. If `OUTPUT_OUTSIDE_REPO=true`: `  Note: output directory is outside the repository — .gitignore entries will be skipped.`
2. If `POST_SUMMARY_NOTE` is set: `  <POST_SUMMARY_NOTE>`
3. **Always when `MODE=incremental`** (regardless of `COMPAT_LABEL`): `  Recommendation: Run with --full periodically to ensure complete coverage with plugin v<PLUGIN_VERSION>.`
4. If `CHECK_REQUIREMENTS=false` **and** `REQUIREMENTS_LABEL` starts with `disabled (config)` (i.e. the skip was not explicit via `--no-requirements`): `  Tip: requirements compliance is disabled. Pass --requirements or set requirements_yaml_url in claude-plugin/skills/check-appsec-requirements/config.json to enable Section 7b (compliance overview) and authoritative requirement links in the threat register.`

The tip is deliberately suppressed when the user explicitly passed `--no-requirements` — they already know and do not need reminding. It is also suppressed when requirements are already enabled (nothing to hint at).

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

Then print a blank line and the Stage 1 handoff banner:

```
▶ Stage 1/<total_stages> — Threat Model Orchestrator starting  (expect ~<duration>)
```

Where:
- `<total_stages>` is `3` when `ARCHITECT_REVIEW=true`, otherwise `2`
- `<duration>` depends on `ASSESSMENT_DEPTH`: `~15 min` (quick), `~25 min` (standard), `~40 min` (thorough)

No other text — no explanatory prose, no duplicated mode description — belongs between these lines.

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

Invoke the `appsec-plugin:appsec-threat-analyst` agent **exactly once** using `"Threat Model Orchestrator"` as the Agent tool `description`. The orchestrator handles all phases internally (including context resolution in Phase 1) — do **not** invoke `appsec-context-resolver` or any other agent from the skill level. Only invoke the orchestrator here.

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

**Recovery path.** If `STAGE1_CUTOFF=true`, spawn a **second** `appsec-plugin:appsec-threat-analyst` Agent call (fresh turn budget) with the description `"Threat Model Orchestrator (resume)"` and a prompt that:

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

After the orchestrator completes (and `DRY_RUN` is `false`), verify that `$OUTPUT_DIR/threat-model.md` exists. If it does, **first print a blank line and the Stage 2 handoff banner**:

```
▶ Stage 2/<total_stages> — QA Review starting  (expect ~5 min, model: sonnet-4-6)
```

Where `<total_stages>` is `3` when `ARCHITECT_REVIEW=true`, otherwise `2`.

Then invoke the `appsec-plugin:appsec-qa-reviewer` agent using `"QA review of threat model"` as the Agent tool `description`.

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

**Repair-mode Stage 1 invocation.** The skill re-spawns the `appsec-plugin:appsec-threat-analyst` agent with:

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
```

Then invoke the `appsec-plugin:appsec-architect-reviewer` agent using `"Architect review of threat model"` as the Agent tool `description`, and **pass the `model` field explicitly** so the frontmatter default is overridden:

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

When `DRY_RUN=true`, the orchestrator has written the full threat model to the temp `OUTPUT_DIR`. Extract the Management Summary and key metrics, print them to the console, then clean up.

**Step 1 — Extract the Management Summary** from `$OUTPUT_DIR/threat-model.md`. Read the section between `## Management Summary` and the next `## ` heading (exclusive). This includes: Verdict, Top Threats, Worst Case Scenarios, Architecture Assessment, Mitigations, and (if present) Requirements Compliance and Operational Strengths.

**Step 2 — Strip HTML formatting** from the extracted Management Summary. Convert HTML blockquotes (`<blockquote>...</blockquote>`) to plain indented text. Remove `<br/>` tags and `style="..."` attributes. The console output must be readable without HTML rendering.

**Step 3 — Extract metrics** from the threat model (same extraction as the normal completion summary below).

**Step 4 — Print the dry-run console summary:**

```
══════════════════════════════════════════════════════════════
  Dry-Run — Threat Model Preview
══════════════════════════════════════════════════════════════

  Repository      : <REPO_ROOT>
  Components      : <n> analyzed

<Management Summary content — Verdict, Top Threats table, Worst Case Scenarios, Architecture Assessment, Mitigations>

  -- Metrics -----------------------------------------------

  Threats         : <n> total (Critical: <n>, High: <n>, Medium: <n>, Low: <n>)
  Controls        : <n> cataloged (adequate: <n>, partial: <n>, missing: <n>)

  Note: This is a preview. No files were written to the repository.
  Run without --dry-run to generate the full threat model report.
══════════════════════════════════════════════════════════════
```

**Step 5 — Clean up** the temp directory and the verbose marker:
```bash
rm -rf "$OUTPUT_DIR"
rm -f "${TMPDIR:-/tmp}/.appsec-verbose-$(id -u)"
```

Exit after printing. Do not print file paths, log files, or run statistics — the temp directory is gone.

### Normal Completion (DRY_RUN=false)

**Design intent.** The completion block is the *only* thing the user reliably sees in headless (`claude -p`) mode and the dominant visible artifact in interactive mode. It is therefore a **fixed template** with four clearly separated sections — Files, Metrics, Run Statistics, Next Steps — each preceded by an `-- Section ---` divider. The divider discipline gives the reader an immediate visual anchor ("here is where Claude's narrative ends and the result begins") and makes the block grep-parseable for CI.

**Printing order:**

1. Header banner (`══` rules + `ASSESSMENT COMPLETE — Summary follows`)
2. `-- Files ---` section (paths of generated artifacts)
3. `-- Change Summary ---` section (only when a baseline existed — see below)
4. `-- Metrics ---` section (threats / components / controls / requirements)
5. `-- Run Statistics ---` section (durations, agents, tokens, cost)
6. `-- Next Steps ---` section (concrete, state-aware follow-up actions)
7. `-- Log Files ---` section
8. Closing rule

Read `$OUTPUT_DIR/threat-model.md` and extract key metrics. Then print:

```
══════════════════════════════════════════════════════════════
  ASSESSMENT COMPLETE — Summary follows
══════════════════════════════════════════════════════════════

  Repository          : <REPO_ROOT>
  Mode                : <full | incremental | rebuild>   (delta: +<n> / ~<n> / -<n>   when a baseline existed)

  -- Files ---------------------------------------------------
    $OUTPUT_DIR/threat-model.md
    $OUTPUT_DIR/threat-model.yaml        ← always, unless --no-yaml was passed
```

The `(delta: ...)` suffix on the Mode line is printed **only** when the first `changelog[]` entry in the just-written `threat-model.yaml` carries an `added`/`changed`/`resolved` breakdown. It appears for all incremental runs and for `--full` runs that overwrote a prior yaml. It is **never** printed for `--rebuild` (the wipe eliminated the baseline before the run) or for a first-ever full assessment (no prior yaml to diff against).

Use the Mode value from `MODE_LABEL` resolved earlier: `rebuild` for `--rebuild`, `incremental` for incremental runs, `full` for everything else. Do not read the mode from `changelog[0]` — that reflects how the orchestrator wrote it (which for rebuild is `mode: full` in the yaml; the skill-level Mode label is the authoritative one for display).

If `WRITE_YAML=false` (user passed `--no-yaml`), omit the yaml line.
If `WRITE_SARIF=true` and `$OUTPUT_DIR/threat-model.sarif.json` exists, add:
```
    $OUTPUT_DIR/threat-model.sarif.json
```

If `ARCHITECT_REVIEW=true` and `$OUTPUT_DIR/.architect-review.md` exists, add:
```
    $OUTPUT_DIR/.architect-review.md                 ← architect review (advisory)
```

### Change Summary block (conditional)

Print the `-- Change Summary ---` block **only** when the just-written `threat-model.yaml` contains a `changelog[0]` entry with `added`/`changed`/`resolved` fields — i.e. whenever a baseline existed before this run (all incremental runs, and all `--full` runs against a prior model). For a first-ever full assessment with `baseline_sha: null`, skip this block entirely.

**Extract data from `changelog[0]`** in `$OUTPUT_DIR/threat-model.yaml`. Use Python (via Bash) for robust YAML parsing — do not use grep:

```bash
CHANGE_SUMMARY=$(python3 -c "
import sys, yaml
try:
    with open('$OUTPUT_DIR/threat-model.yaml') as f:
        data = yaml.safe_load(f)
    cl = (data.get('changelog') or [])
    if not cl:
        sys.exit(1)
    e = cl[0]
    added    = (e.get('added') or {}).get('threats') or []
    changed  = (e.get('changed') or {}).get('threats') or []
    resolved = (e.get('resolved') or {}).get('threats') or []
    notes    = (e.get('changed') or {}).get('notes_by_id') or {}
    reasons  = (e.get('resolved') or {}).get('reason_by_id') or {}
    reanalyzed = e.get('reanalyzed_components') or []
    carried    = e.get('carried_forward_components') or []
    mode = e.get('mode', '?')
    baseline_sha = e.get('baseline_sha') or 'n/a'
    version = e.get('version', '?')
    date = e.get('date', '?')
    # Sample first 5 IDs of each list with optional truncation marker
    def sample(ids, fmt=lambda i: i):
        if not ids: return ''
        shown = [fmt(i) for i in ids[:5]]
        extra = len(ids) - 5
        suffix = f', +{extra} more' if extra > 0 else ''
        return ', '.join(shown) + suffix
    # For changed/resolved, append the short note/reason in parens
    changed_s  = sample(changed,  lambda i: f'{i} ({notes.get(i, \"updated\")})' if notes.get(i) else i)
    resolved_s = sample(resolved, lambda i: f'{i} ({reasons.get(i, \"removed\")})' if reasons.get(i) else i)
    # Emit tab-delimited for easy shell parsing
    print(f'{len(added)}\t{len(changed)}\t{len(resolved)}\t{sample(added)}\t{changed_s}\t{resolved_s}\t{len(reanalyzed)}\t{len(carried)}\t{mode}\t{baseline_sha[:12] if baseline_sha != \"n/a\" else \"n/a\"}\t{version}\t{date}')
except (FileNotFoundError, yaml.YAMLError, KeyError, IndexError, TypeError):
    sys.exit(1)
" 2>/dev/null)

if [ -n "$CHANGE_SUMMARY" ]; then
  IFS=$'\t' read -r ADDED_N CHANGED_N RESOLVED_N ADDED_IDS CHANGED_IDS RESOLVED_IDS REANALYZED_N CARRIED_N CL_MODE BASELINE_SHORT CL_VERSION CL_DATE <<< "$CHANGE_SUMMARY"
fi
```

If `CHANGE_SUMMARY` is empty (parse failed, or `changelog[0]` has no delta block — first-run full), skip the block.

Otherwise print:

```

  -- Change Summary (vs. prior run) --------------------------
    Prior baseline     : <CL_MODE> run from <CL_DATE>, commit <BASELINE_SHORT>
    + Added            : <ADDED_N> threats<if ADDED_N > 0: `  (<ADDED_IDS>)`>
    ~ Changed          : <CHANGED_N> threats<if CHANGED_N > 0: `  (<CHANGED_IDS>)`>
    - Resolved         : <RESOLVED_N> threats<if RESOLVED_N > 0: `  (<RESOLVED_IDS>)`>
    Components         : <REANALYZED_N> re-analyzed<if CL_MODE == incremental: `, <CARRIED_N> carried forward`>
    Changelog entry    : v<CL_VERSION> prepended to threat-model.md
```

**Formatting rules for the block:**
- Omit `(<IDS>)` suffix when the count is `0` — show just the bare count.
- The `Components:` line omits the "carried forward" segment when `CL_MODE=full` (always zero there).
- If all three deltas are zero (no meaningful changes), still print the block — an explicit "0 / 0 / 0" tells the user "I checked, and truly nothing changed." More useful than silence.

Then extract and print metrics from the threat model:
```

  -- Metrics -------------------------------------------------
  Threats             : <n> total (Critical: <n>, High: <n>, Medium: <n>, Low: <n>)
  Components          : <n> analyzed
  Controls            : <n> cataloged (adequate: <n>, partial: <n>, missing: <n>)
```

If `CHECK_REQUIREMENTS=true`:
```
  Requirements        : <n> checked (pass: <n>, fail: <n>, partial: <n>)
```

Then extract run statistics from `$OUTPUT_DIR/.hook-events.log` and `$OUTPUT_DIR/.agent-run.log` and print them:
```

  -- Run Statistics --------------------------------------------
  Total Duration      : <Xm YYs>  (assessment: <Xm YYs> + QA review: <Xm YYs> [+ architect review: <Xm YYs>])
    Phase 1   Context Resolution      threat-analyst (sonnet-4-6)    :  0m 02s
    Phase 2   Reconnaissance          recon-scanner (sonnet-4-6)     :  4m 19s
    Phase 3   Architecture Modeling    threat-analyst (sonnet-4-6)    :  0m 21s
    ...
    Phase 9   STRIDE Enumeration      5x stride-analyzer (opus-4-6)  : 18m 30s
    ...
    Phase 11  Finalization            threat-analyst (sonnet-4-6)     :  0m 30s
    QA        QA Review               qa-reviewer (sonnet-4-6)        :  5m 35s
    ARCH      Architect Review        architect-reviewer (opus-4-7)   :  3m 12s   ← only when ARCHITECT_REVIEW=true (auto at thorough, or --architect-review)
  Agents              : threat-analyst=sonnet-4-6, recon-scanner=sonnet-4-6, stride-analyzer=opus-4-6, qa-reviewer=sonnet-4-6
  Tokens              : <total> total (in: <input>, out: <output>, cache_write: <cw>, cache_read: <cr>)    [host session only — see note]
  Est. Cost           :
    <model-1> rates   : <prefix>$<cached> cached / <prefix>$<no_cache> no cache
    <model-2> rates   : <prefix>$<cached> cached / <prefix>$<no_cache> no cache
    Cache savings     : <n.n>%
    Billing           : <api / subscription (estimated)>
    ⚠ Scope          : host session ONLY — sub-agent token spend (STRIDE ×N, triage, merger,
                        QA, architect) is NOT captured by Claude Code's hook infrastructure.
                        True cost for thorough runs is typically 5–10× the number shown above.
```

**How to extract run statistics:** Parse `$OUTPUT_DIR/.hook-events.log` and `$OUTPUT_DIR/.agent-run.log`. For durations and models, use Bash with grep/awk. For tokens and cost, call the delta-based verification script — **do not** manually sum SESSION_STOP lines, as they are cumulative per session and naive summation produces grossly inflated numbers. Extract the data as follows:

1. **Duration** — compute three values plus per-phase breakdown. Duration values must reflect **actual analysis time**, not wall-clock time. Wall-clock timestamps include time spent waiting for user permission prompts, which can dwarf the real work.
   
   **Assessment duration** (Stage 1 only): read `analysis_duration_seconds` from `threat-model.yaml`. This value is written by the orchestrator agent and represents actual analysis time, excluding any idle waits for permission prompts.
   ```bash
   ASSESS_SECS=$(grep 'analysis_duration_seconds:' "$OUTPUT_DIR/threat-model.yaml" | grep -oP '\d+' | head -1)
   if [ -n "$ASSESS_SECS" ]; then
     ASSESS_DUR="$((ASSESS_SECS / 60))m $(printf '%02d' $((ASSESS_SECS % 60)))s"
   fi
   ```
   If `threat-model.yaml` does not contain `analysis_duration_seconds`, fall back to the `ASSESSMENT_END` line in `.agent-run.log`:
   ```bash
   ASSESS_DUR=$(grep 'ASSESSMENT_END' "$OUTPUT_DIR/.agent-run.log" | grep -oP 'completed in \K\d+ min \d+ s' | head -1)
   ```
   Note: the `.agent-run.log` fallback uses wall-clock time and may overcount if permission prompts caused delays.
   
   **QA duration**: compute from QA reviewer timestamps in `.agent-run.log` (QA typically has no permission-prompt delays since all permissions are already granted by then):
   ```bash
   QA_START=$(grep 'qa-reviewer.*AGENT_START' "$OUTPUT_DIR/.agent-run.log" | tail -1 | grep -oP '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z')
   QA_END=$(grep 'qa-reviewer.*AGENT_COMPLETE' "$OUTPUT_DIR/.agent-run.log" | tail -1 | grep -oP '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z')
   ```
   Convert both to epoch seconds with `date -d "$TS" +%s` and subtract. Format as `Xm YYs`. If either timestamp is missing, omit the QA duration from the breakdown.
   
   **Total duration**: sum of assessment + QA durations (not wall-clock first-to-last timestamp). If QA duration is unavailable, show assessment duration only.
   
   Format the output as: `Total Duration: Xm YYs  (assessment: Xm YYs + QA review: Xm YYs)`
   
   **Per-phase durations and agents**: extract from `PHASE_START`/`PHASE_END` lines in `.agent-run.log`. For each phase, compute the duration from the timestamp delta between its PHASE_START and PHASE_END. Also extract the agent that ran each phase from `AGENT_INVOKE`/`AGENT_DISPATCH` lines — map phase numbers to agents (e.g., Phase 2 → recon-scanner, Phase 9 → stride-analyzer). Include the model in parentheses (extract from the `model:` field in the AGENT_INVOKE line). For STRIDE analyzers dispatched in parallel, show the count (e.g., `5x stride-analyzer (opus-4-6)`). Phases that ran inline within another phase (same start/end timestamp) should show `(inline)` as the duration. Append a QA row at the end using the QA duration computed above.

   Format each line as: `    Phase N   <Description padded to 24 chars>  <agent (model) padded to 30 chars>  : <duration>`

   ```
     Phase 1   Context Resolution      threat-analyst (sonnet-4-6)    :  0m 02s
     Phase 2   Reconnaissance          recon-scanner (sonnet-4-6)     :  4m 19s
     ...
     Phase 9   STRIDE Enumeration      5x stride-analyzer (opus-4-6)  : 18m 30s
     ...
     QA        QA Review               qa-reviewer (sonnet-4-6)        :  5m 35s
   ```

   If `PHASE_START`/`PHASE_END` lines are not found, fall back to the `ASSESSMENT_PHASES` summary line. If neither is found, skip the per-phase breakdown.

2. **Agents** — grep for `AGENT_INVOKE`, `AGENT_DISPATCH`, and `AGENT_START` lines in `.agent-run.log`, extract the agent name and `model: <value>` field. Use full model short names (e.g., `sonnet-4-6`, `opus-4-6`). Also include the orchestrator's own model from the `ASSESSMENT_START` line. Deduplicate — if the same agent was spawned multiple times with the same model, list it once. Format as comma-separated `agent=model` pairs.

3. **Tokens and Cost** — invoke the delta-based verification script:
   ```bash
   COST_JSON=$(python3 "$CLAUDE_PLUGIN_ROOT/scripts/verify_run_costs.py" "$OUTPUT_DIR" --json 2>/dev/null)
   COST_EXIT=$?
   ```
   
   Parse the JSON output to extract:
   - **Tokens**: format as `<total> total (in: <input>, out: <output>, cache_write: <cw>, cache_read: <cr>)`. All values with thousands separators.
   - **Est. Cost**: show one line per model. When `mixed_model_costs` is present, iterate each model key and show `<model> rates: <prefix>$<cached> cached / <prefix>$<no_cache> no cache`. When single model, show one line. Prefix is `~` for subscription, empty for API.
   - **Scope warning**: if the `warnings` array from `verify_run_costs.py` contains `"Mixed models detected"` (the standard signal for sub-agent fan-out) OR the run's total wall time was > 15 min, append the `⚠ Scope: host session ONLY` block exactly as shown in the template above. This must be emitted to prevent users from under-budgeting future runs — cost transparency is a hard requirement for AppSec use cases where a single assessment can consume $5–$20 of subagent tokens invisible to this script.
   - **Cache Savings**: `totals.cache_savings_pct`%.
   - **Billing**: `api` or `subscription (estimated)`.
   - **Cross-check**: append `(verified)` or `(MISMATCH)` after the billing line.
   
   **Why delta-based extraction is required:** SESSION_STOP lines in `.hook-events.log` are **cumulative** per session ID. A Claude Code session can span multiple skill invocations, and sessions are reused for subagent work and post-assessment activity. Naive summation of raw values inflates costs by 3–50x depending on session reuse. The verification script determines the assessment run window, computes per-session deltas, and cross-verifies against the API pricing formula.
   
   **Fallback**: If the script fails (exit code ≥ 2), print: `  Tokens/Cost     : unavailable (verify_run_costs.py failed)`

   If `.hook-events.log` does not exist, skip the "Run Statistics" section entirely — do not print it with zeros or placeholders.

4. **Patch placeholders into threat-model.md** — After extracting durations (item 1), use the Edit tool to replace `_pending_` placeholders in the `## Appendix: Run Statistics` section:
   - `| **Assessment Total** | | | **_pending_** |` → actual assessment duration
   - QA Review duration row → actual QA duration
   - `| **Grand Total** | | | **_pending_** |` → actual total duration (assessment + QA)
   - qa-reviewer `_pending_` model in Agents & Models table → actual model from QA AGENT_START log line
   
   Token and cost placeholders are patched by the QA reviewer's Check 12, not by the skill layer. If the QA reviewer did not run (e.g., dry-run mode), and `_pending_` placeholders remain for tokens/cost, replace them with `n/a`.
   If `.hook-events.log` is not available, replace all `_pending_` with `n/a`.

```

  -- Next Steps ----------------------------------------------
<emit the Next Steps block here — see "Next Steps block" section below>

  -- Log Files -----------------------------------------------
    Hook events : $OUTPUT_DIR/.hook-events.log
    Agent run   : $OUTPUT_DIR/.agent-run.log

══════════════════════════════════════════════════════════════
```

After printing the closing rule, remove the verbose marker file (no-op when the skill was invoked without `--verbose`):

```bash
rm -f "${TMPDIR:-/tmp}/.appsec-verbose-$(id -u)"
```

To extract metrics: scan `threat-model.md` for the threat register table (count rows by severity), the components section (count ### headings in Section 2.3), and the controls catalog (count status badges in Section 7). Use Grep on the file — do not re-read the entire document.

### Next Steps block

Print 3–5 concrete follow-up actions tailored to the run's state. These are not motivational filler — each line is either a file to open, a command to run, or an integration task. Rules:

- **Always line 1:** point to the Management Summary so stakeholders know the single highest-value file to open first:
  ```
    1. Open $OUTPUT_DIR/threat-model.md → "Management Summary" for verdict + top risks
  ```
- **Always line 2 (if Critical or High threats exist):** direct the reader to the Threat Register, noting the highest severity present. Skip this line only when both Critical and High counts are zero.
  ```
    2. Review <Critical | High> findings in Section 8 "Threat Register"
  ```
- **Conditional line — SARIF uploaded:** present only when `WRITE_SARIF=true` **and** `$OUTPUT_DIR/threat-model.sarif.json` exists.
  ```
    3. Upload threat-model.sarif.json to GitHub Advanced Security / SonarQube / DefectDojo
  ```
- **Conditional line — requirements not checked:** present only when `CHECK_REQUIREMENTS=false`. Guides the user to the next capability.
  ```
    4. Re-run with --requirements to verify SEC-* baseline compliance
  ```
- **Conditional line — Sonnet-only run with Critical/High findings:** present only when the STRIDE analyzer model was Sonnet (check `ASSESSMENT_MODELS` line in `.hook-events.log` or the orchestrator's model param) **and** the Critical+High count is ≥ 3. Signals that a higher-quality second pass might uncover depth the first pass missed.
  ```
    5. Re-run with --stride-model opus for deeper analysis (~5× cost, typically +15-25% finding depth)
  ```
- **Conditional line — dep-scan was skipped:** present only when `--with-sca` was not passed and `package.json`/`requirements.txt`/`go.mod`/etc. exist in the repo.
  ```
    6. Re-run with --with-sca to include CVE data from dependency advisories
  ```
- **Conditional line — incremental baseline just established:** present only on a first full run (no prior `.appsec-cache/baseline.json`). Signals the follow-up value.
  ```
    7. Future runs will auto-detect this baseline and switch to incremental mode (faster, cheaper)
  ```
- **Conditional line — architect review available:** present only when `ARCHITECT_REVIEW=true` **and** `$OUTPUT_DIR/.architect-review.md` exists. Points the reader at the advisory findings.
  ```
    8. Review $OUTPUT_DIR/.architect-review.md → architect-level verdict and findings
  ```

Cap the Next Steps block at **five** lines even if more conditionals match — pick the most actionable five, drop the rest. Always-lines 1 and 2 take priority, then architect-review (when present), then SARIF, then requirements, then stride-model, then dep-scan, then baseline.

Prepend each line with two spaces + index + period + space to match the overall indentation of the completion block.

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
3. Remove the verbose marker file so the next run is not accidentally verbose:
   ```bash
   rm -f "${TMPDIR:-/tmp}/.appsec-verbose-$(id -u)"
   ```
4. Skip Stage 2.

Every other abort path (conflicting flags, missing baseline for `--incremental`, incompatible plugin version, failed `CLAUDE_PLUGIN_ROOT` discovery) must also run the `rm -f` cleanup before exiting non-zero. This keeps the verbose marker strictly scoped to the single run that asked for it.
