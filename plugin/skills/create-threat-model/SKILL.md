---
name: create-threat-model
description: Perform a threat assessment of a repository and produce a threat-model.md. Supports --repo to analyze external repos and --output to set the output directory. Optionally also writes threat-model.yaml with --yaml flag.
---

This skill runs in two stages: first the threat analyst orchestrator (Phases 1–10), then the QA reviewer (Phase 11). Each stage is a separate Agent invocation with its own turn budget.

## Prerequisites — Environment & Allow-Listed Commands

### `CLAUDE_PLUGIN_ROOT` discovery

Several downstream scripts (`plugin_meta.py`, `baseline_state.py`, `agent_logger.py`) expect `$CLAUDE_PLUGIN_ROOT` to point at the plugin directory. Claude Code sets this when a plugin command runs, but in some harness configurations (e.g. headless `claude -p`, older claude-code releases) the variable is **not** propagated into Bash sub-processes. Resolve it explicitly at the start of the skill and pass it through to every agent invocation:

```bash
if [ -z "$CLAUDE_PLUGIN_ROOT" ]; then
  CLAUDE_PLUGIN_ROOT=$(find /root /home /opt -maxdepth 6 \
    -path "*/appsec-plugin/plugin/skills/create-threat-model/SKILL.md" \
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
| `python3 <plugin>/scripts/*.py` | orchestrator, skill | `plugin_meta.py`, `baseline_state.py`, `stride_progress.py`, `validate_intermediate.py` |
| `find /root /home /opt -maxdepth 6 …` | skill fallback | `CLAUDE_PLUGIN_ROOT` discovery when env is empty |
| `date -u +%Y-%m-%dT%H:%M:%SZ` / `date +%s` | all agents | log timestamps and phase-epoch tracking |
| `grep -c`, `wc -l`, `wc -c`, `awk`, `sed`, `stat`, `ls`, `basename` | all agents | count aggregation for PHASE_END/STEP_END lines |
| `mkdir -p`, `rm -f`, `cat`, `echo`, `printf`, `cp`, `mv` | all agents | intermediate file handling, checkpoints, lock |
| `sha256sum` / `shasum -a 256` | `baseline_state.py` | stride file fingerprinting |

**None** of the above are destructive against `$REPO_ROOT` — every write targets `$OUTPUT_DIR` (default `$REPO_ROOT/docs/security`) or a temp file under it. If you want a minimally-scoped allow-list, permit `Bash(git:*)`, `Bash(python3:*)`, `Bash(grep:*)`, `Bash(find:*)`, and `Bash(date:*)` plus the file-handling basics.

## Argument Parsing

Parse the user's arguments for the following flags:

| Flag | Variable | Default |
|------|----------|---------|
| `--yaml` | `WRITE_YAML=true` (no-op — yaml is always written) | `true` (always on) |
| `--no-yaml` | `WRITE_YAML=false` (escape hatch — suppresses yaml output) | `false` |
| `--sarif` | `WRITE_SARIF=true` | `false` |
| `--requirements` | `CHECK_REQUIREMENTS=true` | from config `enabled` |
| `--requirements <url>` | `CHECK_REQUIREMENTS=true`, `REQUIREMENTS_URL_OVERRIDE=<url>` | from config `enabled` |
| `--no-requirements` | `CHECK_REQUIREMENTS=false` | from config `enabled` |
| `--dry-run` | `DRY_RUN=true` | `false` |
| `--resume` | Resume from last checkpoint | n/a |
| `--incremental` | `INCREMENTAL=true` — assertion that a baseline exists (hard abort otherwise) | auto-detected from baseline |
| `--full` | `INCREMENTAL=false` — force full scan even when prior output exists. Conflicts with `--incremental`. | `false` |
| `--with-sca` | `WITH_SCA=true` | `false` |
| `--repo <path>` | `REPO_ROOT=<abs-path>` | current working directory |
| `--output <path>` | `OUTPUT_DIR=<abs-path>` | `$REPO_ROOT/docs/security` |
| `--stride-model <model>` | `STRIDE_MODEL=<model>` | (none — use agent frontmatter) |
| `--assessment-depth <level>` | `ASSESSMENT_DEPTH=<quick\|standard\|thorough>` | `standard` |
| `--verbose` | `VERBOSE_REPORT=true` | `false` |

**Deprecated aliases:** The old flags `--with-requirements`, `--ignore-requirements`, and `--requirements-url <url>` are accepted for backward compatibility. If encountered, print a deprecation warning and map them:
- `--with-requirements` → `--requirements`
- `--ignore-requirements` → `--no-requirements`
- `--requirements-url <url>` → `--requirements <url>`

Any remaining text (after extracting flags and their values) is treated as scope constraints (e.g., component name, subdirectory, focus area).

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
    -path "*/appsec-plugin/plugin/skills/check-appsec-requirements/config.json" \
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

### Resolution order — first match wins

For each case, set `MODE`, `MODE_LABEL`, and (if listed) `POST_SUMMARY_NOTE`. Nothing is printed here — everything is emitted later in the Configuration Summary block.

1. **`--full` is set** → `MODE=full`, `MODE_LABEL="full (--full)"`. If `BASELINE_STATE` is `structured` or `legacy`, set `POST_SUMMARY_NOTE="Warning: existing threat model at <OUTPUT_DIR> will be overwritten. Changelog history (if any) is preserved."`.

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

Then print a blank line and `Invoking Stage 1 orchestrator.` No other text — no explanatory prose, no duplicated mode description — belongs between these lines.

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

Pass along any arguments the user provided as additional focus areas or scope constraints (e.g., a specific subdirectory, component name, or "focus on auth"). If no arguments were given, analyze the entire repository.

Use the `REPO_ROOT` and `OUTPUT_DIR` values resolved in the Path Resolution section above.

Pass the following variables to the agent prompt:
- `CLAUDE_PLUGIN_ROOT=<absolute plugin path>` (resolved in the "Prerequisites" section above — **always pass this explicitly**; do not rely on the variable being inherited by the sub-session, because some harness/headless configurations drop it)
- `REPO_ROOT=<absolute repo path>`
- `OUTPUT_DIR=<absolute output path>`
- `WRITE_YAML=<true|false>`
- `WRITE_SARIF=<true|false>`
- `CHECK_REQUIREMENTS=<true|false>`
- `REQUIREMENTS_URL_OVERRIDE=<url>` (only if `--requirements <url>` was provided)
- `INCREMENTAL=<true|false>`
- `WITH_SCA=<true|false>`
- `STRIDE_MODEL=<model>` (only if `--stride-model` was provided)
- `RESUME_FROM_PHASE=<N>` (only if resuming from checkpoint)
- `ASSESSMENT_DEPTH=<quick|standard|thorough>`
- `MAX_STRIDE_COMPONENTS=<3|5|8>`
- `STRIDE_TURNS_SIMPLE=<10|15|20>`
- `STRIDE_TURNS_MODERATE=<15|22|28>`
- `STRIDE_TURNS_COMPLEX=<20|31|35>`
- `DIAGRAM_DEPTH=<minimal|standard|extended>`
- `QA_DEPTH=<core|full|extended>`
- `VERBOSE_REPORT=<true|false>`
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

After the orchestrator completes (and `DRY_RUN` is `false`), verify that `$OUTPUT_DIR/threat-model.md` exists. If it does, invoke the `appsec-plugin:appsec-qa-reviewer` agent using `"QA review of threat model"` as the Agent tool `description`.

Pass the following in the prompt:
- `REPO_ROOT=<absolute repo path>` (same value resolved above)
- `OUTPUT_DIR=<absolute output path>` (same value resolved above)
- `CONTEXT_FILE=$OUTPUT_DIR/.threat-modeling-context.md`
- `QA_DEPTH=<core|full|extended>`

The QA reviewer runs with its own turn budget (up to 40 turns) and fixes broken VS Code links, linkifies bare file references, verifies cross-references, checks YAML/MD consistency, flags unaddressed prior findings, removes unfilled placeholders, and verifies section completeness. It updates `$OUTPUT_DIR/threat-model.md` in-place.

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

**Step 5 — Clean up** the temp directory:
```bash
rm -rf "$OUTPUT_DIR"
```

Exit after printing. Do not print file paths, log files, or run statistics — the temp directory is gone.

### Normal Completion (DRY_RUN=false)

Read `$OUTPUT_DIR/threat-model.md` and extract key metrics. Then print:

```
==============================================================
  Threat Model Complete
==============================================================

  Repository          : <REPO_ROOT>
  Generated Threat Model:
    $OUTPUT_DIR/threat-model.md
    $OUTPUT_DIR/threat-model.yaml        ← always, unless --no-yaml was passed
```

If `WRITE_YAML=false` (user passed `--no-yaml`), omit the yaml line.
If `WRITE_SARIF=true` and `$OUTPUT_DIR/threat-model.sarif.json` exists, add:
```
    $OUTPUT_DIR/threat-model.sarif.json
```

Then extract and print metrics from the threat model:
```

  Threats             : <n> total (Critical: <n>, High: <n>, Medium: <n>, Low: <n>)
  Components          : <n> analyzed
  Controls            : <n> cataloged (adequate: <n>, partial: <n>, missing: <n>)
```

If `CHECK_REQUIREMENTS=true`:
```
  Requirements        : <n> checked (pass: <n>, fail: <n>, partial: <n>)
```

Then extract run statistics from `$OUTPUT_DIR/.hook-events.log` and print them:
```

  -- Run Statistics --------------------------------------------
  Total Duration      : <Xm YYs>  (assessment: <Xm YYs> + QA review: <Xm YYs>)
    Phase 1  Context Resolution     :  2m 08s
    Phase 2  Reconnaissance         :  1m 59s
    Phase 3  Architecture Modeling   :  0m 07s
    ...
    Phase 11 Finalization            :  3m 12s
  Models              : <agent1>=<model1>, <agent2>=<model2>, ...
  Tokens              : <total> total
  Est. Cost           : $<n.nn>  (or "~$<n.nn> (estimated — subscription plan)" if no API key)
```

**How to extract run statistics:** Parse `$OUTPUT_DIR/.hook-events.log` and `$OUTPUT_DIR/.agent-run.log` using Bash with grep/awk. The data is already there in structured log lines written by the hook logger — do **not** call `agent_logger.py` or any Python script. Extract the data as follows:

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
   
   **Per-phase durations**: extract from the `ASSESSMENT_PHASES` line in `.hook-events.log` or `.agent-run.log`. The line contains space-separated `Phase N/11 <label>=<duration>` entries. Parse and display each phase indented under the total duration line. Format:
   ```
     Phase 1  Context Resolution     :  2m 08s
     Phase 2  Reconnaissance         :  1m 59s
     ...
   ```
   If `ASSESSMENT_PHASES` is not found, skip the per-phase breakdown.

2. **Models** — grep for `AGENT_SPAWN` lines, extract the agent name (`appsec-*`) and `model=<value>` pairs. Use short names: drop the `appsec-` prefix (e.g., `threat-analyst=sonnet, stride-analyzer=opus`). Deduplicate — if the same agent was spawned multiple times with the same model, list it once.

3. **Tokens** — grep for all `SESSION_STOP` lines and sum up the token fields: `in=`, `out=`, `cache_write=`, `cache_read=`. Compute `total = in + out + cache_write + cache_read`. Format the total with thousands separators. Show **only** the total — do not show the per-category breakdown.

4. **Est. Cost** — sum all `cost=$` values from `SESSION_STOP` lines. Always display the dollar amount. If the `ANTHROPIC_API_KEY` environment variable is set, display as `$X.XX` (actual API cost). Otherwise display as `~$X.XX (estimated — subscription plan)` to indicate this is the approximate cost the run would have incurred under API-based billing.

If `.hook-events.log` does not exist or contains no `SESSION_STOP` entries, skip the "Run Statistics" section entirely — do not print it with zeros or placeholders.

5. **Patch placeholders into threat-model.md** — After extracting tokens, cost, and durations, use the Edit tool to replace `_pending_` placeholders in the `## Appendix: Run Statistics` section:
   - `| Tokens | _pending_ |` → `| Tokens | <total> total (in: <N>, out: <N>, cache write: <N>, cache read: <N>) |`
   - `| Est. Cost | _pending_ |` → `| Est. Cost | <cost string> |` (e.g., `~$6.71 (estimated — subscription plan)` or `$6.71`)
   - `| **Assessment Total** | | | **_pending_** |` → actual assessment duration
   - QA Review duration row → actual QA duration
   - `| **Grand Total** | | | **_pending_** |` → actual total duration (assessment + QA)
   If `.hook-events.log` is not available, replace `_pending_` with `n/a`.

```

  Log files:
    Hook events : $OUTPUT_DIR/.hook-events.log
    Agent run   : $OUTPUT_DIR/.agent-run.log

==============================================================
```

To extract metrics: scan `threat-model.md` for the threat register table (count rows by severity), the components section (count ### headings in Section 2.3), and the controls catalog (count status badges in Section 7). Use Grep on the file — do not re-read the entire document.

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
3. Skip Stage 2.
