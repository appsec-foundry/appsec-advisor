---
name: create-threat-model
description: Perform a threat assessment of a repository and produce a threat-model.md. Supports --repo to analyze external repos and --output to set the output directory. Optionally also writes threat-model.yaml with --yaml flag.
---

This skill runs in two stages: first the threat analyst orchestrator (Phases 1–10), then the QA reviewer (Phase 11). Each stage is a separate Agent invocation with its own turn budget.

## Argument Parsing

Parse the user's arguments for the following flags:

| Flag | Variable | Default |
|------|----------|---------|
| `--yaml` | `WRITE_YAML=true` | `false` |
| `--sarif` | `WRITE_SARIF=true` | `false` |
| `--requirements` | `CHECK_REQUIREMENTS=true` | from config `enabled` |
| `--requirements <url>` | `CHECK_REQUIREMENTS=true`, `REQUIREMENTS_URL_OVERRIDE=<url>` | from config `enabled` |
| `--no-requirements` | `CHECK_REQUIREMENTS=false` | from config `enabled` |
| `--dry-run` | `DRY_RUN=true` | `false` |
| `--resume` | Resume from last checkpoint | n/a |
| `--incremental` | `INCREMENTAL=true` | `false` |
| `--with-sca` | `WITH_SCA=true` | `false` |
| `--repo <path>` | `REPO_ROOT=<abs-path>` | current working directory |
| `--output <path>` | `OUTPUT_DIR=<abs-path>` | `$REPO_ROOT/docs/security` |
| `--stride-model <model>` | `STRIDE_MODEL=<model>` | (none — use agent frontmatter) |

**Deprecated aliases:** The old flags `--with-requirements`, `--ignore-requirements`, and `--requirements-url <url>` are accepted for backward compatibility. If encountered, print a deprecation warning and map them:
- `--with-requirements` → `--requirements`
- `--ignore-requirements` → `--no-requirements`
- `--requirements-url <url>` → `--requirements <url>`

Any remaining text (after extracting flags and their values) is treated as scope constraints (e.g., component name, subdirectory, focus area).

## Requirements Resolution

After parsing flags, resolve `CHECK_REQUIREMENTS` before invoking any agent.

### Conflict detection

If both `--requirements` and `--no-requirements` are present, abort immediately:

- `--requirements` + `--no-requirements` → `✗ Conflicting flags: --requirements and --no-requirements cannot be used together.`

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

Print the resolved state:
```
↳ Requirements : <enabled (config) | enabled (--requirements) | enabled (--requirements <url>) | disabled (config) | disabled (--no-requirements)>
```

## Path Resolution

Resolve `REPO_ROOT` and `OUTPUT_DIR` before invoking any agent:

1. **REPO_ROOT** — if `--repo <path>` was provided, use that path. Otherwise use the current working directory. In both cases, resolve the git root:
   ```bash
   git -C "<path>" rev-parse --show-toplevel 2>/dev/null || echo "<path>"
   ```
   Store the result as `REPO_ROOT`. If the path does not exist or is not a directory, print an error and abort:
   ```
   ✗ Repository path does not exist: <path>
   ```

2. **OUTPUT_DIR** — if `--output <path>` was provided, use that absolute path. Otherwise default to `$REPO_ROOT/docs/security`. Create the directory if it does not exist:
   ```bash
   mkdir -p "$OUTPUT_DIR"
   ```

3. **Print resolved paths:**
   ```
   ↳ Repository : <REPO_ROOT>
   ↳ Output     : <OUTPUT_DIR>
   ```
   If `OUTPUT_DIR` is not under `REPO_ROOT`, also print:
   ```
   ↳ Note: Output directory is outside the repository — .gitignore entries will be skipped
   ```

## Resume from Checkpoint

If `--resume` is passed, check for `$OUTPUT_DIR/.appsec-checkpoint`:

1. Read the checkpoint file. It contains `phase=<N> status=<started|completed> timestamp=<ISO>`.
2. Inform the user what was found:
   ```
   ⟳ Checkpoint found: Phase <N> (<status>) at <timestamp>
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
- `REPO_ROOT=<absolute repo path>`
- `OUTPUT_DIR=<absolute output path>`
- `WRITE_YAML=<true|false>`
- `WRITE_SARIF=<true|false>`
- `CHECK_REQUIREMENTS=<true|false>`
- `REQUIREMENTS_URL_OVERRIDE=<url>` (only if `--requirements <url>` was provided)
- `DRY_RUN=<true|false>`
- `INCREMENTAL=<true|false>`
- `WITH_SCA=<true|false>`
- `STRIDE_MODEL=<model>` (only if `--stride-model` was provided)
- `RESUME_FROM_PHASE=<N>` (only if resuming from checkpoint)

## Incremental Mode

When `INCREMENTAL=true`, the orchestrator performs a **delta analysis** instead of a full scan:

1. Before Phase 2, run `git -C "$REPO_ROOT" diff --name-only HEAD~1..HEAD` (or `git -C "$REPO_ROOT" diff --name-only` for uncommitted changes) to identify changed files
2. Map changed files to components identified in the previous threat model (read existing `$OUTPUT_DIR/threat-model.md` and `threat-model.yaml`)
3. Only dispatch STRIDE analyzers for components affected by the changes
4. Reuse the existing threat model as a base and update only the affected sections
5. Mark unchanged sections with `<!-- unchanged since last assessment -->`

This significantly reduces token consumption for incremental security reviews after small code changes. If no previous threat model exists, falls back to a full assessment.

When `CHECK_REQUIREMENTS=true` and no requirements YAML is available, the context-resolver aborts with an error. The error behavior depends on the source:
- **`REQUIREMENTS_URL_OVERRIDE` set** (from `--requirements <url>`) — the override URL must be reachable; no cache fallback (abort immediately on fetch failure)
- **`--requirements` (without URL) or config `enabled: true`** — tries the configured URL, falls back to plugin cache; aborts only if both are unavailable

## Dry-Run Mode

When `DRY_RUN=true`, the orchestrator runs only Phases 0–1 (context resolution and reconnaissance), then prints a summary of what would be analyzed and exits. **Skip Stage 2 entirely** — the QA reviewer is not needed for a dry run.

Print the dry-run summary to the user and exit.

## Stage 2 — QA Review

After the orchestrator completes (and `DRY_RUN` is `false`), verify that `$OUTPUT_DIR/threat-model.md` exists. If it does, invoke the `appsec-plugin:appsec-qa-reviewer` agent using `"QA review of threat model"` as the Agent tool `description`.

Pass the following in the prompt:
- `REPO_ROOT=<absolute repo path>` (same value resolved above)
- `OUTPUT_DIR=<absolute output path>` (same value resolved above)
- `CONTEXT_FILE=$OUTPUT_DIR/.threat-modeling-context.md`

The QA reviewer runs with its own turn budget (up to 25 turns) and fixes broken VS Code links, linkifies bare file references, verifies cross-references, checks YAML/MD consistency, flags unaddressed prior findings, removes unfilled placeholders, and verifies section completeness. It updates `$OUTPUT_DIR/threat-model.md` in-place.

## Completion Summary

After Stage 2 completes (or after Stage 1 if `DRY_RUN=true`), **always** print a final summary. This is the last thing the skill outputs and is critical for headless mode (`claude -p`) where it becomes the entire visible output.

Read `$OUTPUT_DIR/threat-model.md` and extract key metrics. Then print:

```
══════════════════════════════════════════════════════════════
  ✓ Threat Model Complete
══════════════════════════════════════════════════════════════

  Repository : <REPO_ROOT>
  Output     : $OUTPUT_DIR/threat-model.md
```

If `WRITE_YAML=true` and `$OUTPUT_DIR/threat-model.yaml` exists:
```
               $OUTPUT_DIR/threat-model.yaml
```
If `WRITE_SARIF=true` and `$OUTPUT_DIR/threat-model.sarif.json` exists:
```
               $OUTPUT_DIR/threat-model.sarif.json
```

Then extract and print metrics from the threat model:
```

  Threats    : <n> total (Critical: <n>, High: <n>, Medium: <n>, Low: <n>)
  Components : <n> analyzed
  Controls   : <n> cataloged (✅ <n> adequate, ⚠️ <n> partial, ❌ <n> missing)
```

If `CHECK_REQUIREMENTS=true`:
```
  Requirements: <n> checked (✅ <n> pass, ❌ <n> fail, ⚠️ <n> partial)
```

Then extract run statistics from `$OUTPUT_DIR/.hook-events.log` and print them:
```

  ── Run Statistics ─────────────────────────────────────────
  Duration   : <Xm YYs>
  Models     : <agent1>=<model1>, <agent2>=<model2>, ...
  Tokens     : <total> total (in: <n>, out: <n>, cache_write: <n>, cache_read: <n>)
  Est. Cost  : $<n.nn>  (or "subscription" if no API key)
```

**How to extract run statistics:** Parse `$OUTPUT_DIR/.hook-events.log` using Bash with grep/awk. The data is already there in structured log lines written by the hook logger — do **not** call `agent_logger.py` or any Python script. Extract the data as follows:

1. **Duration** — find the first and last ISO timestamp (`YYYY-MM-DDTHH:MM:SSZ`) in `.hook-events.log`. Compute the difference in seconds and format as `Xm YYs`. Use this Bash snippet:
   ```bash
   FIRST_TS=$(grep -oP '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z' "$OUTPUT_DIR/.hook-events.log" | head -1)
   LAST_TS=$(grep -oP '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z' "$OUTPUT_DIR/.hook-events.log" | tail -1)
   ```
   Then convert both to epoch seconds with `date -d "$TS" +%s` and subtract.

2. **Models** — grep for `AGENT_SPAWN` lines, extract the agent name (`appsec-*`) and `model=<value>` pairs. Use short names: drop the `appsec-` prefix (e.g., `threat-analyst=sonnet, stride-analyzer=opus`). Deduplicate — if the same agent was spawned multiple times with the same model, list it once.

3. **Tokens** — grep for all `SESSION_STOP` lines and sum up the token fields: `in=`, `out=`, `cache_write=`, `cache_read=`. Compute `total = in + out + cache_write + cache_read`. Format numbers with thousands separators.

4. **Est. Cost** — sum all `cost=$` values from `SESSION_STOP` lines. If the `ANTHROPIC_API_KEY` environment variable is set, display as `$X.XX`. Otherwise display `subscription (no per-token cost)`.

If `.hook-events.log` does not exist or contains no `SESSION_STOP` entries, skip the "Run Statistics" section entirely — do not print it with zeros or placeholders.

```

  Log files:
    Hook events : $OUTPUT_DIR/.hook-events.log
    Agent run   : $OUTPUT_DIR/.agent-run.log

══════════════════════════════════════════════════════════════
```

To extract metrics: scan `threat-model.md` for the threat register table (count rows by severity), the components section (count ### headings in Section 2.3), and the controls catalog (count status badges in Section 7). Use Grep on the file — do not re-read the entire document.

## Error Handling

If `$OUTPUT_DIR/threat-model.md` does not exist after Stage 1 (orchestrator failed before writing output):
1. Check for `$OUTPUT_DIR/.appsec-checkpoint` to determine which phase failed.
2. Inform the user:
   ```
   ✗ Assessment did not complete successfully.
     Last checkpoint: Phase <N> (<status>)
     Available intermediate files can be inspected in <OUTPUT_DIR>/
     Run with --resume to continue from the last completed phase.
   ```
3. Skip Stage 2.
