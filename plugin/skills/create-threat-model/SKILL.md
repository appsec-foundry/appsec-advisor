---
name: create-threat-model
description: Perform a threat assessment of the current repository and produce docs/security/threat-model.md. Optionally also writes threat-model.yaml with --yaml flag.
---

This skill runs in two stages: first the threat analyst orchestrator (Phases 0–9), then the QA reviewer (Phase 10). Each stage is a separate Agent invocation with its own turn budget.

## Argument Parsing

Parse the user's arguments for the following flags:

| Flag | Variable | Default |
|------|----------|---------|
| `--yaml` | `WRITE_YAML=true` | `false` |
| `--sarif` | `WRITE_SARIF=true` | `false` |
| `--requirements` | `CHECK_REQUIREMENTS=true` | `false` |
| `--dry-run` | `DRY_RUN=true` | `false` |
| `--resume` | Resume from last checkpoint | n/a |
| `--incremental` | `INCREMENTAL=true` | `false` |
| `--with-sca` | `WITH_SCA=true` | `false` |

Any remaining text is treated as scope constraints (e.g., component name, subdirectory, focus area).

## Resume from Checkpoint

If `--resume` is passed, check for `docs/security/.appsec-checkpoint` in the repository:

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

Invoke the `appsec-plugin:appsec-threat-analyst` agent **exactly once** using `"Threat Model Orchestrator"` as the Agent tool `description`. The orchestrator handles all phases internally (including context resolution in Phase 0) — do **not** invoke `appsec-context-resolver` or any other agent from the skill level. Only invoke the orchestrator here.

Pass along any arguments the user provided as additional focus areas or scope constraints (e.g., a specific subdirectory, component name, or "focus on auth"). If no arguments were given, analyze the entire repository.

Use the current working directory as the repository root unless the user specified a different path. Resolve the repo root via `git rev-parse --show-toplevel` and store it as `REPO_ROOT`.

Pass the following variables to the agent prompt:
- `WRITE_YAML=<true|false>`
- `WRITE_SARIF=<true|false>`
- `CHECK_REQUIREMENTS=<true|false>`
- `DRY_RUN=<true|false>`
- `INCREMENTAL=<true|false>`
- `WITH_SCA=<true|false>`
- `RESUME_FROM_PHASE=<N>` (only if resuming from checkpoint)

## Incremental Mode

When `INCREMENTAL=true`, the orchestrator performs a **delta analysis** instead of a full scan:

1. Before Phase 1, run `git diff --name-only HEAD~1..HEAD` (or `git diff --name-only` for uncommitted changes) to identify changed files
2. Map changed files to components identified in the previous threat model (read existing `docs/security/threat-model.md` and `threat-model.yaml`)
3. Only dispatch STRIDE analyzers for components affected by the changes
4. Reuse the existing threat model as a base and update only the affected sections
5. Mark unchanged sections with `<!-- unchanged since last assessment -->`

This significantly reduces token consumption for incremental security reviews after small code changes. If no previous threat model exists, falls back to a full assessment.

When `CHECK_REQUIREMENTS=true` and no requirements YAML is available (no remote URL configured and no plugin cache), the context-resolver aborts with an error.

## Dry-Run Mode

When `DRY_RUN=true`, the orchestrator runs only Phases 0–1 (context resolution and reconnaissance), then prints a summary of what would be analyzed and exits. **Skip Stage 2 entirely** — the QA reviewer is not needed for a dry run.

Print the dry-run summary to the user and exit.

## Stage 2 — QA Review

After the orchestrator completes (and `DRY_RUN` is `false`), verify that `docs/security/threat-model.md` exists in the repository. If it does, invoke the `appsec-plugin:appsec-qa-reviewer` agent using `"QA review of threat model"` as the Agent tool `description`.

Pass the following in the prompt:
- `REPO_ROOT=<absolute repo path>` (same value resolved above)
- `CONTEXT_FILE=docs/security/.threat-modeling-context.md`

The QA reviewer runs with its own turn budget (up to 25 turns) and fixes broken VS Code links, linkifies bare file references, verifies cross-references, checks YAML/MD consistency, flags unaddressed prior findings, removes unfilled placeholders, and verifies section completeness. It updates `docs/security/threat-model.md` in-place.

## Error Handling

If `docs/security/threat-model.md` does not exist after Stage 1 (orchestrator failed before writing output):
1. Check for `docs/security/.appsec-checkpoint` to determine which phase failed.
2. Inform the user:
   ```
   ✗ Assessment did not complete successfully.
     Last checkpoint: Phase <N> (<status>)
     Available intermediate files can be inspected in docs/security/
     Run with --resume to continue from the last completed phase.
   ```
3. Skip Stage 2.
