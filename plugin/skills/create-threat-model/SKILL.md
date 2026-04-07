---
name: create-threat-model
description: Perform a threat assessment of the current repository and produce docs/security/threat-model.md. Optionally also writes threat-model.yaml with --yaml flag.
---

This skill runs in two stages: first the threat analyst orchestrator (Phases 0–9), then the QA reviewer (Phase 10). Each stage is a separate Agent invocation with its own turn budget.

## Stage 1 — Threat Model Orchestrator

Invoke the `appsec-plugin:appsec-threat-analyst` agent **exactly once** using `"Threat Model Orchestrator"` as the Agent tool `description`. The orchestrator handles all phases internally (including context resolution in Phase 0) — do **not** invoke `appsec-context-resolver` or any other agent from the skill level. Only invoke the orchestrator here.

Pass along any arguments the user provided as additional focus areas or scope constraints (e.g., a specific subdirectory, component name, or "focus on auth"). If no arguments were given, analyze the entire repository.

Use the current working directory as the repository root unless the user specified a different path. Resolve the repo root via `git rev-parse --show-toplevel` and store it as `REPO_ROOT`.

If the user passes `--yaml` as an argument, pass `WRITE_YAML=true` to the agent. Otherwise pass `WRITE_YAML=false`.

If the user passes `--sarif` as an argument, pass `WRITE_SARIF=true` to the agent. Otherwise pass `WRITE_SARIF=false`.

## Stage 2 — QA Review

After the orchestrator completes, verify that `docs/security/threat-model.md` exists in the repository. If it does, invoke the `appsec-plugin:appsec-qa-reviewer` agent using `"QA review of threat model"` as the Agent tool `description`.

Pass the following in the prompt:
- `REPO_ROOT=<absolute repo path>` (same value resolved above)
- `CONTEXT_FILE=docs/security/.threat-modeling-context.md`

The QA reviewer runs with its own turn budget (up to 25 turns) and fixes broken VS Code links, linkifies bare file references, verifies cross-references, checks YAML/MD consistency, flags unaddressed prior findings, removes unfilled placeholders, and verifies section completeness. It updates `docs/security/threat-model.md` in-place.

If `docs/security/threat-model.md` does not exist after Stage 1 (orchestrator failed before writing output), skip Stage 2 and inform the user that the assessment did not complete successfully.
