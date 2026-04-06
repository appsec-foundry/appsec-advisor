---
name: create-threat-model
description: Perform a threat assessment of the current repository and produce docs/security/threat-model.md. Optionally also writes threat-model.yaml with --yaml flag.
---

Invoke the `appsec-plugin:appsec-threat-analyst` agent using `"Threat Model Orchestrator"` as the Agent tool `description`. Perform a full STRIDE-based threat assessment of the current repository and write the results to `docs/security/threat-model.md` (human-readable). The threat model context should be written in the first stage to `docs/security/threat-modeling-context.md` which will then be used as basis for the threat assessment.

Pass along any arguments the user provided as additional focus areas or scope constraints (e.g., a specific subdirectory, component name, or "focus on auth"). If no arguments were given, analyze the entire repository.

Use the current working directory as the repository root unless the user specified a different path.

If the user passes `--force-full` as an argument, pass `FORCE_FULL=true` to the agent. Otherwise pass `FORCE_FULL=false`.

If the user passes `--yaml` as an argument, pass `WRITE_YAML=true` to the agent. Otherwise pass `WRITE_YAML=false`.
