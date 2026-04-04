---
name: create-threat-model
description: Perform a full STRIDE-based threat assessment of the current repository and produce docs/security/threat-model.md and threat-model.yaml.
---

Invoke the `appsec-plugin:appsec-threat-analyst` agent to perform a full STRIDE-based threat assessment of the current repository and write the results to `docs/security/threat-model.md` (human-readable) and `threat-model.yaml` (machine-readable). The threat model context should be written in the first stage to `docs/security/threat-model.context.md` which will then be uses as basis for the threat assessment.

Pass along any arguments the user provided as additional focus areas or scope constraints (e.g., a specific subdirectory, component name, or "focus on auth"). If no arguments were given, analyze the entire repository.

Use the current working directory as the repository root unless the user specified a different path.
