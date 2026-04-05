# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## What This Is

A Claude Code plugin that adds automated STRIDE-based security threat modeling to any repository. Invoking it produces two output files in the analyzed repo:

- `docs/security/threat-model.md` — human-readable report with C4 architecture diagrams, security use case flows, annotated technology diagram, threat register with colored severity badges, and clickable VS Code links to all referenced source files
- `threat-model.yaml` — machine-readable structured export of the same data

## Agent Architecture

The plugin uses a four-agent pipeline. Only `appsec-threat-analyst` is user-facing; the other three are internal specialists invoked by the orchestrator.

```
User
 └── /appsec-plugin:create-threat-model
          └── appsec-plugin:appsec-threat-analyst          Opus    orchestrator, entry point
                   ├── appsec-plugin:appsec-context-resolver    Sonnet  Phase 0:  external context + business context
                   ├── appsec-plugin:appsec-dep-scanner         Sonnet  Phase 1:  secrets & dep scan
                   ├── appsec-plugin:appsec-stride-analyzer     Sonnet  Phase 8:  one per component
                   └── appsec-plugin:appsec-qa-reviewer         Sonnet  Phase 10: verify & fix output
```

### appsec-threat-analyst (orchestrator)
`agents/appsec-threat-analyst.md` — Opus, 50 max turns

Owns the full assessment lifecycle. Dispatches the three specialist agents at the right points, reads their output files, and assembles the final threat model. The only agent a user or skill should ever invoke.

**Phases:**
0. Invoke `appsec-context-resolver` → write `docs/security/threat-modeling-context.md`
1. Reconnaissance — tech stack, directory structure, deployment configs, key source files
   - Dispatch `appsec-dep-scanner` (runs independently during Phases 2–7)
2. Architecture Modeling — C4 diagrams (Context / Container / Component) scaled to complexity
3. Security-Relevant Use Cases — sequence diagrams for auth, authz, input validation, etc.
4. Asset Identification — data, code/IP, infrastructure, availability assets
5. Attack Surface Mapping — all entry points and interfaces
6. Trust Boundary Analysis — where trust levels change
   - Dispatch one `appsec-stride-analyzer` per major component
7. Security Controls Catalog — existing controls rated ✅ Adequate / ⚠️ Partial / 🔶 Weak / ❌ Missing
8. STRIDE Synthesis — merge stride analyzer results, assign global IDs, deduplicate
9. Dep Scan Synthesis — read dep scanner results, fold into threat register
   - Write draft `docs/security/threat-model.md` and `threat-model.yaml`
   - Invoke `appsec-qa-reviewer`
10. QA Review — verify VS Code links, linkify bare file references, check cross-references, YAML/MD consistency, prior finding coverage, placeholder cleanup, section completeness

### appsec-context-resolver (internal)
`agents/appsec-context-resolver.md` — Sonnet, 25 max turns

Optionally calls an external REST context endpoint and reads a prioritized set of common repository files for context. Sources checked (in addition to the external endpoint and `docs/business-context.md`): `SECURITY.md`, architecture docs, ADRs, OpenAPI/Swagger specs, `docker-compose.yml`, Kubernetes/Terraform configs, database schemas (SQL, Prisma, GraphQL), `.env.example` / config templates, and `CHANGELOG.md`. Writes everything to `docs/security/threat-modeling-context.md`. All other agents read this file.

### appsec-dep-scanner (internal)
`agents/appsec-dep-scanner.md` — Sonnet, 20 max turns

Scans for hardcoded secrets (passwords, API keys, tokens, private keys), vulnerable/outdated dependencies, and insecure defaults (debug mode, HTTP, weak crypto, disabled TLS verification). Writes findings to `docs/security/.dep-scan.json`.

### appsec-stride-analyzer (internal)
`agents/appsec-stride-analyzer.md` — Sonnet, 30 max turns

Performs focused STRIDE analysis for a single component. Receives the component's interfaces, trust boundaries, and relevant controls from the orchestrator. Reads `threat-modeling-context.md` for compliance scope and prior findings. Writes per-component threats to `docs/security/.stride-<component-id>.json`.

### appsec-qa-reviewer (internal)
`agents/appsec-qa-reviewer.md` — Sonnet, 20 max turns

Final phase after both output files are written. Runs 7 checks against `docs/security/threat-model.md`: verifies VS Code deep links exist on disk, linkifies bare file path mentions, checks threat ID cross-references between sections, verifies YAML/MD consistency, flags prior findings not addressed in the threat register, removes unfilled placeholders, and confirms all 11 required sections are present. Fixes issues in-place and prints a summary of what was corrected.

## Skills

`skills/` contains two user-invocable slash commands:

| Skill | Command | Description |
|-------|---------|-------------|
| `create-threat-model` | `/appsec-plugin:create-threat-model` | Full assessment or incremental update (auto-detected) |
| `check-appsec-requirements` | `/appsec-plugin:check-appsec-requirements` | Verify tagged `[SEC-*]` requirements against the codebase |

`create-threat-model` delegates to `appsec-threat-analyst`; `check-appsec-requirements` runs inline.

The `create-threat-model` skill automatically detects whether `docs/security/threat-model.md` already exists and runs incrementally if so. Pass `--force-full` to override and run a full assessment regardless.

## Output Features

- **VS Code deep links** — every referenced source file is linked as `vscode://file/<abs-path>:<line>` so clicking opens the file at the right line
- **Colored severity badges** — HTML inline badges for Critical / High / Medium / Low render in VS Code Markdown preview
- **Security controls effectiveness** — emoji badges: ✅ Adequate, ⚠️ Partial, 🔶 Weak, ❌ Missing; adequate controls include a justification note
- **Context source callout** — System Overview names every context source used (external context endpoint, business-context.md) and summarizes what each contributed
- **Technology Architecture diagram** — high-level vertical stack diagram (section 2.4), always produced regardless of complexity tier; nodes are colored pink when they carry Medium+ threats

## Intermediate Files

These files are written during assessment and persist afterward:

| File | Written by | Purpose |
|------|-----------|---------|
| `docs/security/threat-modeling-context.md` | context-resolver | Combined external context + business context; human-readable, auditable |
| `docs/security/.dep-scan.json` | dep-scanner | Raw dependency and secret scan results |
| `docs/security/.stride-<id>.json` | stride-analyzer (per component) | Per-component STRIDE threat lists before merge |

## External Context *(optional)*

Set `rest_url` in `config.json` to have the context resolver call your own endpoint during Phase 0:

```json
{
  "external_context": {
    "enabled": true,
    "rest_url": "http://127.0.0.1:4444/context"
  }
}
```

The endpoint receives `POST {"repo_url": "..."}` and should return `{"context": "<any text>"}`. The response is written verbatim into `docs/security/threat-modeling-context.md` and read by all agents. Use it to inject team ownership, compliance scope, prior findings, architecture notes, or anything else relevant.

A development mock is included: `python3 scripts/mock-context-server.py [port]`

## Security Requirements Baseline

`skills/check-appsec-requirements/appsec-requirements-fallback.yaml` contains 57 baseline requirements across 8 categories (`SEC-INV`, `SEC-ENC`, `SEC-AUTH`, `SEC-AUTHZ`, `SEC-DATA`, `SEC-ERR`, `SEC-CSP`, `SEC-HARD`) in structured YAML format with per-requirement URLs. The skill loads requirements via a four-tier fallback: cached `.requirements.yaml` in the analyzed repo → `requirements_yaml_url` from `config.json` → plugin-bundled fallback YAML → error. Run `scripts/harvest-requirements.py` to regenerate the fallback from live requirement pages.

## Usage

```bash
# Load the plugin
claude --plugin-dir /path/to/appsec-plugin/plugin

# Full assessment (or incremental update if threat-model.md already exists)
/appsec-plugin:create-threat-model

# With scope constraint
/appsec-plugin:create-threat-model focus on the authentication service

# Force a full re-run even if a prior threat model exists
/appsec-plugin:create-threat-model --force-full

# Check security requirements compliance
/appsec-plugin:check-appsec-requirements

# Filter to one category
/appsec-plugin:check-appsec-requirements SEC-AUTH
```

## No Build System

All agent and skill definitions are plain Markdown — no build or lint tooling. Edit them directly.
