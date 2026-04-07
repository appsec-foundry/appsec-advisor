# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Model Policy

**All agents in this plugin use `claude-sonnet-4-6` (Sonnet).** Do not upgrade any agent to Opus — cost is the constraint. This applies to the orchestrator (`appsec-threat-analyst`) and all internal specialists (`appsec-context-resolver`, `appsec-dep-scanner`, `appsec-stride-analyzer`, `appsec-qa-reviewer`). Every agent's `model:` frontmatter is set to `sonnet` and must stay that way.

## What This Is

A Claude Code plugin that adds automated STRIDE-based security threat modeling to any repository. Invoking it produces output files in the analyzed repo:

- `docs/security/threat-model.md` — human-readable report with C4 architecture diagrams, security use case flows, annotated technology diagram, threat register with colored severity badges, and clickable VS Code links to all referenced source files
- `threat-model.yaml` — machine-readable structured export of the same data (with `--yaml` flag)
- `threat-model.sarif.json` — SARIF v2.1.0 export for CI/CD integration with GitHub Advanced Security, SonarQube, DefectDojo, etc. (with `--sarif` flag)

## Plugin Status

**Version: 0.9.0-beta** — Functionally complete and suitable for guided use by AppSec teams. Not yet hardened for unattended CI/CD pipeline execution. See [Roadmap](#roadmap) for remaining items before 1.0.

## Agent Architecture

The plugin uses a four-agent pipeline. Only `appsec-threat-analyst` is user-facing; the other three are internal specialists invoked by the orchestrator.

```
User
 └── /appsec-plugin:create-threat-model          (skill — two-stage invocation)
          ├── Stage 1: appsec-plugin:appsec-threat-analyst     Sonnet  orchestrator (Phases 0–10)
          │        ├── appsec-plugin:appsec-context-resolver    Sonnet  Phase 0:  external context + business context
          │        ├── appsec-plugin:appsec-recon-scanner       Sonnet  Phase 1:  repo structure & code analysis
          │        ├── appsec-plugin:appsec-dep-scanner         Sonnet  Phase 1:  secrets & dep scan (bg)
          │        └── appsec-plugin:appsec-stride-analyzer     Sonnet  Phase 8:  one per component (bg)
          └── Stage 2: appsec-plugin:appsec-qa-reviewer        Sonnet  Phase 10: verify & fix output
```

**Important:** The QA reviewer is invoked by the skill (Stage 2), not by the orchestrator. This ensures it always runs with its own turn budget, even if the orchestrator consumed all its turns during Phases 0–9.

### appsec-threat-analyst (orchestrator)
`agents/appsec-threat-analyst.md` — Sonnet, 60 max turns

Owns the assessment lifecycle (Phases 0–10). Dispatches four specialist agents at the right points, reads their output files, and assembles the final threat model. Invoked by the skill as Stage 1.

**Phases:**
0. Invoke `appsec-context-resolver` → write `docs/security/.threat-modeling-context.md`
1. Reconnaissance — dispatch `appsec-recon-scanner` → read `docs/security/.recon-summary.md`
   - Dispatch `appsec-dep-scanner` (runs independently during Phases 2–7)
2. Architecture Modeling — C4 diagrams (Context / Container / Component) scaled to complexity
3. Security-Relevant Use Cases — sequence diagrams for auth, authz, input validation, etc.
4. Asset Identification — data, code/IP, infrastructure, availability assets
5. Attack Surface Mapping — all entry points and interfaces
6. Trust Boundary Analysis — where trust levels change
7. Security Controls Catalog — existing controls rated ✅ Adequate / ⚠️ Partial / 🔶 Weak / ❌ Missing
8. STRIDE Threat Enumeration — dispatch one `appsec-stride-analyzer` per major component (requires outputs from Phases 5–7), merge results, assign global IDs, deduplicate
9. Dep Scan Synthesis — read dep scanner results, fold into threat register
   - Write `docs/security/threat-model.md` and `threat-model.yaml`
10. Finalization — release lock, record duration, print completion summary

### appsec-context-resolver (internal)
`agents/appsec-context-resolver.md` — Sonnet, 25 max turns

Optionally calls an external REST context endpoint and reads a prioritized set of common repository files for context. Sources checked (in addition to the external endpoint and `docs/business-context.md`): `SECURITY.md`, architecture docs, ADRs, OpenAPI/Swagger specs, `docker-compose.yml`, Kubernetes/Terraform configs, database schemas (SQL, Prisma, GraphQL), `.env.example` / config templates, and `CHANGELOG.md`. Writes everything to `docs/security/.threat-modeling-context.md`. All other agents read this file.

### appsec-recon-scanner (internal)
`agents/appsec-recon-scanner.md` — Sonnet, 25 max turns

Performs Phase 1 reconnaissance: scans the repository structure, tech stack, package manifests, deployment artifacts, and 11 security-relevant code categories (auth, authorization, data access, input handling, serialization, crypto, error handling, dangerous sinks, OAuth/OIDC, SPA/BFF, exposed routes). Writes a comprehensive markdown summary to `docs/security/.recon-summary.md` that the orchestrator uses throughout Phases 2–10. This avoids the orchestrator spending its turn budget on file-by-file code reading.

### appsec-dep-scanner (internal)
`agents/appsec-dep-scanner.md` — Sonnet, 20 max turns

Scans for hardcoded secrets (passwords, API keys, tokens, private keys), vulnerable/outdated dependencies, and insecure defaults (debug mode, HTTP, weak crypto, disabled TLS verification). Writes findings to `docs/security/.dep-scan.json`.

### appsec-stride-analyzer (internal)
`agents/appsec-stride-analyzer.md` — Sonnet, 30 max turns

Performs focused STRIDE analysis for a single component. Receives the component's interfaces, trust boundaries, and relevant controls from the orchestrator. Reads `.threat-modeling-context.md` for compliance scope and prior findings. Writes per-component threats to `docs/security/.stride-<component-id>.json`.

### appsec-qa-reviewer (skill-level, Stage 2)
`agents/appsec-qa-reviewer.md` — Sonnet, 45 max turns

Invoked by the `create-threat-model` skill as Stage 2, after the orchestrator completes. Runs 10 checks against `docs/security/threat-model.md`: verifies VS Code deep links exist on disk, linkifies bare file path mentions, checks threat ID cross-references between sections, verifies YAML/MD consistency, flags prior findings not addressed in the threat register, removes unfilled placeholders, confirms all required sections are present, validates diagrams, and verifies internal anchors. Fixes issues in-place and prints a summary of what was corrected.

**Why skill-level:** Previously invoked by the orchestrator in Phase 10, the QA reviewer was consistently skipped because the orchestrator exhausted its 60-turn budget during Phases 0–9 (especially Phase 8 with multiple parallel STRIDE analyzers). Moving the invocation to the skill level gives the QA reviewer its own independent turn budget.

## Skills

`skills/` contains two user-invocable slash commands:

| Skill | Command | Description |
|-------|---------|-------------|
| `create-threat-model` | `/appsec-plugin:create-threat-model` | Full STRIDE-based threat assessment |
| `check-appsec-requirements` | `/appsec-plugin:check-appsec-requirements` | Verify tagged `[SEC-*]` requirements against the codebase |

`create-threat-model` delegates to `appsec-threat-analyst` (Stage 1) then `appsec-qa-reviewer` (Stage 2); `check-appsec-requirements` runs inline.

The `create-threat-model` skill always runs a full assessment. Any existing `docs/security/threat-model.md` will be overwritten. Use `git diff` after the assessment to review what changed compared to a prior version.

**Output format flags:**
- `--yaml` — also write `docs/security/threat-model.yaml`
- `--sarif` — also write `docs/security/threat-model.sarif.json` (SARIF v2.1.0 for CI/CD integration)

## Output Features

- **VS Code deep links** — every referenced source file is linked as `vscode://file/<abs-path>:<line>` so clicking opens the file at the right line
- **Colored severity badges** — HTML inline badges for Critical / High / Medium / Low render in VS Code Markdown preview
- **Security controls effectiveness** — emoji badges: ✅ Adequate, ⚠️ Partial, 🔶 Weak, ❌ Missing; adequate controls include a justification note
- **Context source callout** — System Overview names every context source used (external context endpoint, business-context.md) and summarizes what each contributed
- **Technology Architecture diagram** — high-level vertical stack diagram (section 2.4), always produced regardless of complexity tier; nodes are colored pink when they carry Medium+ threats
- **SARIF export** — machine-readable CI/CD-compatible output via `--sarif` flag, maps threats to SARIF results with severity levels and file locations

## Reliability Features

### Sub-agent retry logic
If a `appsec-stride-analyzer` or `appsec-dep-scanner` fails (missing output, validation error, or error stub), the orchestrator retries once synchronously before skipping the component. This handles transient failures like token-limit timeouts without losing threat coverage.

### Concurrent run locking
The orchestrator acquires a lock file (`docs/security/.appsec-lock`) before starting. If another assessment is already running (lock < 1 hour old), the new run stops with an error. Stale locks (> 1 hour) are automatically overwritten. The lock is released after Phase 10 or on any early exit.

### Stale file cleanup
Intermediate files from previous runs (`.stride-*.json`, `.dep-scan.json`) are automatically deleted before each new assessment starts. This prevents stale data from interfering with the current run.

## Security Steering Hook

A `UserPromptSubmit` hook injects secure-by-default context into prompts that are code- or security-related. Uses tiered keyword matching:
- **Strong keywords** (auth, token, sql, xss, etc.) — single match triggers
- **Code keywords** (api, database, docker, etc.) — 2+ matches required
- **Action keywords** (write, create, build, etc.) — only trigger in combination with code keywords

This avoids false positives on generic prompts like "create a README" while still activating on "create an API endpoint".

## Intermediate Files

These files are written during assessment and persist afterward:

| File | Written by | Purpose |
|------|-----------|---------|
| `docs/security/.threat-modeling-context.md` | context-resolver | Combined external context + business context; human-readable, auditable |
| `docs/security/.recon-summary.md` | recon-scanner | Repository structure, tech stack, and security-relevant code analysis |
| `docs/security/.dep-scan.json` | dep-scanner | Raw dependency and secret scan results |
| `docs/security/.stride-<id>.json` | stride-analyzer (per component) | Per-component STRIDE threat lists before merge |
| `docs/security/.appsec-lock` | orchestrator | Concurrent run lock (deleted after assessment) |

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

The endpoint receives `POST {"repo_url": "..."}` and should return `{"context": "<any text>"}`. The response is written verbatim into `docs/security/.threat-modeling-context.md` and read by all agents. Use it to inject team ownership, compliance scope, prior findings, architecture notes, or anything else relevant.

A development mock is included: `python3 scripts/mock-context-server.py [port]`

## Security Requirements Baseline

`skills/check-appsec-requirements/appsec-requirements-fallback.yaml` contains 53 baseline requirements across 10 categories (`SEC-INV`, `SEC-AUTH`, `SEC-AUTHZ`, `SEC-DATA`, `SEC-TLS`, `SEC-ERR`, `SEC-HARD`, `SEC-DOCKER`, `SEC-DEP`, `SEC-IAC`) in structured YAML format with per-requirement CWE/OWASP reference URLs. Most requirements are `MUST` priority; context-dependent items (internal TLS, image scanning, IaC version pinning) use `SHOULD`. The skill loads requirements via a four-tier fallback: cached `.requirements.yaml` in the analyzed repo → `requirements_yaml_url` from `config.json` → plugin-bundled fallback YAML → error. Run `scripts/harvest-requirements.py` to regenerate the fallback from live requirement pages.

## Usage

```bash
# Load the plugin
claude --plugin-dir /path/to/appsec-plugin/plugin

# Run threat assessment
/appsec-plugin:create-threat-model

# With scope constraint
/appsec-plugin:create-threat-model focus on the authentication service

# Include SARIF output for CI/CD integration
/appsec-plugin:create-threat-model --sarif

# Include both YAML and SARIF output
/appsec-plugin:create-threat-model --yaml --sarif

# Check security requirements compliance
/appsec-plugin:check-appsec-requirements

# Filter to one category
/appsec-plugin:check-appsec-requirements SEC-AUTH
```

## No Build System

All agent and skill definitions are plain Markdown — no build or lint tooling. Edit them directly.

## Roadmap

Items remaining before 1.0 release:

- [ ] Token-budget tracking and cost estimation per assessment
- [ ] Dep-scanner caching (skip re-scan when lock files unchanged)
- [ ] `--dry-run` mode showing what would be analyzed without running the full pipeline
- [ ] Config schema validation (`config.json` with JSON Schema)
