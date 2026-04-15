# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Model Policy

**All agents default to `claude-sonnet-4-6` (Sonnet).** Every agent's `model:` frontmatter is set to `sonnet`. The STRIDE analyzer model can be overridden at runtime via `--stride-model opus` to get higher-quality threat analysis at increased cost (~5× per token). The override is passed through the Agent tool's `model` field, which takes precedence over frontmatter. All other agents remain on Sonnet — their tasks (orchestration, file I/O, tool invocation, mechanical checking) do not benefit enough from Opus to justify the cost.

## What This Is

A Claude Code plugin that adds automated STRIDE-based security threat modeling to any repository. Invoking it produces output files in a configurable output directory (default: `docs/security/` inside the analyzed repo):

- `threat-model.md` — human-readable report with C4 architecture diagrams, security use case flows, annotated technology diagram, threat register with colored severity badges, and clickable VS Code links to all referenced source files
- `threat-model.yaml` — machine-readable structured export of the same data (with `--yaml` flag)
- `threat-model.sarif.json` — SARIF v2.1.0 export for CI/CD integration with GitHub Advanced Security, SonarQube, DefectDojo, etc. (with `--sarif` flag)

The plugin supports two usage modes:
- **Dev team mode** (default): Run from within the repository being analyzed. Output goes to `docs/security/` inside the repo.
- **AppSec team mode**: Analyze an external repository via `--repo <path>` and write output to a separate location via `--output <path>`. This allows centralized security reviews without modifying the target repository.

## Plugin Status

**Version: 0.9.0-beta** — Functionally complete and suitable for guided use by AppSec teams. Not yet hardened for unattended CI/CD pipeline execution. See [Roadmap](#roadmap) for remaining items before 1.0.

## Agent Architecture

The plugin uses a seven-agent pipeline. Only `appsec-threat-analyst` is user-facing; the others are internal specialists invoked by the orchestrator or the skill.

```
User
 └── /appsec-plugin:create-threat-model          (skill — two-stage invocation)
          ├── Stage 1: appsec-plugin:appsec-threat-analyst     Sonnet  orchestrator (Phases 1–11)
          │        ├── appsec-plugin:appsec-context-resolver    Sonnet  Phase 1:   external context + business context
          │        ├── appsec-plugin:appsec-recon-scanner       Sonnet  Phase 2:   repo structure & code analysis
          │        ├── appsec-plugin:appsec-dep-scanner         Sonnet  Phase 2:   secrets & dep scan (bg)
          │        ├── appsec-plugin:appsec-stride-analyzer     Sonnet* Phase 9:   one per component (bg)
          │        └── appsec-plugin:appsec-triage-validator    Sonnet  Phase 10b: rating consistency validation
          └── Stage 2: appsec-plugin:appsec-qa-reviewer        Sonnet  Phase 11:  verify & fix output
```

*\* overridable at runtime via `--stride-model opus`*

**Important:** The QA reviewer is invoked by the skill (Stage 2), not by the orchestrator. This ensures it always runs with its own turn budget, even if the orchestrator consumed all its turns during Phases 1–10.

### appsec-threat-analyst (orchestrator)
`agents/appsec-threat-analyst.md` — Sonnet, 75 max turns

Owns the assessment lifecycle (Phases 1–11). Dispatches four specialist agents at the right points, reads their output files, and assembles the final threat model. Invoked by the skill as Stage 1.

**Phases:**
1. Invoke `appsec-context-resolver` → write `$OUTPUT_DIR/.threat-modeling-context.md`
2. Reconnaissance — dispatch `appsec-recon-scanner` → read `$OUTPUT_DIR/.recon-summary.md`
   - Dispatch `appsec-dep-scanner` (runs independently during Phases 2–7)
3. Architecture Modeling — C4 diagrams (Context / Container / Component) scaled to complexity
4. Security-Relevant Use Cases — sequence diagrams for auth, authz, input validation, etc.
5. Asset Identification — data, code/IP, infrastructure, availability assets
6. Attack Surface Mapping — all entry points and interfaces
7. Trust Boundary Analysis — where trust levels change
8. Security Controls Catalog — existing controls rated ✅ Adequate / ⚠️ Partial / 🔶 Weak / ❌ Missing
8b. Requirements Compliance *(when config `enabled: true`, or `--requirements` flag is passed)* — verify each requirement from loaded YAML against codebase, generate FAIL threats for Phase 9
9. STRIDE Threat Enumeration — dispatch one `appsec-stride-analyzer` per major component (requires outputs from Phases 6–8), merge results, assign global IDs, deduplicate
10. Dep Scan Synthesis — read dep scanner results, fold into threat register
10b. Triage Validation — dispatch `appsec-triage-validator` to validate cross-component rating consistency, severity plausibility, priority alignment, and rating completeness. Writes `.triage-flags.json` and annotates `.threats-merged.json`
   - Write `docs/security/threat-model.md` and `threat-model.yaml`
11. Finalization — release lock, record duration, print completion summary

### appsec-context-resolver (internal)
`agents/appsec-context-resolver.md` — Sonnet, 25 max turns

Optionally calls an external REST context endpoint and reads a prioritized set of common repository files for context. Sources checked (in addition to the external endpoint and `docs/business-context.md`): `SECURITY.md`, architecture docs, ADRs, OpenAPI/Swagger specs, `docker-compose.yml`, Kubernetes/Terraform configs, database schemas (SQL, Prisma, GraphQL), `.env.example` / config templates, `CHANGELOG.md`, and `docs/known-threats.yaml` (team-provided known threats). Writes everything to `$OUTPUT_DIR/.threat-modeling-context.md`. All other agents read this file.

### appsec-recon-scanner (internal)
`agents/appsec-recon-scanner.md` — Sonnet, 25 max turns

Performs Phase 1 reconnaissance: scans the repository structure, tech stack, package manifests, deployment artifacts, and 26 security categories (auth, authorization, data access, input handling, serialization, crypto, error handling, dangerous sinks, OAuth/OIDC, SPA/BFF, exposed routes, ecosystem supply chain hygiene). Writes a comprehensive markdown summary to `$OUTPUT_DIR/.recon-summary.md` that the orchestrator uses throughout Phases 2–10. This avoids the orchestrator spending its turn budget on file-by-file code reading.

### appsec-dep-scanner (internal, optional)
`agents/appsec-dep-scanner.md` — Sonnet, 15 max turns

**Only dispatched when `--with-sca` flag is passed.** Performs pure SCA (Software Composition Analysis): scans dependency manifests for known CVEs using native audit tools (`npm audit`, `pip-audit`, `govulncheck`, etc.) with heuristic fallback. Writes findings to `$OUTPUT_DIR/.dep-scan.json`. Secret detection is handled by `appsec-recon-scanner` (category 12), insecure defaults by Phase 8 Security Controls.

### appsec-stride-analyzer (internal)
`agents/appsec-stride-analyzer.md` — Sonnet, 31 max turns

Performs focused STRIDE analysis for a single component. Receives the component's interfaces, trust boundaries, and relevant controls from the orchestrator. Reads `.threat-modeling-context.md` for compliance scope and prior findings. Writes per-component threats to `$OUTPUT_DIR/.stride-<component-id>.json`.

### appsec-triage-validator (internal)
`agents/appsec-triage-validator.md` — Sonnet, 20 max turns

Invoked by the orchestrator in Phase 10b after STRIDE merge and dep scan synthesis. Validates the final `.threats-merged.json` for cross-component rating consistency, severity plausibility, P1/P2 priority alignment, and rating completeness. Writes validation flags to `$OUTPUT_DIR/.triage-flags.json` and annotates `.threats-merged.json` with `triage_flags` arrays per threat. Phase 11 renders triage warnings in the Threat Register and Management Summary. Non-fatal — if the validator fails, Phase 11 proceeds without triage annotations.

### appsec-qa-reviewer (skill-level, Stage 2)
`agents/appsec-qa-reviewer.md` — Sonnet, 40 max turns

Invoked by the `create-threat-model` skill as Stage 2, after the orchestrator completes. Runs 10 checks against `$OUTPUT_DIR/threat-model.md`: verifies VS Code deep links exist on disk, linkifies bare file path mentions, checks threat ID cross-references between sections, verifies YAML/MD consistency, flags prior findings not addressed in the threat register, removes unfilled placeholders, confirms all required sections are present, validates diagrams, and verifies internal anchors. Fixes issues in-place and prints a summary of what was corrected.

**Why skill-level:** Previously invoked by the orchestrator in Phase 11, the QA reviewer was consistently skipped because the orchestrator exhausted its 60-turn budget during Phases 1–10 (especially Phase 9 with multiple parallel STRIDE analyzers). Moving the invocation to the skill level gives the QA reviewer its own independent turn budget.

## Skills

`skills/` contains two user-invocable slash commands:

| Skill | Command | Description |
|-------|---------|-------------|
| `create-threat-model` | `/appsec-plugin:create-threat-model` | Full STRIDE-based threat assessment |
| `check-appsec-requirements` | `/appsec-plugin:check-appsec-requirements` | Verify tagged `[SEC-*]` requirements against the codebase |

`create-threat-model` delegates to `appsec-threat-analyst` (Stage 1) then `appsec-qa-reviewer` (Stage 2); `check-appsec-requirements` runs inline.

When `$OUTPUT_DIR/threat-model.md` already exists, `create-threat-model` defaults to **incremental mode** — only re-analyzing components affected by code changes. Use `--full` to force a complete re-assessment, or `--incremental` to explicitly request delta analysis.

**Flags:**
- `--repo <path>` — path to the repository to analyze (default: current working directory). Allows AppSec teams to analyze external repositories.
- `--output <path>` — output directory for all generated files (default: `$REPO_ROOT/docs/security`). Allows writing results outside the analyzed repository.
- `--yaml` — also write `$OUTPUT_DIR/threat-model.yaml`
- `--sarif` — also write `$OUTPUT_DIR/threat-model.sarif.json` (SARIF v2.1.0 for CI/CD integration)
- `--pentest-tasks` — also write `$OUTPUT_DIR/pentest-tasks.yaml`, a vendor-neutral, structured task list for AI pentest agents (Strix et al.) and DAST orchestrators. Only threats with `source ∈ {stride, dep-scan, known-vuln}`, a CWE on `plugin/data/pentest-eligible-cwes.yaml`, and concrete `evidence.file`[+`.line` for stride] are emitted. Every task carries a `safety` block (`read_only=true`, `destructive_actions=forbidden`) — consumers must honour it to avoid destructive probes against production.
- `--pentest-format <generic|strix>` — dialect for `pentest-tasks.yaml`. `generic` (default) is the full schema; `strix` flattens the shape for the Strix AI-pentester API surface.
- `--pentest-target <url>` — optional base URL written into `meta.target.base_url`. When omitted, consumers must inject the target themselves.
- `--requirements [<url>]` — enable requirements compliance check (Phase 8b). Without a URL, uses the configured `requirements_yaml_url` with cache fallback. With a URL, fetches from that URL (no cache fallback). Aborts if requirements are unavailable.
- `--no-requirements` — skip requirements compliance check even when `enabled: true` in config.
- `--full` — force a complete re-assessment even when a prior `threat-model.md` exists. Without this flag, the skill auto-detects prior output and switches to incremental mode.
- `--with-sca` — dispatch the dep-scanner for SCA (Software Composition Analysis). Without this flag, the dep-scanner is skipped — hardcoded secrets and insecure defaults are already covered by the recon-scanner and Phase 8 respectively. Use `--with-sca` when you want CVE data from live advisory databases included in the threat model.
- `--stride-model <model>` — override the model used by STRIDE analyzers (e.g. `opus` for higher-quality threat analysis). The override is passed via the Agent tool's `model` field, taking precedence over the agent's `model: sonnet` frontmatter. Other agents are unaffected. Use this when threat model quality matters more than cost (~5× per token for Opus vs Sonnet).
- `--assessment-depth <level>` — control analysis depth: `quick` (~15 min, 3 STRIDE components, minimal diagrams, core QA checks only), `standard` (default, ~25 min, 5 components, full diagrams and QA), or `thorough` (~40 min, 8 components, extended diagrams and QA). Affects STRIDE component count, per-component turn budgets, diagram depth, coverage checks, Phase 8 control rating strategy, and QA review scope.
- `--verbose` — include the metadata table (Generated, Analysis Duration, Model, Agent Models, Context Sources, Est. Cost) at the top of `threat-model.md` and the Run Statistics appendix (mode, plugin version, per-phase duration breakdown, coverage summary) at the end. Without this flag, the report starts directly with the Table of Contents after the title — metadata is still available in `threat-model.yaml` and on the console completion summary.

## Output Features

- **Management Summary** — executive-level overview placed before Section 1 with risk distribution table, key strengths (positive controls), top findings (linked to details), priority actions with threat counts, and overall security rating. When requirements are enabled, includes a requirements compliance subsection with baseline source, pass/fail counts, and top violated requirements. Designed for stakeholders who don't read the full report
- **Section introductory sentences** — every section opens with 1-2 sentences explaining what it contains and why, improving readability and navigation
- **Requirements integration** — when `--requirements` is enabled: Section 7b provides a full requirements compliance table (status, evidence, linked threats for every requirement); Section 8 (Threat Register) shows `Violated:` requirement IDs inline in each threat scenario; Section 9 (Critical Findings) shows `Violated Requirements:` with clickable links; Section 10 (Mitigation Register) shows `Fulfills Requirements:` indicating which requirements are satisfied. Requirements are only propagated from Phase 8b — never invented by mitigations
- **Security controls with threat cross-references** — Section 7 controls table includes a "Linked Threats" column referencing T-NNN IDs for controls rated below Adequate
- **Risk methodology** — Section 8 opens with a brief risk rating methodology note (Likelihood × Impact matrix) before the threat table
- **CWE references in Threat Register** — each threat scenario MUST include its CWE ID for traceability (mandatory, not optional)
- **VS Code deep links** — every referenced source file is linked as `vscode://file/<abs-path>:<line>` so clicking opens the file at the right line
- **Clickable T-NNN/M-NNN cross-references** — all threat and mitigation IDs throughout the entire document (including Linked Threats columns in Sections 2, 4, 5, 6, 7) are written as clickable internal links from the start by the orchestrator. The QA reviewer serves as a safety net but pre-linking is mandatory during output generation
- **Colored severity badges** — HTML inline badges for Critical / High / Medium / Low render in VS Code Markdown preview
- **Security controls effectiveness** — emoji badges: ✅ Adequate, ⚠️ Partial, 🔶 Weak, ❌ Missing; adequate controls include a justification note
- **Context source callout** — System Overview names every context source used (external context endpoint, business-context.md) and summarizes what each contributed
- **Technology Architecture diagram** — high-level vertical stack diagram (section 2.4), always produced regardless of complexity tier; nodes are colored pink when they carry Medium+ threats
- **SARIF export** — machine-readable CI/CD-compatible output via `--sarif` flag, maps threats to SARIF results with severity levels and file locations
- **Cross-repository dependency coverage** — auto-discovers SCM sibling projects and SaaS integrations, probes siblings for existing threat models, annotates C4 diagrams with coverage status (green/red/purple), adds a dependency coverage table to Section 5, and elevates risk at trust boundaries where upstream services lack a threat model

## Reliability Features

### Sub-agent retry logic
If a `appsec-stride-analyzer` or `appsec-dep-scanner` fails (missing output, validation error, or error stub), the orchestrator retries once synchronously before skipping the component. This handles transient failures like token-limit timeouts without losing threat coverage.

### Concurrent run locking
The orchestrator acquires a lock file (`$OUTPUT_DIR/.appsec-lock`) before starting. If another assessment is already running (lock < 1 hour old), the new run stops with an error. Stale locks (> 1 hour) are automatically overwritten. The lock is released after Phase 11 or on any early exit.

### Stale file cleanup (mode-aware)
Intermediate files from previous runs (`.stride-*.json`, `.dep-scan.json`, `.recon-summary.md`, `.appsec-cache/baseline.json`) in `$OUTPUT_DIR` are deleted **only when a full scan is starting** (`INCREMENTAL=false`). In **incremental mode** (`INCREMENTAL=true`, including the auto-detected default when a prior `threat-model.yaml` exists) these files are **preserved** — they are the carry-forward source: unchanged components reuse their existing `.stride-<id>.json`, Phase 2 may skip entirely when the recon fingerprint in `.appsec-cache/baseline.json` is unchanged, and the dep-scan cache survives between runs. Volatile per-phase files (`.phase-epoch`, `.progress/`) are always reset at the start of every run regardless of mode.

## Security Steering Hook

A `UserPromptSubmit` hook injects secure-by-default context into prompts that are code- or security-related. Uses tiered keyword matching:
- **Strong keywords** (auth, token, sql, xss, etc.) — single match triggers
- **Code keywords** (api, database, docker, etc.) — 2+ matches required
- **Action keywords** (write, create, build, etc.) — only trigger in combination with code keywords

This avoids false positives on generic prompts like "create a README" while still activating on "create an API endpoint".

## Verbose Logging

By default, hook events (agent spawns, file writes, tool errors, session stops with token/cost data) are only written to `$OUTPUT_DIR/.hook-events.log`. When the outermost session ends, an `ASSESSMENT_SUMMARY` block is automatically appended with aggregated duration, mode, threat counts (Critical/High/Medium/Low), total tokens, estimated cost (labeled as estimated under subscription plans, actual under API billing), models used by each agent, and per-phase duration breakdown (`ASSESSMENT_PHASES`). This summary is also mirrored to `.agent-run.log`.

**Progress indicators inside long phases.** Every intra-phase substep is prefixed with a `[k/N]` counter and annotated with an elapsed-time marker `(+MMmSSs)` read from `$OUTPUT_DIR/.phase-epoch`, e.g. `[4/13] Rating Secret Management… (+1m02s) ⚠️ Partial`. Phase 2 (recon) prints `[k/24]` per security category as it scans. Phase 9 (STRIDE) enters a polling loop that calls `scripts/stride_progress.py` every ~20 seconds to print one line per running sub-agent: `[stride] 3/5 ready — Auth Service [4/9 Tampering] · REST API [2/9 reading sources] · …`. Each STRIDE sub-agent writes its current substep to `$OUTPUT_DIR/.progress/<component-id>.json` (9 substeps: Loading context, Reading source files, the six STRIDE letters, Writing output). The `.progress/` directory and `.phase-epoch` file are cleared at the start of each assessment.

Enable verbose mode to mirror all events (including the summary) to stderr in real time:

**Option 1 — Environment variable** (per-invocation):
```bash
APPSEC_VERBOSE=1 claude --plugin-dir /path/to/plugin
```

**Option 2 — Config** (persistent, in `config.json`):
```json
{
  "logging": {
    "verbose": true
  }
}
```

**Option 3 — Headless script** (recommended for CI/CD):
```bash
./scripts/run-headless.sh --verbose --repo /path/to/repo
```
The `--verbose` flag starts a background `tail -f` on the log file and exports `APPSEC_VERBOSE=1`, providing real-time output on stderr via both mechanisms.

## Headless Output

`claude -p` (and `run-headless.sh`) displays the **completion summary** after the assessment finishes — including threat counts, component stats, and output file paths. Use `--verbose` for real-time hook events (agent spawns, file writes, token costs) on stderr during execution.

## Intermediate Files

These files are written during assessment and persist afterward:

All intermediate files are written to `$OUTPUT_DIR/` (which defaults to `docs/security/` inside the analyzed repo):

| File | Written by | Purpose |
|------|-----------|---------|
| `$OUTPUT_DIR/.threat-modeling-context.md` | context-resolver | Combined external context + business context; human-readable, auditable |
| `$OUTPUT_DIR/.recon-summary.md` | recon-scanner | Repository structure, tech stack, and security-relevant code analysis |
| `$OUTPUT_DIR/.dep-scan.json` | dep-scanner | Raw dependency and secret scan results |
| `$OUTPUT_DIR/.stride-<id>.json` | stride-analyzer (per component) | Per-component STRIDE threat lists before merge |
| `$OUTPUT_DIR/.threats-merged.json` | orchestrator (Phase 9) | Canonical merged threat list with global T-NNN IDs; deterministic source for diagram annotation, YAML/SARIF export, and changelog generation. Annotated with `triage_flags` arrays by Phase 10b |
| `$OUTPUT_DIR/.triage-flags.json` | triage-validator (Phase 10b) | Triage validation flags: rating consistency, plausibility, priority, and completeness checks |
| `$OUTPUT_DIR/.appsec-lock` | orchestrator | Concurrent run lock (deleted after assessment) |

## External Context *(optional)*

Set `rest_url` in `config.json` to have the context resolver call your own endpoint during Phase 1:

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

## Known Threats Input *(optional)*

Teams can provide known threats, prior pentest findings, and accepted risks by creating `docs/known-threats.yaml` in the analyzed repository. The context resolver reads this file during Phase 1 and includes it in `.threat-modeling-context.md`.

The STRIDE analyzer uses known threats as mandatory verification targets: `open` threats are confirmed against the current codebase, `mitigated` threats are verified, `accepted` threats are documented in Section 11 (Out of Scope), and `false-positive` threats are skipped. The QA reviewer checks that all `open` and `mitigated` known threats are addressed in the final threat model.

## Security Requirements Baseline

Requirements are loaded from a remote URL (`requirements_yaml_url` in `skills/check-appsec-requirements/config.json`) and cached persistently at `$CLAUDE_PLUGIN_ROOT/.cache/requirements.yaml`. This cache survives across assessments of different repositories.

### Config: `skills/check-appsec-requirements/config.json`

```json
{
  "requirements_source": {
    "enabled": false,
    "requirements_yaml_url": null
  }
}
```

- **`enabled`** — controls whether the `create-threat-model` skill includes requirements compliance (Phase 8b) by default. When `true`, every threat model includes a requirements check without needing `--with-requirements`. Default: `false`.
- **`requirements_yaml_url`** — URL to fetch the requirements YAML from. Set to your organization's requirements endpoint.

### Requirements resolution for `create-threat-model`

The `CHECK_REQUIREMENTS` flag is resolved from flags and config in this order:
1. `--no-requirements` → `false` (explicit skip)
2. `--requirements` or `--requirements <url>` → `true` (explicit enable)
3. Config `enabled` → its value (default behavior)

Loading behavior when `CHECK_REQUIREMENTS=true`:
- **`--requirements <url>` with URL:** fetch from that URL; no cache fallback — abort if unreachable
- **Otherwise:** fetch from configured URL → cache fallback → abort if both unavailable

### Requirements resolution for `check-appsec-requirements`

The skill is an explicit user action and always attempts to load requirements, regardless of the `enabled` config value. It supports `--requirements <url>` to override the configured URL (no cache fallback for explicit URLs).

`data/appsec-requirements-fallback.yaml` contains a reference set of 53 baseline requirements across 10 categories in structured YAML format with per-requirement CWE/OWASP reference URLs. It is **not** used as a runtime fallback — it serves as a starting point for teams to create their own requirements YAML. Run `scripts/harvest-requirements.py` to regenerate it from live requirement pages.

## Usage

### Dev Team Mode (from within the repository)

```bash
# Load the plugin
claude --plugin-dir /path/to/appsec-plugin/plugin

# Run threat assessment (output goes to docs/security/ in the current repo)
/appsec-plugin:create-threat-model

# With scope constraint
/appsec-plugin:create-threat-model focus on the authentication service

# Include SARIF output for CI/CD integration
/appsec-plugin:create-threat-model --sarif

# Include both YAML and SARIF output
/appsec-plugin:create-threat-model --yaml --sarif

# Include requirements compliance check (Phase 8b)
/appsec-plugin:create-threat-model --requirements

# Use requirements from a specific URL
/appsec-plugin:create-threat-model --requirements http://localhost:8000/appsec-requirements.yaml

# Skip requirements even when enabled in config
/appsec-plugin:create-threat-model --no-requirements

# Use Opus for STRIDE analyzers (higher quality, higher cost)
/appsec-plugin:create-threat-model --stride-model opus

# Quick assessment (~15 min)
/appsec-plugin:create-threat-model --assessment-depth quick

# Thorough assessment with Opus STRIDE analyzers
/appsec-plugin:create-threat-model --assessment-depth thorough --stride-model opus

# All flags combined
/appsec-plugin:create-threat-model --yaml --sarif --requirements --stride-model opus

```

### AppSec Team Mode (analyzing external repositories)

```bash
# Analyze an external repository (output goes to docs/security/ in that repo)
/appsec-plugin:create-threat-model --repo /path/to/team-frontend

# Analyze an external repo, write output to a separate directory
/appsec-plugin:create-threat-model --repo /path/to/team-frontend --output /appsec-reports/team-frontend

# Dry-run — full analysis, console-only output (no files written to repo)
/appsec-plugin:create-threat-model --repo /path/to/team-api --dry-run

# Full assessment with all outputs to a dated directory
/appsec-plugin:create-threat-model --repo /path/to/team-api --output /appsec-reports/team-api/2026-04-08 --yaml --sarif

# Incremental review after code changes
/appsec-plugin:create-threat-model --repo /path/to/team-api --output /appsec-reports/team-api --incremental

# High-quality assessment with Opus STRIDE analyzers
/appsec-plugin:create-threat-model --repo /path/to/team-api --output /appsec-reports/team-api --stride-model opus --yaml --sarif
```

### Requirements Compliance

```bash
# Check security requirements compliance (console output only)
/appsec-plugin:check-appsec-requirements

# Filter to one category
/appsec-plugin:check-appsec-requirements SEC-AUTH

# Save as Markdown report
/appsec-plugin:check-appsec-requirements --md

# Save as JSON
/appsec-plugin:check-appsec-requirements --json

# Save both formats
/appsec-plugin:check-appsec-requirements --save

# Filter and save
/appsec-plugin:check-appsec-requirements SEC-AUTH --json

# Use requirements from a specific URL
/appsec-plugin:check-appsec-requirements --requirements http://localhost:8000/appsec-requirements.yaml
```

## No Build System

All agent and skill definitions are plain Markdown — no build or lint tooling. Edit them directly.

## ⚠ Maintaining the Permission Allow-List

The canonical list of required Bash permissions lives in **`skills/create-threat-model/SKILL.md`** under "Permission auto-check". This list must be kept in sync whenever plugin code changes introduce new Bash command patterns.

**When to update the list:**

- Adding a new Bash code block to any agent or phase-group file
- Introducing a new shell variable assignment (e.g. `NEW_VAR=$(...)`)
- Adding a new shell builtin to agent prompts (e.g. `until`, `select`)
- Changing Write/Edit target paths in any agent
- Adding a new sub-agent with its own Bash patterns

**How to update:**

1. Identify the first token of the new Bash command (the prefix Claude Code matches on). Variable assignments like `FOO=$(...)` → prefix is `FOO=`. Shell builtins like `while` → prefix is `while`.
2. Add the entry to the canonical list in `SKILL.md` → "Permission auto-check" → Step 2, in the appropriate section (command prefixes or variable assignment prefixes).
3. If the new command writes to a path outside `$OUTPUT_DIR`, add a path-scoped `Write()` or `Bash(rm ...)` entry to the path permissions block below the canonical list.

**Why this matters:** Users who don't have `Bash(*)` enabled (the recommended secure default) will see confirmation prompts for every unrecognized command prefix. A single missing entry can cause dozens of prompts during an 80-minute assessment, effectively blocking unattended runs. The permission auto-check at skill startup warns users about missing entries, but only if the canonical list is complete.

**Validation:** After editing the list, grep all agent files for `bash` code blocks and verify every first-token is covered:
```bash
grep -hP '^\w+=\$|^\w+ ' plugin/agents/**/*.md plugin/agents/*.md | \
  sed 's/[=(].*//' | sort -u
```

## New Features (v0.10.0)

### `--repo` and `--output` flags (AppSec team mode)
The plugin now supports analyzing external repositories and writing output to a configurable directory. Use `--repo <path>` to point at a repository outside the current working directory, and `--output <path>` to write all output (reports, intermediate files, logs) to a separate location. When `--output` points outside the repository, `.gitignore` entries are automatically skipped. This enables centralized AppSec reviews without modifying target repositories.

### `--dry-run` mode
Run `create-threat-model --dry-run` to get a full threat model preview without writing any files to the repository. The full assessment pipeline runs (Phases 1–11) with all output directed to a temporary directory. After completion, the Management Summary (verdict, top risks, worst case scenarios, architecture assessment, follow-up actions) and key metrics are printed to the console. The temp directory is cleaned up automatically. Dry-run forces a full analysis (`INCREMENTAL=false`) — incremental mode is not supported in dry-run.

### Auto-incremental default
When `$OUTPUT_DIR/threat-model.md` exists from a previous run, the skill automatically switches to incremental mode — only re-analyzing components affected by code changes since the last assessment. This avoids unnecessary token consumption on repeated runs. The auto-detection is overridden by `--full` (force complete re-assessment) or `--incremental` (explicit delta). First runs without prior output always perform a full scan.

### `--resume` from checkpoint
If an assessment fails partway through, a checkpoint file preserves the last completed phase. Run `create-threat-model --resume` to continue from where it left off.

### Phase-group reference files
The orchestrator's 1241-line prompt has been decomposed into 4 phase-group reference files under `agents/phases/`. The orchestrator reads them at runtime, improving reliability for focused instruction sets.

### Configurable pricing and logging
`config.json` now includes `pricing` (cost estimation rates) and `logging` (max log file size with automatic rotation) sections. Cost prices are no longer hardcoded.

### Config schema validation
`scripts/validate_config.py` validates `config.json` and skill config files against a defined schema. Run it in CI or before deployment.

### Configurable security steering keywords
`hooks/steering_keywords.json` externalizes the keyword lists used by the security steering hook. Teams can customize trigger keywords without editing Python code.

### Dynamic STRIDE analyzer turn budgets
The orchestrator now assesses component complexity (simple/moderate/complex) and passes a suggested turn budget to each STRIDE analyzer, avoiding wasted turns on simple components.

### Shared logging standard
All sub-agents reference `agents/shared/logging-standard.md` instead of carrying ~40 lines of identical logging templates each. Reduces prompt size across all agents.

### Phase-group authority rule
Phase-group files are the authoritative source for phase instructions. The orchestrator contains only execution flow, parameters, and brief summaries — reducing its prompt from ~1500 lines to ~820 lines (~45% reduction).

### Phase 8 reuses Phase 2 reconnaissance
Phase 8 (Security Controls) now uses `.recon-summary.md` Section 7 as baseline instead of re-grepping all 13 categories. Only runs targeted greps for gaps or ❌ Missing confirmations, saving 5-10 orchestrator turns.

### Selective STRIDE context
STRIDE analyzers receive pre-extracted context parameters (COMPLIANCE_SCOPE, ASSET_TIER, PRIOR_FINDINGS, KNOWN_THREATS) instead of reading the full `.threat-modeling-context.md`. This avoids loading 3-5K tokens into each analyzer's context for the entire run.

### Dep-scanner caching
The dep-scanner caches results based on manifest file hashes. Runs within 1 hour with unchanged manifests skip the scan entirely.

### Log rotation
Hook event logs and agent run logs automatically rotate at 5 MB (configurable), keeping up to 2 archived copies.

### Restricted Bash permissions
Plugin-level `settings.json` now allowlists specific commands instead of granting broad `Bash(*)` access.

### SARIF output validation
New test suite validates SARIF v2.1.0 output against the specification schema.

### Supply chain threat coverage
The recon scanner now scans 26 security categories (up from 13), with 5 supply chain categories: CI/CD action pinning (7.14), container base image hygiene (7.15), dependency confusion indicators (7.16), postinstall script detection (7.17), and ecosystem supply chain hygiene (7.26). Category 7.26 adds ecosystem-specific CI install integrity checks (npm ci, --frozen-lockfile, --immutable, --require-hashes, --locked, go mod verify, etc.), dependency management tooling detection (Renovate/Dependabot), SCA tooling detection in CI (Snyk, Trivy, Grype, OSV-Scanner, npm audit, pip-audit, cargo audit, etc.), and lockfile presence verification across 13 ecosystems (npm, pnpm, yarn, pip, pipenv, poetry, uv, Go, Rust, Maven, Gradle, .NET, Ruby, PHP). Phase 8 "Dependency & Supply Chain" domain has 9 sub-controls with ecosystem-aware rating criteria. The CI/CD pipeline is now a selectable STRIDE component (standard/thorough depth), and the STRIDE analyzer includes a supply chain threat pattern table for evidence-backed Tampering/EoP threats.

### Assessment depth control (`--assessment-depth`)
Three-tier depth system (`quick`/`standard`/`thorough`) that controls analysis scope across the entire pipeline. A single flag resolves to 7 internal variables: `MAX_STRIDE_COMPONENTS` (3/5/8), `STRIDE_TURNS_SIMPLE` (10/15/20), `STRIDE_TURNS_MODERATE` (15/22/28), `STRIDE_TURNS_COMPLEX` (20/31/35), `DIAGRAM_DEPTH` (minimal/standard/extended), `QA_DEPTH` (core/full/extended), and coverage check behavior. Quick mode also skips active greps in Phase 8 (controls rated from recon baseline only) and all coverage checks in Phase 9.

### Cross-repository & SaaS dependency threat correlation
The plugin now automatically discovers cross-repository dependencies and SaaS integrations without manual configuration. The recon scanner (category 7.25) identifies SCM sibling projects (via docker-compose build paths, .gitmodules, K8s service DNS, internal HTTP clients, Go module imports, workspace references) and SaaS services (via SDK imports in manifests, API URL patterns, environment variable prefixes for 30+ known providers including Stripe, Auth0, Twilio, Sentry, etc.).

The context resolver auto-probes sibling directories and git submodule paths for existing `docs/security/threat-model.yaml` files, reading threat counts and component lists from found models. Results are written into `.threat-modeling-context.md` as a structured cross-repo dependency register.

**Architecture diagrams** annotate external nodes with coverage status: SCM siblings show `TM: ✓ 14 threats, 3 open` or `TM: ✗ missing` with green/red styling; SaaS nodes use purple styling. **Trust boundary analysis** (Section 5) includes a Cross-Repository Dependency Coverage table. **STRIDE analyzers** receive cross-repo context per component — they elevate risk at boundaries with missing threat models and consider open threats from sibling models at shared interfaces. **Coverage check D** adds gap threats for unanalyzed cross-repo trust boundaries. The `threat-model.yaml` schema includes a new `cross_repo_dependencies` array.

### Enhanced Mermaid diagram validation
The QA reviewer now checks 11 Mermaid syntax issues (up from 5), including HTML characters, placeholder tokens, layout orientation, quoted labels, and Trust Boundary Key comments.

### CVSS v4.0 scoring (scoped to exploitable findings)

Threats can carry an optional `cvss_v4` block (`{vector, base_score, severity, source, version_fallback}`) that propagates into `threat-model.yaml`, the Section 8 threat register (as a conditional `CVSS v4` column), and SARIF output (`rule.properties.security-severity` + `cvss-v4-vector`). Scoring is **not** applied uniformly — it is deliberately restricted to findings where the CVSS Base metrics can be grounded in code:

- `source: dep-scan` and `source: known-vuln` → CVSS vector **required**. Dep-scanner copies the vector from the upstream advisory (NVD, OSV, GHSA). Advisories that only publish CVSS v3.1 are carried through unchanged with `version_fallback: "3.1"` — consumers check this flag before comparing scores.
- `source: stride` → CVSS vector **allowed** iff (a) the threat's CWE appears in `plugin/data/cvss-eligible-cwes.yaml` (injection, XSS, SSRF, path traversal, deserialization, auth bypass, hardcoded credentials, crypto misuse, and similar concrete-sink weaknesses) **and** (b) `evidence.file` + `evidence.line` point at an exploitable code location. The STRIDE analyzer emits vectors only when both conditions hold.
- `source: architectural-anti-pattern`, `requirements-compliance`, `coverage-gap` → CVSS vector **forbidden**. Design, policy, and coverage gaps cannot be scored honestly on the CVSS Base metrics; they remain governed by the qualitative Likelihood × Impact matrix.

Eligibility is enforced by `validate_intermediate.py` (post-check against the positive list) and the triage validator's Step 5 (`cvss_missing` / `cvss_scope_violation` / `cvss_band_mismatch` flags). The QA reviewer's Check 13 strips out-of-scope vectors and keeps the Section 8 `CVSS v4` column in sync with the presence of scored threats. The Likelihood × Impact matrix remains authoritative — CVSS augments, never replaces, the qualitative rating.

## Roadmap

Items remaining before 1.0 release:

- [ ] Token-budget tracking and cost estimation per assessment (runtime counters)
- [ ] End-to-end CI test against a reference repository
- [ ] MCP server authentication for team deployments
