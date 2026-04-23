# CLAUDE.md

Guidance for Claude Code when working in this repository.

## 1. Overview

A Claude Code plugin that runs automated STRIDE-based security threat modeling against any repository. Outputs to `$OUTPUT_DIR` (default: `docs/security/` inside the analyzed repo):

- `threat-model.md` — human-readable report: C4 diagrams, security use cases, threat register with severity badges, VS Code deep links
- `threat-model.yaml` — structured export (`--yaml`)
- `threat-model.sarif.json` — SARIF v2.1.0 for CI/CD (`--sarif`)
- `pentest-tasks.yaml` — task list for AI pentesters / DAST (`--pentest-tasks`)

**Two modes:**
- **Dev team** (default): run inside the repo, output to `docs/security/`.
- **AppSec team**: `--repo <path>` to analyze externally, `--output <path>` to write elsewhere.

**Status:** 0.9.0-beta — functionally complete, guided AppSec-team use. Not yet hardened for unattended CI/CD.

## 2. Architecture

Seven-agent pipeline plus one WIP agent; only `appsec-threat-analyst` is user-facing.

```
User
 └── /appsec-advisor:create-threat-model          (skill — up to 3 stages)
      ├── Stage 1: appsec-threat-analyst        Sonnet  orchestrator (Phases 1–11)
      │     ├── appsec-context-resolver          Sonnet  Phase 1:  context
      │     ├── appsec-recon-scanner             Sonnet  Phase 2:  repo & code recon
      │     ├── scripts/dep_scan.py              Python  Phase 2:  SCA (--with-sca, bg)
      │     ├── appsec-stride-analyzer           Sonnet* Phase 9:  per component (bg)
      │     ├── appsec-threat-merger             Sonnet* Phase 9:  merge candidates
      │     ├── scripts/triage_validate_ratings.py Python  Phase 10b: Steps 1–5 (pre-flight, no LLM)
      │     └── appsec-triage-validator          Sonnet* Phase 10b: Step 6 (ranking)
      ├── Stage 2: appsec-qa-reviewer            Sonnet  verify & fix output
      └── Stage 3: appsec-architect-reviewer     Opus    advisory review (auto @ thorough)
```

*\* reasoning-model-overridable*

**Why Stages 2 and 3 are skill-level, not orchestrator-level:** each gets its own independent turn budget so they can't be starved by Phase 9. Stage 3 is strictly advisory — it writes `.architect-review.md` and never modifies `threat-model.md/yaml/sarif.json`.

**WIP agent** — `appsec-config-scanner` (15 turns, `data/config-iac-checks.yaml`) is defined but not yet dispatched. Intended for a future Phase 2.5 between recon and STRIDE to emit IaC/CI findings (Dockerfile, GitHub Actions, docker-compose, Dependabot/Renovate). Wire it up or delete before 1.0.

### 2.1 Orchestrator phases (`appsec-threat-analyst`, 75 turns)

1. Context resolution → `.threat-modeling-context.md`
2. Recon → `.recon-summary.md`; launch dep_scan.py in background if `WITH_SCA`
3. Architecture (C4: Context / Container / Component)
4. Security use cases (sequence diagrams)
5. Asset identification
6. Attack surface
7. Trust boundaries
8. Security controls catalog (✅ / ⚠️ / 🔶 / ❌)
8b. Requirements compliance (when enabled) → FAIL threats feed Phase 9
9. STRIDE enumeration (one analyzer per component, merge, global T-IDs, dedup)
10. Dep scan synthesis
10b. Triage validation → `.triage-flags.json` (Steps 1–5: Python; Step 6: LLM agent)
11. Finalization: write `threat-model.md` + `.yaml`, release lock, print summary

### 2.2 Sub-agents

| Agent | Role |
|-------|------|
| `threat-analyst` (75 turns, orchestrator) | Phases 1–11. Loads phase instructions from `agents/phases/phase-group-*.md`. Handles `REPAIR_MODE` re-runs when QA/architect emit repair plans. |
| `context-resolver` (25 turns) | Reads `SECURITY.md`, ADRs, OpenAPI, docker-compose, K8s/Terraform, schemas, `docs/known-threats.yaml`, optional external REST endpoint. Loads interface-relevant findings from declared dependency repos via `docs/related-repos.yaml` (primary deep-read); auto-discovers filesystem siblings for "TM found/missing" annotations only (no findings read). |
| `recon-scanner` (25 turns) | Scans 26 security categories; keeps orchestrator out of per-file reads. |
| `dep_scan.py` (script) | Native audit tools (`npm audit`, `pip-audit`, `govulncheck`, `mvn dependency-check`); static heuristics fallback (`data/dep-scan-heuristics.yaml`); 1 h manifest-hash cache. |
| `stride-analyzer` (31 turns) | One per component; writes `.stride-<id>.json`. |
| `threat-merger` (12 turns) | Only when candidate groups exist; decides merge / consolidate / keep. |
| `triage-validator` (20 turns, Step 6 only) | Breach-distance inference, compound-chain detection, effective-severity computation (`severity-caps.yaml`, `critical-criteria.yaml` gate), multi-view ranking. Steps 1–5 (consistency/plausibility/completeness/CVSS) run as `scripts/triage_validate_ratings.py` before dispatch. |
| `qa-reviewer` (80 turns, Stage 2) | Contract QA via `scripts/qa_checks.py` (11 deterministic checks). Emits `.qa-repair-plan.json` on drift → analyst re-runs in `REPAIR_MODE` → re-render. Up to 3 iterations. |
| `architect-reviewer` (40 turns, Stage 3, advisory) | 6 checks (skips 1/4/6 at quick). May emit `.architect-repair-plan.json`; never directly modifies output. |
| `config-scanner` (15 turns, **WIP — not yet dispatched**) | Phase 2.5 IaC/CI scan: Dockerfile, GitHub Actions, docker-compose, Dependabot/Renovate vs. `data/config-iac-checks.yaml`. Emits `.config-scan-findings.json`. Wire up or delete before 1.0. |

Agent file inventory (for doc-drift detection):
`agents/appsec-threat-analyst.md` — Sonnet, 75 max turns
`agents/appsec-context-resolver.md` — Sonnet, 25 max turns
`agents/appsec-recon-scanner.md` — Sonnet, 25 max turns
`agents/appsec-stride-analyzer.md` — Sonnet, 31 max turns
`agents/appsec-triage-validator.md` — Sonnet, 20 max turns
`agents/appsec-threat-merger.md` — Sonnet, 12 max turns
`agents/appsec-qa-reviewer.md` — Sonnet, 80 max turns
`agents/appsec-architect-reviewer.md` — Sonnet, 40 max turns
`agents/appsec-config-scanner.md` — Sonnet, 15 max turns

**Shared agent utilities** (`agents/shared/`, included by multiple agents): `validation-routine.md` (threat-field validation), `logging-standard.md` (PHASE_START/END, STEP_START/END format), `owasp-llm-top10.md` (LLM-surface threat guidance).

**Phase-group files** (`agents/phases/`, authoritative phase instructions — the orchestrator **lazy-loads** these at the boundary of each phase-group rather than reading all four at startup; `phase-group-recon.md` is the only file read during Pre-Phase checklist, the other three are read just-in-time before Phase 3, Phase 9, and Phase 11 respectively — see `appsec-threat-analyst.md` "Lazy loading protocol" in the Pre-Phase checklist):

| File | Owns |
|------|------|
| `phase-group-recon.md` | Phases 1–2 (context + recon + optional SCA + IaC checks) |
| `phase-group-architecture.md` | Phases 3–8 (C4, use cases, assets, attack surface, trust boundaries, controls). Pins the exact `PHASE_START`/`PHASE_END` log format that downstream tooling parses. |
| `phase-group-threats.md` | Phases 9–10 (parallel STRIDE dispatch, merge-candidates → merge-decisions → `.threats-merged.json`, triage). |
| `phase-group-finalization.md` | Phase 11 (compose → QA → optional architect-review → re-render loop → annotators → cleanup). |

### 2.3 Model policy

All agents default to `claude-sonnet-4-6`. Opus is used only where deep reasoning pays off:

- `--reasoning-model opus-cheap` (**default at `standard` and `thorough`**): Opus for triage-validator (Step 6) + threat-merger (~$0.03–0.05 extra; Steps 1–5 are now Python).
- `--reasoning-model sonnet`: opt-out to Sonnet-only (fastest, cheapest).
- `--reasoning-model opus`: additionally Opus for STRIDE analyzers (~$2–5 extra).
- `--architect-model opus` (default when Stage 3 runs): architect-reviewer.
- `--stride-model opus` — deprecated, use `--reasoning-model`.

Overrides pass via the Agent tool's `model` field, taking precedence over agent frontmatter.

### 2.4 Rendering pipeline

**Invariant:** agents never write `threat-model.md` directly. They emit JSON data fragments (schema-validated) and Markdown prose fragments. `scripts/compose_threat_model.py` is the sole canonical renderer.

```
agents write fragments → validate_fragment.py → compose_threat_model.py → threat-model.md
       ↓                                                      ↑
  JSON (6 types)                                    sections-contract.yaml
  Markdown (prose)                                  templates/fragments/*.j2
```

- **`data/sections-contract.yaml`** — single source of truth for document structure: section order, fragment type per section (`data` | `markdown` | `computed`), required schema, required template. Bump `contract_version` on breaking changes.
- **`templates/threat-model.template.md`** — master template (currently a single include of the full body).
- **`templates/fragments/*.md.j2`** — 10 Jinja2 fragments rendered by `compose_threat_model.py`: `management-summary`, `toc`, `verdict`, `architecture-assessment`, `critical-attack-chain`, `top-findings`, `mitigations`, `operational-strengths`, `infobox`, `changelog`. Filters: `severity_emoji`, `effectiveness_badge`, `linkify_with_label`.
- **`schemas/fragments/*.schema.json`** — 6 fragment schemas (JSON-Schema draft 2020-12) enforced by `validate_fragment.py` as a hard gate when agents write LLM-authored JSON: `verdict`, `architecture-assessment`, `critical-attack-chain`, `compound-chains`, `architectural-findings`, `operational-strengths-overrides`.
- **Post-processing annotators** run after compose, are idempotent (guarded by `%% anno-*-start/end` fences), and decorate diagrams with threat badges/links: `annotate_architecture.py` (Mermaid graph nodes) and `annotate_sequences.py` (sequence "Note over" top-3 threats).
- **QA re-render loop** — when `qa_checks.py` detects contract drift it writes `.qa-repair-plan.json`; the orchestrator is re-invoked in `REPAIR_MODE`, fragments are updated, `compose_threat_model.py` re-runs. Bounded to 3 iterations. Same mechanism for architect-reviewer via `.architect-repair-plan.json`.
- **Determinism** — identical inputs produce byte-identical `threat-model.md`. Exit codes: 0 ok, 1 missing/invalid fragment, 2 contract error, 3 IO error.

## 3. Usage

### 3.1 Skills

`skills/` contains five slash commands:

| Skill | Description |
|-------|-------------|
| `/appsec-advisor:create-threat-model` | Full STRIDE assessment (main entry point). The canonical Bash permission allow-list it depends on lives in `data/required-permissions.yaml` — see §7.5. |
| `/appsec-advisor:generate-threat-summary` | Aggregates one or more existing `threat-model.yaml` files into a consolidated `threat-summary.md`. No new analysis or STRIDE scanning — pure aggregation with cross-repo pattern detection. Supports `--repos` for multi-repo use. |
| `/appsec-advisor:check-appsec-requirements` | Verify `[SEC-*]` requirements are implemented. Its own `config.json` controls the requirements source. |
| `/appsec-advisor:check-permissions` | Preflight the Claude Code permission allow-list. Reports which entries from `data/required-permissions.yaml` are missing from `~/.claude/settings.json` and `.claude/settings.{json,local.json}`; `--update` merges them in. Delegates to `scripts/check_permissions.py`. |
| `/appsec-advisor:status` | Read-only overview — plugin version, available capsules, last-run identity, config sources, fast-path preview. No writes, no agent dispatch. Delegates to `scripts/appsec_status.py`. |

### 3.2 Run modes

If `$OUTPUT_DIR/threat-model.md` exists, the skill runs incremental by default. Override with:

- `--full` — fresh re-analysis, preserves changelog + T-IDs
- `--rebuild` — wipe all prior state
- `--incremental` — explicit
- `--resume` — continue a prior interrupted run

### 3.3 Flags

**Output formats**
| Flag | Purpose |
|------|---------|
| `--yaml` / `--sarif` | Additional output formats |
| `--pentest-tasks [--pentest-format strix] [--pentest-target <url>]` | Emit task list for AI pentesters; only STRIDE/dep-scan/known-vuln threats with concrete evidence and eligible CWE. All tasks carry `safety` block (read-only, no destructive probes). |
| `--dry-run` | Full analysis, no files written to repo (temp output, console summary) |
| `--verbose` | Metadata table + Run Statistics appendix in `threat-model.md` |

**Scope & targeting**
| Flag | Purpose |
|------|---------|
| `--repo <path>` / `--output <path>` | External repo / separate output dir |
| `--assessment-depth quick\|standard\|thorough` | Scope control: 3/5/8 STRIDE components; diagram depth; QA breadth; Phase 8 grep strategy |
| `--requirements [<url>]` / `--no-requirements` | Enable/disable Phase 8b compliance check |
| `--with-sca` | Run dep-scanner (secrets and insecure defaults are already covered elsewhere) |

**Models & review stages**
| Flag | Purpose |
|------|---------|
| `--reasoning-model sonnet\|opus-cheap\|opus` | Phase 9/10 reasoning models (see §2.3) |
| `--architect-review` / `--no-architect-review` / `--architect-model` | Stage 3 control (auto-on at thorough) |

**Housekeeping**
| Flag | Purpose |
|------|---------|
| `--keep-runtime-files` | Skip Phase 11 transient-file cleanup |

## 4. Output Contract

What the report must contain:

- **Management Summary** before Section 1: risk distribution, strengths, top findings, priority actions, overall rating. Requirements subsection when enabled.
- **CWE ID mandatory** in every threat scenario.
- **VS Code deep links** (`vscode://file/<abs-path>:<line>`) for every referenced source file.
- **Clickable T-NNN / M-NNN** cross-references everywhere (orchestrator pre-links; QA reviewer is the safety net).
- **Severity badges** (Critical/High/Medium/Low) and control badges (✅ Adequate / ⚠️ Partial / 🔶 Weak / ❌ Missing).
- **Technology Architecture diagram** (Section 2.4) always produced; Medium+ threat nodes in pink.
- **Cross-repo dependency coverage** (Section 5): SCM siblings with existing threat models annotated green/red; SaaS purple. Missing upstream models elevate risk at shared boundaries.
- **CVSS v4.0** scoring only where groundable: required for `dep-scan` / `known-vuln`; allowed for `stride` iff CWE ∈ `data/cvss-eligible-cwes.yaml` AND evidence has file+line; forbidden for architectural / requirements / coverage-gap threats. Enforced by `validate_intermediate.py` + triage-validator Step 5.
- **Change Summary** (`+N added / ~N changed / -N resolved`) on every re-run with a baseline. T-IDs stable across `--full` runs so Jira/Linear refs don't break.

## 5. Runtime

### 5.1 Logging & progress

- Hook events (agent spawns, file writes, token/cost) → `$OUTPUT_DIR/.hook-events.log`.
- Structured agent events → `$OUTPUT_DIR/.agent-run.log`. Both rotate at 5 MB.
- `ASSESSMENT_SUMMARY` + `ASSESSMENT_PHASES` blocks appended at session end.
- **Phase banners** on every phase start/end with expected + actual duration.
- **Intra-phase progress**: `[k/N]` counters with `(+MMmSSs)` markers. Phase 9 polls `scripts/stride_progress.py` ~20 s for live per-component substep status (9 substeps → `.progress/<component>.json`).
- Enable real-time stderr mirroring via `APPSEC_VERBOSE=1`, `logging.verbose: true` in `config.json`, or `scripts/run-headless.sh --verbose`.

### 5.2 Reliability

- **Sub-agent retry** — stride-analyzer / dep-scanner retry once on failure.
- **Concurrent-run lock** — `.appsec-lock` (< 1 h = blocks; > 1 h = stale, overwritten).
- **Stale-file cleanup is mode-aware**: full runs wipe `.stride-*.json`, `.dep-scan.json`, `.recon-summary.md`, `.appsec-cache/baseline.json`; incremental preserves them (carry-forward source). `.phase-epoch` and `.progress/` reset every run.
- **Runtime artifact cleanup** (skill-level + Phase 11): `scripts/runtime_cleanup.py` is the deterministic single source of truth. Called by the skill at the end of Completion Summary (`--stage post-qa`, and `--stage post-architect` when enabled). Phase 11 also invokes it with `--stage pre-qa` as a best-effort early cleanup inside the orchestrator. Whitelist groups:
  - **always** — `.dep-scan.pid`, `.dep-scan.stdout`, `.merge-candidates.json`, `.merge-decisions.json`, `.management-summary-draft.md`, `.phase-epoch`, `.session-agent-map`, `.assessment-summary-emitted`, `.prior-findings-index.json`, `.progress/`
  - **post-QA (only when `.qa-status.json=pass` and repair-plan empty)** — `.qa-status.json`, `.qa-repair-plan.json`, `.pre-render-report.json`, `.fragments/`
  - **post-architect (only when `.architect-status.json=pass` and repair-plan empty)** — `.architect-status.json`, `.architect-repair-plan.json`
  Safety gates: `KEEP_RUNTIME_FILES=true`, `threat-model.md` presence, no `AGENT_ERROR` in last 100 log lines. **Audit artifacts never touched** (`.threat-modeling-context.md`, `.recon-summary.md`, `.dep-scan.json`, `.stride-*.json`, `.threats-merged.json`, `.triage-flags.json`, `.architect-review.md`, `.appsec-cache/`, logs, `analysis-model.md`). Whitelist pinned in `tests/test_runtime_cleanup.py` — drift guard across script + docs + skill.

### 5.3 Intermediate files (persisted, in `$OUTPUT_DIR/`)

`.threat-modeling-context.md`, `.recon-summary.md`, `.dep-scan.json`, `.stride-<id>.json`, `.threats-merged.json` (canonical, annotated with `triage_flags`), `.triage-flags.json`, `.architect-review.md`, `.appsec-cache/baseline.json` (carry-forward), `.appsec-lock`, `.progress/`, `.phase-epoch`, `.agent-run.log`, `.hook-events.log`.

### 5.4 Prompt caching contract

Anthropic's Prompt Caching caches a **prefix** of the assembled prompt (system + tools + user message up to the cache breakpoint). The Claude Code harness sets cache breakpoints automatically; on the plugin side we keep the downstream prompts cache-friendly by ordering their payload stably-first, volatile-last. This matters most for sub-agent dispatches the orchestrator issues many times in a row (Phase 9 STRIDE analyzers — up to 8 dispatches per run with ≥80% identical prefix).

**Invariants for every sub-agent dispatch prompt the orchestrator builds:**

- **Group A — stable across every dispatch of the same agent type** (e.g. `REPO_ROOT`, `OUTPUT_DIR`, `COMPLIANCE_SCOPE`, `ASSET_TIER`): emit **first**. These form the cacheable prefix.
- **Group B — small per-dispatch scalars** (component id/name, complexity, turn budget, short lists like `INTERFACES`, `TRUST_BOUNDARIES`): emit next. Cache hits become partial here; acceptable tradeoff for readability.
- **Group C — large volatile JSON blobs** (`PRIOR_FINDINGS_INDEX`, `KNOWN_THREATS_INDEX`, `CROSS_REPO_CONTEXT`): emit **last**. These are per-component JSON slices that change every dispatch — emitting them first would invalidate the cache for the entire prompt.

Canonical spec: `agents/phases/phase-group-threats.md` → "Dispatch" (three-group layout). Drift-guarded by `tests/test_dispatch_prompt_cache_order.py`. Lazy-loading of phase-group files (Sprint 4 Item #9) reinforces the same principle at the orchestrator level — large phase-specific instructions only enter context when needed, so the startup prefix remains cache-stable across the 4–5 turns that build the Phase 1–2 working memory.

## 6. Configuration

### 6.1 External context *(optional)*

`config.json` → `external_context.rest_url` enables a POST to your endpoint in Phase 1. Endpoint receives `{"repo_url": "..."}`, returns `{"context": "..."}`, appended to `.threat-modeling-context.md`. Dev mock: `python3 scripts/mock-server.py [port]`.

Teams can also drop `docs/known-threats.yaml` in the analyzed repo. STRIDE analyzer verifies `open`/`mitigated` against current code; `accepted` goes to Section 11; `false-positive` is skipped. QA reviewer ensures coverage.

### 6.2 Related repositories *(optional)*

Teams that want dependency-service threats to flow into their STRIDE analysis can place `docs/related-repos.yaml` in the analyzed repository. The context-resolver reads this file in Phase 1 (Step 4j, Sub-step A) and performs a **findings deep-read** for each declared dependency.

```yaml
# docs/related-repos.yaml
related:
  - name: auth-service
    threat_model: ../auth-service/docs/security/threat-model.yaml
    interface: REST API /v1/auth
    components:           # optional — omit to include all components
      - TokenService
      - AuthController
  - name: payment-gateway
    threat_model: https://gitlab.internal/payments/-/raw/main/docs/security/threat-model.yaml
    interface: gRPC PaymentService
```

`threat_model` accepts a relative path (from `REPO_ROOT`), an absolute local path, or an HTTP/HTTPS URL. Open Critical and High findings from the declared interface are injected into the STRIDE analyzer's `CROSS_REPO_CONTEXT` for each boundary component.

**Key distinction from sibling auto-discovery:** filesystem siblings (repos detected by scanning the parent workspace directory) are never deep-read — they only produce C4 diagram annotations and trust boundary "TM missing" warnings. Only repos listed in `related-repos.yaml` have their findings loaded into the analysis.

Schema: `schemas/related-repos.schema.yaml`. Validated by the context-resolver at Phase 1 — malformed files fail loudly rather than producing silent gaps downstream.

Use `generate-threat-summary` (see §3.1) to aggregate results across related repos after individual assessments are complete.

### 6.3 Security requirements baseline

Config: `skills/check-appsec-requirements/config.json` → `requirements_source.{enabled, requirements_yaml_url}`. Persistent cache at `$CLAUDE_PLUGIN_ROOT/.cache/requirements.yaml`.

Resolution for `create-threat-model`: `--no-requirements` > `--requirements[=<url>]` > config `enabled`. With explicit `<url>`: no cache fallback. Otherwise: configured URL → cache fallback → abort.

`check-appsec-requirements` always loads regardless of `enabled`. `data/appsec-requirements-fallback.yaml` (53 requirements, 10 categories) is a starting template, **not** a runtime fallback; regenerate via `scripts/harvest-requirements.py`.

### 6.4 Hooks

`hooks/hooks.json` registers 5 event types:

| Event | Handler | Purpose |
|-------|---------|---------|
| `UserPromptSubmit` | `scripts/security_steering.py` | Inject secure-by-default guidance on code/security prompts. Tiered keyword match (strong / code / action) from `hooks/steering_keywords.json` (8 topics: general, auth, injection, crypto, xss_csrf, secrets, iac, llm). Disabled by default. |
| `PreToolUse` | `scripts/agent_logger.py` | Log `AGENT_SPAWN` before tool invocations. |
| `PostToolUse` | `scripts/agent_logger.py` | Log `AGENT_INVOKE`, `FILE_WRITE`, `FILE_EDIT`, `TOOL_ERROR`. |
| `SubagentStop` | `scripts/agent_logger.py` | Log sub-agent completion. |
| `Stop` | `scripts/agent_logger.py` | Log session termination; append `ASSESSMENT_SUMMARY` + `ASSESSMENT_PHASES` blocks. |

All logger output → `$OUTPUT_DIR/.hook-events.log` (separate from `.agent-run.log` to avoid chronological interleaving).

### 6.5 Taxonomies & rule data (`data/`)

Rule data is kept out of agent prompts so it can be versioned and tuned without model changes.

| File | Consumed by | Purpose |
|------|-------------|---------|
| `sections-contract.yaml` | `compose_threat_model.py`, contract tests | Document structure contract — see §2.4. |
| `cwe-taxonomy.yaml` | stride-analyzer, threat-merger, qa-reviewer | Curated CWE definitions. |
| `threat-category-taxonomy.yaml` | stride-analyzer, threat-merger, §8 renderer | Canonical architectural threat classes (TH-NN); CWE→TH mapping. |
| `finding-types.yaml` | §8 renderer | Fine-grained subtypes between TH-NN and F-NNN. |
| `architectural-controls.yaml` | stride-analyzer, threat-merger, Operational Strengths renderer | Canonical control vocabulary + effectiveness levels. |
| `breach-vector-taxonomy.yaml` | triage-validator, §8 | 7 attacker positions (internet-unauth, internal-auth, supply-chain, …). |
| `breach-distance-patterns.yaml` | triage-validator | Regex patterns → breach_distance (1=internet-reachable, 2=one-hop, 3+=multi-hop). |
| `compound-chain-patterns.yaml` | triage-validator | Multi-finding attack chains; classifies KEYSTONE vs. CONTRIBUTOR. |
| `severity-caps.yaml` | triage-validator Step 6 | Max effective severity per CWE (applied after compound-chain elevation). |
| `critical-criteria.yaml` | triage-validator Step 6 | Final "Critical" gatekeeper (prevents inflation). |
| `cvss-eligible-cwes.yaml` | triage-validator Step 5, `validate_intermediate.py` | Positive list where CVSS v4.0 may attach to STRIDE threats. |
| `pentest-eligible-cwes.yaml` | `render_pentest_tasks.py` | Positive list for pentest-task emission (only actively probeable weaknesses). |
| `dep-scan-heuristics.yaml` | `dep_scan.py` | Static fallback when native audit tools unavailable. |
| `config-iac-checks.yaml` | `appsec-config-scanner` (WIP) | IaC/CI security checks (Dockerfile, GH Actions, compose, k8s, Terraform). |
| `appsec-requirements-fallback.yaml` | `check-appsec-requirements` skill | 53 requirements / 10 categories; starting template, not a runtime fallback. Regenerate via `scripts/harvest-requirements.py`. |

## 7. Developer Notes

### 7.1 Editing model (no build system)

All agents and skills are plain Markdown. Phase-group files under `agents/phases/` are the **authoritative** source for phase instructions; the orchestrator prompt contains only execution flow and parameters. Edit directly.

`scripts/validate_config.py` validates `config.json` + skill configs against a schema — run in CI.

### 7.2 Schemas (`schemas/`)

JSONSchema draft 2020-12 contracts for every structured artifact. See `schemas/README.md` for the full producer/consumer matrix.

**Top-level (YAML)** — enforced by `scripts/validate_intermediate.py`, which also runs Python post-checks for rules JSONSchema can't express (sequential `T-NNN` / `TF-NNN`, t_id uniqueness, snippet redaction, min scenario length, counter consistency):

- `dep-scan.schema.yaml` — `.dep-scan.json`
- `stride.schema.yaml` — `.stride-<component-id>.json`
- `threats-merged.schema.yaml` — `.threats-merged.json`
- `triage-flags.schema.yaml` — `.triage-flags.json`
- `threat-model.output.schema.yaml` — `threat-model.yaml` (CI/CD consumer)
- `known-threats.schema.yaml` — user-supplied `docs/known-threats.yaml`
- `pentest-tasks.schema.yaml` — `pentest-tasks.yaml`

**Fragment (JSON)** — enforced by `scripts/validate_fragment.py` as a hard gate before compose; see §2.4. Any new schema must be registered in `validate_fragment.py` — `tests/test_new_schemas.py` is the drift guard.

### 7.3 Scripts inventory (`scripts/`)

**Rendering** (none of these are LLM-driven — pure Python):

- `compose_threat_model.py` — canonical Markdown renderer; Jinja2 + `sections-contract.yaml` + fragments. See §2.4.
- `render_threat_model.py` — legacy marker-substitution renderer (`{{include: path}}` / `{{include?: path}}`); fallback for non-contract renders.
- `render_threat_model_schema.py` — fragment-ID registry imported by renderer and tests (single source of truth).
- `render_pentest_tasks.py` — `.threats-merged.json` → `pentest-tasks.yaml`; filtered by `pentest-eligible-cwes.yaml`; injects `safety` block.
- `annotate_architecture.py` / `annotate_sequences.py` — idempotent post-compose diagram decorators.

**Validation & QA:**

- `validate_config.py` — `config.json` + skill configs (CI gate).
- `validate_fragment.py` — LLM-authored fragments vs. `schemas/fragments/*.json` (runtime hard gate).
- `validate_intermediate.py` — intermediate JSON artifacts + Python invariants (T-NNN, snippet redaction, …).
- `qa_checks.py` — 11 deterministic QA checks (subcommands: `links`, `xrefs`, `anchors`, `invariants`, `ms_structure`, `contract`, `repair_plan`, `all`). Auto-applies safe fixes; otherwise emits `.qa-repair-plan.json` for the re-render loop.

**Pipeline state & incremental:**

- `baseline_state.py` — owns `.appsec-cache/baseline.json` (manifest hashes, ID counters, STRIDE integrity).
- `security_relevance_filter.py` — per-file relevance classifier; drives Phase 2/9 skip/carry-forward in incremental runs.
- `merge_threats.py` — collect → dedup → candidate-gen → finalize with global T-NNN.
- `dep_scan.py` — native SCA with static fallback; see §2.2.
- `stride_progress.py` — one-line progress summary read from `.progress/<component>.json` (polled by orchestrator ~20 s).
- `triage_validate_ratings.py` — deterministic Phase 10b pre-flight: Steps 1–5 (consistency, plausibility, priority, completeness, CVSS scope). Runs as Bash call before the triage-validator agent; merges flags into `.triage-flags.json`. Agent retains only Step 6 (breach-distance, compound chains, effective severity, ranking).

**Hooks & runtime:**

- `security_steering.py` — `UserPromptSubmit` handler (§6.3).
- `agent_logger.py` — handler for the other 4 hook events (§6.3).

**Meta, status & migrations:**

- `plugin_meta.py` — single source for `plugin_version` / `analysis_version` / `compatible_analysis_versions` (read from `.claude-plugin/plugin.json`).
- `appsec_status.py` — backs the `status` skill.
- `check_permissions.py` — backs the `check-permissions` skill; diffs `data/required-permissions.yaml` against user/project/local `settings.json` and optionally merges missing entries.
- `verify_run_costs.py` — delta token/cost extraction from `SESSION_STOP` log blocks; Anthropic pricing with/without cache.
- `harvest-requirements.py` — crawler that regenerates `appsec-requirements-fallback.yaml` (config: `harvest-config.example.json`).
- `migrate_v3_to_v4.py` — v1→v2 schema migration (flat threats → `threat_categories` + `findings`; preserves T-NNN as `legacy_id`).
- `mock-server.py` — dev HTTP endpoints for testing `external_context.rest_url` (POST /) and `requirements_yaml_url` (GET /requirements.yaml).
- `run-headless.sh` — CI entry point (non-interactive invocation).

### 7.4 Tests (`tests/`)

32 test modules. Categories worth knowing when editing:

- **Drift guards** — `test_contract_integrity.py` (sections-contract self-consistency), `test_schema_integrity.py` (fragment schemas vs. registry), `test_new_schemas.py` (registration enforcement), `test_runtime_cleanup.py` (transient-file whitelist), `test_taxonomy_coverage.py` (no orphan CWEs).
- **Rendering determinism** — `test_compose_threat_model.py`, `test_render_threat_model.py`, `test_render_properties.py`, `test_annotate_architecture.py`, `test_annotate_sequences.py`, `test_reference_parity.py`.
- **Validation gates** — `test_validate_config.py`, `test_intermediate_json.py`, `test_threats_merged_schema.py`, `test_cvss_eligibility.py`, `test_pentest_tasks.py`, `test_sarif_validation.py`, `test_enforcement_mutations.py`.
- **Pipeline** — `test_incremental_mode.py`, `test_merge_threats.py`, `test_dep_scan.py`, `test_stride_progress.py`, `test_security_relevance_filter.py`, `test_reasoning_model_resolution.py`, `test_integration.py`.
- **Requirements & hooks** — `test_requirements_yaml.py`, `test_requirements_resolution.py`, `test_agent_definitions.py`, `test_agent_logger.py`, `test_security_steering.py`, `test_hooks_schema.py`.

### 7.5 ⚠ Maintaining the permission allow-list

The canonical Bash/Write/Edit/Read permission list lives in **`data/required-permissions.yaml`**. It is consumed by `scripts/check_permissions.py` (backing the `/appsec-advisor:check-permissions` skill) and should be kept in sync whenever plugin code introduces new Bash patterns or write targets.

**Update when:** new Bash block, new `VAR=$(...)` assignment, new shell builtin, changed Write/Edit target, new sub-agent.

**How:** take the first token (prefix Claude Code matches on — `FOO=` for assignments, `while` for builtins), add a new `{ entry, reason, category }` item in `data/required-permissions.yaml`. Paths outside `$OUTPUT_DIR` need a scoped `Write(...)` / `Bash(rm:...)` entry. Use the placeholders `${OUTPUT_DIR}` and `${REPO_ROOT}` for paths resolved per-repo at check-time.

**Why:** users without `Bash(*)` get a prompt per unrecognized prefix — a single missing entry can cause dozens of prompts during an 80-minute assessment and block unattended runs.

**Verify drift:** run `/appsec-advisor:check-permissions` (or `python3 scripts/check_permissions.py`) against a fresh checkout with empty settings to see which rules are still required. To discover new Bash prefixes introduced by recent edits:

```bash
grep -hP '^\w+=\$|^\w+ ' agents/**/*.md agents/*.md | \
  sed 's/[=(].*//' | sort -u
```

Drift between the YAML and the shipped `.claude/settings.json` is guarded by `tests/test_check_permissions.py`.

**Standing instruction for Claude Code:** whenever you edit any file under `agents/`, `agents/phases/`, `skills/`, or `scripts/` in this repository, scan your changes for new Bash invocations, new Write/Edit targets, or new sub-agent dispatches. If any are found, update `data/required-permissions.yaml` in the same commit — add the new `{ entry, reason, category }` item(s) before closing the task. Do not wait to be asked.

## 8. Roadmap (before 1.0)

- [ ] Token-budget tracking and cost estimation per assessment (runtime counters)
- [ ] End-to-end CI test against a reference repository
- [ ] MCP server authentication for team deployments
- [ ] Resolve `appsec-config-scanner`: wire into a Phase 2.5 dispatch in `phase-group-recon.md` and the analyst orchestrator, or remove the orphaned agent and its `data/config-iac-checks.yaml` consumer.
