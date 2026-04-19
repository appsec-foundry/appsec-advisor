# Architecture

> Back to [README](../README.md)

This document describes how the plugin works internally — the agent pipeline, the orchestrator's phase sequence, the intermediate files agents exchange, and the reliability features that keep long runs recoverable. Read it if you want to understand why a phase ran or failed the way it did, extend the pipeline, or integrate the plugin into a larger AppSec workflow.

The rest of the docs cover complementary concerns: [configuration.md](configuration.md) for external integrations, [flags-reference.md](flags-reference.md) for every runtime flag, [headless-mode.md](headless-mode.md) for CI/CD execution.

## Stages

The plugin runs in three stages. Each stage has its **own independent turn budget**, so exhausting Stage 1 turns cannot starve the QA reviewer (a past failure mode that moved QA out of the orchestrator).

| Stage | Agent | Purpose |
|-------|-------|---------|
| **Stage 1 — Analysis** | `appsec-threat-analyst` (orchestrator) | Runs Phases 1–11 and dispatches sub-agents in parallel where safe. Produces `threat-model.md` and optional YAML/SARIF. |
| **Stage 2 — QA** | `appsec-qa-reviewer` | Runs after Stage 1 completes. 10-check verification pass (diagrams, links, references, coverage) with in-place fixes. |
| **Stage 3 — Architect review** *(conditional, `--architect-review`)* | `appsec-architect-reviewer` | Advisory architect-level pass over the finished report. Writes `.architect-review.md` without modifying the threat model. |

## Agent Pipeline

The plugin uses a 9-agent pipeline. Only `appsec-threat-analyst` is user-facing; the rest are dispatched internally. SCA dependency scanning is performed by a deterministic Python helper (`scripts/dep_scan.py`), not an agent.

```mermaid
flowchart TD
    U(["User"])
    U -->|"/create-threat-model"| SKILL["create-threat-model<br/>skill · multi-stage"]
    U -->|"/check-appsec-requirements"| SKL["check-appsec-requirements<br/>skill"]

    SKILL -->|"Stage 1"| TA["appsec-threat-analyst<br/>Sonnet · 75 turns<br/>Orchestrator · Phases 1–11"]
    SKILL -->|"Stage 2"| QA["appsec-qa-reviewer<br/>Sonnet · 80 turns"]
    SKILL -->|"Stage 3 · --architect-review"| AR["appsec-architect-reviewer<br/>Sonnet · 40 turns"]

    TA -->|"Phase 1"| CR["appsec-context-resolver<br/>Sonnet · 25 turns"]
    TA -->|"Phase 2"| RS["appsec-recon-scanner<br/>Sonnet · 25 turns"]
    TA -->|"Phase 2 · bg · --with-sca only"| DS["scripts/dep_scan.py<br/>Python · SCA"]
    TA -->|"Phase 2.5"| CFG["appsec-config-scanner<br/>Sonnet · 15 turns"]
    TA -->|"Phase 9 · bg · parallel"| SA["appsec-stride-analyzer<br/>Sonnet · up to 31 turns<br/>× one per component"]
    TA -->|"Phase 9 · fan-in"| TM["appsec-threat-merger<br/>Sonnet · 12 turns"]
    TA -->|"Phase 10b · blocking"| TV["appsec-triage-validator<br/>Sonnet · 20 turns"]

    CR -. "shares .requirements.yaml" .-> SKL
```

### Agents

All agents run on Sonnet by default. `--stride-model opus` overrides the model used by `appsec-stride-analyzer` only (roughly 5× API cost; other agents continue on Sonnet).

| Agent | Turns | Role |
|-------|-------|------|
| `appsec-threat-analyst` | 75 | **Stage 1 — orchestrator.** Drives Phases 1–11, dispatches sub-agents, assembles output |
| `appsec-context-resolver` | 25 | Phase 1 — resolves external context, repo files, and known threats into `.threat-modeling-context.md` |
| `appsec-recon-scanner` | 25 | Phase 2 — scans repo structure, tech stack, 26 security categories (incl. supply chain and hardcoded secrets) → `.recon-summary.md` |
| `appsec-config-scanner` | 15 | Phase 2.5 — scans Dockerfile, GitHub Actions, docker-compose, Dependabot/Renovate, and npm config against `plugin/data/config-iac-checks.yaml` |
| `appsec-stride-analyzer` | up to 31 | Phase 9 (bg, parallel) — one instance per component, dynamic turn budget based on complexity, writes `.stride-<id>.json` |
| `appsec-threat-merger` | 12 | Phase 9 fan-in — reviews candidate duplicate/systemic threat groups produced by `merge_threats.py` and emits merge/keep/consolidate decisions |
| `appsec-triage-validator` | 20 | Phase 10b (blocking) — validates cross-component rating consistency, severity plausibility, P1/P2 priority alignment, and rating completeness. Writes `.triage-flags.json` and annotates `.threats-merged.json` |
| `appsec-qa-reviewer` | 80 | **Stage 2.** 10 checks (including 11-point Mermaid validation) on the finished threat model, fixes in-place |
| `appsec-architect-reviewer` | 40 | **Stage 3** *(only with `--architect-review`)* — advisory architect-level review, writes `.architect-review.md`, does not modify the threat model |

Plus the deterministic Python helper `scripts/dep_scan.py` for Phase 2 SCA (only with `--with-sca`).

The QA reviewer runs at the skill level (Stage 2) with its own turn budget, not inside the orchestrator. This guarantees it always executes even when the orchestrator uses all its turns during Phases 1–11 — a past failure mode that motivated the split.

### Orchestrator Phases

| Phase | Description |
|-------|-------------|
| 1. Context Resolution | `appsec-context-resolver` fetches pre-existing AppSec knowledge (external context, blueprints, requirements, known threats) |
| 2. Reconnaissance | `appsec-recon-scanner` maps tech stack, structure, and 26 security categories (incl. supply chain and hardcoded secrets); optionally launches `scripts/dep_scan.py` in background (only with `--with-sca`) |
| 2.5. Config & IaC Scan | `appsec-config-scanner` scans Dockerfile, GitHub Actions, docker-compose, Dependabot/Renovate, and npm config against `plugin/data/config-iac-checks.yaml` |
| 3. Architecture Modeling | C4 diagrams (context / container / component) + technology architecture diagram |
| 4. Attack Walkthroughs | Step-by-step exploitation paths for the highest-risk scenarios (renders Section 4 of the report) |
| 5. Asset Identification | Catalogs data, code/IP, infrastructure, and availability assets |
| 6. Attack Surface Mapping | Enumerates API endpoints, auth mechanisms, file uploads, inter-service calls |
| 7. Trust Boundary Analysis | Identifies privilege and network boundary crossings |
| 8. Security Controls | Catalogs existing controls by domain with effectiveness rating |
| 8b. Requirements Compliance | *(only with `--requirements`)* Verifies each requirement against codebase; FAIL requirements become threat candidates for Phase 9 |
| 9. Threat Enumeration | Dispatches `appsec-stride-analyzer` per component (requires Phases 6–8 outputs). `merge_threats.py` produces candidate duplicate groups; `appsec-threat-merger` decides merge/keep. Final list + Phase 8b candidates get global T-xxx IDs and risk ratings |
| 10. Scan Synthesis | Incorporates hardcoded secrets (from recon) and SCA findings (from `dep_scan.py`, if `--with-sca`) |
| 10b. Triage Validation | `appsec-triage-validator` validates cross-component rating consistency, severity plausibility, priority alignment, and rating completeness; writes `.triage-flags.json` and annotates `.threats-merged.json` |
| 11. Finalization | Writes `threat-model.md` and optional YAML/SARIF exports; renders triage flags in Threat Register and Management Summary; releases lock, records duration, prints completion summary |
| *(Stage 2)* | `appsec-qa-reviewer` verifies and fixes links, references, consistency, diagrams |
| *(Stage 3, optional)* | `appsec-architect-reviewer` writes an advisory `.architect-review.md` |

## Intermediate Files

Sub-agents communicate via files written to the **output directory** (`docs/security/` by default, or the path from `--output`). These files are gitignored by default when the output is inside the repository.

| File | Written by | Read by |
|------|-----------|---------|
| `.threat-modeling-context.md` | `appsec-context-resolver` | orchestrator, `appsec-stride-analyzer` |
| `.recon-summary.md` | `appsec-recon-scanner` | orchestrator (Phases 2–10) |
| `.requirements.yaml` | `appsec-context-resolver` | `appsec-stride-analyzer`, `appsec-qa-reviewer`, `check-appsec-requirements` skill |
| `.dep-scan.json` | `scripts/dep_scan.py` (Phase 2 bg, `--with-sca` only) | orchestrator (Phase 10) |
| `.config-scan.json` | `appsec-config-scanner` | orchestrator (Phase 10) |
| `.stride-<id>.json` | `appsec-stride-analyzer` | orchestrator (Phase 9), `appsec-threat-merger` |
| `.architect-review.md` | `appsec-architect-reviewer` *(Stage 3)* | advisory — not consumed by the pipeline |
| `.threats-merged.json` | orchestrator (Phase 9) | `appsec-triage-validator` (Phase 10b), orchestrator (Phase 11) |
| `.triage-flags.json` | `appsec-triage-validator` | orchestrator (Phase 11 — renders flags in report) |
| `.appsec-lock` | orchestrator | orchestrator (concurrent-run guard; deleted after assessment) |
| `.appsec-checkpoint` | orchestrator | skill (phase progress; used by `--resume`; deleted after successful completion) |

All paths are relative to the output directory. When using `--output /appsec-reports/team-api`, intermediate files appear as `/appsec-reports/team-api/.recon-summary.md`, etc.

The **persistent requirements cache** lives at `$CLAUDE_PLUGIN_ROOT/.cache/requirements.yaml` (outside the analyzed repo). It is updated on every successful remote fetch and used as a fallback when the remote URL is unreachable. The per-assessment copy at `.requirements.yaml` is written to the output directory during each assessment for use by the STRIDE analyzer and QA reviewer.

## Reliability Features

### Sub-agent retry logic

If a sub-agent (primarily `appsec-stride-analyzer`) fails — missing output, schema validation error, or error stub — the orchestrator retries it **once** synchronously before skipping. This handles transient failures (token-limit timeouts, temporary filesystem issues) without losing threat coverage for an entire component. If the retry also fails, the affected component is marked as a partial result in the Threat Register so reviewers can see which area needs manual analysis. `scripts/dep_scan.py` has its own internal retry for transient network/tool errors and caches results on success.

### Concurrent run locking

The orchestrator acquires a lock file (`.appsec-lock` in the output directory) at startup. If another assessment is already running (lock file exists and is less than 1 hour old), the new run stops with a clear error message. Stale locks (older than 1 hour) are automatically overwritten. The lock is always released at the start of Phase 11 or on any early exit.

### Stale file cleanup

Intermediate files from previous runs (`.stride-*.json`, `.dep-scan.json`) are automatically deleted before each new assessment starts. This prevents stale data from interfering with the current run.

### Schema validation

All intermediate JSON files (`.dep-scan.json`, `.stride-*.json`) are validated against strict schemas by `validate_intermediate.py` before the orchestrator reads them. Invalid files trigger the retry logic above rather than causing silent data corruption.

### Log rotation

Hook event logs (`.hook-events.log`) and agent run logs (`.agent-run.log`) are automatically rotated when they exceed 5 MB (configurable via `logging.max_log_bytes` in `plugin/config.json`). Up to 2 rotated copies are kept (`.log.1`, `.log.2`). This prevents unbounded log growth across multiple assessment runs.

### Error recovery & checkpoints

The orchestrator writes a checkpoint file (`.appsec-checkpoint`) at the start and end of each phase, recording the phase number, status, and timestamp. If an assessment is interrupted (token limit, network issue, manual cancellation), the checkpoint preserves which phase last completed.

Run `/appsec-plugin:create-threat-model --resume` to inspect the checkpoint and continue from the last completed phase, reusing existing intermediate files instead of starting from scratch.

### Dep-scanner caching

The dep-scanner caches its results in `.dep-scan.json` along with MD5 hashes of all scanned manifest files. On subsequent runs within 1 hour, if no manifest file has changed, the scanner reuses the cached results and skips expensive audit tool invocations (`npm audit`, `pip-audit`, etc.).

### Config schema validation

`plugin/scripts/validate_config.py` validates both `plugin/config.json` and `skills/check-appsec-requirements/config.json` against defined schemas. Run it before deployment or in CI to catch misconfigurations:

```bash
python3 plugin/scripts/validate_config.py plugin/
```

## Plugin Structure

```
appsec-plugin/
├── plugin/                                     # Plugin root — pass to --plugin-dir
│   ├── .claude-plugin/
│   │   └── plugin.json                         # Plugin manifest (v0.10.0-beta)
│   ├── .claude/
│   │   └── settings.json                       # Allowlisted Bash commands (restricted permissions)
│   ├── config.json                             # external_context, pricing, logging config
│   ├── .cache/                                 # Persistent cache (gitignored, auto-created)
│   │   └── requirements.yaml                   # Cached requirements from last successful fetch
│   ├── agents/
│   │   ├── appsec-threat-analyst.md            # Orchestrator (Sonnet, 75 turns)
│   │   ├── appsec-context-resolver.md          # Context resolver (Sonnet, 25 turns)
│   │   ├── appsec-recon-scanner.md             # Repo recon + supply chain + secret detection (Sonnet, 25 turns)
│   │   ├── appsec-dep-scanner.md               # SCA dependency scanner (Sonnet, 15 turns, --with-sca only)
│   │   ├── appsec-stride-analyzer.md           # Per-component STRIDE analysis (Sonnet, 15–31 turns)
│   │   ├── appsec-triage-validator.md          # Rating consistency validation (Sonnet, 20 turns)
│   │   ├── appsec-qa-reviewer.md               # Output verification (Sonnet, 40 turns)
│   │   ├── shared/                              # Reusable content loaded conditionally
│   │   │   ├── logging-standard.md             # Logging format shared by all sub-agents
│   │   │   ├── owasp-llm-top10.md              # OWASP LLM Top 10 (loaded only when LLM detected)
│   │   │   └── validation-routine.md           # JSON validation shared by dep-scanner & STRIDE
│   │   └── phases/                             # Phase-group reference files (read at runtime)
│   │       ├── phase-group-recon.md            # Phases 0–1: Context & Reconnaissance
│   │       ├── phase-group-architecture.md     # Phases 3–8: Architecture, Assets, Controls
│   │       ├── phase-group-threats.md          # Phases 9–10b: STRIDE, Dep Scan Synthesis & Triage Validation
│   │       └── phase-group-finalization.md     # Phase 11: Output & Finalization
│   ├── data/
│   │   └── appsec-requirements-fallback.yaml   # Reference baseline (53 requirements, 10 categories)
│   ├── hooks/
│   │   ├── hooks.json                          # UserPromptSubmit, PreToolUse, PostToolUse, Stop, SubagentStop
│   │   └── steering_keywords.json              # Configurable keyword lists for security steering
│   ├── scripts/
│   │   ├── security_steering.py                # Tiered keyword steering (loads from steering_keywords.json)
│   │   ├── agent_logger.py                     # Audit log writer with log rotation and configurable pricing
│   │   ├── validate_intermediate.py            # JSON schema validator for .dep-scan / .stride files
│   │   ├── validate_config.py                  # Config schema validator for config.json files
│   │   └── .gitignore-template                 # Template for analyzed repos (covers all intermediate files)
│   └── skills/
│       ├── create-threat-model/
│       │   └── SKILL.md                        # /appsec-plugin:create-threat-model (all flags incl. --assessment-depth --stride-model)
│       └── check-appsec-requirements/
│           ├── SKILL.md                        # /appsec-plugin:check-appsec-requirements
│           └── config.json                     # requirements_source config (enabled, url)
├── docs/
│   ├── architecture.md                         # Agent pipeline, phases, reliability features
│   ├── configuration.md                        # External context, known threats, requirements, steering
│   ├── headless-mode.md                        # Non-interactive / CI/CD execution
│   ├── flags-reference.md                      # Complete flag reference (interactive + headless)
│   ├── harvester.md                            # Harvester config, scheduling, indexing modes
│   └── comparison-sonnet-opus.md               # Model performance comparison
├── examples/                                   # Example outputs
│   ├── juice-shop/                             # OWASP Juice Shop threat model examples
│   └── appsec-requirements-example.yaml        # Example requirements YAML (53 requirements, 10 categories)
├── scripts/                                    # Development & automation tools
│   ├── run-headless.sh                         # Headless wrapper for non-interactive / CI/CD usage
│   ├── mock-context-server.py                  # Mock for the external context REST endpoint
│   ├── harvest-requirements.py                 # Crawls requirements pages -> YAML
│   ├── harvest-config.json                     # Crawler source URLs and indexing config
│   └── requirements.txt                        # Python deps for harvester
├── tests/                                      # Test suite (440 tests)
│   ├── test_agent_definitions.py               # Agent frontmatter, model, maxTurns validation
│   ├── test_agent_logger.py                    # Hook logger event handling, secret masking, cost estimation
│   ├── test_intermediate_json.py               # Schema validation for .dep-scan / .stride JSON
│   ├── test_security_steering.py               # Tiered keyword matching, false positive guards
│   ├── test_requirements_yaml.py               # Requirements YAML schema and cross-references
│   ├── test_integration.py                     # Plugin manifest, hooks, config, phase-groups, skill integrity
│   ├── test_sarif_validation.py                # SARIF v2.1.0 output schema validation
│   └── fixtures/                               # Test data (valid/error JSON stubs)
├── SECURITY.md
└── README.md
```
