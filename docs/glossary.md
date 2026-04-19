# Glossary

Definitions for terms that recur across plugin documentation. When you hit an unfamiliar identifier in a skill doc or architecture reference, the definition lives here.

## Contents

- [Finding and threat identifiers](#finding-and-threat-identifiers)
- [Stage](#stage)
- [Phase](#phase)
- [Phase 8b](#phase-8b)
- [Component](#component)
- [Recon fingerprint](#recon-fingerprint)
- [Baseline](#baseline)
- [Assessment depth](#assessment-depth)
- [SEC-\* requirement IDs](#sec--requirement-ids)
- [Reasoning model](#reasoning-model)

## Finding and threat identifiers

The plugin uses three related identifier formats. Knowing which is which matters when you cross-reference between the Markdown report, the YAML export, and external systems (Jira, Linear, SARIF).

| ID format | Meaning | Where it appears |
|-----------|---------|-------------------|
| **F-NNN** | **Finding** — a concrete, exploitable issue tied to a specific file and line. Assigned to code-level issues. | Primary identifier in `threat-model.yaml`, the Markdown report's Threat Register, and SARIF `result.ruleId`. Stable across incremental runs. |
| **AF-NNN** | **Architectural Finding** — a systemic weakness spanning multiple files or components. | Section §8.D of the Markdown report. Cannot be patched in a single place; requires architectural rework. |
| **T-NNN** | **Threat** *(legacy)* — identifier used before the plugin split into Finding (F) and Architectural Finding (AF). | Retained for v1 baselines and for external systems that referenced T-IDs before the migration. Every F-NNN carries a `legacy_id: T-NNN` mapping in YAML. |

When reading a document, `[F-NNN](#f-NNN)` is a clickable anchor to the full finding detail. Bare `F-NNN` or `T-NNN` mentions are a format defect auto-repaired by the QA reviewer.

ID stability rule: an F-NNN stays pinned to the same underlying defect across incremental runs. New findings get the next unused slot; retired findings leave holes. External tracker tickets referencing F-NNN do not break when the codebase changes.

## Stage

A coarse-grained phase of the pipeline with its own independent turn budget. The plugin has three stages:

1. **Stage 1 — Analysis** (`appsec-threat-analyst` orchestrator) — runs Phases 1–11.
2. **Stage 2 — QA** (`appsec-qa-reviewer`) — runs after Stage 1 completes.
3. **Stage 3 — Architect review** (`appsec-architect-reviewer`, optional) — advisory pass at `--assessment-depth thorough`.

The separation matters because Stage 2 and Stage 3 are dispatched by the skill, not by the orchestrator. A Stage 1 that consumes all its turns cannot starve Stage 2 of its own budget.

## Phase

A fine-grained step inside a Stage. Stage 1 contains Phases 1–11 (plus one inline sub-phase, [Phase 8b](#phase-8b)). Phases are logged as `PHASE_START` / `PHASE_END` in `.agent-run.log` and visible in the console progress banner (`[Phase 2/11] ▶ Reconnaissance…`).

The full phase list and per-phase responsibilities live in [`architecture.md`](architecture.md#phases-111).

## Phase 8b

A conditional sub-phase inserted between Phase 8 (Security Architecture Catalog) and Phase 9 (STRIDE Threat Enumeration). Phase 8b grades every `SEC-*` requirement in the loaded catalog against the codebase and writes the result into `§7b Requirements Compliance` of the Markdown report. It runs only when `--requirements` is set (or when the config enables it by default).

Why the `b` suffix: the phase was added after the original 1–11 numbering was established. Renumbering Phases 9–11 would have broken external audit trails referencing those numbers. `8b` is a stable insertion point that does not shift the subsequent phase IDs.

## Component

A bounded unit of the system that the STRIDE analyser reasons about independently. Component extraction happens in Phase 2 (Reconnaissance) based on repository structure, framework conventions, and tech-stack-specific heuristics. Each component gets its own STRIDE analyser instance in Phase 9, dispatched in parallel.

Typical component examples from the Juice Shop reference: `REST API`, `Auth Service`, `Admin Panel`, `B2B Orders`, `File Upload`, `Chatbot`, `Product Reviews`, `Frontend SPA`.

The number of components the orchestrator analyses is capped by `--assessment-depth`: 3 at `quick`, 5 at `standard`, 8 at `thorough`. When the codebase has more components than the cap, the orchestrator prioritises by attack-surface-weighted risk.

Component IDs follow the format `C-NN`. They appear in the report as `[C-NN](#c-NN) — <Component name>` — e.g. `[C-01](#c-01) — REST API`.

## Recon fingerprint

A cryptographic hash covering the files the recon scanner relies on: source files per component, package manifests, configuration files, framework descriptors, and the plugin version. Stored in `.appsec-cache/baseline.json` at the end of every successful run.

On an incremental re-run, the orchestrator computes the current fingerprint and compares it against the baseline. Components whose fingerprint has not changed skip Phase 9 entirely and reuse their previous `.stride-<component-id>.json`. This is the mechanism that makes daily incremental runs in CI cost near-zero when no code has changed.

The fingerprint also invalidates on plugin upgrade: if the recorded `plugin_version` in the baseline differs from the currently-loaded plugin, every component is re-analysed, because new phase logic should not be patched on top of old analysis.

## Baseline

The frozen state of a prior assessment run. A baseline consists of:

- `docs/security/threat-model.yaml` — the canonical machine-readable report.
- `docs/security/.appsec-cache/baseline.json` — the recon fingerprint and incremental-mode carry-forward state.
- Persistent per-component files: `.stride-<component-id>.json`, `.recon-summary.md`, `.threat-modeling-context.md`.

Incremental mode requires a baseline; first runs always execute full. `--rebuild` wipes the baseline before starting; `--full` preserves baseline history but forces a complete re-analysis.

## Assessment depth

The single flag `--assessment-depth {quick|standard|thorough}` controls seven internal knobs simultaneously:

| Knob | `quick` | `standard` | `thorough` |
|------|---------|------------|------------|
| Max STRIDE components | 3 | 5 | 8 |
| STRIDE turn budget (simple / moderate / complex) | 10 / 15 / 20 | 15 / 22 / 28 | 20 / 31 / 35 |
| Diagram depth | Minimal (Context only) | Standard (Context + Container) | Extended (Context + Container + Components) |
| QA scope | Core checks only | Full checks | Extended checks incl. advisory flags |
| Phase 9 coverage checks | Skipped | Enabled | Enabled |
| Phase 8 control-rating strategy | Recon baseline only | Recon + targeted greps | Recon + targeted greps |
| Stage 3 (architect review) | Off by default | Off by default | **On** by default |

Defaults are tuned so that `quick` takes ~15 minutes and costs under $2, `standard` takes ~25 minutes, and `thorough` takes ~45 minutes. See [`threat-model-skill.md`](threat-model-skill.md#cost-and-duration) for cost ranges.

## SEC-\* requirement IDs

Identifier format used in example requirements catalogs (e.g. `SEC-AUTH-01`, `SEC-TLS`, `SEC-IV`). The `SEC-` prefix is **a convention from the bundled reference catalog, not a hard requirement**. The plugin imposes no naming rule — your catalog YAML can use `AUTH-1`, `POLICY-007`, `R-INJ-3`, or any other scheme. Whichever prefix your YAML defines is what appears in the Threat Register, Mitigation Register, and Security Coach injections.

Wherever this documentation writes `SEC-*`, read it as "the requirement-ID shape your catalog defines".

## Reasoning model

The subset of agents whose output quality is most sensitive to model capability: the STRIDE analyser, the triage validator, and the threat merger. These agents accept a coordinated override via `--reasoning-model {sonnet|opus-cheap|opus}`.

| Value | What runs on Opus |
|-------|-------------------|
| `sonnet` | None — everything stays on Sonnet |
| `opus-cheap` *(default at `thorough`)* | Triage validator + threat merger (single-shot, ~$0.07 extra) |
| `opus` | All STRIDE analysers (~5× baseline cost) |

The context resolver, recon scanner, dep-scanner, and QA reviewer remain on Sonnet regardless — their tasks are mechanical (file I/O, structural checking) and do not benefit from Opus.
