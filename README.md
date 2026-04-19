# appsec-plugin

Claude Code plugin for repository-level AppSec work. Core capability is code-driven STRIDE threat modeling; a requirements audit and a security coach sit alongside it.

[![Version](https://img.shields.io/badge/version-0.10.0--beta-orange.svg)](#)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-plugin-5A67D8.svg)](https://docs.claude.com/en/docs/claude-code)
[![SARIF](https://img.shields.io/badge/SARIF-v2.1.0-green.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

---

## Contents

- [The idea](#the-idea)
- [Status](#status)
- [Install](#install)
- [Quick start](#quick-start)
- [Capabilities](#capabilities)
  - [Threat model](#threat-model)
  - [Requirements audit](#requirements-audit)
  - [Security coach](#security-coach)
- [Organisation context](#organisation-context)
  - [Threat model](#threat-model-1)
  - [Requirements audit](#requirements-audit-1)
  - [Security coach](#security-coach-1)
- [CI/CD](#cicd)
- [Example report](#example-report)
- [Related projects](#related-projects)
- [Contributing](#contributing)

Definitions for recurring terms (F-NNN, Phase 8b, recon fingerprint, SEC-\*, …) live in [`docs/glossary.md`](docs/glossary.md).

## The idea

Threat modelling done well is one of the highest-leverage security activities. Done at real-world cadence — once per release train, quarterly at best — it drifts out of sync with the code within days. This plugin treats the threat model as an artefact derived from the code on every run, not a parallel document that needs curation, and uses that derived model as the anchor for the rest of the AppSec toolbox: requirements audits against a catalog, inline security coaching while coding, SARIF imports for CI gates.

Generic best practices are not enough on their own, so each capability can pull in organisation-specific context — your own security requirements, architecture blueprints, known threats, and steering keywords — and apply it differently where it is most useful. What each capability consumes is summarised in [Organisation context](#organisation-context) below.

## Status

Current release: **0.10.0-beta**. The plugin follows [Semantic Versioning](https://semver.org). While `0.x` is in effect, minor-version bumps (`0.10 → 0.11`) may introduce breaking changes to flags, intermediate-file schemas, or YAML output formats — check the release notes before upgrading. The `-beta` suffix means the feature set is stable but the plugin has not yet been battle-tested across a wide range of repositories; expect rough edges on unusual tech stacks.

Compatibility: requires Claude Code CLI ≥ 2.0. Tested against Sonnet 4.6 and Opus 4.7. A Sonnet model upgrade may shift cost and wall-clock time but should not change F-NNN ID stability — see [`docs/glossary.md`](docs/glossary.md).

## Install

Requires Claude Code, Python 3.10+, and `git` on `PATH`.

```bash
claude --plugin-dir /path/to/appsec-plugin/plugin
```

Optional integrations (external context endpoint, requirements source, logging sink) are off by default. See [`docs/configuration.md`](docs/configuration.md).

## Quick start

From inside the repository you want to analyse:

```
/appsec-plugin:create-threat-model
```

A `standard`-depth run takes about 25 minutes on a mid-size repository. Re-runs are incremental by default and touch only components affected by code changes since the last scan. Use `--full` to force a complete re-assessment.

Common flags:

| Flag | Effect |
|------|--------|
| `--assessment-depth {quick\|standard\|thorough}` | Scope: 3 / 5 / 8 components, STRIDE turn budgets, diagram depth |
| `--full` | Force complete re-assessment (ignore incremental cache) |
| `--rebuild` | Superset of `--full` — wipes prior state and starts fresh |
| `--incremental` | Explicit delta analysis (default when a prior run exists) |
| `--resume` | Continue from last checkpoint after a failure |
| `--yaml --sarif` | Additional machine-readable exports |
| `--requirements [<url>]` | Enable Phase 8b requirements compliance check |
| `--repo <path>` | Analyse a repository other than the current directory |
| `--output <path>` | Write output somewhere other than `docs/security/` |
| `--dry-run` | Full analysis, no files written, Management Summary printed |
| `--verbose` | Stream hook events to stderr; emit Run Statistics appendix |

Full flag reference and examples: [`docs/threat-model-skill.md`](docs/threat-model-skill.md).

## Capabilities

### Threat model

Entry point: `/appsec-plugin:create-threat-model`.

Code-driven, multi-phase threat assessment. No diagrams or design docs required upfront — the plugin derives architecture (C4), attack walkthroughs, trust boundaries, assets, attack surface, STRIDE threats per component, and mitigations directly from the repository.

Details: [`docs/threat-model-skill.md`](docs/threat-model-skill.md) · Architecture internals: [`docs/architecture.md`](docs/architecture.md).

### Requirements audit

Entry point: `/appsec-plugin:check-appsec-requirements`.

Grades the repository against an `SEC-*` requirements catalog. Each requirement returns **PASS / PARTIAL / FAIL** with code-level evidence and a before/after fix snippet. Faster than a full threat model — fits PR gates and compliance dashboards.

Shares the requirements source with Phase 8b of the threat model. Three paths to the catalog: adapt the bundled reference (53 baseline requirements), harvest from internal wiki pages, or pass a URL at invocation time.

Details: [`docs/security-requirements-audit-skill.md`](docs/security-requirements-audit-skill.md) · Catalog setup: [`docs/harvester.md`](docs/harvester.md).

### Security coach

Inline guidance during coding sessions. A `UserPromptSubmit` hook scans prompts for security-relevant keywords (auth, crypto, injection, IaC, secrets) and injects context-aware guidance. When a requirements catalog is loaded, the coach references concrete `SEC-*` controls.

Off by default. Enable via `APPSEC_COACH=1` or in `plugin/config.json`.

Details: [`docs/security-coach-skill.md`](docs/security-coach-skill.md).

## Organisation context

Four optional sources carry organisational context into the plugin. Each capability consumes a different subset — the table below shows which source is wired into which capability. All sources are optional; the plugin works without them but falls back to generic OWASP/CWE references.

| Source | Threat model | Requirements audit | Security coach |
|--------|:---:|:---:|:---:|
| Security requirements catalog (`SEC-*` YAML) | ● (Phase 8b) | ● (primary input) | ● (inline `SEC-*` refs) |
| External context REST endpoint | ● (Phase 1) | — | — |
| Known threats (`docs/known-threats.yaml`) | ● (Phase 1) | — | — |
| Steering keywords (`plugin/hooks/steering_keywords.json`) | — | — | ● (trigger / topic routing) |

### Threat model

Pulls in the richest context. Phase 1 reads the external REST endpoint (team ownership, compliance scope, prior incidents, architecture notes) and `docs/known-threats.yaml` in the analysed repo (accepted risks, prior pentest findings). When `--requirements` is set, Phase 8b additionally grades every `SEC-*` requirement against the codebase and annotates the threat register with traceability. Details: [`docs/threat-model-skill.md`](docs/threat-model-skill.md). Endpoint contract and YAML schemas: [`docs/configuration.md`](docs/configuration.md).

### Requirements audit

Scope-limited by design. The only organisational input is the `SEC-*` requirements catalog — loaded from the configured URL, a runtime-passed `--requirements <url>`, or the plugin cache. Catalog formats and three paths to setup (adapt baseline / harvest from wiki / ad-hoc URL): [`docs/security-requirements-audit-skill.md`](docs/security-requirements-audit-skill.md). Harvester tool and CI scheduling: [`docs/harvester.md`](docs/harvester.md).

### Security coach

Runtime hook, so its context is narrower and read on every prompt rather than once per run. Steering keywords drive trigger detection and per-topic guidance; the requirements catalog, when loaded, lets the coach reference concrete `SEC-*` IDs instead of generic advice. Activation, trigger tiers, topic tuning: [`docs/security-coach-skill.md`](docs/security-coach-skill.md).

## CI/CD

`scripts/run-headless.sh` wraps the skill for non-interactive execution. A fast-path pre-check short-circuits in under a second when nothing has changed since the last scan.

```bash
./scripts/run-headless.sh --repo . --output docs/security --incremental --no-qa --max-duration 1800
```

PR-gate mode (`--pr-mode --fail-on high`), GitHub Actions example, artifact caching, exit codes: [`docs/headless-mode.md`](docs/headless-mode.md).

## Example report

Full threat model for OWASP Juice Shop (thorough depth, 8 components, 47 threats): [`examples/juice-shop/threat-model-juiceshop-thorough.md`](examples/juice-shop/threat-model-juiceshop-thorough.md).

## Related projects

- **[davidmatousek/tachi](https://github.com/davidmatousek/tachi)** — Claude Code plugin focused on STRIDE methodology with narrative reporting and PDF output. Fits when the deliverable is a polished stakeholder document.
- **[mrwadams/stride-gpt](https://github.com/mrwadams/stride-gpt)** — Streamlit app that derives STRIDE threats from a prose system description. Useful early in design, before code exists.

This plugin differs by driving analysis from the actual repository, linking every threat to file/line evidence, and integrating organisation-specific requirements and blueprints.

## Contributing

Before submitting a change, run the test suite and validate the plugin config:

```bash
pytest tests/
python3 plugin/scripts/validate_config.py plugin/
```

Issue and PR templates: [`.github/`](.github/). Security vulnerabilities: open a [GitHub Security Advisory](../../security/advisories/new), not a public issue. See [`SECURITY.md`](SECURITY.md).
