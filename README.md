# appsec-advisor

A Claude Code plugin for AppSec work on code repositories. The headline capability is automated, code-driven STRIDE threat modelling; alongside it the plugin ships a security requirements auditor and an inline security coach.

[![Version](https://img.shields.io/badge/version-0.10.0--beta-orange.svg)](#)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-plugin-5A67D8.svg)](https://docs.claude.com/en/docs/claude-code)
[![SARIF](https://img.shields.io/badge/SARIF-v2.1.0-green.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

---

## Contents

- [Why](#why)
- [Install](#install)
- [Quick start](#quick-start)
- [Capabilities](#capabilities)
- [CI/CD](#cicd)
- [Example report](#example-report)
- [Configuration](#configuration)
- [Related projects](#related-projects)
- [Contributing](#contributing)

## Why

Threat modelling done well is one of the highest-leverage security activities. Done at real-world cadence — once per release train, quarterly at best — it drifts out of sync with the code within days. This plugin treats the threat model as an artefact derived from the code on every run, not a parallel document that needs curation, and uses that derived model as the anchor for the rest of the AppSec toolbox: requirements audits against a catalog, inline coaching while coding, SARIF imports for CI gates.

Generic best practices are not enough on their own, so each capability can pull in organisation-specific context — your own security requirements, architecture blueprints, known threats, steering keywords — and apply it where it matters.

## Install

Requires Claude Code, Python 3.10+, and `git` on `PATH`.

```bash
claude --plugin-dir /path/to/appsec-advisor
```

Optional integrations (external context endpoint, requirements source, logging sink) are off by default. See [Configuration](#configuration).

## Quick start

From inside the repository you want to analyse:

```
/appsec-advisor:create-threat-model
```

A `standard`-depth run takes about 25 minutes on a mid-size repository. Re-runs are incremental by default and only touch components affected by code changes since the last scan. Use `--full` to force a complete re-assessment.

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

### Architectural Threat Modeller

Entry point: `/appsec-advisor:create-threat-model`.

- **Code-driven, multi-agent.** Automated threat modelling directly from code repositories.
- **STRIDE-based analysis.** Applies the STRIDE methodology and incorporates known or anticipated threats.
- **Architecture-focused insights.** Security architecture assessments with actionable mitigation guidance.
- **Incremental scanning.** Analyses only security-relevant changes and updates the threat model incrementally, fits into CI pipelines and PR checks.
- **Composable outputs.** Results can be reused in downstream or multi-repository assessments.
- **Extensible context and requirements.** Ingests external context (e.g. via REST APIs) and supports custom AppSec requirements.

Details: [`docs/threat-model-skill.md`](docs/threat-model-skill.md) · Architecture internals: [`docs/architecture.md`](docs/architecture.md).

### Security Requirements Auditor

Entry point: `/appsec-advisor:check-appsec-requirements`.

Grades the repository against an `SEC-*` requirements catalog. Each requirement returns **PASS / PARTIAL / FAIL** with code-level evidence and a before/after fix snippet. Faster than a full threat model — fits PR gates and compliance dashboards.

Shares the requirements source with Phase 8b of the threat model. Three paths to the catalog: adapt the bundled reference (53 baseline requirements), harvest from internal wiki pages, or pass a URL at invocation time.

Details: [`docs/security-requirements-audit-skill.md`](docs/security-requirements-audit-skill.md) · Catalog setup: [`docs/harvester.md`](docs/harvester.md).

### Security Coach

Inline guidance during coding sessions. A `UserPromptSubmit` hook scans prompts for security-relevant keywords (auth, crypto, injection, IaC, secrets) and injects context-aware guidance. When a requirements catalog is loaded, the coach references concrete `SEC-*` controls.

Off by default. Enable via `APPSEC_COACH=1` or in `config.json`.

Details: [`docs/security-coach-skill.md`](docs/security-coach-skill.md).

## CI/CD

`scripts/run-headless.sh` wraps the skill for non-interactive execution. A fast-path pre-check short-circuits in under a second when nothing has changed since the last scan.

```bash
./scripts/run-headless.sh --repo . --output docs/security \
                          --incremental --no-qa --max-duration 1800
```

PR-gate mode (`--pr-mode --fail-on high`), GitHub Actions example, artifact caching, exit codes: [`docs/headless-mode.md`](docs/headless-mode.md).

## Example report

Full threat model for OWASP Juice Shop (thorough depth, 8 components, 47 threats): [`examples/juice-shop/threat-model-juiceshop-thorough.md`](examples/juice-shop/threat-model-juiceshop-thorough.md).

## Configuration

Cross-cutting configuration — external context endpoint, known-threats input, requirements source, coach activation — is documented in [`docs/configuration.md`](docs/configuration.md). Plugin-level defaults live in `config.json`; skill-specific settings sit next to each skill under `skills/<skill>/config.json`.

## Related projects

- **[davidmatousek/tachi](https://github.com/davidmatousek/tachi)** — Claude Code plugin focused on STRIDE methodology with narrative reporting and PDF output. Fits when the deliverable is a polished stakeholder document.
- **[mrwadams/stride-gpt](https://github.com/mrwadams/stride-gpt)** — Streamlit app that derives STRIDE threats from a prose system description. Useful early in design, before code exists.

This plugin differs by driving analysis from the actual repository, linking every threat to file/line evidence, and integrating organisation-specific requirements and blueprints.

## Contributing

Before submitting a change, run the test suite and validate the plugin config:

```bash
pytest tests/
python3 scripts/validate_config.py .
```

Issue and PR templates: [`.github/`](.github/). Development conventions and agent-definition format: [`CONTRIBUTING.md`](CONTRIBUTING.md). Security vulnerabilities: open a [GitHub Security Advisory](../../security/advisories/new), not a public issue. See [`SECURITY.md`](SECURITY.md).
