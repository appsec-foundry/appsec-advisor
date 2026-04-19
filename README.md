# appsec-plugin

A Claude Code plugin that bundles per-repository AppSec work — **architectural STRIDE threat modeling at its core**, alongside a focused requirements audit and a background security coach.

[![Version](https://img.shields.io/badge/version-0.10.0--beta-orange.svg)](#)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-plugin-5A67D8.svg)](https://docs.claude.com/en/docs/claude-code)
[![SARIF](https://img.shields.io/badge/SARIF-v2.1.0-green.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

---

## The idea

The plugin is not a single tool. It is a capsule of three AppSec disciplines that typically apply at the repository level: *produce a threat model*, *audit the codebase against a security-requirements baseline*, *steer the surrounding coding session toward secure defaults*. Claude Code provides the runtime — slash commands, hooks, agents — and the plugin fills it with these capabilities.

Instead of maintaining three separate tools with three separate data flows and three separate result silos, the plugin consolidates them into one environment: same output convention (`docs/security/`), same organisational context (requirements YAML, architecture-blueprint endpoint, known-threats file), same artifact language (Markdown, YAML, SARIF). A requirements URL configured once governs all three. A blueprint source registered once applies to all three.

**The clear focus remains threat modeling.** It is the most comprehensive of the three and transitively exercises the other two: the requirements audit runs as an optional phase inside the threat assessment, and the coach shapes the code that the threat model later reads. But both neighbouring disciplines remain independently invokable because each has its own cadence and use case.

## The three capsules

### 1. Architectural Threat Assessment (Beta)

The core run: a multi-stage, **code-based** pipeline that produces a complete, architecture-driven threat model **directly from the repository's source code** — not from a prose description or an externally supplied diagram. An orchestrator agent walks eleven phases — context resolution, reconnaissance (tech stack, security categories, config and IaC), architecture modelling (C4 diagrams, sequence diagrams, trust boundaries, assets, attack surface, all derived from the code), parallel per-component STRIDE analysis, triage validation, finalisation. A QA stage then verifies links, diagrams, and cross-references; an optional architect-review stage adds an advisory opinion. Every threat in the register carries a `file:line` citation back to the evidence that produced it.

Output: `threat-model.md` (human-readable, with diagrams and attack walkthroughs), `threat-model.yaml` (structured for ticketing systems and dashboards), `threat-model.sarif.json` (for GitHub Code Scanning, SonarQube, DefectDojo). The emphasis is deliberately **architectural** — the report is only finished when the code's structure has been understood, not just when individual vulnerabilities have been enumerated.

Invoked via `/appsec-plugin:create-threat-model`. A complete real-world report generated against OWASP Juice Shop lives at [`examples/juice-shop/threat-model.md`](examples/juice-shop/threat-model.md).

### 2. Security Requirements Audit (Experimental)

The focused compliance view: instead of building a complete model, the repository is measured directly against the organisation's security-requirements catalog. Every `SEC-*` requirement receives a **PASS / PARTIAL / FAIL** status with evidence references pointing back into the code.

This capsule is intentionally lightweight and fast. It fits PR gates, daily compliance dashboards, and audit preparation where the full threat assessment would be too heavy. Technically it shares the requirements source (URL + local cache) with the threat assessment, whose Phase 8b invokes exactly this logic as an integrated sub-step.

Invoked via `/appsec-plugin:check-appsec-requirements`.

### 3. Security Coach (Experimental)

The quiet background colleague: not a slash command but a hook that reads along with every prompt in the coding session. When a prompt touches a security-relevant topic — authentication, injection, cryptography, XSS/CSRF, secrets, container/IaC, or LLM surfaces — the coach injects topic-specific secure-by-default guidance into the prompt. The topics, their trigger keywords, and the guidance text are all configured in `plugin/hooks/steering_keywords.json`; organisations override them per repository.

When the same repository has a security-requirements catalog available (the cache the requirements audit populates), the coach resolves the relevant `SEC-*` requirements and appends them inline, so the code being written references the organisation's actual controls rather than generic advice. This is the feedback loop that ties the three capsules together: the coach steers code toward the baseline that the audit later grades, which the threat assessment later stress-tests.

Unlike the first two capsules, the coach produces no artifact. **It is opt-in** — disabled by default, activated either per session with `APPSEC_COACH=1` in the shell or persistently by flipping `"enabled": true` in `plugin/hooks/steering_keywords.json`. Whenever it fires, the injected `systemMessage` names its activation source so you always see why it is on. See [`docs/configuration.md`](docs/configuration.md) for the activation details.

### When to use which

The three capsules cover **different moments** in the AppSec lifecycle of a repository: the **Security Coach** while the code is being written, the **Security Requirements Audit** during review cycles, the **Architectural Threat Assessment** at milestones and releases. All three read the same organisational context and write to the same output convention, so repository-level security remains *one* coherent workflow rather than three disconnected audits.

### Discovery & maintenance

Two support commands are available alongside the three capsules:

- **`/appsec-plugin:status`** — a read-only overview: plugin version, available capsules, last-run identity, configuration sources, and a fast-path preview that tells you whether the next incremental run would short-circuit. A good place to start when you're unsure what's configured or why a run behaves the way it does.
- **`--help` / `-h`** on any capsule — prints the flag reference for that capsule and exits without running. Works for `create-threat-model`, `check-appsec-requirements`, and `status`.
- **Cleanup** — two disjoint verbs via `scripts/run-headless.sh`:
  - `--clean-cache` removes caches and transient state while keeping the committed threat model and audit logs. Useful when `analysis_version` drifted or you want to force the next run to rebuild from scratch without losing history.
  - `--clean-all` wipes everything the plugin has written into the output directory, with an interactive confirmation (skip with `--force`, auto-skipped in CI). Unknown files in the output directory are never touched.

## Installation

Requires Claude Code, Python 3.10+, and `git` in `PATH`.

```bash
claude --plugin-dir /path/to/appsec-plugin/plugin
```

Optional integrations — external context endpoint, requirements source, logging sink — can be enabled independently. See [`docs/configuration.md`](docs/configuration.md).

## Quick start

Inside Claude Code, in the repository you want to analyze:

```
/appsec-plugin:create-threat-model
```

The orchestrator prints each phase as it runs (`[Phase 2/11] Reconnaissance…`) and writes checkpoints between phases, so interrupted runs resume with `--resume`. A `standard`-depth run takes about 25 minutes on a mid-size repository. Output lands in `docs/security/threat-model.md`.

> The `/appsec-plugin:` prefix is the Claude Code plugin namespace — it disambiguates commands when several plugins are installed.

## Examples

**Architectural Threat Assessment**

```bash
# Focus the analysis on a specific area
/appsec-plugin:create-threat-model focus on the authentication service

# Re-scan after code changes — only re-analyses what changed since the last run
/appsec-plugin:create-threat-model --incremental

# Preview scope before a full run
/appsec-plugin:create-threat-model --dry-run

# Also emit machine-readable exports
/appsec-plugin:create-threat-model --yaml --sarif

# Deeper analysis (roughly 40 minutes, more components, extended diagrams)
/appsec-plugin:create-threat-model --assessment-depth thorough

# Analyze a repository you don't own — typical AppSec reviewer workflow
/appsec-plugin:create-threat-model --repo /path/to/team-api --output /reports/team-api

# Headless / CI mode — fast-aborts when nothing changed since the last run
./scripts/run-headless.sh --repo /path --output /out --incremental --sarif --no-qa

# PR gate: diff against target branch, fail CI on new High/Critical threats
./scripts/run-headless.sh --repo . --base origin/main --pr-mode --fail-on high

# Inline help for a capsule (no analysis is run)
/appsec-plugin:create-threat-model --help
/appsec-plugin:check-appsec-requirements --help

# Plugin status: configuration, last run, fast-path preview
/appsec-plugin:status

# Clean up caches only (keeps the model + logs)
./scripts/run-headless.sh --output /out --clean-cache

# Clean up everything (with confirmation; --force in CI)
./scripts/run-headless.sh --output /out --clean-all --force
```

See [**Running in CI**](#running-in-ci) for the full workflow including a GitHub Actions example.

**Security Requirements Audit**

```bash
# Grade the repository against the SEC-* baseline
/appsec-plugin:check-appsec-requirements

# Narrow the audit to a single category
/appsec-plugin:check-appsec-requirements SEC-AUTH

# Persist as Markdown or JSON
/appsec-plugin:check-appsec-requirements --md
/appsec-plugin:check-appsec-requirements --json
```

Full flag reference (interactive and headless): [`docs/flags-reference.md`](docs/flags-reference.md).

## Report contents (Architectural Threat Assessment)

| Section | Content |
|---|---|
| 1 | System overview — team, compliance scope, asset classification |
| 2 | C4 architecture diagrams and technology-stack view (Mermaid) |
| 3 | Sequence diagrams for authentication, authorization, and critical flows |
| 4 | Attack walkthroughs — step-by-step exploitation paths for top-ranked threats |
| 5 | Assets — data, code/IP, infrastructure, availability |
| 6 | Attack surface — entry points with protocol and auth requirements |
| 7 | Trust boundaries |
| 8 | Security controls with effectiveness ratings |
| 8b | Requirements compliance — per-requirement PASS/PARTIAL/FAIL *(with `--requirements`)* |
| 9 | STRIDE threat register with CVSS v4.0 scoring |
| 10 | Critical findings |
| 11 | Prioritized mitigation register and explicit out-of-scope notes |

Sample YAML export:

```yaml
meta:
  project: juice-shop
  generated: 2026-04-18T14:32:11Z
  model: claude-sonnet-4-6
  compliance_scope: [PCI-DSS, SOC2]
threats:
  - id: T-001
    stride: Spoofing
    cwe: CWE-798
    likelihood: High
    impact: Critical
    risk: Critical
    evidence: routes/login.ts:42
```

## Organisation context (shared by all three capsules)

Phase 1 of the threat assessment — and the load step of the requirements audit — both read from several optional sources before work begins:

- **Security requirements** — a YAML catalog of `SEC-*` controls fetched from a configurable URL, or the bundled fallback at `plugin/data/appsec-requirements-fallback.yaml`. The threat assessment's Phase 8b grades every requirement against the codebase and annotates the threat register with traceability; the requirements audit uses the same source as its primary input.
- **Architecture blueprints and threat intel** — served by the external context REST endpoint defined in `plugin/config.json`. Useful for approved-stack patterns, prior incident context, and team-specific constraints.
- **Known threats** — `docs/known-threats.yaml` in the analyzed repository carries accepted risks and prior mitigations forward across runs.
- **Steering keywords** — `plugin/hooks/steering_keywords.json` defines the trigger words and injected guidance the Security Coach uses.

See [`docs/configuration.md`](docs/configuration.md) for schemas and endpoint contracts.

## How the threat assessment works

The pipeline runs across three stages, each with its own turn budget — so Stage 1 exhaustion cannot starve Stage 2.

- **Stage 1 — Analysis.** The `appsec-threat-analyst` orchestrator drives Phases 1–11. It dispatches the context resolver, recon scanner, config scanner, per-component STRIDE analyzers (in parallel), a threat merger for duplicate resolution, and the triage validator for cross-component consistency.
- **Stage 2 — QA.** `appsec-qa-reviewer` runs a 10-check pass over the finished report (diagrams, links, references, coverage) and fixes issues in place.
- **Stage 3 — Architect review** *(optional, `--architect-review`, auto-on at `thorough` depth)*. Advisory architect-level pass, writing findings to `.architect-review.md` without modifying the threat model.

Intermediate state is checkpointed after every phase. Schema validation on each intermediate file prevents silent data corruption. Dep-scan results are cached against manifest hashes and skipped on re-runs when nothing changed.

For the full pipeline — phase-by-phase responsibilities, intermediate-file contracts, retry logic, locking, and cache semantics — see [`docs/architecture.md`](docs/architecture.md).

## Running in CI

The plugin is designed to run fast in CI. `scripts/run-headless.sh` performs a **fast-path pre-check** before dispatching Claude: when the incremental run is requested, it inspects git, the recon fingerprint, and the plugin version — if nothing has changed since the last scan, the run exits in under a second without burning a single token.

### Incremental on every push

```bash
./scripts/run-headless.sh \
  --repo . \
  --output docs/security \
  --incremental \
  --no-qa \
  --max-duration 1800
```

- `--no-qa` skips Stage 2 (useful in CI where the report is machine-consumed).
- `--max-duration` is an absolute timeout (wraps the run with `timeout(1)`).
- Passing `CI=true` (most CI runners set this automatically) signals the script to use non-interactive defaults and honour plugin-version drift silently.

### MR / pull request mode

`--pr-mode` implies `--incremental`, diffs `HEAD` against a base ref, and produces a focused report that only covers components affected by the change. Combined with `--fail-on <level>` it becomes a PR gate:

```bash
./scripts/run-headless.sh \
  --repo . \
  --base origin/main \
  --pr-mode \
  --fail-on high
```

Exit codes: `0` = no new Critical/High, `20` = new Critical or High introduced.

### CI cache

The fast-path relies on `docs/security/threat-model.yaml` and `docs/security/.appsec-cache/` surviving between CI runs. Either commit the `threat-model.yaml` (common — it IS the machine-readable artifact) or cache `docs/security/` as a CI artifact and restore it at the start of the next run via `--restore-from`:

```bash
# Restore a previously cached state before running
./scripts/run-headless.sh \
  --repo . \
  --restore-from ./ci-cache/appsec-state/ \
  --incremental
```

### GitHub Actions example

```yaml
name: AppSec Threat Model

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write   # needed to upload SARIF

jobs:
  threat-model:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0     # incremental mode needs git history for the base diff

      - name: Restore previous threat model cache
        uses: actions/cache/restore@v4
        with:
          path: docs/security
          key: appsec-${{ github.ref }}-${{ hashFiles('docs/security/threat-model.yaml') }}
          restore-keys: |
            appsec-${{ github.ref }}-
            appsec-refs/heads/main-

      - name: Install Claude Code
        run: curl -fsSL https://claude.ai/install.sh | sh

      - name: Run threat model (incremental / PR delta)
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          if [ "${{ github.event_name }}" = "pull_request" ]; then
            ./scripts/run-headless.sh \
              --repo . \
              --base origin/${{ github.base_ref }} \
              --pr-mode \
              --fail-on high \
              --sarif \
              --no-qa \
              --max-duration 1800
          else
            ./scripts/run-headless.sh \
              --repo . \
              --incremental \
              --sarif \
              --no-qa \
              --max-duration 1800
          fi

      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: docs/security/threat-model.sarif.json

      - name: Save updated threat model cache
        if: always() && github.event_name == 'push'
        uses: actions/cache/save@v4
        with:
          path: docs/security
          key: appsec-${{ github.ref }}-${{ hashFiles('docs/security/threat-model.yaml') }}
```

Notes on the workflow:

- `fetch-depth: 0` is required so the incremental mode can diff against `origin/main` (PR) or the last scan's `commit_sha` (push).
- The `restore-keys` fallback chain lets a feature branch pick up `main`'s last threat model as its starting baseline.
- Scheduled **full** refresh to pick up plugin upgrades — drop a separate workflow:
  ```yaml
  on:
    schedule:
      - cron: '0 4 * * 1'   # weekly, Monday 04:00 UTC
  ```
  …that runs `./scripts/run-headless.sh --repo . --full --sarif` without `--no-qa`.

## Cost and data handling

A `standard` run consumes a few USD of API credit with Sonnet on a mid-size repository. `--stride-model opus` raises that roughly 5×. The hook logger estimates per-session cost using rates configured in `plugin/config.json`; actual billing is visible in the Anthropic Console.

The plugin reads local source code and sends prompts to the Anthropic API. No other external service receives code. Review [Anthropic's privacy policy](https://www.anthropic.com/privacy) before running on sensitive codebases; see [`SECURITY.md`](SECURITY.md) for responsible-disclosure details.

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — Agent pipeline, phases, intermediate files, reliability
- [`docs/configuration.md`](docs/configuration.md) — External context, requirements source, known threats, steering hook
- [`docs/flags-reference.md`](docs/flags-reference.md) — Complete flag reference (interactive + headless)
- [`docs/headless-mode.md`](docs/headless-mode.md) — Non-interactive execution and CI integration
- [`docs/harvester.md`](docs/harvester.md) — Requirements crawler configuration
- [`docs/comparison-sonnet-opus.md`](docs/comparison-sonnet-opus.md) — Sonnet vs Opus quality/cost trade-offs

## Related projects

- **[davidmatousek/tachi](https://github.com/davidmatousek/tachi)** — Claude Code plugin focused on STRIDE methodology itself, with narrative reporting and PDF output. A good fit when the deliverable is a polished stakeholder document.
- **[mrwadams/stride-gpt](https://github.com/mrwadams/stride-gpt)** — Streamlit app that derives STRIDE threats from a prose system description. Useful early in design, before code exists.

This plugin's emphasis is different: deep architecture analysis from the actual repository, evidence-linked threats, and integration of organisation-specific requirements and blueprints — packaged with the two adjacent capsules so that repository-level AppSec lives in one workflow.

## Contributing

```bash
pytest tests/
python3 plugin/scripts/validate_config.py plugin/
```

Issue and pull-request templates live under [`.github/`](.github/). Security issues should not be filed as public issues — open a [GitHub Security Advisory](../../security/advisories/new) instead ([`SECURITY.md`](SECURITY.md)).
