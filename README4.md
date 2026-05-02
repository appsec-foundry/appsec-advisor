# appsec-advisor

A Claude Code plugin that delivers automated, code-centric STRIDE threat modeling and architectural security assessments directly inside any repository. Purpose-built for enterprise environments and tailored to both development and AppSec teams.

[![Version](https://img.shields.io/badge/version-0.9.0--beta-orange.svg)](#)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-plugin-5A67D8.svg)](https://docs.claude.com/en/docs/claude-code)
[![SARIF](https://img.shields.io/badge/SARIF-v2.1.0-green.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

> **Status:** 0.9.0-beta. Good for guided use by an AppSec engineer.

---

## Contents

- [Quick start](#quick-start)
- [What you get](#what-you-get)
- [Example reports](#example-reports)
- [What it checks](#what-it-checks)
- [Example usage](#example-usage)
- [Assessment depth and costs](#assessment-depth-and-costs)
- [CI integration](#ci-integration)
- [Cross-repo analysis](#cross-repo-analysis)
- [Architecture](#architecture)
- [Additional skills](#additional-skills)
- [Related projects](#related-projects)
- [Contributing](#contributing)

## Quick start

Requires Claude Code, Python 3.10+, and `git` on `PATH`.

```bash
git clone <repository-url> /path/to/appsec-advisor
claude --plugin-dir /path/to/appsec-advisor
```

In Claude Code, type `/appsec-advisor:` — you should see the registered skills.

Before your first run, merge the required Claude Code permissions once (otherwise you'll hit a prompt every ~30 seconds):

```
/appsec-advisor:check-permissions --update
```

From the repo you want to analyse:

```
/appsec-advisor:create-threat-model
```

Output lands by default in `docs/security/` of the repository (configurable) and is git-ignored by default — threat reports contain vulnerability details that should not be committed unintentionally.

To commit the report, use the publish-threat-model skill:

```
/appsec-advisor:publish-threat-model
```

## What you get

The main result of an assessment is a report with a comprehensive list of **threats** and respective **mitigations**.

By default the skill writes:

- `threat-model.md` — human-readable threat model report
- `threat-model.yaml` — machine-readable export, consumable by other repos for cross-repo analysis (see [Cross-repo analysis](#cross-repo-analysis))

Optional outputs (flag-gated):

- `threat-model.sarif.json` — SARIF v2.1 findings (`--sarif`)
- `threat-model.pdf` — print-ready PDF (`--pdf`)
- `pentest-tasks.yaml` — task list for AI pentesters such as Strix (`--pentest-tasks`)

A full report includes a heatmap visualising threat-actor → architecture-tier → business-impact paths:

![Threat Heatmap — OWASP Juice Shop](docs/images/heatmap.png)

See the full report: [`examples/threat-modeler/threat-model-juice-shop-thorough.md`](examples/threat-modeler/threat-model-juice-shop-thorough.md).

## Example reports

Real reports produced against publicly available OWASP training apps — browse the full set in [`examples/threat-modeler`](examples/threat-modeler/).

| Target | Mode | Components | Findings | Attack Chains | Mitigations |
|---|---|---:|---|---:|---:|
| [OWASP Juice Shop](examples/threat-modeler/threat-model-juice-shop-thorough.md) — *Node.js / Angular web shop* | `thorough --full` | 8 | **35** — 12 Critical · 19 High · 3 Medium · 1 Low | 4 | 28 |
| [OWASP VulnerableApp](examples/threat-modeler/threat-model-vulnerable-app-standard.md) — *Java / Spring Boot learning platform* | `standard` | 5 | **24** — 8 Critical · 11 High · 5 Medium | 3 | 20 |

Every finding cites a concrete `file:line`. "Chains" are multi-step compound attacks correlated across components. "Mitigations" are the deduplicated actions in the report's §9 Mitigation Register.

## What it checks

The recon scanner runs **32 structured checks** across eight areas before any STRIDE analysis starts. This is the floor, not the ceiling — STRIDE agents read source code broadly and derive additional findings from observed code paths.

| Area | Reference | What is checked |
|------|-----------|-----------------|
| **Security Architecture** | [A06:2025 - Insecure Design](https://owasp.org/Top10/2025/A06_2025-Insecure_Design/) | Security architecture aspects like compartmentalization, dataflows, AuthN/AuthZ |
| **Authentication & Access Control** | [A01:2025 - Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/) ·<br>[A07:2025 - Authentication Failures](https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/) | Token handling, role checks, OAuth/OIDC, client-side guards |
| **Input Processing & Injection** | [A05:2025 - Injection](https://owasp.org/Top10/2025/A05_2025-Injection/) ·<br>[A08:2025 - Software and Data Integrity Failures](https://owasp.org/Top10/2025/A08_2025-Software_and_Data_Integrity_Failures/) | SQL/NoSQL, request parameters, deserializers, dangerous sinks |
| **Cryptography & Secrets** | [A04:2025 - Cryptographic Failures](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/) | Insecure algorithms, key management, hardcoded credentials |
| **Frontend / Client-Side** | [A05:2025 - Injection](https://owasp.org/Top10/2025/A05_2025-Injection/) ·<br>[A02:2025 - Security Misconfiguration](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/) | Browser storage, XSS, DOM sources, bundled API keys, WebSocket + postMessage auth |
| **Configuration & Exposure** | [A02:2025 - Security Misconfiguration](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/) ·<br>[A09:2025 - Security Logging & Alerting Failures](https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/) ·<br>[A10:2025 - Mishandling of Exceptional Conditions](https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/) | Stack-trace leakage, exposed management endpoints, security headers, CORS |
| **Supply Chain Security** | [A03:2025 - Software Supply Chain Failures](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/) ·<br>[A08:2025 - Software and Data Integrity Failures](https://owasp.org/Top10/2025/A08_2025-Software_and_Data_Integrity_Failures/) | Unpinned Actions/images, lockfile integrity, install flags, SCA tooling |
| **AI/LLM in the Application** | [OWASP LLM Top 10 - 2025](https://genai.owasp.org/llm-top-10/) | LLM API usage, prompt templates, vector stores |

## Example usage

```bash
# Focus on a specific area
/appsec-advisor:create-threat-model focus on the authentication service

# Analyse a repo you don't own
/appsec-advisor:create-threat-model --repo /path/to/team-api --output /reports/team-api

# Dry run — full pipeline, no files written, summary to console
/appsec-advisor:create-threat-model --dry-run

# Force a full scan at thorough depth
# (use --rebuild instead if you also want to wipe all intermediate files, caches, and model data)
/appsec-advisor:create-threat-model --full --assessment-depth thorough

# Extra output formats
/appsec-advisor:create-threat-model --yaml --sarif --pentest-tasks
```

## Assessment depth and costs

The threat modeler provides multiple options to influence scanning thoroughness and costs. The main lever is the assessment-depth switch:

| Mode | Switch | Explanation |
|------|--------|-------------|
| **Quick**    | `--assessment-depth quick`    | lightweight STRIDE, core QA, mostly Haiku with Sonnet for reasoning |
| **Standard** | *(default)*                   | full STRIDE, full QA, Sonnet by default with Opus for triage and merger |
| **Thorough** | `--assessment-depth thorough` | deep scan, extended STRIDE & QA, additional architect reviewer, broader Opus use |

Indicative cost and runtime on a medium-sized repository (OWASP Juice Shop, 608 source files):

| Mode         |          Cost |    Wallclock |
|--------------|--------------:|-------------:|
| **Quick**    |        ~$1.80 |      ~10 min |
| **Standard** |        ~$3.70 |      ~22 min |
| **Thorough** |  ~$5.30–$7.40 |   ~33–40 min |

Premium mode (`--reasoning-model opus`) lifts STRIDE analysis to Opus and lands in the $5.50 (quick) to $17 (thorough) range. See [`README3.md`](README3.md) for the full tier matrix.

You can constrain costs further with hard caps:

```bash
# Stop when estimated API spend hits $5 and abort after 30 minutes
/appsec-advisor:create-threat-model --max-cost 5 --max-wall-time 30m

# Quick assessment with limited depth
/appsec-advisor:create-threat-model --assessment-depth quick
```

The default settings have been tuned to deliver the best cost–quality ratio. Restricting them may noticeably lower the quality of the threat model.

## CI integration

`scripts/run-headless.sh` drives the same skill non-interactively and propagates exit codes.

```bash
./scripts/run-headless.sh --incremental --max-duration 1800 --max-budget 5 --sarif
```

Note: `run-headless.sh` uses `--max-duration` and `--max-budget` (its own surface); the interactive skill uses `--max-wall-time` and `--max-cost`. Same semantics.

Full guide (GitHub Actions, GitLab, Jenkins, PR-gate mode): [`docs/headless-mode.md`](docs/headless-mode.md).

## Cross-repo analysis

Drop a `docs/related-repos.yaml` in a repository to pull findings from upstream services into the STRIDE analysis at trust boundaries:

```yaml
related:
  - name: auth-service
    threat_model: ../auth-service/docs/security/threat-model.yaml
    interface: REST API /v1/auth
  - name: payment-gateway
    threat_model: https://gitlab.internal/payments/-/raw/main/docs/security/threat-model.yaml
    interface: gRPC PaymentService
```

Open Critical and High findings from the declared interfaces feed the STRIDE analyzer's `CROSS_REPO_CONTEXT`. Missing upstream models elevate risk at shared boundaries.

To aggregate results across the set into a consolidated `threat-summary.md`:

```
/appsec-advisor:generate-threat-summary --repos auth-service,payment-gateway
```

This pulls the published `threat-model.yaml` files and produces a single cross-repo summary with shared-pattern detection.

## Architecture

Seven-agent pipeline orchestrated by `appsec-threat-analyst` across 11 phases. The user-facing entry point is the `create-threat-model` skill; the orchestrator dispatches sub-agents for context resolution, reconnaissance, IaC scanning, parallel STRIDE analysis (one analyzer per component), threat merging, triage validation, and output composition. Stages 3 (QA) and 4 (architect review) gate the rendered report.

Agent model routing follows a **reasoning-tier** policy:

- `haiku-economy` — default at quick; pre-extraction agents on Haiku 4.5, reasoning core on Sonnet
- `opus-cheap` — default at standard and thorough; Opus for triage and merger
- `sonnet` — Sonnet everywhere
- `opus` — STRIDE itself on Opus for premium quality

Override per agent via env vars (`APPSEC_STRIDE_MODEL`, `APPSEC_TRIAGE_MODEL`, …) or globally via `--reasoning-model`.

![Threat Model Pipeline](docs/images/threat-model-pipeline.png)

Pipeline details: [`docs/threat-model-skill.md`](docs/threat-model-skill.md). Full tier matrix and cost tradeoffs: [`README3.md`](README3.md).

## Additional skills

### Security Requirements Auditor

**Command:** `/appsec-advisor:check-appsec-requirements` · *experimental*

Grades the repository against a custom AppSec requirements catalog. Each requirement returns PASS / PARTIAL / FAIL with code-level evidence and a before/after fix snippet. Faster than a full threat model.

Details: [`docs/security-requirements-audit-skill.md`](docs/security-requirements-audit-skill.md) · Catalog setup: [`docs/harvester.md`](docs/harvester.md).

### Security Coach

**Trigger:** `UserPromptSubmit` hook · *off by default*

Inline guidance during coding sessions. Scans prompts for security-relevant keywords (auth, crypto, injection, IaC, secrets, LLM) and injects context-aware guidance. When a requirements catalog is loaded, the coach references your controls by ID.

Enable via `APPSEC_COACH=1` or in `config.json`.

Details: [`docs/security-coach-skill.md`](docs/security-coach-skill.md).

## Related projects

- **[davidmatousek/tachi](https://github.com/davidmatousek/tachi)** — STRIDE plugin with narrative reporting and PDF output. Fits when the deliverable is a polished stakeholder document.
- **[mrwadams/stride-gpt](https://github.com/mrwadams/stride-gpt)** — Streamlit app that derives STRIDE threats from a prose system description. Useful early in design, before code exists.

## Contributing

```bash
pytest tests/
python3 scripts/validate_config.py .
```

Issue and PR templates: [`.github/`](.github/). Conventions and agent-definition format: [`CONTRIBUTING.md`](CONTRIBUTING.md). Security vulnerabilities: open a [GitHub Security Advisory](../../security/advisories/new) rather than a public issue. See [`SECURITY.md`](SECURITY.md).
