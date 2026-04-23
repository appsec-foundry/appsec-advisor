# appsec-advisor

STRIDE threat modeling that reads your actual code instead of a whiteboard sketch.
A Claude Code plugin that produces an evidence-linked report with `file:line`
citations for every finding — built for AppSec teams working across many repos.

[![Version](https://img.shields.io/badge/version-0.9.0--beta-orange.svg)](#)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-plugin-5A67D8.svg)](https://docs.claude.com/en/docs/claude-code)
[![SARIF](https://img.shields.io/badge/SARIF-v2.1.0-green.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

> **Status:** 0.9.0-beta. Good for guided use by an AppSec engineer.
> Not yet hardened for unattended CI/CD runs. See [CHANGELOG.md](CHANGELOG.md).

<!-- TODO: replace with a real screenshot of docs/security/threat-model.md:
     the Management Summary + one Mermaid diagram with pink threat nodes.
     Save under docs/images/report-preview.png. -->
![Sample report](docs/images/report-preview.png)

**How it differs from similar tools.** [stride-gpt](https://github.com/mrwadams/stride-gpt)
derives threats from a prose system description; [tachi](https://github.com/davidmatousek/tachi)
produces a polished stakeholder PDF. appsec-advisor grounds every threat in
a specific file and line in your repo, and knows about your upstream services
if you declare them.

**What it costs.** A standard-depth scan takes ~25 minutes and runs around
$2–4 in Anthropic API credits on a mid-sized service. `thorough` is ~50 min
and $6–10. Incremental re-runs on small diffs are under a minute and cents.

---

## Contents

- [Quick start](#quick-start)
- [What you get](#what-you-get)
- [What it checks](#what-it-checks)
- [Example usage](#example-usage)
- [Cross-repo analysis](#cross-repo-analysis)
- [Additional skills](#additional-skills)
- [Related projects](#related-projects)
- [Contributing](#contributing)

## Quick start

Requires Claude Code, Python 3.10+, and `git` on `PATH`.

```bash
git clone <repository-url> /path/to/appsec-advisor
claude --plugin-dir /path/to/appsec-advisor    # TODO: verify install command
```

In Claude Code, type `/appsec-advisor:` — you should see the registered skills.
From the repo you want to analyse:

```
/appsec-advisor:create-threat-model
```

Output lands in `docs/security/` and is **git-ignored by default** — threat
reports contain vulnerability details that shouldn't be committed without
thinking about it. To commit intentionally:

```
/appsec-advisor:publish-threat-model
```

Before your first run, merge the required Claude Code permissions once
(otherwise you'll hit a prompt every ~30 seconds):

```
/appsec-advisor:check-permissions --update
```

## What you get

Real reports produced against public OWASP training apps
(full set at [`examples/threat-modeler`](examples/threat-modeler/README.md)):

| Target | Mode | Components | Findings | Chains | Mitigations |
|---|---|---:|---|---:|---:|
| [OWASP Juice Shop](examples/threat-modeler/threat-model-juice-shop-thorough.md) — *Node.js / Angular* | `thorough --full` | 8 | **35** — 12C · 19H · 3M · 1L | 4 | 28 |
| [OWASP VulnerableApp](examples/threat-modeler/threat-model-vulnerable-app-standard.md) — *Java / Spring Boot* | `standard` | 5 | **24** — 8C · 11H · 5M | 3 | 20 |

Every finding cites a concrete `file:line`. "Chains" are multi-step attacks
correlated across components. "Mitigations" are the deduplicated actions
in the report's §9 Mitigation Register.

Outputs:

- `threat-model.md` — human-readable report with C4 diagrams, STRIDE register, VS Code deep links
- `threat-model.yaml` (`--yaml`) — structured export
- `threat-model.sarif.json` (`--sarif`) — SARIF v2.1.0 for CI/CD
- `pentest-tasks.yaml` (`--pentest-tasks`) — task list for AI pentesters / DAST, with a per-task safety block

## What it checks

The recon scanner runs **28 structured checks** across ten areas before
any STRIDE analysis starts. This is the floor, not the ceiling — STRIDE
agents read source code broadly and derive additional findings from
observed code paths.

| Area | What is checked |
|------|-----------------|
| **Authentication & Access Control** | Token handling, role checks, OAuth/OIDC, client-side guards |
| **Input Processing & Injection** | SQL/NoSQL, request parameters, deserializers, dangerous sinks (`eval`, `innerHTML`, `subprocess`) |
| **Cryptography & Secrets** | Algorithm choices, key management, hardcoded credentials (7 pattern types) |
| **Frontend / Client-Side** | Browser storage, XSS, DOM sources, bundled API keys, WebSocket + postMessage auth |
| **Configuration & Exposure** | Stack-trace leakage, exposed management endpoints, security headers, CORS |
| **Supply Chain: Dependencies** | Unpinned Actions/images, lockfile integrity, install flags, SCA tooling |
| **Supply Chain: CI/CD Privileges** | `pull_request_target`, missing `permissions:` blocks, self-hosted runners |
| **AI/LLM in the Application** | LLM API usage, prompt templates, vector stores — triggers OWASP LLM Top 10 |
| **AI Developer Tooling** | Committed assistant configs, wildcard permissions, MCP servers, prompt-injection payloads |
| **External & Cross-Repo Dependencies** | SCM siblings, SaaS SDK integrations (Stripe, Auth0, Firebase, …) |

## Example usage

```bash
# Focus a specific area
/appsec-advisor:create-threat-model focus on the authentication service

# Analyse a repo you don't own
/appsec-advisor:create-threat-model --repo /path/to/team-api --output /reports/team-api

# Dry run — full pipeline, no files written, summary to console
/appsec-advisor:create-threat-model --dry-run

# Force a full rebuild at thorough depth
/appsec-advisor:create-threat-model --full --assessment-depth thorough

# Extra output formats
/appsec-advisor:create-threat-model --yaml --sarif --pentest-tasks
```

**CI integration.** `scripts/run-headless.sh` drives the same skill
non-interactively and propagates exit codes.

```bash
./scripts/run-headless.sh --incremental --max-duration 1800 --max-budget 5 --sarif
```

Full guide (GitHub Actions, GitLab, Jenkins, PR-gate mode): [`docs/headless-mode.md`](docs/headless-mode.md).

## Cross-repo analysis

Drop a `docs/related-repos.yaml` in a repository to pull findings from
upstream services into the STRIDE analysis at trust boundaries:

```yaml
related:
  - name: auth-service
    threat_model: ../auth-service/docs/security/threat-model.yaml
    interface: REST API /v1/auth
  - name: payment-gateway
    threat_model: https://gitlab.internal/payments/-/raw/main/docs/security/threat-model.yaml
    interface: gRPC PaymentService
```

Open Critical and High findings from the declared interfaces feed the
STRIDE analyzer's `CROSS_REPO_CONTEXT`. Missing upstream models elevate
risk at shared boundaries. Use `/appsec-advisor:generate-threat-summary`
to aggregate results across the set.

## Architecture

![Threat Model Pipeline](docs/images/threat-model-pipeline.png)

Details: [`docs/threat-model-skill.md`](docs/threat-model-skill.md).

## Additional skills

### Security Requirements Auditor

**Command:** `/appsec-advisor:check-appsec-requirements` · *experimental*

Grades the repository against a custom AppSec requirements catalog.
Each requirement returns PASS / PARTIAL / FAIL with code-level evidence
and a before/after fix snippet. Faster than a full threat model.

Details: [`docs/security-requirements-audit-skill.md`](docs/security-requirements-audit-skill.md) ·
Catalog setup: [`docs/harvester.md`](docs/harvester.md).

### Security Coach

**Trigger:** `UserPromptSubmit` hook · *off by default*

Inline guidance during coding sessions. Scans prompts for security-relevant
keywords (auth, crypto, injection, IaC, secrets, LLM) and injects
context-aware guidance. When a requirements catalog is loaded, the coach
references your controls by ID.

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

Issue and PR templates: [`.github/`](.github/). Conventions and agent-definition
format: [`CONTRIBUTING.md`](CONTRIBUTING.md). Security vulnerabilities: open a
[GitHub Security Advisory](../../security/advisories/new) rather than a public
issue. See [`SECURITY.md`](SECURITY.md).
