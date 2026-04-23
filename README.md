# appsec-advisor

A Claude Code plugin that performs automated, code-driven architectural threat modeling directly within repositories, along with other practical AppSec tasks, designed specifically for enterprise environments.

[![Version](https://img.shields.io/badge/version-0.10.0--beta-orange.svg)](#)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-plugin-5A67D8.svg)](https://docs.claude.com/en/docs/claude-code)
[![SARIF](https://img.shields.io/badge/SARIF-v2.1.0-green.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

---

## Contents

- [Quick start](#quick-start)
- [Capabilities](#capabilities)
- [Related projects](#related-projects)
- [Contributing](#contributing)

## Key Features

Core capabilities of the threat modeling functionality in this plugin:

* **Code-driven threat modeling** — derives architecture and potential threats directly from the codebase, without relying on separate documentation  
* **Multi-agent analysis** — runs multiple coordinated analyses using shared schemas to improve coverage and consistency  
* **STRIDE-based classification** — classifies findings using a standard threat model  
* **Evidence-linked findings** — links each finding to specific files and line numbers in the code  
* **Incremental analysis** — analyzes only modified components to reduce runtime  
* **CI/CD integration** — can be executed as part of pipelines.  
* **Customizable** — allows adding internal requirements or external context (e.g., via APIs)  

## Quick start

Requires Claude Code, Python 3.10+, and `git` on `PATH`.

#### 1. Clone the repo

```bash
git clone <repository-url> /path/to/appsec-advisor
```

#### 2. Start Claude Code with the plugin

```bash
claude --plugin-dir /path/to/appsec-advisor
```

After Claude Code starts, type `/appsec-advisor:`. You should see three registered skills.

#### 3. Run your first threat analysis

Run your first threat assessment from the repository you want to assess:

```
/appsec-advisor:create-threat-model
```

A standard-depth run takes roughly 25 minutes.

Output lands in `docs/security/` and is **git-ignored by default** — threat reports contain vulnerability details and attack vectors that should not be committed unintentionally.

#### 4. Publish the threat model (optional)

To commit the report to version control (private repos only, where your security policy permits):

```
/appsec-advisor:publish-threat-model
```

This skill runs pre-flight checks (repository visibility, secret scan), patches `.gitignore` with negation exceptions for the publishable files, and creates a git commit with threat-count metadata. `pentest-tasks.yaml` and all intermediate files remain permanently ignored.

Publishing `threat-model.yaml` also enables other repositories to declare this service as a dependency in their `docs/related-repos.yaml` for cross-repo STRIDE analysis.

## Example Reports

Real reports produced against publicly available OWASP training apps — browse the full set with the side-by-side standard vs. thorough Juice Shop reports at [`examples/threat-modeler`](examples/threat-modeler/README.md).

| Target | Mode | Components | Findings | Attack Chains | Mitigations |
|---|---|---:|---|---:|---:|
| [OWASP Juice Shop](examples/threat-modeler/threat-model-juice-shop-thorough.md) — *Node.js / Angular web shop* | `thorough --full` | 8 | **35** — 12 Critical · 19 High · 3 Medium · 1 Low | 4 | 28 |
| [OWASP VulnerableApp](examples/threat-modeler/threat-model-vulnerable-app-standard.md) — *Java / Spring Boot learning platform* | standard | 5 | **24** — 8 Critical · 11 High · 5 Medium | 3 | 20 |

Every finding cites a concrete `file:line`; "Chains" are multi-step compound attacks correlated across components; "Mitigations" are the deduplicated actions in the report's §9 Mitigation Register.

## Example Usage

Here are some practical examples:

**Assessment Scope**

The following examples explain how you can change the scope of an assessment. 

```bash

# Focus on a specific area
/appsec-advisor:create-threat-model focus on the authentication service

# Analyse a different repository you don't own (by default, the current working directory is used)
/appsec-advisor:create-threat-model --repo /path/to/team-api --output /reports/team-api

# Full analysis, no files written, Management Summary printed
/appsec-advisor:create-threat-model --dry-scan
```
Also relevant to the assessment scope are the tests of custom requirements (see below).

**Assessment Depth**

You can also define the assessment depth:

```bash
# Enforce rebuild of the threea model and scan in verbose mode (standard is incremental mode when a threat model already exists)
/appsec-advisor:create-threat-model  --full --verbose

# Perform a more in-depth scan (standard is --assessment-depth standard)
/appsec-advisor:create-threat-model --assessment-depth thorough
```

**Output Format**

By default, the threat modeler only writes the threat model report (threat-model.ms) + internal model files. Some use cases may require adding additional output formats:
```bash

# Emit machine-readable exports alongside the Markdown report
/appsec-advisor:create-threat-model --yaml --sarif

# Create pentest-tasks.yaml that can be consumed by AI pentest tools like striks
/appsec-advisor:create-threat-model --pentest-tasks
```

**CI Integration**

To run the threat modeler in a CI/CD pipeline, use the headless wrapper `scripts/run-headless.sh`. It drives the same skill non-interactively and propagates exit codes so a build can gate on findings.

```bash
# Minimal incremental CI scan with a hard timeout and budget cap
./scripts/run-headless.sh --incremental --max-duration 1800 --max-budget 5 --sarif
```

Even an incremental scan with no changes takes roughly one minute, so it is typically not suitable for every push or pull request. Use it for scheduled runs (daily/weekly), release pipelines, or manual triggers when security-sensitive changes land.

Full guide — including GitHub Actions / GitLab CI / Jenkins examples, PR-gate mode (`--pr-mode --fail-on high`), cost & duration expectations, and troubleshooting — in **[docs/headless-mode.md](docs/headless-mode.md)**.

**Integrating Custom Requirements**

The plugin can grade your repository against your organisation's own AppSec requirements catalog. You point it at a YAML file, and every `create-threat-model --requirements` (or `/appsec-advisor:check-appsec-requirements`) run picks up that catalog automatically. There are three ways to produce the YAML, in rough order of effort:

1. **Try it locally first.** The repo ships with a 53-requirement example YAML and a tiny mock HTTP server. No crawl needed — it verifies the end-to-end loop on your own machine:

   ```bash
   python3 scripts/mock-server.py   # serves the example on 127.0.0.1:4444
   /appsec-advisor:create-threat-model --requirements http://127.0.0.1:4444/requirements.yaml
   ```

2. **Adapt the fallback YAML** (`data/appsec-requirements-fallback.yaml`) — copy, edit to match your organisation's IDs and wording, commit, and point `requirements_yaml_url` in the skill config at the raw URL. Good enough for small teams.

3. **Harvest from a live catalog.** `scripts/harvest-requirements.py` crawls Confluence / Antora / any HTML pages, extracts structured requirement IDs, and writes the YAML. Schedule it on CI so the catalog stays fresh.

Full walkthrough with flow diagram, CI scheduling examples, and troubleshooting: **[docs/harvester.md](docs/harvester.md)**.

## What the Threat Modeler Checks

The recon scanner runs **28 structured check categories** before any threat analysis begins, covering ten areas:

| Area | What is checked |
|------|-----------------|
| **Authentication & Access Control** | Token handling, role checks, OAuth/OIDC flows, client-side guard enforcement |
| **Input Processing & Injection** | SQL/NoSQL queries, request parameters, deserializers, dangerous sinks (`eval`, `innerHTML`, `subprocess`) |
| **Cryptography & Secrets** | Algorithm choices, key management, hardcoded credentials across 7 pattern types |
| **Frontend / Client-Side** | Browser storage, XSS patterns, DOM sources, bundled API keys, WebSocket and postMessage auth |
| **Configuration & Exposure** | Stack-trace leakage, exposed management endpoints, security headers and CORS config |
| **Supply Chain: Dependencies** | Unpinned Actions/images, dependency confusion, lockfile integrity, CI install flags, SCA tooling |
| **Supply Chain: CI/CD Privileges** | `pull_request_target` misuse, missing `permissions:` blocks, self-hosted runner exposure |
| **AI/LLM in the Application** | LLM API usage, prompt templates, vector stores — triggers OWASP LLM Top 10 analysis |
| **AI Developer Tooling** | Committed assistant configs, wildcard shell permissions, MCP servers, prompt-injection payloads in instruction files |
| **External & Cross-Repo Dependencies** | SCM sibling services, SaaS SDK integrations (Stripe, Auth0, Firebase, …) |

These categories define a **minimum floor**, not a ceiling. The STRIDE agents read source code broadly beyond the named entry points and derive findings from observed code paths. Every threat requires a specific file and line number as evidence.

## Architecture

The following diagram shows the internal agentic pipeline, which creates the threat model:

![Threat Model Pipeline](docs/images/threat-model-pipeline.png)

More technical details can be found at [`docs/threat-model-skill.md`](docs/threat-model-skill.md).

## Additional Capabilities

The plugin provides the following additional capabilities:

### Security Requirements Auditor

**Status:** Experimental &nbsp;·&nbsp; **Command:** `/appsec-advisor:check-appsec-requirements`

Grades the repository against a custom AppSec requirements catalog. Each requirement returns **PASS / PARTIAL / FAIL** with code-level evidence and a before/after fix snippet. Faster than a full threat model.

Details: [`docs/security-requirements-audit-skill.md`](docs/security-requirements-audit-skill.md) · Catalog setup: [`docs/harvester.md`](docs/harvester.md).

### Security Coach

**Status:** Experimental &nbsp;·&nbsp; **Trigger:** `UserPromptSubmit` hook, off by default

Inline guidance during coding sessions. A `UserPromptSubmit` hook scans prompts for security-relevant keywords (auth, crypto, injection, IaC, secrets) and injects context-aware guidance. When a requirements catalog is loaded, the coach references custom AppSec controls.

Off by default. Enable via `APPSEC_COACH=1` or in `config.json`.

Details: [`docs/security-coach-skill.md`](docs/security-coach-skill.md).

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
