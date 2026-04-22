# appsec-advisor

A Claude Code plugin that performs automated, code-driven architectural threat modeling directly on repositories, plus other practical AppSec tasks, designed specifically for use in enterprise environments.

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
* **CI/CD integration** — can be executed as part of pipelines or pull request checks  
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

Run your first threet assessment from the repository you want to assess is particularily easy:

```
/appsec-advisor:create-threat-model
```

A standard-depth run takes roughly 25 minutes. 

Output: `docs/security/threat-model.md` 

## Example Reports

Real reports produced against publicly available OWASP training apps — browse the full set with the side-by-side standard vs. thorough Juice Shop reports at [`examples/threat-modeler`](examples/threat-modeler/README.md).

| Target | Mode | Components | Findings | Chains | Mitigations |
|---|---|---:|---|---:|---:|
| [OWASP Juice Shop](examples/threat-modeler/threat-model-juice-shop-thorough.md) — *Node.js / Angular web shop* | `thorough --full` | 8 | **35** — 🔴 12 · 🟠 19 · 🟡 3 · 🟢 1 | 4 | 28 |
| [OWASP VulnerableApp](examples/threat-modeler/threat-model-vulnerable-app-standard.md) — *Java / Spring Boot learning platform* | standard | 5 | **24** — 🔴 8 · 🟠 11 · 🟡 5 | 3 | 20 |

Severity: 🔴 Critical · 🟠 High · 🟡 Medium · 🟢 Low. Every finding cites a concrete `file:line`; "Chains" are multi-step compound attacks correlated across components; "Mitigations" are the deduplicated actions in the report's §9 Mitigation Register.

## Example Usage

Here are some practical examples:

**Assement Scope**

The following examples explain how you canchange the scope of an assessment. 

```bash

# Focus on a specific area
/appsec-advisor:create-threat-model focus on the authentication service

# Analyse a different repository you don't own (by default the current working directory is used)
/appsec-advisor:create-threat-model --repo /path/to/team-api --output /reports/team-api

# Full analysis, no files written, Management Summary printed
/appsec-advisor:create-threat-model --dry-scan
```
Also relevant to assessment scope is the tests of custom requirements (see below).

**Assement Depth**

You can also define the assessment depth:

```bash
# Enforce rebuild of the threea model and scan in verbose mode (standard is incremental mode when a threat model already exist)
/appsec-advisor:create-threat-model  --full --verbose

# Perform a more in depth scan (standard is --assessment-depth standard)
/appsec-advisor:create-threat-model --assessment-depth thorough
```

**Output Format**

By default, the threat modeler only write the threat model report (threat-model.ms) + internal model files. Some use cases may require to add additional output formats:
```bash

# Emit machine-readable exports alongside the Markdown report
/appsec-advisor:create-threat-model --yaml --sarif

# Create pentest-tasks.yaml that can be consumed by AI pentest tools liks striks
/appsec-advisor:create-threat-model --pentest-tasks

```

**CI & PR Integration**
If you want to use the threat modeler from your CI or PR workflow you can use the headless mode

```bash
# CI on every push — incremental with a hard timeout
./scripts/run-headless.sh --repo . --output docs/security --incremental --max-duration 1800

# PR gate — diffs HEAD against origin/main, fails the build on new Critical/High findings
./scripts/run-headless.sh --repo . --base origin/main --pr-mode --fail-on high
```

**Integrating Custom Requirements**

First you need to index ("harvest") them using the following script:
```bash
[`docs/harvester.md`](docs/harvester.md)
```
then, you need point the threat modeler to the url with the harvested requirements (alternatively via config):
```bash
/appsec-advisor:create-threat-model --requirements [<url>]
```
To test requirement inclusion you can use the included requirements example and use the also included mock to provide it:

```bash
$ python3 scripts/mock-server.py  
```

and then start

```bash
/appsec-advisor:create-threat-model --requirements http://127.0.0.1:4444/requirements.yaml
```

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

The following diagram shows the internal agentic pipeline which creates the threat model:

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
