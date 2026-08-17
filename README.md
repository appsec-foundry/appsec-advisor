# appsec-advisor

[![Version](https://img.shields.io/badge/version-0.5.1--beta-orange.svg)](#)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-plugin-5A67D8.svg)](https://docs.claude.com/en/docs/claude-code)
[![SARIF](https://img.shields.io/badge/SARIF-v2.1.0-green.svg)](https://docs.oasis-open.org/sarif/sarif-v2.1.0/sarif-v2.1.0.html)
[![codecov](https://codecov.io/gh/matthiasrohr/appsec-advisor/graph/badge.svg)](https://codecov.io/gh/matthiasrohr/appsec-advisor)

> ⚠️ **Beta — not production ready.** `appsec-advisor` is under active development. Interfaces, schemas, and output may change without notice.

`appsec-advisor` is a Claude Code plugin for **code-derived threat modeling**: it reads the code and configuration in a repository, builds an architecture model, and runs STRIDE against it. The findings point back to repository evidence and include suggested fixes.

Run it again when the code changes. It does not replace workshops or scanners. It gives reviewers an implementation-level model to work from. The plugin also includes requirements audits, change reviews, and CI gates.

[Why appsec-advisor?](#why-appsec-advisor) · [Security](#security-notes) · [Quick start](#quick-start) · [Threat Modeler](#threat-modeler) · [Documentation](#documentation) · [Contributing](#contributing)

---

## Why appsec-advisor?

Most threat models start in a workshop and end up as a document. The document ages as the implementation changes. Scanners catch many code, dependency, secret, and configuration problems, but they rarely describe how the parts of the system trust each other.

`appsec-advisor` takes the repository as its source. It looks for missing controls at trust boundaries, implicit trust between services, unauthenticated paths, and other design risks. A new scan rebuilds that view from the current code.

The repository cannot explain business intent or decide which risks the organization should accept. Those decisions still belong to the people reviewing the model.

### Why this isn't a SAST tool

A scanner usually points to a bad line or code path. Some security problems do not have one: an internal service may trust every caller, or a boundary may have no control at all. Those are the problems `appsec-advisor` is meant to find.

The tool only sees the repository and any related repositories you configure. It cannot check runtime behavior, production-only controls, business processes, or user journeys. The report needs review before it drives remediation or risk acceptance.

## Security notes

> [!IMPORTANT]
> **Treat scanned repositories as untrusted input.** Repository content enters the LLM context and may attempt prompt injection. Untrusted mode is the default; keep it enabled and use a container or VM for third-party or vendor code. See [Security: Untrusted repositories](SECURITY.md#known-issues--untrusted-repositories).

**Data handling.** Source, manifests, and configuration for analyzed components are sent to Anthropic. Surfaced secrets are masked. The plugin requires `api.anthropic.com`, cannot run air-gapped, and uses provider-side prompt caching.

### Output safety

Python renders reports from validated structured data. If a run artifact contains an unmasked secret, the run fails before its outputs are considered publishable.

---

## Quick start

Requires [Claude Code](https://docs.claude.com/en/docs/claude-code), Python 3.10+, and `git` on `PATH`. Optional Mermaid dependencies provide stricter diagram validation; see the [Threat Modeler reference](docs/threat-modeler.md).

For a normal repository, run the Claude Code session on Sonnet 4.6. The orchestrator stays active for the whole scan, so its model has the largest effect on cost. Agent models are routed separately: a standard scan uses Sonnet 5 for judgment and writing, while STRIDE discovery stays on Sonnet 4.6. Very large repositories may need a Sonnet 5 session for the larger context window. See [Model Selection](docs/model-selection.md).

### 1. Start Claude Code in the target repository

Clone the plugin once, then start Claude Code from the repository you want to assess:

```bash
git clone https://github.com/matthiasrohr/appsec-advisor.git /path/to/appsec-advisor
cd /path/to/repository-to-assess
claude --plugin-dir /path/to/appsec-advisor
```

### 2. Configure permissions and create the model

Run the one-time permission setup:

```text
/appsec-advisor:check-permissions --update
```

Restart or reload Claude Code, then create the model:

```text
/appsec-advisor:create-threat-model
```

The assessment writes `threat-model.md` and `threat-model.yaml` to `docs/security/`.

### 3. Work with the model

```text
# Reassess components affected by code changes
/appsec-advisor:update-threat-model

# Record fix, accept-risk, or defer decisions
/appsec-advisor:review-threat-model

# Publish a reviewed model to version control
/appsec-advisor:publish-threat-model

# Or ask a question directly
what are the most critical findings?
what should I fix first?
does it cover SSRF?
```

Updates preserve finding IDs. Review decisions are stored separately, and publishing remains optional. Run `/appsec-advisor:help` for the complete command list.

## What's new in 0.5.1-beta & 0.5.2-beta

- Trust boundaries are assessed, drawn in the architecture diagram, and linked to findings that cross them.
- `install-baseline` and `verify-baseline` put the bundled [AI Secure Coding Baseline](https://github.com/matthiasrohr/ai-secure-coding-baseline) into Claude Code's instruction files and let CI verify it.
- The Cheap-STRIDE tier reduces cost outside thorough scans without skipping any STRIDE category.
- `--formats threatdragon` exports Threat Dragon v2 JSON for Threat Dragon and OWASP ThreatAtlas. The export remains alpha and opt-in.
- Organization profiles can include custom skills and baselines, configure the session banner, and disable individual skills.

See the [full changelog](CHANGELOG.md) for all changes.

## Threat Modeler

Run `/appsec-advisor:create-threat-model` to get:

- an architecture model with components, data flows, and trust boundaries;
- findings ordered by risk and tied to repository evidence;
- a Weakness Register for systemic and design patterns;
- mitigation guidance and generated diagrams;
- `threat-model.md` and `threat-model.yaml`, with optional PDF, HTML, SARIF, Threat Dragon, and pentest-task exports.

The report links findings to the [OWASP Top 10:2025](https://owasp.org/Top10/2025/). If the repository contains an LLM or agentic application, it also checks the relevant [OWASP LLM](https://genai.owasp.org/llm-top-10/) and [Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) categories.

**Example:** [Read a thorough assessment of OWASP Juice Shop](examples/threat-modeler/threat-model-juice-shop-thorough-v0.5.2.md) or browse [more examples](examples/threat-modeler/README.md).

![Threat Model Juice Shop Thorough](./examples/threat-modeler/threat-model-juice-shop-thorough-v0.5.2.figure1.svg)

Assessments consume model tokens and usually take tens of minutes; thorough runs may exceed an hour. The [Threat Modeler reference](docs/threat-modeler.md#assessment-depth--cost-control) covers depth, focused scans, repository context, measured costs, and limits.

## Requirements Audit

`/appsec-advisor:audit-security-requirements` checks the repository against an AppSec requirements catalog. Use it when you need a quicker requirements check for a pull request, compliance dashboard, or audit.

```text
# Use the configured catalog
/appsec-advisor:audit-security-requirements

# Use a catalog URL for this run
/appsec-advisor:audit-security-requirements --requirements https://URL/appsec-requirements.yaml
```

If you do not have a catalog, adapt `data/appsec-requirements-fallback.yaml` or use the [requirements harvester](docs/harvester.md). See the [Requirements Audit reference](docs/security-requirements-audit-skill.md) for setup and options.

## Additional developer tools

| Tool | Use |
|---|---|
| Secure-coding baseline | Install, verify, or remove secure-coding instructions with `install-baseline`, `verify-baseline`, and `remove-baseline`. |
| [Security Coach](docs/dev-security-helper-usage.md#security-coach-hook) (*experimental*) | Add security guidance while writing security-sensitive code. |
| [appsec-reviewer](docs/dev-security-helper-usage.md#appsec-reviewer-agent) (*experimental*) | Embed change review in Claude Code or an Agent SDK workflow. |
| [verify-requirements](docs/dev-security-helper-usage.md#verify-requirements-skill) (*experimental*) | Review an interactive diff against the requirements catalog. |
| [appsec-reviewer-cli](docs/dev-security-helper-usage.md#appsec-reviewer-cli) (*experimental*) | Run the same change review in CI or other automation. |

See the [developer tools guide](docs/dev-security-helper-usage.md) for commands and configuration.

## Report a failed run

Create an anonymized diagnostic bundle with:

```text
/appsec-advisor:report-error
```

Review the bundle before attaching it to a GitHub issue. The command excludes source code, findings, evidence, and report content, and sends nothing automatically.

## Enterprise rollout

AppSec and Platform teams can add their own requirements, defaults, guardrails, skills, hooks, and MCP servers. The [organization packaging template](https://github.com/matthiasrohr/appsec-advisor-packaging-template) keeps that configuration in a separate internal package built from a pinned upstream release. The core agents stay unchanged.

![Example rollout from an upstream release to an Acme-branded plugin](docs/images/orgpackaging.svg)

See [Internal Plugin Packaging](docs/internal-plugin-packaging.md) and [Organization Profiles](docs/org-profiles.md).

## Documentation

| Goal | Start here |
|---|---|
| Run or configure a threat model | [Threat Modeler](docs/threat-modeler.md) |
| Add repository context or trust-boundary declarations | [Repo-local context](docs/threat-modeler.md#repo-local-context) |
| Configure models, cost, logging, or organization settings | [Configuration](docs/configuration.md) and [Model Selection](docs/model-selection.md) |
| Configure requirements audits | [Requirements Audit](docs/security-requirements-audit-skill.md) |
| Run without interaction or integrate with CI | [Non-interactive Mode](docs/headless-mode.md) |
| Package the plugin for an organization | [Internal Plugin Packaging](docs/internal-plugin-packaging.md) |
| Browse complete report examples | [Threat Modeler Examples](examples/threat-modeler/README.md) |
| Develop or contribute | [Contributing](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md) |
| Report a vulnerability | [Security Policy](SECURITY.md) |

## Project structure

Agents read the repository and handle the parts that need security judgment. Python handles the repeatable work: validating data, rendering reports, creating exports, and enforcing gates. Schemas define what passes between the two.

The main directories are `agents/`, `skills/`, `scripts/`, `schemas/`, `templates/`, and `tests/`. See the [repository layout](CONTRIBUTING.md#repository-layout) for the complete map and the tests required for each kind of change.

## Related projects

### Companion repositories

- [appsec-advisor-packaging-template](https://github.com/matthiasrohr/appsec-advisor-packaging-template) builds organization-specific plugin packages from pinned upstream releases.
- [ai-secure-coding-baseline](https://github.com/matthiasrohr/ai-secure-coding-baseline) contains the secure-coding rules bundled by the plugin.

### Comparable tools

| Project | What it does | How it differs |
|---|---|---|
| [tachi](https://github.com/davidmatousek/tachi) | Runs multi-agent analysis over an architecture description. | Tachi starts with the description. `appsec-advisor` starts with code and configuration. |
| [stride-gpt](https://github.com/mrwadams/stride-gpt) | Runs provider-independent STRIDE analysis from a description or codebase. | `stride-gpt` works with several model providers. `appsec-advisor` is tied to Claude Code and puts validation and stable IDs around the result. |
| [OWASP pytm](https://github.com/OWASP/pytm) | Stores a threat model as Python code. | With pytm, developers write the model. `appsec-advisor` derives it from the implementation. |
| [OWASP Threat Dragon](https://owasp.org/www-project-threat-dragon/) | Provides a visual editor for threat models and data-flow diagrams. | Threat Dragon starts with a diagram drawn by a modeler. `appsec-advisor` can generate that starting point from a repository. |
| [OWASP ThreatAtlas](https://owasp.org/www-project-threatatlas/) | Supports team workshops on shared diagrams. | ThreatAtlas records the workshop. `appsec-advisor` keeps a code-derived model current between sessions. |
| [OWASP Precogly](https://github.com/precogly/precogly) | Manages threat models, libraries, and compliance links across a program. | Precogly is the maintained system of record. `appsec-advisor` creates a model for one repository at a time. |
| [Claude Security](https://support.claude.com/en/articles/14661296-use-claude-security) | Scans codebases for exploitable vulnerabilities. | Claude Security focuses on implementation flaws. `appsec-advisor` also looks for architectural gaps with no single vulnerable line. |

The Threat Dragon export can carry generated models into Threat Dragon and ThreatAtlas.

## Contributing

Development happens on [`dev`](../../tree/dev). Branch from it and target it with your pull request; `main` contains tagged releases.

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and repository conventions. Read [AGENTS.md](AGENTS.md) before changing runtime behavior, schemas, prompts, permissions, cleanup behavior, or report output. Report vulnerabilities through [SECURITY.md](SECURITY.md).
