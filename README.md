# appsec-advisor

[![Version](https://img.shields.io/badge/version-0.5.1--beta-orange.svg)](#)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-plugin-5A67D8.svg)](https://docs.claude.com/en/docs/claude-code)
[![SARIF](https://img.shields.io/badge/SARIF-v2.1.0-green.svg)](https://docs.oasis-open.org/sarif/sarif-v2.1.0/sarif-v2.1.0.html)
[![codecov](https://codecov.io/gh/matthiasrohr/appsec-advisor/graph/badge.svg)](https://codecov.io/gh/matthiasrohr/appsec-advisor)

> ⚠️ **Beta — not production ready.** `appsec-advisor` is under active development. Interfaces, schemas, and output may change without notice.

`appsec-advisor` is a Claude Code plugin for **code-derived threat modeling**. It builds the model from a repository's code and configuration, applies STRIDE, and produces evidence-backed findings with mitigation guidance.

It complements security workshops and code scanners. Re-run it as the code changes, then use expert review for business context, difficult findings, and risk decisions. It also supports requirements audits, change reviews, and CI gates.

[Why appsec-advisor?](#why-appsec-advisor) · [Security](#security-notes) · [Quick start](#quick-start) · [Threat Modeler](#threat-modeler) · [Documentation](#documentation) · [Contributing](#contributing)

---

## Why appsec-advisor?

Threat models created in workshops or design reviews often become stale as the implementation changes. Most automated tools cover dependencies, code patterns, secrets, and configuration errors, but not the architecture between them.

`appsec-advisor` derives that architectural view from the repository. It looks for missing trust-boundary controls, implicit service trust, unauthenticated paths, and similar design risks. Re-running the scan updates the model instead of leaving a separate document to drift.

People still provide intent, business impact, and risk decisions. The tool provides a repeatable technical first pass so specialists can focus on the areas that need judgment.

### Why this isn't a SAST tool

SAST finds flaws on concrete code paths. `appsec-advisor` examines the architecture around those paths, including risks with no single vulnerable line. It sits next to scanners rather than replacing them.

The analysis is limited to the repository and configured related repositories. It cannot verify runtime behavior, production-only controls, business processes, or user journeys. Treat the report as review input, not a release verdict.

## Security notes

> [!IMPORTANT]
> **Treat scanned repositories as untrusted input.** Repository content enters the LLM context and may attempt prompt injection. Untrusted mode is the default; keep it enabled and use a container or VM for third-party or vendor code. See [Security: Untrusted repositories](SECURITY.md#known-issues--untrusted-repositories).

**Data handling.** Source, manifests, and configuration for analyzed components are sent to Anthropic. Surfaced secrets are masked. The plugin requires `api.anthropic.com`, cannot run air-gapped, and uses provider-side prompt caching.

### Output safety

Python renders reports from validated structured data. If a run artifact contains an unmasked secret, the run fails before its outputs are considered publishable.

---

## Quick start

Requires [Claude Code](https://docs.claude.com/en/docs/claude-code), Python 3.10+, and `git` on `PATH`. Optional Mermaid dependencies provide stricter diagram validation; see the [Threat Modeler reference](docs/threat-modeler.md).

For normal repositories, use Sonnet 4.6 for the Claude Code session that orchestrates the run; this is the main cost lever. The plugin routes agent work separately. Standard scans use Sonnet 5 for judgment and report quality while keeping STRIDE discovery on Sonnet 4.6. Very large repositories may benefit from a Sonnet 5 session for its larger context window. See [Model Selection](docs/model-selection.md).

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

`/appsec-advisor:create-threat-model` reads the repository and produces:

- an architecture model with components, data flows, and trust boundaries;
- risk-ranked findings tied to repository evidence;
- a Weakness Register for systemic and design patterns;
- mitigation guidance and generated diagrams;
- `threat-model.md` and `threat-model.yaml`, with optional PDF, HTML, SARIF, Threat Dragon, and pentest-task exports.

Findings are cross-referenced to the [OWASP Top 10:2025](https://owasp.org/Top10/2025/). Repositories with LLM or agentic surfaces also receive the applicable [OWASP LLM](https://genai.owasp.org/llm-top-10/) and [Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) lenses.

**Example:** [Read a thorough assessment of OWASP Juice Shop](examples/threat-modeler/threat-model-juice-shop-thorough-v0.5.2.md) or browse [more examples](examples/threat-modeler/README.md).

![Threat Model Juice Shop Thorough](./examples/threat-modeler/threat-model-juice-shop-thorough-v0.5.2.figure1.svg)

Assessments consume model tokens and usually take tens of minutes; thorough runs may exceed an hour. The [Threat Modeler reference](docs/threat-modeler.md#assessment-depth--cost-control) covers depth, focused scans, repository context, measured costs, and limits.

## Requirements Audit

`/appsec-advisor:audit-security-requirements` checks the repository against an AppSec requirements catalog. It is faster than a full threat model and can be used for PR gates, compliance dashboards, and audit preparation.

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

AppSec and Platform teams can package the plugin with organization-owned requirements, defaults, guardrails, skills, hooks, and MCP servers. The [organization packaging template](https://github.com/matthiasrohr/appsec-advisor-packaging-template) builds an internal plugin from a pinned upstream release without modifying the core agents.

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

Agents inspect the repository and make security judgments. Python validates structured artifacts, renders reports, generates exports, and enforces gates. Schemas define the data exchanged between those stages.

The main directories are `agents/`, `skills/`, `scripts/`, `schemas/`, `templates/`, and `tests/`. See the [repository layout](CONTRIBUTING.md#repository-layout) for the complete map and the tests required for each kind of change.

## Related projects

### Companion repositories

- [appsec-advisor-packaging-template](https://github.com/matthiasrohr/appsec-advisor-packaging-template) builds organization-specific plugin packages from pinned upstream releases.
- [ai-secure-coding-baseline](https://github.com/matthiasrohr/ai-secure-coding-baseline) contains the secure-coding rules bundled by the plugin.

### Comparable tools

| Project | Primary focus | Difference from `appsec-advisor` |
|---|---|---|
| [tachi](https://github.com/davidmatousek/tachi) | Multi-agent analysis from an architecture description. | The description is the main input; `appsec-advisor` starts with repository evidence. |
| [stride-gpt](https://github.com/mrwadams/stride-gpt) | Provider-independent STRIDE analysis from descriptions or code. | It supports multiple model providers; `appsec-advisor` runs in Claude Code and adds validated artifacts and stable finding IDs. |
| [OWASP pytm](https://github.com/OWASP/pytm) | Threat models maintained as Python code. | Developers declare the model; `appsec-advisor` derives it from the implementation. |
| [OWASP Threat Dragon](https://owasp.org/www-project-threat-dragon/) | Visual threat modeling and editable data-flow diagrams. | A modeler draws the system; `appsec-advisor` can generate and export a starting model. |
| [OWASP ThreatAtlas](https://owasp.org/www-project-threatatlas/) | Collaborative workshops on shared diagrams. | It supports the workshop; `appsec-advisor` keeps a code-derived model current between sessions. |
| [OWASP Precogly](https://github.com/precogly/precogly) | Program-level modeling, libraries, and compliance traceability. | It is a maintained system of record; `appsec-advisor` produces a per-repository model. |
| [Claude Security](https://support.claude.com/en/articles/14661296-use-claude-security) | Enterprise codebase vulnerability scanning. | It targets exploitable implementation flaws; `appsec-advisor` also covers architectural gaps without one vulnerable line. |

The Threat Dragon export can carry generated models into Threat Dragon and ThreatAtlas.

## Contributing

Development happens on [`dev`](../../tree/dev). Branch from it and target it with your pull request; `main` contains tagged releases.

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and repository conventions. Read [AGENTS.md](AGENTS.md) before changing runtime behavior, schemas, prompts, permissions, cleanup behavior, or report output. Report vulnerabilities through [SECURITY.md](SECURITY.md).
