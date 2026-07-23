# appsec-advisor

[![Version](https://img.shields.io/badge/version-0.5.0--beta-orange.svg)](#)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-plugin-5A67D8.svg)](https://docs.claude.com/en/docs/claude-code)
[![SARIF](https://img.shields.io/badge/SARIF-v2.1.0-green.svg)](https://docs.oasis-open.org/sarif/sarif-v2.1.0/sarif-v2.1.0.html)
[![codecov](https://codecov.io/gh/matthiasrohr/appsec-advisor/graph/badge.svg)](https://codecov.io/gh/matthiasrohr/appsec-advisor)

> ⚠️ **Beta — not production ready.** `appsec-advisor` is under active development. Interfaces, schemas, and output may change without notice.

`appsec-advisor` is a Claude Code plugin for repository-based threat modeling. It derives a security architecture model from code, identifies trust boundaries and data flows, applies STRIDE, and produces reviewable findings.

Beyond threat modeling, it supports requirements audits, change reviews, and CI gates. AppSec teams can tailor it for internal use; see [Enterprise rollout](#enterprise-rollout).

[Why appsec-advisor?](#why-appsec-advisor) · [Security](#security-notes) · [Quick start](#quick-start) · [Workflow](docs/threat-modeler.md#threat-model-lifecycle) · [Documentation](#documentation) · [Project structure](#project-structure) · [Contributing](#contributing)

**Model compatibility.** `appsec-advisor` supports current Anthropic models and is tuned for Sonnet 5. Economy defaults keep token-heavy work on Sonnet 4.6 and use Sonnet 5 selectively; explicit per-agent pins remain available. Each scan prints the resolved routing. See [Session Model](docs/threat-modeler.md#session-model).

---

## Why appsec-advisor?

### The problem

Workshop and design-review threat models become stale as the implementation changes.

Most automated security tools focus on dependencies, code patterns, secrets, and misconfigurations. `appsec-advisor` covers the gap to manual architecture review by identifying risks such as missing trust-boundary controls, implicit service trust, and unauthenticated internal paths.

### Why this isn't a SAST tool

SAST finds implementation flaws in specific code paths. `appsec-advisor` models the system around them: components, trust boundaries, data flows, attacker goals, and missing controls. Its primary output is an architecture-level threat grounded in repository evidence.

It complements rather than replaces code scanners. Threat modeling can surface risks with no vulnerable line to point to, such as missing authorization, an undefined trust boundary, or a service with excessive trust.

## Security notes

> [!IMPORTANT]
> **Treat scanned repositories as untrusted input.** Repository content enters the LLM context and may attempt prompt injection. The interactive setup grants unrestricted shell access to avoid mid-run prompts, so scan third-party or vendor code with `--trust-mode untrusted` inside a container or VM. See [Security: Untrusted repositories](SECURITY.md#known-issues--untrusted-repositories).

**Data handling.** Only source, manifests, and configuration for analyzed components are sent to Anthropic; surfaced secrets are masked. The plugin requires `api.anthropic.com`, cannot run air-gapped, and uses provider-side prompt caching.

**Output safety.** Python renders reports from validated structured data, and publishing stops if the secret scan finds an unmasked secret.

---

## Quick start

Requires [Claude Code](https://docs.claude.com/en/docs/claude-code), Python 3.10+, and `git` on `PATH`. Optional Mermaid dependencies add stricter diagram validation; see the [Threat Modeler reference](docs/threat-modeler.md).

**1. Start Claude Code in the target repository**

Clone the plugin once, then start Claude Code from the repository you want to assess:

```bash
git clone https://github.com/matthiasrohr/appsec-advisor.git /path/to/appsec-advisor
cd /path/to/repository-to-assess
claude --plugin-dir /path/to/appsec-advisor
```

Typing the plugin namespace in Claude Code should show the registered skills:

```text
/appsec-advisor:
```

**2. Configure permissions and create the model**

Run the one-time permission setup:

```text
/appsec-advisor:check-permissions --update
```

Restart or reload Claude Code, then create the model:

```text
/appsec-advisor:create-threat-model
```

The assessment writes `threat-model.md` and `threat-model.yaml` to `docs/security/`.

**3. Continue with the model**

After the first assessment, use the model directly from the Claude Code console:

```text
# Reassess components affected by code changes
/appsec-advisor:update-threat-model

# Review findings and record fix, accept-risk, or defer decisions
/appsec-advisor:review-threat-model

# Optionally publish a reviewed model to version control
/appsec-advisor:publish-threat-model

# Or ask about the model without a command
what are the most critical findings?
what should I fix first?
does it cover SSRF?
```

Updates preserve finding IDs; questions are read-only and cite them. Review decisions are stored separately, and publishing remains optional.

For depth, cost, focused scans, actors, and repository context, see the [Threat Modeler reference](docs/threat-modeler.md).

## What's new in 0.5-beta

**Ask questions about your threat model — just type them in the Claude Code console.** No command to remember: the new `ask-threat-model` skill picks up any question about the model, so there is no report to re-read and no export to grep:

```text
what are the most critical findings?
what should I fix first?
does it cover SSRF?
```

Answers stay grounded in the model and cite finding IDs. See the [Quick start](#quick-start).

- **`review-threat-model`** — decide fix, accept, or defer in bulk, with owners.
- **Weakness Register** — surfaces systemic and design weaknesses with a security-principles verdict.
- **Beyond JavaScript** — access-control, crypto, and mass-assignment checks now cover Java, Python, Go, PHP, C#/.NET, Ruby/Rails, and mobile.

[Full changelog](CHANGELOG.md)

## Threat Modeler

`/appsec-advisor:create-threat-model` derives an architecture model from the repository and runs STRIDE analysis to produce a structured security review.

Each assessment is:

- **Repository-grounded:** Derives architecture, trust boundaries, and data flows from code and configuration.
- **Organization-aware:** Incorporates requirements, known threats, and related services when configured.
- **Architecture-focused:** Identifies risks such as implicit service trust and unauthenticated paths that code scanners often miss.
- **Validated:** Passes findings through schemas, validation, and fixed report templates.
- **Stable across reruns:** Preserves finding IDs so changes remain traceable.

The report covers architecture observations, risk-ranked findings, affected components, remediation guidance, and generated diagrams. Default outputs are `threat-model.md` and `threat-model.yaml`; optional exports include PDF, HTML, SARIF, and pentest task lists.

The result is a starting point for security review, not a release verdict. An AppSec engineer or security architect should validate findings before they drive remediation, exceptions, or risk acceptance.

**Standards coverage.** Findings are cross-referenced to established OWASP catalogs, rendered as linked reference badges in the report:

- [OWASP Top 10:2025](https://owasp.org/Top10/2025/) — the web application security risks, mapped per finding with a deterministic coverage check that flags any category with no identified threat.
- [OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/llm-top-10/) — applied as an additional lens whenever the repository has an LLM/AI surface.
- [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) — applied on top of the LLM lens when the surface is agentic (an LLM wired to tools, memory, or other agents).

**Example:** [Read a thorough assessment of OWASP Juice Shop](examples/threat-modeler/threat-model-juice-shop-thorough-v0.5.md) — or browse [more examples](examples/threat-modeler/README.md).

![Threat Model Juice Shop Thorough](./examples/threat-modeler/threat-model-juice-shop-thorough-v0.5.figure1.svg)

Assessments consume model tokens and typically take tens of minutes; thorough runs may exceed an hour. The [Threat Modeler reference](docs/threat-modeler.md#assessment-depth--cost-control) compares measured costs by depth and model and documents hard cost and time limits.

**Session model.** For normal runs, use Sonnet 4.6 (`/model claude-sonnet-4-6`); it delivered comparable threat models at lower cost in our tests and is already the headless default. See [Session Model](docs/threat-modeler.md#session-model) for routing and overrides.

The committed pricing values used for local cost calculation can be adjusted independently of model routing. See [Pricing](docs/configuration.md#pricing) for the scope and precedence of those values.

## Requirements Audit

`/appsec-advisor:audit-security-requirements` grades the repository against an internal AppSec requirements catalog. It is faster than a full threat model and fits PR gates, compliance dashboards, and audit preparation.

```text
# Run with the configured catalog
/appsec-advisor:audit-security-requirements

# Run standalone with a URL (no config change needed)
/appsec-advisor:audit-security-requirements --requirements https://URL/appsec-requirements.yaml
```

The requirements audit and threat modeler use the same configured catalog.

If you do not have a catalog, adapt `data/appsec-requirements-fallback.yaml`. The [requirements harvester](docs/harvester.md) can build and refresh the YAML from Confluence, Antora, or static HTML.

See the [Requirements Audit reference](docs/security-requirements-audit-skill.md) for catalog setup, status values, and flags.

## Additional developer tools

These developer tools provide security guidance while code is being written or reviewed. They use the configured requirements catalog, or the bundled baseline when none is configured.

| Tool | Type | Scope | Entry point | When to use it |
|---|---|---|---|---|
| [Security Coach hook](docs/dev-security-helper-usage.md#security-coach-hook) (*experimental*) | Hook | Prompt-time guidance | `APPSEC_COACH=1 claude --plugin-dir /path/to/appsec-advisor` | Add security guidance to Claude's context while you write security-sensitive code. |
| [appsec-reviewer](docs/dev-security-helper-usage.md#appsec-reviewer-agent) (*experimental*) | Agent | Change review engine | `appsec-reviewer` | Embed the reviewer in a Claude Code or Agent SDK workflow. |
| [verify-requirements](docs/dev-security-helper-usage.md#verify-requirements-skill) (*experimental*) | Skill | Interactive diff review | `/appsec-advisor:verify-requirements` | Review current, staged, or base-ref changes from an interactive Claude Code session. |
| [appsec-reviewer-cli](docs/dev-security-helper-usage.md#appsec-reviewer-cli) (*experimental*) | CLI | CI diff review | `appsec-reviewer-cli review --diff origin/main --output security-review.md` | Run the same requirements review headlessly in CI or other automation. |

Full guide: [`docs/dev-security-helper-usage.md`](docs/dev-security-helper-usage.md) · Requirements catalog setup: [`docs/harvester.md`](docs/harvester.md) · Security Coach: [`docs/security-coach-skill.md`](docs/security-coach-skill.md).

For persistent verbose event output and log rotation limits, see [Logging](docs/configuration.md#logging). The `--verbose` flag remains the normal per-run choice.

## Report a failed run

If a threat-model run fails, create an **anonymized** diagnostic bundle:

```text
/appsec-advisor:report-error
```

Review it, then attach it to a GitHub issue if you choose. The command excludes source code, findings, evidence, and report content, and sends nothing automatically.

## Enterprise rollout

AppSec and Platform teams can build an organization-branded plugin while continuing to use the upstream analysis, schemas, and validation. The quickest path is the [organization packaging template](https://github.com/matthiasrohr/appsec-advisor-packaging-template), which creates a separate internal repository for the organization profile, package policy, and CI configuration.

Together, organization profiles and package policy let teams:

- use internal requirements and organization or platform context;
- standardize assessment depth, outputs, and quality controls;
- enforce cost, duration, remote-source, and CI guardrails;
- include only approved skills, hooks, and MCP servers.

The example below combines a pinned upstream release with organization-owned configuration to build an internal plugin package.

![Example rollout from an upstream release to an Acme-branded plugin](docs/images/orgpackaging.svg)

For the full build and publishing workflow, see the [packaging runbook](docs/internal-plugin-packaging.md). The [org profile reference](docs/org-profiles.md) documents supported controls, and [configuration](docs/configuration.md#organization-profile) explains profile selection.

## Documentation

Use these routes to move from the overview into the detailed documentation without losing the context of the workflow you are following.

| Goal | Start here |
|---|---|
| Run, focus, or configure a threat model | [Threat Modeler](docs/threat-modeler.md) |
| Configure external context, local pricing, logging, or an organization profile | [Advanced Configuration](docs/configuration.md) |
| Choose an assessment depth or understand model cost | [Model Selection, Cost & Context Window](docs/model-selection.md) |
| Configure and run requirements audits | [Requirements Audit](docs/security-requirements-audit-skill.md) |
| Build or refresh a requirements catalog | [Requirements Harvester](docs/harvester.md) |
| Use developer-time security guidance | [Dev Security Helper](docs/dev-security-helper-usage.md) |
| Run locally without interaction or integrate with CI | [Non-interactive Mode](docs/headless-mode.md) |
| Package the plugin for an organization | [Internal Plugin Packaging](docs/internal-plugin-packaging.md) |
| Configure organizational context and guardrails | [Organization Profiles](docs/org-profiles.md) |
| Browse complete report examples | [Threat Modeler Examples](examples/threat-modeler/README.md) |
| Develop or contribute to the plugin | [Contributing](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md) |
| Report or understand security concerns | [Security Policy](SECURITY.md) |

## Project structure

The repository separates agent-driven discovery and prose from deterministic contracts, validation, rendering, and release gates.

```text
appsec-advisor/
├── .claude-plugin/     # Claude Code plugin manifest
├── skills/            # User-invocable skills and workflows
├── agents/            # Specialized agents, phase instructions, and shared standards
├── data/              # Policy data, taxonomies, budgets, and report contracts
├── schemas/           # YAML and JSON contracts for intermediate and delivered artifacts
├── templates/         # Deterministic report and fragment templates
├── scripts/           # Orchestration, validation, rendering, export, and CLI helpers
├── hooks/             # Claude Code hooks and security steering configuration
├── docs/              # User references, contracts, runbooks, and design analysis
├── examples/          # Reference reports and enterprise packaging examples
├── tests/             # Contract, regression, integration, and end-to-end tests
└── config.json        # Shared plugin defaults
```

The central implementation boundary is deliberate:

- Agents inspect the repository, build security context, and author analysis.
- Schemas define the shape of artifacts exchanged between pipeline stages.
- Python validates structured artifacts, renders reports, generates exports, and enforces release gates.
- Tests protect schema, report, permission, cleanup, and compatibility contracts from drift.

For the contributor-level path map and the tests required for each kind of change, see [Repository layout](CONTRIBUTING.md#repository-layout) and [AGENTS.md](AGENTS.md).

## Roadmap

- Evaluate proposed changes before merge with scoped threat-model updates for branches, pull requests, and merge requests.
- Extend beyond Claude Code to other coding agents (OpenAI Codex, GitHub Copilot, and similar), keeping the analysis engine agent-agnostic.
- Broaden production readiness across more languages, architectures, and deployment models, including performance on large multi-component repositories.
- Graduate developer-time guidance and change-review tools from experimental to supported.
- Import third-party threat models as non-authoritative context and aggregate per-repository models into cross-repository views.
- Analyze specifications as first-class input, emitting clearly labeled design findings only for explicit insecure statements.
- Make trust boundaries stable and directly linkable from findings, including the violated assumption and attacker impact.
- Let users override recon's component assessment (exposure, sensitivity, type) via a `.appsec/components.yaml` overlay to parametrize STRIDE coverage — escalation-only first, de-escalation logged and surfaced.
- Publish a packaged marketplace release after the beta.

## Related projects

- **[matthiasrohr/appsec-advisor-packaging-template](https://github.com/matthiasrohr/appsec-advisor-packaging-template)**: Template for an internal package with organization defaults and requirements.

- **[davidmatousek/tachi](https://github.com/davidmatousek/tachi)**: Agent-based threat modeling from architecture descriptions.

- **[mrwadams/stride-gpt](https://github.com/mrwadams/stride-gpt)**: STRIDE threat modeling from text descriptions.

- **[Claude Security](https://support.claude.com/en/articles/14661296-use-claude-security)**: Anthropic's repository vulnerability scanner for Enterprise plans.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, repository conventions, repository layout, and required tests.

Read [AGENTS.md](AGENTS.md) before changing runtime behavior, schemas, prompts, permissions, cleanup behavior, or report output. Security vulnerabilities follow the private reporting process in [SECURITY.md](SECURITY.md).