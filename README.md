# appsec-advisor

[![Version](https://img.shields.io/badge/version-0.6.0--beta.6.dev0-orange.svg)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-plugin-5A67D8.svg)](https://docs.claude.com/en/docs/claude-code)
[![Security assessment](https://img.shields.io/badge/security%20assessment-repository--based-5A67D8)](docs/security-assessment.md)
[![SARIF](https://img.shields.io/badge/SARIF-v2.1.0-blue.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![codecov](https://codecov.io/gh/appsec-foundry/appsec-advisor/graph/badge.svg)](https://codecov.io/gh/appsec-foundry/appsec-advisor)

> ⚠️ **Beta.** `appsec-advisor` is under active development. Commands, schemas, and output may change without notice.

`appsec-advisor` is a Claude Code plugin that bundles application security tools for a repository. The tools read code and configuration, and each finding points to the code it is based on.

| Tool | What it does | Command |
|---|---|---|
| [AppSec Analyzer](#appsec-analyzer) | Assesses the whole application: architecture, security controls, findings, and what to fix first. | `/appsec-advisor:appsec-analyzer` |
| [Threat Analyst](#threat-analyst) | Analyzes a planned feature or a code change for threats. | `/appsec-advisor:analyze-threats` |
| [Requirements Audit](#requirements-audit) | Checks the repository against a security requirements catalog. | `/appsec-advisor:audit-security-requirements` |
| [Developer tools](#developer-tools) | Secure-coding baseline, security score, security hints, and change reviews for Claude Code and CI. | `/appsec-advisor:install-baseline`, `/appsec-advisor:security-score`, … |

[Quick start](#quick-start) · [AppSec Analyzer](#appsec-analyzer) · [Threat Analyst](#threat-analyst) · [Requirements Audit](#requirements-audit) · [Developer tools](#developer-tools) · [Enterprise rollout](#enterprise-rollout) · [Documentation](#documentation) · [How the plugin is built](#how-the-plugin-is-built) · [Contributing](#contributing)

---

## Security and data handling

> [!IMPORTANT]
> **Treat scanned repositories as untrusted input.** Repository content goes into the model context and may contain prompt injection. Untrusted mode is on by default; keep it on, and scan third-party or vendor code in a container or VM. See [Untrusted repositories](SECURITY.md#known-issues-untrusted-repositories).

An assessment sends selected source code, manifests, configuration, and any business context you supply to Anthropic. Secrets found in the code are masked. The assessment needs access to `api.anthropic.com` and cannot run air-gapped. Reports are rendered from validated data, and a run fails before publishing anything if an unmasked secret is found in its output.

## Quick start

You need [Claude Code](https://docs.claude.com/en/docs/claude-code), `git`, and Python 3.10+ with the `PyYAML` and `jsonschema` packages, for example installed with `python3 -m pip install PyYAML jsonschema`.

### 1. Install the plugin

```bash
claude plugin marketplace add appsec-foundry/appsec-advisor
claude plugin install appsec-advisor@appsec-foundry
```

If GitHub SSH access is not set up, run `export CLAUDE_CODE_PLUGIN_PREFER_HTTPS=1` first. Update later with `claude plugin update appsec-advisor@appsec-foundry` and restart Claude Code.

To use the development branch instead, clone it and pass the checkout to Claude Code:

```bash
git clone --branch dev https://github.com/appsec-foundry/appsec-advisor.git /path/to/appsec-advisor
cd /path/to/repository-to-assess
claude --plugin-dir /path/to/appsec-advisor
```

### 2. Run the AppSec Analyzer

Start Claude Code in the repository you want to assess and allow the commands the assessment needs:

```text
/appsec-advisor:check-permissions --update
```

This adds the missing rules, including `Bash(*)`, to the repository's `.claude/settings.local.json`. Restart Claude Code, then run:

```text
/appsec-advisor:appsec-analyzer
```

The results (`security-assessment.md` and `security-assessment.yaml`) go to a directory under your user data directory, not into the repository. `/appsec-advisor:status` shows where. Use `--output` to choose another directory.

An assessment usually takes tens of minutes; thorough runs can take over an hour. The plugin chooses the models itself, independent of your Claude Code session model, and stops at a cost limit: 10 USD for quick, 20 USD for standard, and 40 USD for thorough runs. See [model selection](docs/model-selection.md) and [depth and cost](docs/security-assessment.md#assessment-depth--cost-control).

### 3. Work with the results

```text
# Ask questions in plain language
what are the most critical findings?
what should I fix first?

# Fix findings, accept risks, or build a remediation plan
/appsec-advisor:triage-security-assessment

# Export as PDF, HTML, SARIF, Threat Dragon, or pentest tasks
/appsec-advisor:export-security-assessment
```

To reassess after code changes, run `/appsec-advisor:appsec-analyzer` again. Each run is a full assessment that continues the history of the previous one, and your review decisions are kept. `/appsec-advisor:help` lists all commands.

## AppSec Analyzer

Run the AppSec Analyzer when you take over a repository or want to know where its security stands; no architecture document or existing threat model is needed. The report models components, data flows, and trust boundaries, shows which security controls exist or are missing, and lists findings ordered by risk, each linked to the code, together with abuse cases and remediation guidance.

The assessment sees only the repository and any business context you add, not runtime behavior or production-only controls. Have an AppSec engineer review the findings before you act on them or accept a risk.

Findings are mapped to the [OWASP Top 10:2025](https://owasp.org/Top10/2025/). For LLM and agent applications, the assessment also covers the [OWASP LLM](https://genai.owasp.org/llm-top-10/) and [Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) Top 10. Results can be exported as PDF, HTML, SARIF, Threat Dragon, and pentest tasks.

**Example:** [Standard assessment of OWASP Juice Shop](https://github.com/appsec-foundry/appsec-advisor-examples/blob/main/threat-modeler/security-assessment-juice-shop-standard-v0.6.0b5.md). The [examples repository](https://github.com/appsec-foundry/appsec-advisor-examples) also has its diagrams and exports.

The runtime architecture of Juice Shop with its data flows and attack paths:

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/figure1-example-dark.svg">
  <img src="docs/images/figure1-example.svg" alt="Runtime architecture and attack paths in the Juice Shop assessment">
</picture>

The [appsec-analyzer README](https://github.com/appsec-foundry/appsec-analyzer#reports-and-exports) shows the other report diagrams: the build pipeline with its supply-chain attacks, and the threat actors with the business harm they can cause.

The [AppSec Analyzer guide](docs/security-assessment.md) covers depth, result storage, repository context, exports, costs, and limits.

### Abuse cases

An abuse case describes something an attacker or user must not be able to do, for example "a customer must not see another customer's orders". The plugin ships technical attack chains and business rules, and each run checks them against the code. If the code breaks a rule, the run adds a finding or confirms an existing one. If the code does not settle the question, the case is listed as open, not as safe.

To add a rule for one repository, put a YAML file into `docs/security/abuse-cases/`:

```yaml
schema_version: 2
abuse_cases:
  - id: REPO-AC-001
    kind: descriptive
    title: Employee approves their own expense report
    check: Check whether an employee can approve an expense report they submitted.
    scope_qualifier: {path_patterns: ["*expense*"]}
```

`/appsec-advisor:abuse-cases` lists all cases and their results. See [repository abuse cases](docs/security-assessment.md#abuse-cases-docssecurityabuse-cases) and, for organization-wide cases, [organization profiles](docs/org-profiles.md#abuse-cases).

### Several repositories

*Experimental.* To assess a system split across repositories as one, repeat `--repo` in the headless runner:

```bash
./scripts/run-headless.sh \
  --repo /repos/frontend \
  --repo /repos/backend \
  --output /reports/order-system \
  --hard-budget 50
```

The result is one report with a shared architecture model. See [non-interactive mode](docs/headless-mode.md#assess-several-repositories-as-one-system). To keep separate reports and still use the models of related repositories as context, see [cross-repository context](docs/security-assessment.md#cross-repo-context).

## Threat Analyst

*Experimental.* `/appsec-advisor:analyze-threats` looks at a planned feature or a code change and reports likely threats, recommended controls with their trade-offs, applicable requirements, and questions the team needs to answer. It is advisory and does not change the assessment. The threat analysis is part of the AppSec Analyzer.

| When | Command |
|---|---|
| Before coding | `/appsec-advisor:analyze-threats Let support staff export customer data as CSV.` |
| During implementation | `/appsec-advisor:analyze-threats --worktree --question "Can a tenant read another tenant's export?"` |
| Before merging | `/appsec-advisor:analyze-threats --base <target-branch> --head HEAD` |

See the [Threat Analyst guide](docs/threat-analyst.md).

## Requirements Audit

`/appsec-advisor:audit-security-requirements` checks the repository against a security requirements catalog. It is faster than a full assessment and suits pull-request gates and audit preparation.

```text
/appsec-advisor:audit-security-requirements
/appsec-advisor:audit-security-requirements --requirements https://appsec.int.example.com/appsec-requirements.yaml
```

Without a catalog of your own, start from `data/appsec-requirements-fallback.yaml` or the [requirements harvester](docs/harvester.md). See the [Requirements Audit reference](docs/security-requirements-audit-skill.md).

To check only a code change against the catalog, use [`/appsec-advisor:verify-requirements`](docs/dev-security-helper-usage.md#verify-requirements-skill) (*experimental*).

## Developer tools

| Tool | Use |
|---|---|
| [Secure-coding baseline](https://github.com/appsec-foundry/aiscb) | Add secure-coding rules to Claude Code with `install-baseline`; `update-baseline`, `verify-baseline`, and `remove-baseline` manage them. |
| [Security score](#security-score) | Quick 0–100 score from the scanners alone, without a model. |
| [Security Coach](docs/dev-security-helper-usage.md#security-coach-hook) (*experimental*) | Security hints while you write security-sensitive code. |
| [appsec-reviewer](docs/dev-security-helper-usage.md#appsec-reviewer-agent) (*experimental*) | Security review of a code change in Claude Code, an Agent SDK workflow, or CI with [appsec-reviewer-cli](docs/dev-security-helper-usage.md#appsec-reviewer-cli). |

See the [developer tools guide](docs/dev-security-helper-usage.md).

### Security score

`/appsec-advisor:security-score` gives a score from 0 to 100 based on the deterministic scanners, without running the full assessment. It is a quick indicator, not a risk rating. The score is computed by the AppSec Analyzer. For CI, build the packaged plugin once, install its bundled engine, and run the score through it:

```bash
make plugin-package OUT=/path/to/build
mkdir /path/to/plugin
unzip /path/to/build/assembly/appsec-advisor-*-staging.zip -d /path/to/plugin
python3 /path/to/plugin/scripts/composition_runtime.py setup --plugin /path/to/plugin
python3 /path/to/plugin/scripts/composition_runtime.py run --plugin /path/to/plugin --skill security-score -- score /path/to/project --json
```

`make plugin-package` needs network access on its first run; `setup` installs the bundled engine offline. The package currently supports Python 3.10 on Linux x86_64, and the project must be a committed Git checkout. See the [staging runbook](docs/internal/runbooks/composed-score-staging.md).

## Enterprise rollout

AppSec and platform teams can add their own requirements, defaults, skills, hooks, and MCP servers. The [packaging template](https://github.com/appsec-foundry/appsec-advisor-packaging-template) builds an internal plugin from a pinned upstream release, so you do not need to maintain a fork.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/orgpackaging-dark.svg">
  <img src="docs/images/orgpackaging.svg" alt="Example rollout from an upstream release to an Acme-branded plugin">
</picture>

See [Internal Plugin Packaging](docs/internal-plugin-packaging.md) and [Organization Profiles](docs/org-profiles.md).

## Documentation

| Goal | Start here |
|---|---|
| Run or configure the AppSec Analyzer | [AppSec Analyzer](docs/security-assessment.md) |
| Analyze a planned feature or code change | [Threat Analyst](docs/threat-analyst.md) |
| Configure models, cost, or logging | [Configuration](docs/configuration.md) and [Model Selection](docs/model-selection.md) |
| Configure requirements audits | [Requirements Audit](docs/security-requirements-audit-skill.md) |
| Run without interaction, for example in CI | [Non-interactive Mode](docs/headless-mode.md) |
| Product requirements | [requirements.md](requirements.md) |

If a run fails, `/appsec-advisor:report-error` checks a suspected plugin error locally and drafts a GitHub issue without logs, source code, or findings. You see the full draft and decide whether to publish it.

## How the plugin is built

`appsec-advisor` combines separately developed parts into one Claude Code plugin and adds the commands, hooks and display around them:

- the AppSec Analyzer engine from [appsec-analyzer](https://github.com/appsec-foundry/appsec-analyzer), which provides the assessment, the threat analysis and the security score and also runs on its own as a command-line tool;
- skills from [appsec-skills](https://github.com/appsec-foundry/appsec-skills) that call the engine, currently the security score;
- the [secure-coding baseline](https://github.com/appsec-foundry/aiscb), shipped as a copy in `data/baselines/`.

The marketplace release does not use the separate engine yet. It still runs the assessment pipeline in this repository, as does a `--plugin-dir` checkout, and neither needs a build step.

To build the preview that uses the separate engine, run:

```bash
make plugin-package
```

This takes the engine and skills at the commits listed in `data/plugin-package.json` and checks every downloaded file against its recorded checksum. The finished plugin only runs the copies bundled with it, never another version installed on the machine. So far the preview has two commands, `appsec-analyzer` and `security-score`; `analyze-threats` is not included yet. The [packaging guide](docs/internal-plugin-packaging.md#assemble-the-component-artifacts) covers updating the commits and installing the result.

## Related projects

- [appsec-analyzer](https://github.com/appsec-foundry/appsec-analyzer): the assessment, threat analysis and security score as a standalone command-line tool (alpha); see [how the plugin is built](#how-the-plugin-is-built).
- [appsec-advisor-tools](https://github.com/appsec-foundry/appsec-advisor-tools): launcher and CI templates for unattended assessments.
- [appsec-advisor-packaging-template](https://github.com/appsec-foundry/appsec-advisor-packaging-template): builds organization-specific plugin packages.
- [aiscb](https://github.com/appsec-foundry/aiscb): the secure-coding rules bundled with the plugin.

### Comparable tools

| Project | Focus | Difference |
|---|---|---|
| [tachi](https://github.com/davidmatousek/tachi) | Threat analysis of an architecture description | `appsec-advisor` derives the architecture from code and configuration. |
| [stride-gpt](https://github.com/mrwadams/stride-gpt) | STRIDE analysis from a description or codebase, several model providers | `appsec-advisor` runs in Claude Code and validates its output against schemas. |
| [OWASP pytm](https://github.com/OWASP/pytm) | Threat models written as Python code | `appsec-advisor` assesses an existing implementation. |
| [OWASP Threat Dragon](https://owasp.org/www-project-threat-dragon/) | Visual threat modeling | Assessments can be exported to Threat Dragon. |
| [OWASP ThreatAtlas](https://owasp.org/www-project-threatatlas/) | Collaborative threat-modeling workshops | Assessments can be imported as a starting point via the Threat Dragon export. |
| [OWASP Precogly](https://github.com/precogly/precogly) | Program-level threat modeling and compliance tracking | `appsec-advisor` assesses individual repositories. |
| [Claude Security](https://support.claude.com/en/articles/14661296-use-claude-security) | Scanning for exploitable vulnerabilities | `appsec-advisor` also finds architectural gaps that are not tied to a single line of code. |

## What's new in 0.6.0-beta.5

- **Abuse-case catalog.** Built-in business rules, such as "users must not see other users' data", alongside technical attack chains. You can add your own in one sentence each.
- **`/appsec-advisor:abuse-cases`** lists all abuse cases with their results.
- **Threat Analyst** checks a single abuse case against your code with `--abuse-case <ID>` and uses the existing assessment as context.
- **Several repositories, one report** with repeated `--repo` in headless mode.
- **Report improvements.** Critical findings are grouped by root cause, diagrams show trust boundaries more clearly, and secrets are masked in every output.

See the [changelog](CHANGELOG.md) for all changes.

## Contributing

Development happens on [`dev`](../../tree/dev). Branch from it and open your pull request against it; `main` holds tagged releases. See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and the [repository layout](CONTRIBUTING.md#repository-layout). Read [AGENTS.md](AGENTS.md) before changing runtime behavior, schemas, prompts, or report output. Report vulnerabilities through [SECURITY.md](SECURITY.md).
