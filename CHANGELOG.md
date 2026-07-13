# Changelog

All notable changes to this project are documented here.

## Unreleased

### Fixed

- Threat models no longer render evidence-refuted findings. New scans drop those candidates before output; incremental scans record resolutions in the changelog instead.

## 0.4.1 (2026-07-13)

### Added

- Multi-language scanner coverage: deterministic access-control, crypto, and mass-assignment rules now run against Java, Python, Go, and PHP codebases (plus C#/.NET, Ruby/Rails, and mobile stacks), so findings are no longer skewed toward JavaScript/TypeScript projects.
- Headless runs support Claude subscription billing via `CLAUDE_CODE_OAUTH_TOKEN`, enabling unattended CI/dispatch runs without an interactive login or an API key.
- Packaged plugins can ship organization MCP endpoints: MCP servers declared in an org profile are emitted into the built plugin's `.mcp.json`, so internal servers are wired up on install.

### Improved

- Architectural and design-level weaknesses are surfaced more prominently. A unified weakness register classifies findings by evidence tier and implementation strategy, flags home-grown or misused central security controls, and hoists a security-principles verdict into the Management Summary — so systemic design flaws are no longer buried under individual instance findings.

## 0.4.0-beta (2026-07-07)

First public release. Still a beta: good for guided use, but not ready to run unattended in CI yet.

### Added

- Generate STRIDE threat models from a Git repository with `/appsec-advisor:create-threat-model`: architecture diagrams, trust boundaries, risk-ranked findings, affected components, and remediation guidance.
- Three analysis depths: `quick`, `standard`, and `thorough`.
- Reports export to Markdown, YAML, PDF, HTML, SARIF, and pentest task lists.
- Each finding is attributed to the threat actors who could realistically reach it.
- Abuse cases chain individual findings into end-to-end attack scenarios.
- Incremental scans re-analyze only what changed since the last run.
- Feed in project context (business context, known threats, related repositories) or shared organization profiles to improve results.
- Audit a repository against a security-requirements catalog as a standalone check (`/appsec-advisor:audit-security-requirements`).
- Publish a reviewed report with `/appsec-advisor:publish-threat-model`; reports are git-ignored by default.

### Known limitations

- Run `/appsec-advisor:check-permissions --update` once after installing.
- Large repositories (more than ~8–10 components) are slower and not yet parallelized.
- Supply-chain risk is reported as posture only, not per-CVE. Use a dedicated scanner such as Dependabot, Snyk, or Trivy for that.
