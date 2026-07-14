# Changelog

All notable changes to this project are documented here.

## Unreleased

### Added

- Abuse cases can now be selected from repository signals, path patterns, or a bounded source probe, with per-scan case files and optional release gates for verified chains.
- A verifier-confirmed source-probe step can now become a normal finding when its abuse-case definition supplies classification and remediation metadata, so it participates in risk ranking and mitigation tracking.

## 0.5.0-beta (2026-07-14)

### Added

- Deterministic access-control, crypto, and mass-assignment scanners now run across Java, Python, Go, PHP, C#/.NET, Ruby/Rails, and mobile stacks, not just JavaScript/TypeScript.
- Headless runs can bill against a Claude subscription via `CLAUDE_CODE_OAUTH_TOKEN`, so CI and dispatch runs work without an interactive login or an API key.
- MCP servers declared in an org profile are written into the packaged plugin's `.mcp.json` and wired up on install.

### Changed

- Systemic and design-level weaknesses get their own report chapter and link to the findings that support them. A weakness register groups findings by evidence and implementation strategy, flags home-grown or misused central security controls, and surfaces a security-principles verdict in the Management Summary. Broad CWE families no longer collapse unrelated attack paths into one weakness.
- Management Summary verdicts use plain language and drop finding IDs, file paths, and abuse-case IDs; the detail stays in the findings and architecture sections.

### Fixed

- Evidence-refuted findings are no longer rendered. New scans drop them before output; incremental scans note the resolution in the changelog.
- Threat merging keeps every merged location and scenario and can no longer drop a finding through a `keep` decision.
- More consistent mitigation rendering and consolidated finding locations.
- Repair passes no longer drift across re-renders.
- Abuse-case verification now filters cases using recon evidence, avoiding expensive web-authentication checks triggered by documentation, scanner metadata, or broad CWE matches.
- Parallel report rendering now uses focused §7 and Management Summary agents, avoiding the full renderer prompt for both roles. Standard runs defer duplicate Mermaid validation to the required QA stage; repair attempts skip the changelog audit until the final successful render.

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
