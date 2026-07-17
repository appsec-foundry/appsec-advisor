# Changelog

All notable changes to this project are documented here.

## 0.5.0-beta (Unreleased)

### Added

- New Weakness Register: systemic and design-level weaknesses now get their own chapter. Findings are grouped by how strong the evidence is and by how a control is built (home-grown, misused, or missing), linked back to the findings behind them, and summarised as a security-principles verdict in the Management Summary. It also flags supply-chain risks (GitHub Actions on mutable tags/branches) and secrets committed to source. Broad CWE families no longer collapse unrelated issues into one.
- Access-control, crypto, and mass-assignment scanners now cover Java, Python, Go, PHP, C#/.NET, Ruby/Rails, and mobile — not just JavaScript/TypeScript.
- Headless runs can use a Claude subscription (`CLAUDE_CODE_OAUTH_TOKEN`), so CI works without an API key.
- Abuse cases can be picked from repo signals, path patterns, or a source probe, and gated on verified chains. A confirmed probe can turn into a regular finding.
- Figure 1 shows missing architecture tiers as transparent placeholders instead of leaving them out.
- MCP servers from an org profile are shipped in the packaged plugin.
- Org profiles can package the requirements gate policy per preset (`requirements.gate`: `mode`, `gate_on`, `priority_floor`), so a CI preset makes `verify-requirements` and `audit-security-requirements` gate by default. A per-run `--gate` / `--gate-on` / `--priority-floor` still overrides it.
- Org profiles can define their own Security Coach steering rules — a baseline and custom topics (triggers → guidance + requirement IDs) that add to or replace the built-in ones — without forking the plugin.
- Org profiles can package run policy: a per-preset CI severity gate (`guardrails.fail_on`) and an org-wide remote-fetch allowlist (`policy.url_allowlist`). The allowlist now also covers the requirements-catalog fetch, which previously bypassed the SSRF guard; internal catalog hosts stay reachable when listed.
- Org profiles can bundle their own Claude Code hooks (`hooks`), so one internal plugin ships a company's event handlers alongside everything else. The packager merges them into the built `hooks.json` and records each in `package-surface.json` (org-owned) for audit; the smoke test verifies them, and package policy can exclude one by id. Org hooks run at the event layer only — they never touch findings, severity, or schemas.
- OWASP Top 10 for Agentic Applications (2026, ASI) coverage: on an agentic surface (LLM wired to tools, memory, or other agents) the analyzer adds an Agentic-Top-10 lens and the AI/LLM Exposure callout tags each risk with a linked `ASIxx` badge.

### Changed

- OWASP Top 10 references updated from the 2021 to the **2025** edition (SSRF folded into A01, new A03 Software Supply Chain Failures and A10 Mishandling of Exceptional Conditions, categories re-lettered). Finding badges, coverage-gap checks, and the CWE mapping now target 2025.
- Management Summary reads in plain language — no finding IDs, file paths, or abuse-case IDs.
- Report order: Security Architecture before the Weakness Register, and leaner tables.

### Fixed

- Refuted findings are dropped before output; threat merging no longer loses locations or scenarios.
- Scanner findings now get full remediation steps instead of failing the mitigation check.
- Abuse-case verification skips expensive web-auth checks on weak matches, and chains cut off mid-way are marked provisional instead of "viable".
- IAC-005 no longer fires an npm `--ignore-scripts` finding on non-JavaScript images (e.g. Java/Maven).
- Cut-off runs now say what happened, and tell an API stall apart from a lost session. Retries reuse the existing context instead of rebuilding it.
- Long runs keep their place when the context window is compacted.
- `--slug` now also stamps the pentest-tasks export (`pentest-tasks-<slug>.yaml`), so several models with pentest tasks can share one output directory without overwriting each other.

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
