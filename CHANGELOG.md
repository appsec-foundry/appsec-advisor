# Changelog

All notable changes to this project are documented here.

## Unreleased

### Fixed

- Actor discovery now rejects technique-, feature-, and persona-based duplicates before they can affect finding attribution. Actor slices are rebuilt from the finalized component inventory, and architect checks now inspect the actual resolved-actor schema.
- Actor resolution now remains active at quick depth, honors repository discovery opt-outs, reuses valid discovery caches, and validates the resolved actor artifact before rendering.
- Reports retain their contract-defined section numbers across Markdown, incremental runs, and exports; mitigation priority colors are applied inside the final QA pass.
- Referenced report IDs such as `M-001` and `F-001` stay on one line in HTML and PDF exports.

## 0.4.0-beta (2026-06-28)

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
