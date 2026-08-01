# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

<!-- Add entries here as work lands on dev; promote them into a dated heading at release. -->

### Added

- New alpha export: `--formats threatdragon` writes OWASP Threat Dragon v2 JSON, which also imports into OWASP ThreatAtlas. See `docs/threat-dragon-export.md`.
- `create-threat-model` accepts `--threatdragon`, so a scan can write `threat-model.threatdragon.json` directly instead of requiring a separate export run. Opt-in only — no depth or preset implies it.
- New `install-baseline` skill: installs a secure-coding baseline into Claude Code's instruction files, for this machine or a single repository.
- New `verify-baseline` skill: reports which baseline is loaded and through which file; `--enforce` turns that report into a non-zero exit for CI.
- New `remove-baseline` skill: stops an installed baseline loading by dropping its import, and deletes the file only after confirming the path.
- New `help` skill: a short command reference with example calls, plus the repo context files, organization profile, and coach state actually in effect.
- A session now opens with a status banner: plugin identity and help, then the threat model, then the secure-coding baseline under its configured name, with its id and scope. `APPSEC_BANNER=0` turns it off.
- Organizations can ship their own skills in their org profile.
- Organizations can ship their own secure-coding baseline in their org profile, by http(s) URL or git repository, and require it with `baseline.enforce`.
- Organizations can set the banner headline and help URL in their org profile, or ship a build that opens silently.
- Trust boundaries now have stable IDs, can be declared in the repository, link to findings, and appear in the Markdown, YAML, query, and SARIF output.
- A run that recorded an error now points at `/appsec-advisor:report-error`, which builds a local anonymised bundle and sends nothing.
- The triage console now opens with the same freshness verdict as `show-threat-model`, and warns before fixing code against a stale model.

### Fixed

- Client-side code is no longer modelled as a trust zone. A browser SPA, mobile app or desktop client executes on the user's device, on the attacker's side of every server-side control, so a crossing out of it is now anchored at the internet and folds into the perimeter it duplicated, while a crossing into it — which enforces nothing and protects nothing — is removed, with the reason recorded in the signal coverage report. A crossing into client code that names a real control is kept. On a reference scan this took nine boundaries down to seven, one of which was the same API perimeter counted twice.
- `Automated SCA scanning` is now rated only from scanners the pipeline actually invokes. A tool name in a comment, a step label, or string data no longer counts as evidence, and a CodeQL workflow on its own no longer counts as dependency scanning.
- Skills an organization disabled through `skill_toggles` are now actually refused, with the configured reason — whether the command is typed or Claude invokes it. Nothing enforced the policy before. Recovery skills stay reachable, so a broken run can still be cleaned up.
- An organization's `skill_toggles` policy now takes effect from the first command in a session. It was only read from the file a scan writes into its output directory, so before any scan every skill ran while the status output reported it as disabled.
- Any shipped skill can now be named in `skill_toggles`. Ten of the twenty-one — including `review-threat-model`, `ask-threat-model` and `update-threat-model` — were missing from an internal list, and naming one aborted the package build instead of doing nothing.
- Trust-boundary tables now use canonical endpoints and clearly distinguish internet-facing, outbound, internal, inferred, and unresolved crossings.
- The Trust Boundaries table is readable again: each row states the crossing, the enforcement point and the folded-in components once instead of three overlapping times, the linked findings column keeps the severity dot and the id (the title is one click away) and no longer collapses into stacked single characters, and emphasis around an inline code span no longer leaks raw `**` and `\` markers into the rendered cell.
- The trust-boundary note on a finding now leads with the crossing and the point being made, instead of restating the crossing three times before the statement.
- A trust-boundary reference on a finding is now always a working link into the Trust Boundaries table; a boundary below the table's row cap rendered as a bare identifier.
- `show-threat-model` cited findings by an identifier that appears nowhere in the report; it now uses the `F-NNN` identifiers the report shows.
- `show-threat-model` reported severity counts that contradicted the report — 27 Critical against the report's 14 on a reference scan — and could list a Medium finding as Critical.

### Changed

- The `Run Issues` block now appears only when something reached the delivered report; a slow phase, a budget warning, or a recovery that worked no longer makes a sound run look broken.
- A finding with verified evidence at a confirmed internet ingress can now be raised by one severity band, up to High, while CWE caps still apply.
- `show-threat-model` now opens with the report's verdict and the worst-case scenarios behind it, and points at the other skills before the numbers rather than after them.
- `threat-model.yaml` now carries the report's verdict, so other tools can state the assessment's conclusion without reading the Markdown.
- Findings of the same kind at different trust boundaries now stay separate instead of consolidating into one row.
- A trust-boundary reference on a finding now carries the catalogue's `🌐 Public` rating when the crossing is a confirmed internet ingress.
- Figure 1's Trust Boundaries legend now marks a crossing the analysis did not confirm, instead of showing it like a confirmed one.
- SARIF results now name the crossing and its exposure instead of a bare `tb-N`, and the run carries the whole boundary catalogue.
- The Threat Dragon export now folds a finding's trust-boundary crossing into the threat description and marks a data flow across a confirmed internet crossing as `isPublicNetwork`.

## 0.5.1-beta (2026-07-26)

### Added

- Authentication scans now detect security-question password resets and password policies that allow fewer than eight characters.
- `ask-threat-model` can now filter findings by severity, component, and evidence state.
- Headless runs now end with a per-model token and cost breakdown, taken from Claude Code's own accounting and matching what `/cost` reports in an interactive session.
- New screening depth tier that analyzes the internal tail on a smaller budget while everything carrying attack surface or data keeps full depth — on by default in quick and standard scans, off in thorough, overridable with `--cheap-stride` and `--no-cheap-stride`. On the reference OWASP Juice Shop at standard depth this reduced the API cost from $33.21 to $30.83.
- Scans of agentic applications now check Claude Code permissions and hooks for unsafe behavior.

### Changed

- Large scans now analyze components in resumable batches, improving speed without sacrificing coverage.
- Supply-chain scoring now focuses on exploitable risks and better recognizes common Python and npm safeguards.
- Clean reports now skip redundant semantic review, reducing run time and cost.
- Architecture and evidence checks are now faster on larger repositories.
- Attack walkthroughs now present attacker actions in a clearer order and format technical details more consistently.
- The pre-flight now reports the STRIDE threat cap and tail screening in one shorter `STRIDE depth` row.

### Fixed

- Full and rebuild scans are now more reliable on long runs without weakening final checks.
- Evidence results are no longer lost while abuse cases are processed.
- Merged findings now retain their locations and sources, while unrelated architectural risks remain separate.
- Stored XSS is now reported as confirmed only when data is persisted and later reaches an unsafe HTML output.
- Headless runs can resume after analysis and provide clearer failure details and recovery guidance.
- Component analysis no longer runs serially by mistake, and concurrent runs no longer interfere with each other.
- Packaged plugins now work correctly with custom namespaces in headless mode.
- Security architecture reports no longer contain empty control sections or broken two-factor authentication links.
- Container diagrams now stay within their size limit on larger models.
- A finding now carries the same severity everywhere in the report; the attack-path table no longer disagrees with the rest of the document.
- An attack chain is rated fully viable only when every assessed step is confirmed, and its control assessment follows the verifier's reading of the code instead of a keyword guess.
- Attack demonstrations containing an unsigned token or an SQL-injection payload no longer trip the secret gate or get masked into an unusable reproduction step.

## 0.5.0-beta (2026-07-18)

### Added

- `/appsec-advisor:ask-threat-model` answers free-form questions about an existing threat model ("what should I fix first?", "does it cover SSRF?") — no report to re-read, no export to grep. Answers are grounded in the model and cite finding IDs.
- `/appsec-advisor:review-threat-model` is now a guided triage console: a short risk verdict, then work through findings by top risk, fix, or area and decide fix / accept / defer in bulk. Writes a prioritised `remediation-plan.md` and remembers your decisions across re-scans.
- Weakness Register: systemic and design-level weaknesses get their own chapter, grouped by evidence strength and by how a control is built (home-grown, misused, or missing), and summarised as a security-principles verdict. Flags supply-chain risks (mutable GitHub Actions refs) and committed secrets; broad CWE families no longer merge unrelated issues.
- Access-control, crypto, and mass-assignment scanners now cover Java, Python, Go, PHP, C#/.NET, Ruby/Rails, and mobile — not just JavaScript/TypeScript.
- Headless runs can use a Claude subscription (`CLAUDE_CODE_OAUTH_TOKEN`), so CI works without an API key.
- Abuse cases can be picked from repo signals, path patterns, or a source probe, and gated on verified chains. A confirmed probe can turn into a regular finding.
- Figure 1 shows missing architecture tiers as transparent placeholders instead of leaving them out.
- MCP servers from an org profile are shipped in the packaged plugin.
- Org profiles can package the requirements gate policy per preset (`requirements.gate`), so a CI preset gates on requirements by default. Per-run `--gate` / `--gate-on` / `--priority-floor` still overrides.
- Org profiles can define custom Security Coach steering rules (a baseline plus topics) without forking the plugin.
- Org profiles can package run policy: a per-preset CI severity gate (`guardrails.fail_on`) and an org-wide remote-fetch allowlist (`policy.url_allowlist`), which now also covers the previously-unguarded requirements-catalog fetch.
- Org profiles can bundle their own Claude Code hooks, merged into the built `hooks.json` and recorded for audit. Org hooks run at the event layer only — never touching findings, severity, or schemas.
- OWASP Top 10 for Agentic Applications (2026): on an agentic surface (LLM wired to tools, memory, or other agents), adds an Agentic-Top-10 lens and tags each AI/LLM risk with a linked `ASIxx` badge.

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
