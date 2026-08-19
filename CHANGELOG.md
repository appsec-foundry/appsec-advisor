# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

<!-- Add entries here as work lands on dev; promote them into a dated heading at release. -->

### Added

- New context-v2 analysis runtime projects only the facts each component needs instead of a shared prompt context; full and rebuild scans use it by default, `APPSEC_CONTEXT_V2=0` keeps the legacy producer. On the reference OWASP Juice Shop this reduced the API cost by 39.8 % at quick depth ($25.02 → $15.06) and by 26.8 % at thorough depth ($48.01 → $35.15). See `docs/threat-modeler.md`.
- A new or rebuilt analysis now takes optional business context from pasted text or a URL, interactively, through `--context`, or not at all with `--skip-context`. See `docs/threat-modeler.md`.
- A context-v2 scan now shows Stage 1 as one task per analysis step, each numbered within its stage and carrying a component counter while STRIDE runs, instead of a single task for its whole duration.
- An organization profile can declare an `llm_policy` of permitted data classes and approval-required actions. See `docs/org-profiles.md`.
- The LLM lens now asks four questions the OWASP Top 10 leaves out, from prompt-only guardrails to permitted data classes.
- Named sensitive assets in `docs/business-context.md` now mark the components that handle them for full-depth analysis.
- New alpha export: `--formats threatdragon` writes OWASP Threat Dragon v2 JSON, which also imports into OWASP ThreatAtlas; `create-threat-model --threatdragon` writes it during a scan. See `docs/threat-dragon-export.md`.
- Trust boundaries now have stable IDs, can be declared in the repository, link to findings, and appear in the Markdown, YAML, query, and SARIF output.
- New `install-baseline`, `verify-baseline` and `remove-baseline` skills manage a secure-coding baseline in Claude Code's instruction files, with `verify-baseline --enforce` as a CI gate.
- New `help` skill lists available commands and the context, profile, and coach configuration in effect.
- New `examples/abuse-cases.yaml` is a commented, ready-to-adapt abuse case for `--abuse-case-file` and `<repo>/.appsec/abuse-cases/`. See `docs/org-profiles.md`.
- Sessions now open with a status banner naming the plugin, threat model, and loaded baseline; `APPSEC_BANNER=0` disables it.
- Organization profiles can ship custom skills, a secure-coding baseline, and a banner, and disable shipped skills.
- A run that recorded an error now points at `/appsec-advisor:report-error`, which builds a local anonymised bundle and sends nothing.
- Architecture decisions are now recorded in `docs/internal/decisions.md`, each with the guard that enforces it.

### Fixed

- A scan that reaches the merge step twice now repeats the dispatch it already issued instead of aborting with every STRIDE result on disk.
- A weakness that falls back to its weakness class for a mechanism ID now gets a valid one instead of aborting the scan at merge validation.
- The QA gate no longer demands an attack walkthrough the renderer did not select, so a report whose §3 gives a reserved slot to a triage-elevated finding passes instead of entering a repair loop.
- A scan records per-agent token usage again, and says so when part of its compute went unrecorded.
- The running-total banner and `--max-cost` now count sub-agent spend and stop at the end of the run instead of the end of the session.
- An abuse-case file or case id named for a single scan now runs at any depth, and a scan that cannot use it says so instead of skipping it silently.
- The findings register lists an unrestricted CI/CD workflow token permission once instead of twice.
- A guardrail named only in a system prompt no longer counts as a control against the prompt-injection abuse case.
- Cross-repository expectation mismatches now remain hypotheses until target-repository evidence supports a finding.
- An endpoint that reaches a language model is now always modelled: reconnaissance records the call as a structured signal, marks the route, and matches a prompt-injection abuse case.
- A scan no longer ends when an analysis agent writes a malformed artifact: the controller asks that agent once to correct it, naming the exact contract violations.
- Quick-depth scans no longer abort after the architecture stage.
- An interrupted or failed run now releases its lock and reports its abort immediately instead of showing an unknown phase until the heartbeat ages out.
- Headless runs no longer report every completed agent as failed with zero tokens; per-agent usage and cost come from the agent's own return.
- Live progress now reports one start and one outcome per agent, follows the freshest phase, and treats turn consumption as progress instead of a warning.
- Inspecting a run's status no longer writes to its state.
- Final QA now counts rendered finding cards instead of stray global anchors, and preserves F/T cross-references when finding IDs have gaps.
- Client-side code is no longer modelled as a trust zone, preventing invalid browser-boundary crossings.
- `Automated SCA scanning` is now rated only from scanners the pipeline actually invokes, not from a tool name in a comment, a step label, or string data.
- Requested exports are now always written and listed in the completion summary.
- Reconnaissance now reserves its final turns for validated output, so large repositories cannot crowd out required security sections.
- Reconnaissance now excludes prior assessment directories even when the output path was user-named.
- Reconnaissance now surfaces predictable OAuth-derived and bundled client credentials.
- The Findings index now orders entries by effective severity, with Critical findings first and stable IDs within each tier.
- Completion summaries now distinguish STRIDE-analyzed components from the full modeled inventory.
- Composer dependency analysis now retains real packages whose names begin with `php`, including known-bad PHPUnit versions.
- Final threat-model YAML is now schema-validated before it replaces the prior canonical artifact.

### Changed

- Business context now breaks technically equal finding and mitigation ranking ties without changing severity or mitigation priority.
- The risk distribution now reports Low as `n/a` and names the reporting threshold when the register severity floor excluded it, instead of showing `0`.
- Attack walkthroughs now balance chain relevance with threat-category diversity across the findings the register shows as Critical, reserving coverage for Critical Access Control and LLM Abuse findings when present.
- Verified findings at a confirmed internet ingress can now be raised by one severity band, up to High, within CWE caps.
- Findings of the same kind at different trust boundaries now stay separate instead of consolidating into one row.
- Every finding in the register now names its STRIDE category next to the weakness class.
- `threat-model.yaml` now includes the report verdict.
- `show-threat-model` now reports matching finding IDs and severity counts, opens with the report verdict and worst-case scenarios, and triage warns when the model is stale.
- The Management Summary, §1 Scope and §11 now state that the report is a code-derived threat model at implementation level, and what that does not cover.
- The pre-flight summary states the STRIDE depth and the depth tradeoff in one line each instead of repeating what the configuration rows already show.

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
