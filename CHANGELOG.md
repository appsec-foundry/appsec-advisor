# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

<!-- Add entries here as work lands on dev; promote them into a dated heading at release. -->

### Added

- Findings now name the requirements they break, and mitigations quote the blueprint section that prescribes the fix. STRIDE analysis gets that blueprint while it works, so remediation follows the catalog.
- `threat-model.yaml` now preserves requirements provenance, verified abuse-case outcomes, and bounded business-context use, while Threat Dragon retains applicable traces as bounded text instead of dropping them.
- The Management Summary states compliance and lists the requirements that failed.
- The requirements audit says which catalog it uses and how old it is, then reports progress while it grades.
- An organization package records which appsec-advisor revision it was built from.
- `/appsec-advisor:status` shows the package, core and baseline versions with their origin, and `--check-updates` says whether baseline and core are still current.
- `/appsec-advisor:status` also lists the shipped skills with their policy state, the organization profile and the config file in effect.
- `/appsec-advisor:security-score` scores a repository from 0 to 100 using the scanners alone, without running a threat model.
- Source scans now flag LLM output that reaches rendering, interpreters or privileged actions unchecked.
- An organization profile can refresh the secure-coding baseline it vendors from its own source.
- Headless runs can start Claude Code through a wrapper given by the environment.
- Run Issues now reports a stage claiming more agent dispatches than the run spawned, a component whose findings all came from files the context routing never delivered, and a requirements assessment the YAML export does not carry.

### Changed

- A missing lockfile, an undigested base image, a missing workflow `permissions:` block and an unpinned action are now Medium instead of High.
- Business context supplied with `--context` is now captured by the run itself, and a source that cannot be read stops the run instead of being dropped in silence.
- The report's run statistics name the business-context file that was read and how many findings it applied to, and each of those findings records which declared fields apply to it.
- A stage transition no longer replays the whole resolved configuration, so a long run accumulates less orchestrator context.

### Fixed

- An agent call the host answers asynchronously is recorded as launched instead of rejected, so a finished agent no longer holds turns and budget claims that skipped abuse-case verification.
- A subagent that ends its last turn on a tool call is no longer recorded as failed.
- Stage 2 budgets its attempts per blocking cause, and the abort names the step that actually blocked.
- Abuse-case verification suppressed by a budget claim now says so in its receipts.
- A run with the requirements check switched off no longer fails its finished report on an empty catalog, nor reports a requirements disagreement from a stale cached count.
- The abort latch no longer blocks the run diagnostician or unrelated agents.
- Code references now use one balanced formatter across report sections and dependency ecosystems, so packages and complete snippets stay intact while surrounding prose remains outside code spans.
- `--skip-context` now runs without business context, instead of only skipping the question while still reading `docs/business-context.md`.
- A stored `docs/business-context.md` carrying a credential is now withheld from the analysis, the same way a supplied source is refused.
- The help no longer documents `--incremental`, `--pr-mode`, `--resume`, `--dry-run`, `--max-wall-time` and `--max-cost`, which the runtime rejects before a run starts.
- Business context supplied for one run no longer leaks into the next run in the same output directory.
- Artifact receipts are verified against the exact emitted action before every dispatch instead of a mutable plan snapshot, and missing, malformed, or stale verification state now fails closed.
- Run statistics now union exact dispatch events across overlapping and growing measurement windows instead of multiplying or permanently capping the stage count.
- A declared business context that maps to no component is now reported as a run issue instead of passing unnoticed.
- A finished run now clears its transient files from the output directory again; a run that ended with QA unclean still keeps them for diagnosis.

- The requirements harvester now takes the whole requirement section, recognises IDs written without brackets, and no longer duplicates entries.
- Section 9 now says when abuse-case verification did not run instead of reporting that no abuse case was identified, and a quick run names the skipped verification in its scope banner.
- A configured abuse-case release gate still ends the run, but now only after section 9 and the finding ranking are written, so the chain that failed the gate is on disk.

## 0.6.0-beta.1 (2026-08-23)

From this release a `-beta.N` suffix marks the Nth pre-release of the version in
front of it, so 0.6.0 follows once the line is stable. In 0.4 and 0.5 `-beta`
labelled the release line itself.

### Added

- A scan now reports the sandbox, approval, hook and tool-trust posture set by a repository's committed coding-agent configuration for Claude Code, Codex, Copilot, Gemini CLI and Kiro.
- The requirements harvester can emit selected functional requirements as single-file OpenSpec and SpecDD specifications.
- New and rebuilt analyses can collect optional business context interactively or through `--context`, use it to keep named sensitive-asset components in scope and to weight finding impact and order, or leave it out with `--skip-context`.
- LLM analysis now checks prompt-only behavioural limits, action auditability, permitted data classes, and approval gates, with organization policy supplied through `llm_policy`. See `docs/org-profiles.md`.
- Threat models can now be exported as alpha OWASP Threat Dragon v2 JSON for Threat Dragon and ThreatAtlas with `--formats threatdragon` or `create-threat-model --threatdragon`. See `docs/threat-dragon-export.md`.
- Trust boundaries now have stable IDs, can be declared in the repository, link to findings, and appear in the Markdown, YAML, query, and SARIF output.
- New `install-baseline`, `verify-baseline` and `remove-baseline` skills manage a secure-coding baseline in Claude Code's instruction files, with `verify-baseline --enforce` as a CI gate.
- New `help` skill lists available commands and the context, profile, and coach configuration in effect.
- Organization profiles can ship custom skills, a secure-coding baseline, and a banner, and disable shipped skills.
- A run that recorded an error now points at `/appsec-advisor:report-error`, which builds a local anonymised bundle and sends nothing.

### Changed

- Threat analysis now costs 39.8% less at quick depth and 26.8% less at thorough depth in reference runs.
- Live progress now shows each analysis step and current STRIDE component without duplicate or stale agent statuses or internal watchdog identifiers.
- Quick scans now use the Management Summary format, and report summaries and scope sections now explain the implementation-level limits of a code-derived threat model.
- The risk distribution now reports Low as `n/a` and names the reporting threshold when Low findings were excluded, instead of showing `0`.
- Critical attack walkthroughs now cover a broader mix of threat categories, prioritising Access Control and LLM Abuse when present.
- Verified findings at confirmed internet entry points can now be raised by one severity level, up to High.
- Findings of the same kind at different trust boundaries now stay separate instead of being consolidated into one row.
- Every finding in the register now names its STRIDE category next to the weakness class.
- The report verdict now appears in `threat-model.yaml` and leads `show-threat-model`, which also reports worst-case scenarios, matching finding IDs and severity counts, and stale-model warnings.

### Removed

- Threat-model runs now support only full, rebuild, and rerender, while incremental, resume, PR mode, assessment dry runs, baseline restore, `--max-wall-time`, `--max-cost`, and `APPSEC_LIVE_PHASE=1` are rejected before a run starts. Reassess a changed repository with `--full`, which preserves report history.
- The retired `--qa-scan-repo` option is no longer accepted.

### Fixed

- A scan no longer aborts when a component's analysis scope does not match its declared source paths; the scope is narrowed instead, cited evidence is preserved, and what changed is recorded.
- Architecture diagrams now place components in their declared tiers, include every folded component in tier finding counts, and identify components omitted from shortened labels.
- Finding registers and tables now classify scanner findings, avoid duplicate workflow-permission entries, sort by severity, keep risk labels consistent, and preserve finding references when IDs have gaps.
- Long, retried, interrupted, or partially malformed scans now recover or terminate cleanly without discarding completed work, while lock conflicts identify their owner and offer wait or takeover.
- Run summaries now distinguish analyzed components from the full inventory, include all completed agents in token and cost totals, and flag incomplete accounting.
- Per-run abuse-case selections now work at every depth and explain when they cannot be used.
- LLM endpoints are now included in the architecture, and prompt text alone no longer counts as a control against prompt injection.
- Cross-repository expectations and earlier assessment output no longer count as target-repository evidence.
- Client-side code is no longer modelled as a trust zone, preventing invalid browser-boundary crossings.
- Supply-chain analysis now rates only scanners the project actually runs and retains dependencies whose names begin with `php`, including vulnerable PHPUnit versions.
- Requested exports are now always written and listed, and invalid generated YAML can no longer replace the last valid report artifact.
- Large repositories can no longer crowd required security sections out of reconnaissance results.
- Reconnaissance now detects predictable OAuth-derived and bundled client credentials.
- A run can no longer walk past abuse-case verification into report rendering, which left the verified attack chains out of the report without saying so.
- A run now says when it analysed a component from only a fraction of its files, and keeps focus paths that the source-slice budget used to drop.
- A component that overshot its turn budget but finished its analysis is no longer reported as an error.
- The closing summary now splits mitigations by priority and offers its follow-ups as choices.
- Attack arrows in the architecture diagram now land on the tier band instead of inside it.
- The pre-render gate no longer rejects reports the composer accepts.

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
