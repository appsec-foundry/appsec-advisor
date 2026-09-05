# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

<!-- Add entries here as work lands on dev; promote them into a dated heading at release. -->

### Fixed

- A headless run blocked by another run's lock now stops with its exit code instead of printing an interactive menu into the log.
- Interrupting an unattended headless run now actually stops it: the signal reaches Claude without a terminal, the run releases its own lock instead of blocking the next attempt for five minutes, and the printed recovery command offers `--rerender` when Stage 1 had already finished.
- `--full` and `--rebuild` no longer discard a completed Stage 1 without asking, and the `--force` needed to discard it on purpose now reaches the skill.
- The headless progress view no longer prints phase banners twice, shows how many STRIDE components have finished during the long parallel phase, and drops the internal call ids that pushed the readable part of each line off the screen.

### Added

- `/appsec-advisor:repo-profile` reports a repository's size, language split, build manifests and tracked-versus-untracked content before a scan is started — deterministic, no model, no network.

## 0.6.0-beta.2 (2026-09-04)

### Added

- Findings now name the requirements they break, and mitigations quote the blueprint section that prescribes the fix.
- The Management Summary states compliance and lists the failed requirements, and the requirements audit names the catalog it graded against and how old it is.
- A blueprint source can write its blueprints into a catalog file of its own, named by `catalog_file`.
- `threat-model.yaml` now keeps requirements provenance, verified abuse-case outcomes and business-context use, and the Threat Dragon export keeps applicable traces instead of dropping them.
- `/appsec-advisor:status` shows the installed package, the core and baseline versions, the shipped skills and the organization profile in effect; `--check-updates` says whether baseline and core are still current.
- `/appsec-advisor:security-score` scores a repository from 0 to 100 using the scanners alone, without running a threat model.
- Source scans now flag LLM output that reaches rendering, interpreters or privileged actions unchecked.
- `/appsec-advisor:update-baseline` refreshes an installed secure-coding baseline in place and reports when the published one has a new id; an organization profile can point it at its own source.
- Headless runs can start Claude Code through a wrapper given by the environment.
- Run Issues now reports a stage claiming more agent dispatches than the run spawned, a component analysed only from files the context routing never delivered, and a requirements assessment missing from the YAML export.
- `/appsec-advisor:authnz-review` can export its findings as pentest tasks with `--pentest-tasks`, `--pentest-format` and `--pentest-target`, defaulting to the organization profile.

### Changed

- A baseline that lags the configured one is now reported as outdated rather than foreign; both still fail an enforcing check.
- The final stage now polishes the report's prose instead of reviewing it a second time, reverting any rewrite that would change a finding, rating, evidence locator, link or number.
- A missing lockfile, an undigested base image, a missing workflow `permissions:` block and an unpinned action are now Medium instead of High.
- Business context supplied with `--context` is now recorded with the run and named in the run statistics, and a source that cannot be read stops the run instead of being dropped in silence.
- The completion summary's Next Steps now reads as self-contained alternatives, with the example questions on their own lines.
- `/appsec-advisor:help` no longer wraps in a terminal, and no longer documents options the runtime rejects before a run starts.

### Fixed

- A hook firing from a subdirectory now writes to the run's own output directory instead of creating a stray one beside it.
- A run that ends without releasing its lock no longer blocks later runs against the same output directory.
- A plain-HTTP URL in a comment no longer produces a cleartext-transport verdict for a bundled third-party file.
- An agent call the host answers asynchronously, and a subagent that ends its last turn on a tool call, are no longer recorded as failed and no longer hold turns and budget claims.
- Abuse-case verification that did not run is now named as such in section 9, in a quick run's scope banner and in the receipts, instead of being reported as no abuse case identified.
- A configured abuse-case release gate now ends the run only after section 9 and the finding ranking are written, so the chain that failed the gate is on disk.
- The Stage 2 abort now names the step that actually blocked.
- A run with the requirements check switched off no longer fails its finished report on an empty catalog, nor reports a disagreement from a stale count.
- The requirements harvester now takes the whole requirement section, recognises IDs written without brackets, no longer duplicates entries, and writes every format a source declares.
- Code references now use one formatter across report sections and dependency ecosystems, so packages and complete snippets stay intact.
- A stored `docs/business-context.md` carrying a credential is now withheld from the analysis, the same way a supplied source is refused.
- `--skip-context` now runs without business context, context from one run no longer leaks into the next run in the same output directory, and a declared context that maps to no component is reported as a run issue.
- Run statistics no longer multiply or cap the stage count when measurement windows overlap.
- A finished run now clears its transient files again; a run that ended with QA unclean keeps them for diagnosis.
- A run with `--slug` now stamps the PDF and HTML exports as well.

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
