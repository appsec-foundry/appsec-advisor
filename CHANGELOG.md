# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

<!-- Add entries here as work lands on dev; promote them into a dated heading at release. -->

### Added

- Headless assessments accept HTTPS and SSH Git URLs alongside local repositories, with token or SSH authentication and automatic temporary checkout cleanup.
- Experimental: the headless runner assesses several local checkouts as one system when `--repo` is repeated, producing one threat model, report, and Figure 1 that name the repository of every component and finding; it runs STRIDE on Sonnet 5.5 and names each role's model at the start, connects calls between the selected repositories, including through proxies, when a Kubernetes Service, a compose file, or the repository name at an exposed port identifies the receiver, and replaces an earlier combined report in the same output directory only with `--rebuild`.
- Experimental: `/appsec-advisor:create-threat-model2` assesses one repository through the deterministic controller in the background, asks the same business-context questions, writes its report to `docs/security` like `/appsec-advisor:create-threat-model`, limits cost by depth unless you set a budget, and stops with `--stop`.
- Standard and thorough runs check business abuse cases such as access to other users' data or a bypassed approval, thorough runs add up to three application-specific cases, and repositories and organization profiles can add their own as one-sentence checks. Confirmed cases enter the register, at High for access to other users' data, extra rights, or a misused privileged function, and appear on the findings they confirm, cases with cited code but no control found enter it as unproven, and unresolved cases can become team questions.
- The Threat Analyst checks concrete threat hypotheses or a single defined abuse case (`--abuse-case <ID>`) against selected files at a Git revision and rates each attack-chain step with evidence.
- The Threat Analyst can explore a redacted, read-only copy of the repository with `--explore`, answers a concrete question about a change with `--question`, and recommends controls linked to existing threat-model findings.
- `/appsec-advisor:abuse-cases` lists the defined technical and business abuse cases with their origin and recorded result, and `/appsec-advisor:abuse-cases <ID>` explains one case step by step.
- Rerunning `/appsec-advisor:create-threat-model` over an existing model, or passing `--incremental`, re-analyzes only components whose files changed and carries the others' STRIDE results, and is refused before any change when the previous model cannot be carried.
- Figure 1 marks network trust boundaries within a column and into every data store, and Figure 1b draws evidenced build trust boundaries at the column borders they cross, pale when only inferred.

### Changed

- Headless controller assessments analyze and verify up to four components at a time instead of one after another, within the same cost budget.
- Headless controller assessments spend less time preparing repeated source and evidence checks.
- The headless controller console lists each STRIDE component and each verified abuse case with its title on its own line, and ends with one line per delivered file.
- In a terminal, the headless controller's status line turns a spinner and draws a progress bar with each running model call's duration and activity, also with `--verbose`; CI logs are unchanged. During threat analysis each running component has its own bar, and progress follows finished rather than started components.
- Headless controller threat analysis rates a finding as confirmed exploitable when the source shows the insecure code, an input an attacker can reach and no stopping control, instead of leaving most findings unproven for lack of a definition.
- The report's Scope section names how many source files per component had no route, lead or security signal and were not individually examined, how many program files belong to no component at all, and which targets the analysis read but could not decide, instead of leaving these coverage gaps to console warnings or unreported.
- The Figure 1 legend keeps three columns with narrower sections when the diagram is slightly narrower than three standard sections, instead of two columns with a wide empty gap.
- A source target the headless controller's threat analysis could not decide is reported with its file and the reason, such as a helper outside the read source, instead of an arbitrary line of the file.
- The headless controller console counts corrected model answers per role on each phase's done line instead of listing every rejection; `--verbose` still names each reason. Coverage statements, such as files no target covered, are shown as information instead of warnings, collapsed into one line unless `--verbose` lists them per component.
- Headless output is coloured in a terminal, wraps long header values under their column, and honours `NO_COLOR` and `FORCE_COLOR`; logs and CI output carry no colour codes.
- Headless controller assessments run repository discovery on Sonnet 5.5 instead of Haiku, so large repositories no longer stall or fail there; `APPSEC_RECON_SCANNER_MODEL` still selects another model.
- Headless controller assessments need fewer and cheaper model calls: threat-analysis, trust-boundary and control jobs receive their cited source up front, threat analysis decides each route resource once together with its handler and guards instead of every registration line, source files without a security signal are named as not individually examined instead of analysed one by one, a result rejected only for citing a blank or comment line is corrected by asking for that line alone instead of regenerating the whole analysis, and model calls no longer pay the one-hour prompt-cache rate for prompts that are never reused.
- The Management Summary merges Top Weaknesses and Top Mitigations into Remediation Priorities, which follows the verdict and lists the measures to do first under each root cause together with its lasting fix; root causes are ranked by the most severe finding they resolve, and only P1 and P2 measures appear as measures to do first.
- The Critical Attack Tree is replaced by Critical Findings by Root Cause, which links each Critical finding, including OS command injection and caller-controlled authentication bypasses, to its weakness record and the structural fix that closes it.
- A finding whose code an abuse-case verification confirms is shown as verified instead of ambiguous.
- Threat Analyst design questions, reviews, and hypothesis checks use the repository's threat model as context unless you pass `--isolated`, and a review also reads the files the change imports and the files earlier findings cite.
- `appsec-reviewer-cli` refuses a repository that carries its own Claude Code configuration unless you pass `--trust-mode trusted`.
- Standard and thorough runs use Sonnet 5.5 instead of Sonnet 5 for triage, merging, report authoring, and abuse-case verification, and run costs price the 5.5 models.
- Repository abuse cases belong in `docs/security/abuse-cases/` beside the business context; `.appsec/abuse-cases/` is still read.

### Fixed

- Headless controller models keep their verified abuse cases in `threat-model.yaml` instead of reporting the analysis as not run while the report shows them.
- A headless controller run started from a sandboxed Claude Code session in the target repository no longer stops as "Selected source state changed" when the sandbox creates empty placeholder files there.
- A headless controller run no longer stops in architecture modeling when a browser client calls routes whose authentication stays unknown next to proven ones.
- A stopped headless controller run, by `--stop`, Ctrl-C or a closed terminal, ends its model calls, exits with code 3 and continues with `--resume`, also when it stopped during a model call or a model process died without reporting its cost.
- A failed export no longer leaves a new `threat-model.yaml` beside an older report; the headless controller replaces the report files only after all of them were produced.
- A headless controller run whose route inventory or auth scanner failed says so in its warnings, and a broken abuse-case catalog or organization profile stops the run instead of reading as "no abuse case matched".
- A route whose handler module default-exports an anonymous function or a factory, such as `export default () => listUsers`, is attributed to that module and its handler is analysed, instead of to a wrapper such as an async-error helper.
- Routes guarded by `express-jwt`, `koa-jwt`, `express-oauth2-jwt-bearer` (`auth`) or `express-basic-auth`, also through a repository helper such as `isAuthorized = () => expressJwt({...})`, are recognised as authenticated with their credential type instead of being left unresolved; a guard configured not to reject, or whose options are passed by name, stays unresolved.
- Headless controller models preserve distinct client-to-API authentication variants across multiline calls and shortened evidence, without duplicating already covered interfaces or treating request payloads as destinations.
- Headless controller Figure 1 labels components with the functions their code proves, such as JWT issuer, MFA verifier, OAuth client, file upload, WebSocket endpoint and blockchain client, instead of only those a finding implies.
- Headless controller reports take a data flow's authentication from the routes it cites, as single-repository runs do, and show an administrator role when actor discovery confirms one from an access check; the discovery job now receives the role checks that name a privileged role.
- Headless controller threat analysis and evidence review receive bounded source excerpts for imported helpers, earlier route guards and cited exploit steps up front, whichever component owns them, reducing missing-context gaps without adding analysis jobs.
- Headless controller findings retain a short title for their primary mitigation instead of losing it at the analysis handoff.
- Every Critical finding of a headless controller assessment shows at least two attack steps, a missing-control finding may cite the commented-out guard that proves the control is off, a feature flag that switches a vulnerable branch on no longer makes a finding unproven, and a finding whose evidence review stays inconclusive is shown as an unproven practice without a score in single-repository runs too.
- Headless controller threat analysis treats a secret it sees masked in the source, such as a private key, as the hard-coded secret it replaced instead of a placeholder.
- A renamed or archived copy of an earlier report that holds no program code is no longer read as source code, so its old results are not cited as evidence.
- Headless controller assessments give every model the result rules its output tool cannot enforce and derive STRIDE category coverage, identity fields and title locations themselves, so far fewer answers are sent back for correction; control domains are limited to the report's sections.
- The headless controller no longer warns that an LLM provider is unmodeled when the architecture already connects the component to it.
- Headless controller assessments see each source line with its line number, so cited lines no longer drift deep in a file, and a control, flow or boundary that cites a blank line or comment is corrected in its own job instead of failing every later analysis that relies on it.
- Headless controller threat analysis no longer stops on source files that begin with a license header or other comment.
- Headless controller threat analysis decides a route in the component that owns its handler, reading the guards where the route is registered, instead of leaving it unresolved when handler and registration belong to different components; it also receives the source the supplied controls cite and reads an Angular component together with its template, evidence reviews receive each finding's anchor up front, and a target that already links a finding needs no separate reason.
- A configured address quoted as inline code in the controller's Security Architecture section, such as a CORS origin, no longer forces the section to be rewritten.
- Hardcoded secrets that a finding cites, including keys passed directly as call arguments, are masked in every report output, and the secret gate fails when one remains.
- Trust boundaries are detected regardless of source layout, keep separately deployed targets and build channels apart, and link only to findings whose weakness fits them.
- Outbound calls to external services and to request-chosen URLs become data flows with their own trust boundaries.
- Abuse-case chains no longer credit CI, documentation, or test findings, or findings that share only a CWE family, so such findings are no longer raised to a chain's severity.
- Abuse cases that were matched but never verified are retried once and otherwise named in Section 9 and the run issues instead of being reported as checked.
- An invalid, oversized, or symlinked repository abuse-case file is rejected and reported on its own instead of silently dropping every abuse case from the run.
- A wildcard CORS origin without credentials is no longer reported as a credentialed CORS anti-pattern, and OAuth implicit-flow tokens read from `location.hash` are now detected.
- Reports handle empty weakness and boundary registers without broken links or missing remediation tables, and remaining link defects are repaired or stopped immediately after rendering.
- Headless controller assessments exclude prior run products and the plugin's hook state from source evidence while retaining repository inputs stored beside reports, and another run or Claude Code session writing such files into the checkout no longer stops a running assessment.
- Headless controller reports retain linked architecture detail diagrams, include evidenced OAuth and identity-provider integrations including browser location assignments, and mark evidenced embedded database accesses as having no separate authentication.
- Controller root causes and remediation priorities now include the findings that abuse-case verification adds.
- Enabled architect review checks findings added by abuse-case verification and reports unreviewed findings against the final report instead of only the initial review scope.
- Root-cause grouping recognizes verified implementation evidence that begins a multiline call, including entity mass assignment.
- Architect review retains the technical fix when a proposed replacement preserves the vulnerability or only fixes a hypothetical deployment, and explicit preservation instructions no longer pass as fix cards.
- The controller console shows a remaining time only once the first component's threat analysis is finished, and trust-boundary warnings no longer break into its status line.
- Single-repository controller assessments accept `--abuse-case-file`, and an unreadable or invalid case file stops the run instead of being skipped.
- Headless controller assessments now model every route-serving API and browser application, with their handler and client code, instead of publishing a thin report that omits them; a run that still cannot place one stops instead.
- Headless controller analysis uses component-specific guides and checks that every supplied source target was read and assessed, splitting large components into bounded jobs without dropping targets.
- Headless controller assessments repeat a model call that a rate limit or an overloaded API refused, at no model cost, and repeat a paid text answer instead of the requested result at most once per call and three times per run, instead of stopping; the run names its repeated calls as a warning, and no longer stops when the model requests a reversed line range, more source than one request can carry, or a file of another selected repository.
- Headless controller assessments of repositories with several thousand files, or with editor files excluded only by your global Git ignore file, no longer stop before or during analysis.
- Headless controller assessments skip source files over 1 MiB, such as lockfiles, and name them as a warning instead of rejecting the repository, accept a source target the model read but could not settle as a named warning, and keep every finding of a large component analysed in several jobs instead of stopping after all of them were paid.
- A failed requirements-compliance or actor-discovery job no longer discards a finished controller assessment: the report is published with the job named as a warning, while a login or billing failure still stops the run and a nearly spent budget stops it with the remaining amount.
- Headless controller assessments no longer stop over model answers the controller can correct itself, and once STRIDE is complete a failed later model job no longer stops the run: the report is published and the replaced job is named as a warning.
- Headless controller `--resume` continues an interrupted assessment after a plugin update and repeats only the model steps whose input changed.
- Headless controller assessments apply the OWASP LLM guides to components whose source calls a model SDK, so their AI/LLM Exposure section and model provider return, and name a model integration the architecture did not model as a warning.
- Headless controller assessments no longer reject repositories that commit Claude Code configuration such as `CLAUDE.md`, because their model calls never load it; escaping symlinks, IDE-loaded files and unlisted related-repository URLs still stop the run.
- Headless controller progress lines share one column layout with the run's finished share, elapsed and remaining time, counted per analyzed component, and phase durations now match their time stamps.
- Ownership middleware suppresses a source finding only when its defining module and execution order establish the matching request-field binding for every recognized handler registration.
- Threat Analyst runs report evidence they could not obtain, no longer end incomplete when a design question asks for code, and accept source-backed findings introduced by removed controls.
- The completion summary of a run is shown once, in full, by the plugin itself instead of being copied by the session.
- `update-baseline` keeps user scope when the project is the home directory and falls back to the signed updater when delegation fails.
- The Threat Analyst honors the organization's Opus ban, and `appsec-reviewer-cli` no longer reports a verdict file from the checkout as its own result.

## 0.6.0-beta.4 (2026-10-06)

### Added

- `/appsec-advisor:analyze-threats` and `scripts/appsec-analyst-cli` analyze a planned feature or a selected code change on request; the [Threat Analyst](docs/threat-analyst.md) is experimental.
- Repositories with a build pipeline get Figure 1b, a supply-chain diagram linking build inputs and release artifacts to the most severe evidenced attack and the relevant controls.
- GitLab CI pipelines get the same supply-chain facts, build trust-boundary signals and Figure 1b detail as GitHub workflows: job and service images, script installs, piped installers, external `include:` entries and registry pushes.
- `scripts/analyzers/repo_scan.py` lists findings by severity, endpoints and detected technologies without a threat model; it and Security Score accept HTTPS GitHub/GitLab URLs and write YAML or JSON.
- `.appsec/actors.yaml` accepts `legitimate_roles` for declared user roles whose login lives outside the repository.
- Report figures ship with a dark-background variant that GitHub and browsers show automatically in dark mode.
- `export-threat-model` and `authnz-review` accept `--slug` for naming exports and pentest task files.

### Changed

- Malicious insiders and attackers holding a user's device require opt-in through `enable:` in `.appsec/actors.yaml` or `actors.enable` in the organization profile and are otherwise listed as not assessed.
- Interactive runs ask users to confirm the application's purpose and worst plausible business impact, then save the answers in `docs/security/business-context.md` for use in scope and prioritization, with fallback to the legacy path.
- `--stride-cap` and the quick profile never drop Critical or High findings.
- `create-threat-model` runs in `auto` and `bypassPermissions` mode without a separate `Bash(*)` allow-list and says what to fix when it cannot read the settings.
- The Management Summary identifies the modelled system and its confirmed use case and distinguishes findings confirmed in code from unverified findings without claiming exploitability or release readiness.
- The architecture report combines C4 context, deployment details and component control coverage in §2.1–§2.3, replacing the separate Technology Architecture section.
- Figure 1 adds technology and authentication labels, with linked detail views and a PDF appendix for large models; existing models need a new analysis to populate missing authentication evidence.
- Figure 2 connects each attack route to its attacker, access prerequisites, findings and impact.
- Reports show finding references as ID and title without file and line, give every fix a distinct title, and list controls, instance locations, findings and trust-boundary crossings instead of chaining them in prose.
- The configuration scan finds secrets and exposed data ports in Kubernetes, Helm, Terraform and Compose, maps each workload to a component or exclusion, treats deployment networks as possible trust boundaries, and names the IaC files it cannot check.
- Supply-chain controls are assessed from repository and CI evidence, with tools that may run elsewhere marked as not evidenced rather than missing.
- Components analysed with the LLM or agentic lens get a coverage assessment for every OWASP LLM or Agentic Top-10 item.
- Thorough assessments use more scanner evidence and source excerpts within the same token budget.
- Architect review checks ratings and mitigations before prioritization, drops refuted and below-threshold findings, sends unsettled ones to manual review, and keeps accepted corrections when reports are rebuilt.
- Completion summaries lead with the assessment and grouped P1 fixes, while open team questions focus on unresolved business and deployment decisions.
- `/appsec-advisor:report-error` investigates suspected plugin errors and prepares anonymised GitHub issue drafts for explicit publication approval; `--bundle-only` keeps the local diagnostic workflow.
- Run Issues flag duplicate findings, missing verification evidence, incomplete review coverage and sharp drops in Critical or High findings between comparable runs.
- New aiscb installations load verified modules on demand, and `update-baseline` uses compatible signed installers while preserving installation scope and mode.
- The bundled secure-coding baseline is updated to `aiscb-0.1.19`.
- `/appsec-advisor:help` opens with a quick start and keeps the full reference behind `--all`.

### Fixed

- Security controls with a free-text domain such as "Input Handling" are placed in a §6 section instead of stopping the Security Architecture fragment.
- The completion summary offers `/appsec-advisor:report-error` only for regressions, not for known open plugin defects.
- Private keys are fully redacted from findings, and pentest task exports are checked for leaked secrets.
- Config and IaC findings reach reports again with the correct STRIDE category and component attribution.
- Full assessments confirm object-level authorization gaps and entity mass assignment again without importing stale results from earlier runs, and mass-assignment checks exclude code that only reads or rejects privileged fields.
- Route authentication checks follow imported handlers and apply guards only to the routes they protect, so unrelated endpoints no longer appear authenticated.
- HTTP handlers are included in STRIDE analysis even when their component is labelled internal, and large components retain their source coverage with the most severe scanner evidence first.
- `authnz-review` retains scanner findings, checks unresolved operation permissions and disabled JWT claim validation, and fails its gate when analysis is incomplete.
- Duplicate findings from different analyses are merged without losing the highest risk, evidence or scenario references, while distinct JWT signature failures remain separate.
- Finding and abuse-case ratings respect policy limits, and verified attack chains raise finding severity only to their declared goal impact.
- A confirmed worst-case business impact applies to every runtime component, with build and delivery components included only when named in the answer.
- Findings count as verified from an earlier assessment only when they name that earlier finding; others are checked like new findings.
- LLM analysis retains component-specific RAG and agentic evidence, and the AI / LLM Exposure section includes only findings with the relevant OWASP tags.
- Config/IaC checks respect Git ignores and assess only tracked agent settings, while GitHub Actions checks recognise valid job-level permissions.
- SBOM, image-signing and dependency-update checks account for coverage across the repository, and findings about missing controls identify the files searched.
- Architecture diagrams and the trust-boundary catalogue distinguish unprotected endpoints from their hosts' controls and in-process interfaces from separate services.
- Security Architecture includes all assessed controls and lists findings under the controls they concern.
- Security Score withholds a score when a required scanner fails or returns invalid output, while retaining available findings and diagnostics.
- Runs no longer abort on large component inventories, deployment topology, threat-category metadata or a STRIDE finding that cites a line past the end of its file, and report any context omitted because of size limits.
- Declined analyses and exhausted agent budgets show up as coverage gaps without blocking other analyses, and retries resume saved work without duplicating a running attempt.
- An aborted interactive run releases its lock, so the error report can be offered right away; `--rerender` no longer deletes another run's lock.
- Run logs retain earlier events, and cost totals no longer double-count sub-agent tokens or conceal missing measurements.
- Run plans warn when requested PDF or HTML exports cannot complete in the environment.
- Plugin update checks advertise released versions only.

## 0.6.0-beta.3 (2026-09-14)

### Added

- The Management Summary and completion summary give developers concrete starting points for manual threat modeling through up to three open questions about deployment assumptions, business decisions, or unresolved attack chains, with references to findings.
- Cost budgets via `--soft-budget` or organization profiles, with spending warnings and per-phase cost totals in headless runs.
- `/appsec-advisor:repo-profile` shows repository size, languages, and build manifests before a scan, without model calls or network access.

### Changed

- Figure 1 has been completely redesigned to show attack scenarios, grouped data flows, actors, and Critical/High weaknesses in a clearer architecture overview.
- Scenario summaries show attack-path verification status in a compact table.
- Actor grouping accounts for self-registration and public access while preserving login and privilege requirements.
- `fix-run-issues` requires a diagnosis from the affected run and provides manual remediation guidance.
- Threat model examples moved to the companion `appsec-advisor-examples` repository.
- Baseline installation and updates use signed releases with signature and checksum verification.

### Fixed

- Headless runs handle asynchronous agents, interruptions, and lock conflicts without premature completion or interference with other runs.
- Progress displays track completed STRIDE components accurately and avoid repeated status messages.
- Cost reports use the actual model's rates, retain usage from stopped agents, and flag missing measurements.
- `--verbose` and tracing settings apply correctly to each run.
- Unattended runs no longer prompt for business context, and discarding completed analysis with `--full` or `--rebuild` requires confirmation or `--force`.
- Deeper scans reuse reconnaissance for unchanged repositories, and rebuilds preserve derived model details.
- Injection analysis covers more NoSQL, code, and template sinks and distinguishes stored, reflected, and DOM-based XSS.
- Reports retain applicable security controls, merge duplicate findings, and exclude refuted attack chains from open questions.
- Report generation preserves valid editorial work and avoids false QA failures, broken code formatting, and secret masking that corrupts report content.
- Completion summaries list all requested exports and the editorial outcome.

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
