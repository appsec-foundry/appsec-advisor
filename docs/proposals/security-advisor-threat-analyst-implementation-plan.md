# Security Advisor and Threat Analyst implementation plan

Status: proposed implementation sequence, not implemented functionality. This plan complements the [concept](security-advisor-threat-analyst-concept.md). It defines an additive manual and CI workflow while protecting the existing threat-model assessment pipeline. It does not authorize changes to normative requirements or begin runtime implementation.

## Delivery scope

The first release supports design questions without a diff and bounded code-change reviews. A manual skill and a CI CLI share one deterministic controller and one analysis contract. Advisor and Analyst are perspectives within that workflow. Automatic hooks, blocking threat gates, automatic code fixes, canonical threat-model updates, and a second requirements grader are outside this release.

The proposed user-facing skill is `/appsec-advisor:analyze-threats`. The proposed CLI is `scripts/appsec-analyst-cli`. These names and the syntax below are implementation targets, not commands available today. Both entry points work with automation disabled and without aiscb installed in the target project.

The Analyst is an optional developer tool. Installing the plugin, configuring an organization profile, or selecting a question package or methodology profile never starts an analysis. Developers explicitly invoke the skill or CLI. A team may separately opt into merge-request analysis by configuring a trusted CI job. Organization settings govern an invoked analysis; they do not require developers to invoke it or install CI checks. The first release neither installs enforcement hooks nor configures merge restrictions.

The first release supports custom requirements, question packages, and methodology profiles. Organizations can configure defaults and required inputs for an invoked analysis. Developers can explicitly add packages for one analysis while preserving those requirements. The Threat Modeling Manifesto ships as an optional methodology profile that an organization may select as a default.

Feature-context persistence is explicit. A user can retain non-sensitive answers for CI in a versioned file; session-only analysis remains useful without saving anything. CI findings are advisory, but failures and incomplete required work do not return success.

## Architecture and protected boundaries

The controller owns request validation, snapshot creation, context admission, dispatch, questions, limits, cancellation, result validation, publication, and cleanup. Model output supplies analysis and bounded proposals for further evidence or questions. It cannot choose commands, tools, output paths, permissions, or successors.

The affected assets are source code, business context, declared requirements, user answers, model credentials, analysis results, and existing assessment state. Repository files, prior reports, feature files, and model output cross a data boundary into analysis. Trusted packaged policy and caller-authorized configuration determine authority. Context selection and result validation must enforce that distinction outside the model under aiscb.

### Existing files that remain unchanged

Protect these paths throughout the initial implementation. A dependency that cannot be consumed unchanged is a separate prerequisite, not an implicit exception.

| Protected area | Initial implementation rule |
|---|---|
| `skills/create-threat-model/`, `skills/update-threat-model/`, existing assessment agents and `agents/shared/` | No prompt, tool, sequencing, or behavior changes. |
| `skills/internal-threat-analysis-kernel/` | Read its invariants as a compatibility reference; do not modify or blindly preload assessment-specific lifecycle instructions. |
| `scripts/orchestrator/orchestration_controller.py` and existing runtime lifecycle/configuration modules | No new analyst state, mode, defaults, locks, or dispatch branches. |
| Existing files under `scripts/model/`, `scripts/renderers/`, and `scripts/exporters/` | No changes to canonical model construction, reports, identities, or exports. New analyst-only modules may use these domain directories where listed below. |
| Existing canonical schemas, context-routing catalogs/bindings, section registries, and report templates | No analyst fields or assignments added to assessment contracts. |
| `scripts/runtime/runtime_cleanup.py` and its cleanup contract | Analyst artifacts stay outside assessment cleanup ownership. |
| `hooks/hooks.json`, `hooks/steering_keywords.json`, `scripts/analyzers/security_steering.py` | No initial hook integration or change to Coach behavior. |
| `scripts/run-headless.sh`, `scripts/appsec-reviewer-cli`, `agents/appsec-reviewer.md` | Do not retrofit the new workflow or inherit their execution permissions. |

Existing guards and pure helpers may be imported after their side effects and transitive consumers have been reviewed. Avoid broad refactoring and duplicate implementations of security guards. If an existing guard cannot serve the new boundary unchanged, document the exact gap and split the shared fix into a reviewed prerequisite with regression evidence for its current consumers.

### Expected integration edits

New commands and file targets require entries in `data/required-permissions.yaml` and its tests. That inventory suppresses prompts; it is not a sandbox. Keep analyst permissions scoped to its entry point; if the current inventory cannot express this without affecting existing workflows, isolate the required inventory change as a prerequisite. New source-to-test routes and group assignments belong in `scripts/run_tests.py`. Documentation and, only where discovery tests prove necessary, packaging inventories may need additive entries. These edits must not widen existing runtime grants or change assessment defaults.

The current plugin manifest does not enumerate individual skills. Verify installation and discovery before assuming a manifest edit is necessary. Keep dependency additions out of the initial design unless the host feasibility work establishes a need. Any required dependency change is a separate shared-risk review with pinned versions and existing consumer tests.

The current organization-profile contract has no Analyst package selection. Treat its additive extension as an explicit prerequisite, following [org-profile invariants](../internal/contracts/org-profile-invariants.md) across schema, validation, resolution, packaging, surface inventory, and smoke tests. Map affected files in work package 1 before changing shared code. If this needs a protected runtime change, complete the separately reviewed prerequisite first. Preserve existing profile behavior and keep Analyst activation outside profile resolution.

## Proposed components and files

Use the repository's existing domain layout. Every new Python module gets a matching `tests/test_*.py` covering core behavior and failure paths. The filenames below define ownership; split a module only when implementation complexity warrants it and update test routes accordingly.

| Proposed new path | Responsibility | Matching test |
|---|---|---|
| `skills/analyze-threats/SKILL.md`, `HELP.txt`, `references/analysis-contract.md` | Manual adapter and shared semantic instructions used by both entry points | `tests/test_analyst_skill.py` |
| `scripts/appsec-analyst-cli` | Thin noninteractive launcher, with no analysis logic | `tests/test_analyst_cli.py` |
| `scripts/orchestrator/analyst_controller.py` | State transitions and deterministic action admission | `tests/test_analyst_controller.py` |
| `scripts/contexts/build_analyst_snapshot.py` | Exact source views and bounded file admission | `tests/test_build_analyst_snapshot.py` |
| `scripts/contexts/build_analyst_context.py` | Read-only adapters for requirements, business context, and prior models | `tests/test_build_analyst_context.py` |
| `scripts/contexts/resolve_analyst_catalog.py` | Explicit package selection, bounded loading, provenance, conflicts, and the effective analysis catalog | `tests/test_resolve_analyst_catalog.py` |
| `scripts/contexts/analyst_questions.py` | Question identity, answer provenance, reuse, and explicit feature persistence | `tests/test_analyst_questions.py` |
| `scripts/runtime/analyst_host.py` | Restricted host invocation and structured model responses | `tests/test_analyst_host.py` |
| `scripts/runtime/analyst_state.py` | Job directories, locks, ownership, deadlines, cancellation, and cleanup | `tests/test_analyst_state.py` |
| `scripts/validators/validate_analyst.py` | Schemas, references, source receipts, and publication checks | `tests/test_validate_analyst.py` |
| `scripts/renderers/render_analyst_report.py` | Markdown presentation from validated results | `tests/test_render_analyst_report.py` |
| `data/analyst-questions.yaml`, `data/analyst-methods/threat-modeling-manifesto.yaml`, `data/analyst-limits.yaml` | Packaged questions, optional methodology profile, and enforced finite limits | `tests/test_analyst_catalog.py` |
| `schemas/analyst-*.schema.json` | Contracts specified below | `tests/test_analyst_contracts.py` |
| `tests/test_analyst_isolation.py`, neutral fixtures under `tests/fixtures/analyst/` | Cross-workflow and abuse regressions | Direct tests |
| `docs/threat-analyst.md`, `examples/analyst/` | Optional manual and CI usage, package authoring examples, limitations, supported host matrix | Documentation route, catalog, and CLI/skill tests |

No separate Advisor and Analyst agent definitions are required initially. The host adapter invokes the shared semantic instructions in a bounded analysis session. A native subagent adapter is optional only after it can enforce the same contract without inheriting broad parent authority.

## User entry points

The following commands illustrate the proposed interface. Validate unknown flags, incompatible scopes, missing values, and destinations before creating job state or contacting a model.

```text
/appsec-advisor:analyze-threats Design a customer export for support staff.
/appsec-advisor:analyze-threats --worktree
/appsec-advisor:analyze-threats --staged --feature docs/security/features/customer-export.yaml
/appsec-advisor:analyze-threats --base <base-commit> --head <head-commit>
```

Free text starts a design request. A review requires exactly one explicit source scope. Do not infer an empty diff as a request for a whole-repository audit. When scope is omitted or ambiguous, the interactive adapter asks one scope question; CI rejects the request before analysis.

```bash
scripts/appsec-analyst-cli review \
  --repo "$REPO_DIR" \
  --base "$BASE_SHA" \
  --head "$HEAD_SHA" \
  --feature "$FEATURE_FILE" \
  --output "$REPORT_DIR"
```

`--feature` is optional. CI supplies the comparison objects and fetches the needed history before invoking the CLI. The CLI does not fetch implicitly. For branch review, compare the merge-base of the supplied commits to the supplied head and record all resolved object IDs. An exact integration-commit comparison is a distinct explicit option, not an inferred fallback. Invalid history, unrelated histories, or inaccessible source objects fail visibly.

The CLI also supports a design subcommand taking a supplied design file. It never invents answers or reads stdin indefinitely. A reviewed feature file can be passed to either mode. An empty code diff does not skip an explicitly requested reassessment of changed context or pending design assumptions. Exact argument names for answering and saving are finalized with the contract in work package 1.

## Artifact contracts

Schemas reject unknown fields, bound input-driven work, and separate untrusted declarations from trusted execution metadata. All intermediate structured handoffs have a schema and validator. Record schema, catalog, prompt, policy, model, and plugin versions for traceability without claiming model reproducibility.

| Proposed schema | Required content and validation |
|---|---|
| `analyst-request.schema.json` | Controller-assigned job identity; design or review mode; caller-authorized repository/scope/output; resolved policy, package selection authority, package versions and digests, and limits. Untrusted feature data cannot populate authority fields. |
| `analyst-snapshot.schema.json` | Repository/worktree identity; comparison semantics; source object IDs or local content fingerprints; admitted paths and hashes; excluded scope and reasons. |
| `analyst-context.schema.json` | Bounded projections, source provenance, receipts, versions, delivered/omitted categories, and requirement/question selection coverage with omission reasons. |
| `analyst-response.schema.json` | Model proposals: findings with proposed change relationships and comparison evidence, methodology observations, assumptions, questions, evidence requests, and analysis limitations. No commands, write targets, or authoritative completion flags. |
| `analyst-feature.schema.json` | Feature identity, design revision, intent, scoped declarations, sourced answers with originating question references and fingerprints, and pending verification items. No permissions, policy overrides, or risk-acceptance fields. |
| `analyst-state.schema.json` | Controller-owned state, current input fingerprint, admitted response, counters, pending question identities, and terminal reason. |
| `analyst-result.schema.json` | Job/input binding, execution state, assessed scope, effective package receipts, coverage gaps, evidence-backed findings with validated change relationships and comparison references, requirement observations, methodology observations, assumptions, questions, and costs when available. |
| `analyst-catalog.schema.json`, `analyst-methodology.schema.json`, `analyst-limits.schema.json` | Packaged and custom question identities, applicability, evidence needs, provenance and requirement mappings; methodology principles and review criteria; finite limits with explicit units and validated relationships. |

Use controller-owned job-local identifiers for questions and findings. Imported canonical threat IDs may be references only. Validate file/line references and excerpts against the admitted snapshot; schema-valid prose alone is not evidence. Evidence checks can establish source support, not guarantee the model's security judgment is correct.

For change review, each finding records whether the risk is newly introduced, worsened, mitigated, unchanged pre-existing, or unknown. Comparison references identify the baseline or proposed source state they describe. The validator checks those references and requires comparison evidence for every relationship other than unknown; the renderer preserves the validated relationship and any evidence gap. Missing comparison evidence cannot establish that a change introduced a weakness. Include unchanged pre-existing weaknesses only when the change relies on them. Design-only results keep scenarios and assumptions separate from observed findings and do not claim a code-change relationship.

Render Markdown only from validated results using contextual escaping. Never publish raw model output as a successful report. Check for sensitive values before model admission and before publication; failure leaves a content-free diagnostic. Do not copy source or answers into routine telemetry.

## Snapshot and context preparation

For committed comparisons, read Git objects without repository hooks, external diff drivers, text conversion, or checkout filters. For staged review, use index contents for both changed and supporting files. For worktree review, capture admitted working files including selected untracked additions and deletions; detect concurrent changes during capture and reject an inconsistent view. Retain the captured bytes for all subsequent reads.

Inspect renames, binary inputs, large files, symlinks, submodules, and nested repositories explicitly. Unsupported or excluded material becomes a coverage record, never silent omission. Reject path escapes and output paths intersecting the target assessment state. Do not initialize submodules or follow repository-selected external sources. Use registered repository identities if multi-repository support is later added; v1 reports unavailable related code as a limitation.

The controller can admit additional surrounding-code evidence from the same frozen view. It rejects an expansion outside authorized scope. Omitted supporting code may prevent a claim from being verified; a narrow file selection must not be presented as complete feature coverage.

Load trusted local requirements through existing resolution behavior only if its writes, source precedence, and failure handling fit the Analyst contract and an analyst-owned directory. The current resolver can prioritize a repository-local catalog over an organization source; do not inherit that precedence for required organization inputs. Otherwise require a validated, caller-supplied catalog for that adapter until the prerequisite is resolved. Use the packaged fallback only when no configured required source applies. Do not reuse the reviewer's topic-ID intersection as proof that an arbitrary organization catalog was fully considered.

Use durable business context and compatible structured threat-model exports as optional data sources. Record their revisions and project only relevant content. Missing optional sources allow local analysis; malformed explicitly required sources block the dependent assessment. Do not read live assessment intermediates. If a durable artifact changes during reading, retry only within bounded capture rules or reject the receipt.

Reuse the existing team-question topics and exact-source provenance semantics from `schemas/stride-analyst-context.schema.json` and `scripts/contexts/load_business_context.py` through an analyst-specific adapter. Do not depend on its live `.skill-config.json` or output projection. The adapter needs its own contract because a design-only feature may have no finalized component IDs.

The new analysis catalog preserves aiscb source release and rule identifiers for adapted questions. It works without target installation and does not confer policy authority. Explicit runtime aiscb integration is an optional adapter with verified loading and fail-closed required inputs. It must not become a prerequisite for the initial release or a hidden remote dependency.

## Custom questions and methodology profiles

Requirements state applicable obligations. Question packages guide investigation and identify evidence needs. Methodology profiles guide the analysis process and its reflection on coverage. Keep these types distinct in loading, model context, and results. A methodology observation alone cannot establish a vulnerability or requirement violation.

Use schema-validated YAML with bounded text fields and reviewed authoring examples. Packages declare a namespaced identity, version, source provenance, and stable entry identities. Questions specify applicability, the requested fact, its purpose, evidence needs, and applicable requirement references or negative-test expectations. Methodology entries specify principles and review criteria. Package text cannot supply commands, tools, write targets, prompt overrides, or execution permissions. Reuse the requirements interchange format through a validated adapter rather than defining another requirements standard.

Version 1 loads local or packaged content only for question and methodology extensions. Trusted organization configuration selects defaults and inputs required for an invoked analysis. An explicit developer selection may add packages; it cannot remove or weaken required inputs. In CI, trusted pipeline configuration fixes the selected package versions and content digests. A merge request cannot activate or replace the packages used to assess itself. Updates are explicit and produce new input fingerprints; analysis never downloads package updates implicitly.

The deterministic resolver records selection authority separately from package content. Reject ambiguous identities, incompatible versions, and unresolved conflicting definitions instead of silently overwriting entries. Missing or invalid selected packages produce a visible non-success outcome. Report detected semantic conflicts as unresolved; deterministic schema checks cannot prove that arbitrary prose is consistent. Apply controller-owned limits to package count, expanded content, and selected questions. Required coverage that exceeds a limit remains incomplete rather than disappearing from the assessment.

Select relevant questions using the authorized scope and available evidence. Record selected and omitted entries with their reasons without claiming that selection proves complete coverage. Use stable package and entry references alongside job-local question IDs. Recheck saved answers and dependent review items when a referenced question, requirement, methodology profile, feature, or context changes. Package selection never makes every question mandatory; a required answer must be justified by its relevance and dependency within the agreed assessment scope.

Ship an adapted [Threat Modeling Manifesto](https://www.threatmodelingmanifesto.org/) profile with source attribution and a pinned source revision or snapshot. Its review criteria address the system under examination, plausible failures, practical responses, and the adequacy of the investigation. Include stakeholder dialogue, missing perspectives, and iterative refinement as methodology observations. The profile does not certify compliance or replace human collaboration. It applies only when selected for an invoked analysis, including through an organization default.

## Questions and lifecycle

The proposed controller states are `prepared`, `analyzing`, `awaiting_answers`, `complete`, `incomplete`, `failed`, and `cancelled`. Admission failures can exit before a job is created. Only the controller transitions state. Missing required inputs and unresolved mandatory scope prevent `complete`, even if some useful findings exist.

1. Prepare the request, snapshot, and context; record what is unavailable.
2. Run one bounded semantic pass that produces useful analysis plus remaining evidence requests or questions.
3. Resolve admissible evidence requests from the snapshot before asking the user for facts already available.
4. Present unanswered material questions together in the manual skill. Preserve independent valid work and checkpoint at `awaiting_answers` without leaving a model process waiting.
5. Validate each answer against the question, feature, source, and context fingerprint; start another bounded pass over affected items.
6. Validate and publish a terminal result, then clean up job-owned temporary data.

Question fields include identity, originating package/entry references where applicable, topic, affected scope, requested fact, why it matters, suggested answers where useful, and the dependent assessment. Inspect admitted evidence and applicable saved answers before asking the user. The controller checks the question contract; the model explains semantic necessity. Relevance and necessity require evaluation cases because deterministic validation cannot prove them.

Separate factual clarification from risk acceptance. A user statement can change the declared intended behavior, but cannot silently override an active requirement. Risk exceptions use the applicable policy's separate authorized process; v1 does not create an exception mechanism.

In CI, unresolved required questions end the job as `incomplete`; optional questions remain visible alongside a complete scoped result. There is no persistent waiting worker. Interactive users may later open the question artifact and supply answers. Changed source creates a new job; answers can be reused only after their applicability is rechecked. Repeated or unresolved rounds exhaust a finite controller budget and leave an honest incomplete result.

Explicit save writes only validated, non-sensitive declarations and questions to the caller-selected feature file. It preserves unrelated existing content and rejects stale overwrites. It never commits, edits general business context, or updates the canonical model. Removing a saved answer invalidates dependent analyst caches and review items. Contributor edits are distinguishable from earlier operator-supplied answers and do not acquire greater trust through persistence.

## Runtime and CI containment

Use an analyst-owned job root outside assessment output, with canonical path checks, restricted access, unpredictable job directory names, atomic state publication, and ownership-aware cleanup. Temporary snapshots and prompts have finite retention. Results survive according to the explicit retention setting. Cancellation and crash recovery cannot delete another job's directory or a feature file.

The host adapter's retention inventory includes session transcripts, prompt history, caches, and diagnostic copies outside the job root. Disable unnecessary persistence in adapter-created sessions. Any required local copies must have restricted access, explicit ownership, finite retention, and verified cleanup. Document parent-conversation and remote-provider retention separately; analyst job cleanup cannot promise to erase those records. Do not delete shared host state to satisfy job cleanup.

The preferred first host adapter sends prepared context to a model session with no general shell, file-write, network, delegation, or project-discovery tools. Additional evidence is a structured request serviced by the controller. Verify this restriction against actual supported host versions; a prompt instruction, permission inventory, or `--allowedTools` list alone is not a confinement proof. If the host cannot enforce it, stop that adapter's implementation until an enforceable alternative is reviewed.

Trusted plugin code and configuration run outside the untrusted target checkout. Repository-owned instructions, hooks, MCP configuration, plugins, and scripts cannot load as executable configuration. Model credentials remain with the trusted transport and outside admitted inputs and model-readable resources. Limit egress to configured model destinations. Never run repository tests, build steps, installers, or remediation commands as a side effect of analysis.

Enforce time, model calls, evidence expansion, response size, question rounds, and retries outside the model. Measure legitimate work before choosing limit values in work package 1; publish the units and failure behavior. Cancellation stops further dispatch and publication. A host process success code does not replace artifact validation or prove completion.

| CLI outcome | Proposed exit behavior |
|---|---|
| Complete advisory analysis, including one with findings | `0`; the report states coverage and does not claim security approval. |
| No code changes in a valid review scope and no requested context or assumption reassessment | `0` with explicit empty scope and no model dispatch; design mode remains independently available. |
| Invalid input, missing required context/answers, validation failure, or exhausted required work | `2`, with a structured reason when a job exists. |
| Cancellation or external termination | Nonzero; preserve a distinct terminal reason where the controller can record it. |
| Findings that would violate a future gate | No blocking behavior in v1; `1` is reserved for a separately introduced gate contract. |

A CI stage uploads sanitized reports and question artifacts on both complete and incomplete outcomes, using its trusted pipeline configuration. It must not hide execution failures with a blanket success override. PR comments and code-host write access are optional future publishing adapters; the first release needs only CI artifacts and read-only repository access.

## Work packages and acceptance gates

Implement packages in this order on branches from `dev`. Each package ends with reviewable artifacts and the listed evidence. No package is complete merely because a model produced plausible prose.

### 1 Contract and host feasibility

Create a bounded architecture change proposal and map new promises to requirements before runtime edits. Normative requirement changes require explicit operator approval. Record the protected-file inventory and audit candidate reused functions for writes, subprocesses, environment coupling, and cleanup ownership. Finalize the schemas, source comparison semantics, finite limits, supported host versions, and exact entry-point arguments. Define the package selection and update interface, authority precedence, conflict behavior, and organization-profile prerequisite. Keep voluntary invocation separate from configuration of an invoked analysis.

Run a neutral host spike using only synthetic data. Demonstrate structured responses, disabled project discovery, denial of unauthorized tools/resources, controlled credentials, cancellation, and result delivery. Compare interactive and headless invocation. Inventory host storage locations and verify disabled persistence or owned cleanup after success, failure, cancellation, and crash recovery, including copies outside the job root. No bypass mode is an acceptable fallback.

Acceptance: a reviewed file-level dependency map, successful live containment evidence, and verified host retention behavior with documented parent-conversation and provider boundaries. Unsupported host behavior blocks the affected adapter, not a weakening of its contract. This package determines whether a dependency addition or shared-helper prerequisite is needed.

### 2 Deterministic job foundation

Implement request/state validation, job ownership, snapshot capture, context admission, and cleanup. Wire test doubles only at the model transport boundary; exercise real path guards, capture, schema validation, and lifecycle code.

Acceptance: design-only, worktree, staged, and commit scopes have exact input identities. Concurrent edits, path escapes, malformed inputs, output overlap, stale results, two worktrees, interrupted jobs, and cancellation fail or isolate correctly. Existing assessment artifacts remain unchanged.

### 3 Analysis catalog and semantic execution

Implement the versioned questions, aiscb provenance, package resolver, custom YAML contracts, optional Manifesto profile, analyst-specific context adapters, semantic response contract, result validator, and Markdown renderer. Support requirement references without emitting formal reviewer grades. Add isolated reviewer integration only after its tool, input, and output contracts can be satisfied unchanged; otherwise defer that optional capability explicitly.

Acceptance: a neutral export feature, an equivalent case with different names, and a benign control-preserving case produce the expected distinctions between hypotheses, observations, and evidenced findings. Comparison cases cover all five change relationships, removed controls, and missing baseline evidence. Invalid source-state references or change attribution without required comparison evidence fail validation. A relevant non-catalog threat remains discoverable. Required catalog failure cannot masquerade as a fallback assessment. Source excerpts, sensitivity checks, and source receipts are exercised without mocked validation.

Package acceptance covers organization defaults, explicit developer additions, arbitrary requirement IDs, conflicting definitions, missing or invalid packages, budget exhaustion, attempted authority overrides, and changed package fingerprints. The Manifesto profile produces useful methodology observations without fabricated vulnerabilities or mandatory questions unrelated to the scope. Validate all shipped authoring examples.

### 4 Manual skill and question handoff

Implement the thin skill, help, question presentation, answer submission, explicit save, and reload. Use the same controller and semantic instructions as the CLI. Do not make the parent conversation's successful completion the result authority.

Acceptance: a user plans an export, answers an authorization question, saves the declaration, and later checks a compliant implementation and a contradictory variant. No-diff design requests work. No-answer, irrelevant-answer, conflicting-answer, stale-save, removed-answer, and question-budget cases retain correct status. A live supported-host run verifies that the user sees the questions and validated result.

A developer can explicitly select a custom package and see its source and coverage in the result. Evidence already available prevents redundant questions. A changed question or package invalidates affected answer reuse until applicability is rechecked. Installing or configuring the plugin and its profiles without invoking the Analyst produces no Analyst job or model call.

### 5 Advisory CI entry point

Implement the CLI with explicit source comparison, optional feature/context inputs, explicit package selection, trusted runtime configuration, and owned output. Provide a provider-neutral job recipe plus reviewed GitHub Actions and GitLab CI examples that teams install explicitly. Pin external execution dependencies in examples when selecting them; do not execute PR-owned setup or require code-host write tokens. Fix package versions and content digests in trusted CI configuration independently of the reviewed change.

Acceptance: the same inputs through skill and CLI use identical preparation and validation rules, allowing semantic model variation. Missing history, invalid model output, transport failure, stale prior output, required unanswered questions, and budget exhaustion are visible non-success outcomes. A trusted CI test demonstrates fresh JSON/Markdown artifacts and denial of PR-controlled configuration, package replacement, and credential access. Without a team-configured CI job, plugin installation or organization defaults add no merge-request check.

### 6 Isolation and release qualification

Inspect the actual diff against the protected-file inventory. Test a full assessment and analyst job concurrently, then analyst failure/cancellation/cleanup, and verify that assessment artifacts, locks, logs, and outputs are preserved. Test the reciprocal direction: assessment cleanup cannot remove analyst state. Verify packaging/discovery and absence of analyst model calls from existing skills with automation disabled.

Evaluate useful findings beyond the reviewer, false positives, missed business-context cases, question necessity, repeated questions, latency, and cost against thresholds agreed before the evaluation. Compare both workflows using the same source snapshots, applicable requirements, and project context with comparable resource budgets. Record delivered inputs and actual resource usage for each run. Report any comparison with the reviewer's default inputs separately so that additional context is not attributed to the new workflow's analysis quality. Keep design-only evaluation separate from diff review. Record unresolved coverage limitations and supported host versions in user documentation.

Acceptance: deterministic regression evidence, live manual/CI and assessment coexistence evidence, and a reviewer comparison with verified input and budget comparability. Record unmatched conditions as evaluation limitations rather than evidence of superiority. Run the release checks required by `docs/releasing.md` when crossing a release boundary. Do not claim unchanged model behavior solely from unchanged source files or a unit-test pass.

### 7 Optional automation after the first release

Design separate `manual`, `suggest`, and `automatic` activation behavior with automation disabled by default. Any future automatic execution requires a separate explicit opt-in. The existing Coach toggle and Analyst package defaults must not implicitly authorize analyst jobs. Review changes to hook registration and organization configuration as a separate integration.

Acceptance: disabled automation adds no analyst calls; full assessments and nested analyst activity are excluded; duplicate events, external edits, repeated Stop events, cancellation, and result delivery are bounded and tested live. Scheduling invokes the established controller rather than creating a parallel analysis implementation. Gates and canonical model updates remain separate proposals.

## Verification and regression strategy

Before changing each implementation path, run `python3 scripts/check_specs.py --for <path>` and read its returned requirements, decisions, and contracts. Maintain technical bindings, permissions metadata, and exact source-to-test routes with each package. Additions to the catalog or prompt are runtime changes, not documentation-only work.

Run the reviewed selection from `make test-plan` and `make validate test-changed` for the applicable base. Use `BASE=HEAD` for separately bounded local work where appropriate. Run `make lint` for Python edits and `make audit-test-routes` after route changes. Use `make check` when shared runtime impact cannot be bounded or at the required release boundary; multiple new isolated files alone do not require a full suite.

| Boundary or behavior | Required evidence |
|---|---|
| Contracts and model output | Unknown fields, invalid references, fabricated excerpts, and malformed/truncated responses are rejected; injected instructions cannot authorize tools, resources, or policy changes. |
| Change attribution | All five relationships, baseline versus proposed-state references, removed controls, relevant pre-existing weaknesses, and unknown attribution when comparison evidence is unavailable. |
| Snapshots and scope | Neutral additions/deletions/renames, index versus worktree divergence, untracked sensitive files, concurrent edits, and symlink escapes. |
| Questions and persistence | Existing-source answers, material versus optional gaps, changed context, altered provenance, cross-feature answers, and poisoned-entry removal. |
| Custom packages | Namespaced identities, version/digest changes, conflicts, missing selected inputs, bounded selection, rejected policy overrides, and answer invalidation after relevant package changes. |
| Optional activation | Installation, organization defaults, and package configuration cause no Analyst jobs or model calls; merge-request checks require an explicitly configured CI job. |
| Existing helpers | Existing consumer tests for every imported helper; no security guard is mocked around the behavior under test. |
| Assessment isolation | Dedicated analyst tests plus applicable `test_runtime_cleanup.py`, `test_context_routing.py`, `test_load_business_context.py`, and frozen assessment replay tests. |
| Plugin integration | Applicable permission, plugin read/write gate, agent-definition, requirements-verification, and discovery/packaging tests. |
| Live execution | Manual questions and result delivery, headless termination, forbidden tool/resource requests, and concurrent assessment ownership on supported hosts. |
| Host retention | Adapter-created session persistence and storage inventory verified after success, failure, cancellation, and crash recovery; no unowned local copies or deletion of shared host state. |

For a failed selected test, rerun only that failure at the applicable base as described in `CONTRIBUTING.md`. Do not change existing goldens or expectations to accommodate unrelated analyst side effects. New scanner or deterministic-tail work, if separately introduced, also requires the threat-fixture replay prescribed by the repository.

## Completion criteria

The first release is ready only when a developer can voluntarily plan a feature, clarify its protection assumptions, inspect its implementation, and run the same bounded assessment in explicitly configured CI without enabling hooks or installing aiscb. Developers can add custom questions and select the supplied Manifesto profile while preserving applicable organization requirements. Every result identifies its inputs, selected package versions, coverage limitations, and unresolved questions. Existing full assessments retain their own state and behavior under success, failure, cancellation, and concurrent execution.

The remaining implementation choices are the proven host invocation, measured limits, exact argument names for answer submission and package selection, organization-profile integration, and compatible helper reuse. Resolve them in package 1 rather than disguising them as completed integration. No initial package requires changing the canonical threat model or weakening a security boundary.
