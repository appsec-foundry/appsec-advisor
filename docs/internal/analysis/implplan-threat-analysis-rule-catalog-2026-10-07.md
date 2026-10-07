# Business threat analysis and investigation packages implementation plan

Status: proposed implementation plan, revised 2026-10-07. The operator authorized this documentation revision. Runtime implementation and normative requirement changes require separately reviewed scope. The [concept](../../proposals/threat-analysis-rule-catalog-concept.md) defines the agreed direction: retain deterministic analyzers and add focused business authorization, process, and abuse-case investigation. Existing filenames remain stable for links.

## Outcome and scope

Extend model-assisted analysis with descriptive business questions and abuse-case guidance. Existing Python analyzers continue to execute their technical checks. They are not replaced by LLM calls, generated from prose, or migrated wholesale into a new catalog. Python retains source extraction, package admission, execution limits, validation, and result processing.

Deliver shared business questions to two explicit consumers: the on-demand Threat Analyst and the full threat-model assessment. Both use the same package format and authoritative question text through separate scope adapters. Verify delivery and usefulness in each workflow; successful assessment integration does not establish that the Analyst received or investigated the new questions.

The first dedicated package focuses on business authorization, process states and ordering, and repetition or concurrency. Authorization includes tenant and parent-child relationships and relevant separation-of-duties requirements. Cumulative amounts, quotas, and cross-service trust are further package topics; refund limits serve as an initial concurrency test case. Existing STRIDE coverage and investigation of other threats remain intact.

A comprehensive catalog of Python detector meanings, automated translation of questions into Python, an executable rule language, arbitrary user regex or code, remote package downloads, and automatic repository package discovery are outside scope. The earlier source-scanner discrepancies are recorded at the end as separate producer-fix work. They are not a dependency of this feature.

## Existing implementation and contracts

| Existing surface | Reuse and required delta |
|---|---|
| `scripts/analyzers/`, `data/source-auth-checks.yaml`, `data/architecture-coverage-rules.yaml` | Keep technical detection and IDs; reuse relevant evidence without duplicating executable definitions or assuming they prove business authorization. |
| `schemas/analyst-catalog.schema.json`, `data/analyst-questions.yaml`, `scripts/contexts/resolve_analyst_catalog.py` | Reuse existing question identity, schema, provenance, authority, and local package loading. Extend only proven gaps for process-oriented assessment. |
| `scripts/contexts/load_business_context.py` and business-context contracts | Reuse admitted business facts and sourced answers; add a bounded process projection where current fields cannot express participants, states, or expectation provenance. |
| `scripts/model/resolve_abuse_cases.py`, `match_abuse_cases.py`, `scripts/contexts/build_abuse_case_contexts.py` | Reuse case resolution, matching, and bounded candidate context through explicit adapters; model-derived business hypotheses must not require a scanner finding as their sole activation signal. |
| `agents/appsec-abuse-case-verifier.md`, abuse-case validation and promotion | Reuse evidence-chain investigation and acceptance. Review stage ordering before feeding new process hypotheses into the verifier. |
| `schemas/org-profile.schema.yaml`, `scripts/runtime/resolve_org_profile.py` | Existing `analyst.required_packages` and `analyst.default_packages` configure on-demand analysis. Add explicit assessment selection without silently expanding those fields' consumers. |
| `scripts/package_internal_plugin.py`, `scripts/smoke_test_package.py` | Verify and extend copying, relocation, schema validation, package surface inventory, and installed resolution for selected question files. |
| Context-routing catalog, bindings, budgets, and controller | Add independently selectable process/question context with bounded receivers and exact-byte receipts; no global prompt injection. |
| Finding intake, merge, `scripts/shared/_finding_state.py`, renderers and exporters | Preserve confirmation, severity, identities, and consolidation; carry validated package and process provenance through affected outputs. |

The catalog loader and schema now exist; their availability does not imply that the assessment consumes them or packaging covers every new workflow. The current schema's `applies_when` vocabulary describes changes. A whole-assessment applicability adapter must explicitly map process evidence or introduce a versioned extension; it cannot pretend every process is a code change.

Reconcile shared package ownership with the [Threat Analyst plan](../../proposals/security-advisor-threat-analyst-implementation-plan.md#custom-questions-and-methodology-profiles). Keep Analyst job state isolated from assessment state. Share data semantics and pure admission code, not an implicit invocation of an Analyst job inside an assessment.

The [context-routing contract](../contracts/context-routing.md) currently excludes component-type and capability selectors until a resolver can enforce them. `build_abuse_case_contexts.py` projects one candidate at a time. Process grouping or broader applicability is therefore a reviewed contract change, not an existing batching capability to assume. Do not simply put multiple candidates into the current single-candidate packet.

Follow [org-profile invariants](../contracts/org-profile-invariants.md) through schema, validation, resolution, packaging, consumption, and tests. Existing `abuse_cases.add` and `abuse_cases.disable` belong to a different contract. Preserve their compatibility, but do not reuse disable semantics to let question packages remove required business investigations or suppress evidence-backed findings.

Applicable constraints include REQ-MOD-001/004/005/009, REQ-FLW-002/003, REQ-BIZ-001/003/004/005, REQ-REQ-001, REQ-RPT-001/002/006, REQ-ANA-001 through 005, REQ-TRU-001, REQ-CFG-001/002, and REQ-EVO-003 in [the requirements](../../../specs/requirements.md). Before runtime changes, propose new product promises for explicit operator approval and maintain exact bindings. This plan changes no normative requirements.

## Built-in business investigations

Ship general investigation questions that establish the applicable business expectation before testing it. Organization-specific requirements, amounts, thresholds, and approval policies must come from admitted context or confirmed answers, not from model invention.

| Topic | Questions | Representative source evidence |
|---|---|---|
| Business authorization | Who may perform the action on this object and in this state? Do role, tenant, assignment, initiator, or delegated authority impose further conditions? | Identity origins, resource relationships, policy calls, rejecting branches, and alternate action paths. |
| Process integrity | Which transitions are legal? Can required steps be skipped or a later edit invalidate an earlier approval? | State transitions, approval binding, update routes, and execution checks. |
| Repetition and concurrency | Can retries, duplicate requests, or concurrent operations violate a confirmed business invariant? | Transaction boundaries, idempotency handling, atomic updates, aggregate checks, and asynchronous consumers. |
| Abuse of combined operations | Can allowed operations be composed into an unauthorized advantage or harmful outcome? | Multi-step actor paths, intermediate capabilities, and business consequences. |

The first process example follows request creation, approval, recipient modification, and execution. Package questions help identify attack hypotheses; they do not automatically produce findings. A protected path, a supported candidate, an unresolved policy, and an inapplicable expectation must remain distinct.

Maintain one authoritative question text in the shared package. Documentation links it and explains authoring. Existing Python/YAML check descriptions stay at their existing sources. Scanner check IDs, package-qualified question references, abuse-case IDs, process references, requirements, and finding IDs are different identities. A common question does not justify merging different findings.

## User selection and packaged delivery

Both user files and organization-bundled files use `analyst-catalog.schema.json` and the same admission semantics. Existing Analyst content can already express an initial business question as follows; assessment consumption is the new work:

```yaml
schema_version: 1
kind: questions
id: example/payments
version: 1.0.0
title: Payment authorization questions
provenance:
  source: Example organization payment policy
  revision: policy-v1
questions:
  - id: approval-separation
    topic: authorization
    applies_when: [business_operation, changed_permission]
    asks: >
      Where policy requires separate identities, can a payment initiator
      approve the same payment or change its recipient after approval?
    purpose: >
      Self-approval or approval of a different recipient can allow
      unauthorized payouts despite a valid approval role.
    evidence:
      - Applicable policy and its process scope
      - Initiator and approver identity sources
      - Approval, recipient update, and execution controls
    negative_tests:
      - An initiator approving the same payment is refused where policy requires separation.
```

Confirm applicability through the policy or business-context source. A claimed provenance string is not proof that the policy applies. Store observed behavior, confirmed expectation, and provisional assumption separately. Extend structured fields only where the initial process context cannot carry their source and scope without ambiguity.

Use the existing organization profile shape for on-demand analysis:

```yaml
analyst:
  required_packages:
    - file: analysis-rules/payments.yaml
      sha256: <digest of the packaged file>
```

The digest is a placeholder, not a working configuration. A proposed layout is `org-profile/org-profile.yaml` with `org-profile/analysis-rules/payments.yaml`. Retain current profile-relative containment and digest pinning. Define the assessment selection surface explicitly in P0; do not publish an invented `analysis.question_packages` setting as currently supported. An explicit user selection adds packages for an invoked run and cannot remove required organization inputs.

An organization may maintain that profile and its question files in its organization repository and supply the profile to the existing plugin packaging workflow. The built plugin must include the selected files and must not depend on that repository remaining accessible. For the Analyst, users already add a local file through `--package` with an absolute path; CI uses trusted selections through `--trusted-package`, with local files pinned by digest outside the checkout under review. The full assessment needs its own explicit additive package parameter, finalized in P0 and tested in P2/P5. Document that new parameter only when implemented; a parameter passes package data, never Python code or execution permissions.

Package builds must carry selected files, validate their contents and references, record identities, versions and digests in the package surface inventory, and preserve path resolution after relocation. Smoke-test the built plugin from a different directory with the original source profile unavailable. Test both a required organization package and an added user package. Verify existing generic copying before adding special cases, and never claim current packaging is missing functionality solely because it lacks an Analyst-named function.

No target file activates itself. Trusted configuration determines package selection and required status outside package contents. CI pins local package contents outside the checkout under review under the existing resolver contract. Installing packages or configuring defaults does not start an analysis.

All selected inputs load and validate before dependent dispatch. Invalid, missing, conflicting, or incompatible selections produce visible non-success rather than omission or fallback. Preserve no-custom-package behavior and all deterministic checks. Built-in business guidance becomes a documented default for relevant processes within an invoked assessment only after pilot acceptance; this is a deliberate runtime change, not a claim of identical LLM results.

## Admission and trust boundaries

The affected assets are admitted source, business context, organizational expectations, package integrity, and findings. Boundaries are package file to loader, business declarations to process context, source context to model, and model proposals to validated results. Operator configuration determines authority. Neither package prose nor analyzed code nor model output can override that authority.

The aiscb baseline requires packages to remain data. Reject executable tags, duplicate keys, unknown executable or permission fields, ambiguous identities, forged receipts, incompatible versions, escaping paths, and unsafe file references. Bound file bytes, nesting, alias expansion, question count, field lengths, and parsing work outside the model. Audit the existing loader for these required behaviors and implement missing protections in its owning module with tests; reuse alone does not establish compliance.

Packages cannot select commands, tools, output paths, additional source roots, confirmation status, or severity. No remote fetches or arbitrary regex evaluation are added. Keep detected conflicts in business expectations unresolved until authoritative context resolves them; a schema cannot prove arbitrary prose consistent. Preserve required organization inputs and reject attempts to replace them through selection or package identity collisions.

Use existing context isolation and output encoding. Do not put raw proprietary business prose or source contents in public provenance or logs merely to identify a package. Validation checks references and source receipts; it cannot prove that a model's business judgment is correct.

## Process context and analysis flow

The following process pipeline applies to the full assessment. The Analyst uses its own scoped adapter described below and does not acquire an architecture-stage dependency.

1. Resolve selected packages, authority, versions, digests, and existing business context before affected dispatch. Record missing context without replacing it with model defaults.
2. Let architecture analysis identify relevant actors, assets, operations, state transitions, and business processes from admitted evidence. Deterministic validation binds proposed process references to existing components and source evidence.
3. Select relevant questions and form concrete abuse hypotheses. Semantic selection may propose entry IDs, but deterministic admission checks every reference, source scope, and receiving role. Do not make keyword or existing-finding matches the only route to a business hypothesis.
4. Build one bounded process context containing the applicable expectations, assumptions, relevant architecture/control facts, scanner evidence, selected questions, and admitted source slices. Keep full architecture and unrelated source out of focused inputs.
5. Group related questions within an existing model-assisted analysis role. Reuse prior inspected facts. Do not add one agent call per rule. The first integration reuses bounded stage calls; any additional dispatch needs measured evidence and explicit budget accounting.
6. Validate structured model proposals, evidence requests, question references, and coverage dispositions outside the model. Run finding candidates through existing evidence, severity, and consolidation gates. Report unresolved business questions and unexamined scope separately.

A process can span components. Define its bounded connected scope and projection explicitly without treating a process as a new component or skipping per-component STRIDE coverage. Reconcile the timing of architecture discovery, existing abuse-case matching, and verification before scheduling the new hypotheses. If a downstream finding is required by today's matcher, add a source-supported business-candidate path instead of fabricating scanner evidence to activate it.

Proposed handoff semantics include process references, source-bound actors and transitions, expectation references with status and provenance, selected package/question references, admitted source receipts, and omissions. The response carries candidate findings, assessed controls, unresolved hypotheses, missing business facts, and question dispositions. Choose existing schema extensions or a new schema-backed projection in P0 based on the affected consumers; every exchanged artifact needs a validator and owner.

Missing facts that determine whether a policy applies prompt targeted questions in interactive mode. CI returns explicit unresolved items. Independent technical analysis may continue, but required missing business evidence prevents a complete business assessment and follows the existing publication contract. Silence and model-generated guesses are not answers.

## Threat Analyst activation and scope adapter

Extend the existing `appsec/core` question package in `data/analyst-questions.yaml` with the general business questions, refining overlapping entries rather than adding duplicates. Preserve existing entry identities for compatible refinements and update the package version. The Analyst already loads this package on every invocation; a new unregistered package file is not an activation mechanism. The assessment adapter consumes those same entries through its explicit selection contract. User and organization additions retain their existing selection and authority rules.

Release the expanded core content only after the Analyst pilot passes. During evaluation, use isolated baseline and treatment package revisions rather than introducing a production bypass for required core questions. A separate built-in package would require a reviewed replacement decision covering registry entries, default selection in both workflows, versions, and migration; it is not an interchangeable P1 implementation choice.

Trace `scripts/orchestrator/analyst_controller.py` from admission through `scripts/contexts/resolve_analyst_catalog.py`, `scripts/contexts/build_analyst_context.py`, and `scripts/runtime/analyst_host.py` to result validation and rendering. Preserve the Analyst's own job, snapshot, and output contracts. Do not send its findings through assessment writers or mutate `threat-model.yaml`.

The current `select_questions` takes an authority-ordered prefix before source capture. Merely appending new questions can leave relevant additions outside the delivered prefix. Add a bounded scope-aware selection step after request/snapshot context is available and before final context admission. Keep package loading separate from applicability selection. Selection may prioritize optional questions using admitted intent and process evidence, but must preserve core and organization-required authority and record every omission. Undelivered required questions continue to make coverage incomplete under the existing contract; a relevance claim cannot silently waive that requirement. Do not solve selection by blindly increasing the question limit.

Treat `applies_when` as guidance interpreted for the selected mode, not a keyword gate that excludes design or hypothesis analysis merely because no diff exists. Test a relevant question placed after many unrelated entries, including a package set exceeding the configured limit. Demonstrate relevant optional selection, visible omissions, and incomplete required coverage when necessary. Package or selection changes must invalidate dependent answer fingerprints and contexts under existing lifecycle rules.

| Analyst mode | Input and scope | Required acceptance evidence |
|---|---|---|
| Design question | Supplied intent, design and admitted business context; no diff or existing threat model required. | Applicable business questions reach the model; assumptions and missing policy remain explicit; a design scenario is not presented as a code-confirmed vulnerability. |
| Change review | Selected comparison and admitted snapshot, with supporting evidence inside the existing read scope. | New questions reach model input and result provenance; findings retain supported change relationships; unrelated files or processes are not admitted by package text. |
| Hypothesis check | Explicit hypothesis, Git revision, and selected literal paths. | Matching business questions reach the model without a diff; supported, not-confirmed, and unresolved conclusions retain source evidence and scope; an unavailable out-of-scope control leaves the result unresolved rather than expanding access. |

For every mode, verify the actual host payload and resulting report, not only catalog loading. Cover built-in content, a user-added package, an organization-required package, a protected case, and missing evidence. Test CLI/skill input parity where supported and trusted CI package selection without interactive answers. Record Analyst quality and incremental cost separately from assessment results.

## Results, cost, and lifecycle

Keep coverage dispositions separate from confirmation: not selected, not applicable with rationale, investigated with evidence, unresolved, and omitted with reason. A model's claim that a control exists does not establish a verified control. Existing evidence-state and severity contracts decide acceptance. A question package never supplies its own completion or severity verdict.

Preserve package version, content digest, question and process references through intake and consolidation. Retain multiple contributing references without changing public finding IDs. Use existing fields only if they represent these identities faithfully; otherwise version and update response, canonical model, merge, renderer, and exports together. Legacy models remain readable, and narrower exports identify semantics they cannot represent.

Keep ordinary Python checks free of new model calls. Additional cost belongs to selected business investigations. Enforce per-process and per-run bounds on question selection, serialized context, source reads, model steps, retries, and elapsed time. Reuse existing controller counters where they fit and define any new limits in the authoritative budget data. Do not raise global budgets speculatively.

Record selected, omitted, and grouped questions, delivered context size, available token usage, latency, and cost. Optional omissions remain visible; required work exceeding a limit leaves the assessment incomplete. The existence of a required package does not make all of its questions applicable to every process.

Bind cached contexts and results to source revision, expectation/answer provenance, package digests, policy, model, and prompt configuration. Relevant changes invalidate dependent analysis on resume. Recheck admission authority before reuse. Classify new artifacts under the [audit-artifact](../contracts/audit-artifacts.md) and [cleanup](../contracts/cleanup-whitelist.md) contracts. Keep enough provenance to explain delivered findings after cleanup, never delete user packages, and never interpret old results with silently updated package content.

## Delivery sequence and acceptance gates

Each stage covers both consumers explicitly while preserving their separate permissions, scope, state, and output ownership.

| Package | Work and affected surfaces | Acceptance evidence | Depends on |
|---|---|---|---|
| P0: Contracts and integration map | Trace business-context, architecture, abuse-case and STRIDE stages; settle package ownership, assessment selection, process handoff, evidence statuses, limits, and compatibility. Propose normative deltas where needed. | Reviewed producer/consumer map and schema plan; no silent reuse of change-only applicability or single-candidate context; approved product promises before runtime edits. | None. |
| P1: Business questions and cases | Extend and version `appsec/core` with shared authorization, state-transition, and repetition/concurrency questions; preserve stable identities and refine overlaps. Create user examples and expected outcomes for both consumers. | Business-aware reviewer confirms expectations and evidence needs; every new entry is reachable through Analyst core loading and the assessment adapter; pilot variants include design, review, and hypothesis cases. | P0. |
| P2: Admission and packaging | Reuse/harden the catalog loader; add explicit assessment profile/CLI selection; validate and package files with surface metadata and installed smoke coverage. | Required and additive user packages load through one format; invalid or adversarial inputs fail closed; installed package resolves after relocation without original files; existing Analyst behavior remains compatible. | P0 and P1. |
| P3: One end-to-end process in both workflows | Connect payment questions to the assessment role and the Analyst's three mode adapters. Add bounded Analyst selection after scope admission, receipts, dispositions, and provenance in each workflow's outputs. | Actual model inputs and reports show new questions in design, review, hypothesis, and assessment runs; late relevant questions and over-limit packages preserve required coverage semantics; self-approval, protected, and unresolved cases remain distinct without expanded scope. | P2. |
| P4: Comparative pilot | Add refund repetition/concurrency and post-approval recipient-change cases. Compare the same existing analysis with and without guidance. | Predefined quality and incremental-cost gates pass across repeated held-out cases, including an outside-catalog threat; no claim of benefit from scanner fixes or mocked transport tests. | P3. |
| P5: Default integration and delivery | Release expanded Analyst core questions and assessment selection after their respective acceptance; complete both workflows' provenance, lifecycle, user docs, entry-point parity, and installed package smoke tests. | Built-in and custom questions reach each supported consumer; reports retain provenance; Analyst jobs never mutate assessment artifacts; old models and Python checks remain compatible; required missing input never appears complete. | P4 acceptance in both workflows. |

The first implementation slice is P0/P1, followed by one payment process through P2/P3. A scanner documentation project or correction to `AUTHZ-002` is not on this dependency chain. No new executable rule engine or LLM replacement of technical analyzers is part of P5.

## Evaluation design

Compare the same baseline technical and model-assisted analysis with and without admitted business guidance. Keep Python detector revisions, source snapshots, surrounding context, model settings, and comparable budgets fixed. Record package, prompt, model and plugin versions, run order, input fingerprints, and costs. Separate detector corrections from this experiment.

Run and report separate comparisons for full assessments and Analyst design, review, and hypothesis modes. Share case semantics and package text, but adapt expected claims to each mode's available evidence. Passing one consumer's evaluation cannot substitute for another's delivery or usefulness evidence.

Use three main scenarios: self-approval under a confirmed separation requirement; cumulative or concurrent refunds beyond an evidenced payment limit; and changing an approved recipient without reauthorization where approval is bound to that recipient. Supply protected, violating, unresolved, inapplicable, and renamed variants for each. Include a process in another business domain and a threat outside the catalog to detect overfitting and narrowed discovery.

Expected outcomes come from source behavior and established business facts. A business-aware reviewer defines them before model runs, including where no policy can be inferred. Keep held-out cases separate from examples used to author the package. Adjudicate without knowing the treatment where practical. An absent deployment policy or external service must not be silently supplied to only one treatment.

Propose three paired runs per held-out case with treatment order alternated. Finalize repetitions, model, case count, total spend, and maximum added context cost before live evaluation. Report variability rather than claiming universal superiority from a small pilot.

Measure additional supported findings, false positives, missed supported threats, invented expectations, unjustified confirmation of unknown cases, selection omissions, outside-catalog discovery, tokens, latency, and cost. Distinguish selection failures from reasoning failures. Transport doubles test integration; live evaluation is required for usefulness claims.

Promotion requires no permission or evidence-gate bypass, no new false confirmations in protected or unresolved acceptance cases, no invented mandatory business rule, retention of the required outside-catalog case, and a demonstrated investigation benefit within the agreed cost budget. If evidence is insufficient, revise or defer default integration and keep existing analyzers intact.

## Verification routes

Before editing implementation paths, run `python3 scripts/check_specs.py --for <path>` and read the returned requirements, decisions, and contracts. Add a matching test module for each new script. Maintain requirement bindings, permissions metadata for new commands or Read/Write/Edit targets, and reviewed test routes when affected.

| Boundary | Relevant verification |
|---|---|
| Shared questions and schema | `tests/test_analyst_catalog.py`, `tests/test_resolve_analyst_catalog.py`, exact example/schema validation, compatibility of existing packages. |
| Analyst execution and selection | `tests/test_analyst_controller.py` and affected context, host, result, CLI/skill, and report tests; inspect actual delivered questions in all three modes, late relevant entries, budget omissions, required coverage, changed answer fingerprints, and absence of assessment writes. |
| Business facts and hypotheses | Business-context tests; `tests/test_resolve_abuse_cases.py`, `tests/test_match_abuse_cases.py`, `tests/test_build_abuse_case_contexts.py`, and affected verification/promotion tests; new process adapter tests if introduced. |
| Profile and installed distribution | `tests/test_org_profile_schema.py`, `tests/test_resolve_org_profile.py`, affected config tests, `tests/test_package_internal_plugin.py`, `tests/test_smoke_test_package.py`, and relevant packaging end-to-end cases. |
| Untrusted inputs | Unsafe YAML tags, duplicate keys, alias/depth/size limits, traversal and symlinks, forged package identity or provenance, conflicting definitions, missing required files, altered digests, and attempted removal of required questions. |
| Process routing | Authorized question/source references, component isolation, existing single-candidate contract preservation, cross-component process projection, finite work, visible omissions, prompt-injection resistance, and unchanged technical scanner dispatch. |
| Results and lifecycle | Real evidence validation, hypothesis versus finding distinctions, provenance through merge/exports, legacy models, changed-package resume, cache invalidation, cleanup without package deletion, and isolated Analyst/assessment state. |

Use neutral names, equivalent variants, and protected negative cases. Replay the golden fixture under [the threat-fixture runbook](../runbooks/threat-fixture.md) when deterministic tail or source scanners change. Inspect branch and worktree test plans for mixed work, run only affected reviewed routes, audit changed routes, and lint Python when modified. Use the full suite only under repository conditions for unbounded scope or release work. Stop when required checks pass. Changelog entries belong to completed user-visible delivery, not this plan revision.

## Decisions before implementation

| Decision | Recommended starting point | Needed by |
|---|---|---|
| Assessment selection interface | Explicit additive profile/CLI selection, sharing package format and authority semantics with Analyst; no implicit cross-workflow activation. | P0. |
| Process context and receiver | Reuse a bounded existing analysis role and define a process projection; resolve stage ordering and current single-candidate constraints before dispatch changes. | P0. |
| Package ownership and reviewer | One shared source for general questions; business owner or AppSec reviewer establishes domain-specific expectations for the pilot. | P1. |
| Package and process limits | Controller-owned limits derived from measured contexts; no blanket timeout or token increase. | P2/P3. |
| Quality and cost threshold | Agree held-out cases, paired repetitions, total spend, and incremental token/cost ceiling before live runs. | P4. |
| Further default topics | Expand amounts/quotas and cross-service questions only after relevance and cost evidence; existing general threat discovery continues meanwhile. | After P4. |

## Historical detector comparison and separate follow-up

The following earlier experiment is retained as scoped evidence for independent scanner maintenance. It does not measure the business-analysis feature, demonstrate LLM superiority, or require implementing those fixes as part of this plan.

On 2026-10-07, six synthetic handler cases were evaluated under two unrelated store and file names using the real `AUTHZ-002` scanner and `AUTHZ-301` confirmer. Both name variants produced the following outcomes. The expected result was a manual application of the security invariant, not an independently executed Markdown or LLM evaluator.

| Case | Expected interpretation | `AUTHZ-002` | `AUTHZ-301` |
|---|---|---|---|
| Object lookup without authorization | Finding | Finding | Finding |
| Lookup scoped to the authenticated owner's identity | Protected | No finding | Cleared |
| Rejecting ownership comparison before returning the object | Protected | Finding: false positive in this isolated case | Cleared |
| Owner filter populated from a request query parameter | Finding | No finding: false negative in this isolated case | Finding |
| Ownership comparison after sending the object | Finding | Finding | Finding |
| Delegated policy service whose implementation is unavailable | Unresolved | No finding | Unresolved |

The confirmer received a supplied route inventory with `missing_authz_suspect` and authentication present. This did not exercise inventory production, consolidation, downstream evidence verification, or final reporting. Four existing confirmer test cases also passed. The experiment establishes detector-level discrepancies, not end-to-end findings, general accuracy rates, or superiority of model-assisted rules.

The reproductions used these handler operations, wrapped in an asynchronous request handler and repeated with `RecordStore` and `AttachmentStore`:

```javascript
// Protected: the rejecting check occurs before the response.
const obj = await RecordStore.findById(req.params.id);
if (obj.ownerId != req.user.id) throw new Error();
return res.json(obj);
```

```javascript
// Violating: the caller chooses both the object and the alleged owner.
const obj = await RecordStore.findOne({id: req.params.id, ownerId: req.query.ownerId});
return res.json(obj);
```

The producing locations are the `AUTHZ-002` counter-pattern declaration and the scanner's counter-pattern evaluation. A nearby owner-field name cannot establish authorization. An effective rejecting guard before disclosure can protect a path even when its syntax is absent from the current counter-patterns. Fix these mechanisms with identity provenance, resource binding, and control-order checks in the producer, preserving uncertainty where analysis cannot resolve them. Do not fix them through report suppression or fixture-specific names. A catalog description supplies the acceptance standard; it does not repair executable behavior.
