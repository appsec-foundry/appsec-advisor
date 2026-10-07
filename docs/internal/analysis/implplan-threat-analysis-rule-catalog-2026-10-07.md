# Generic abuse cases and investigation packages implementation plan

Status: proposed implementation plan, revised 2026-10-07. The operator authorized this documentation revision. Runtime implementation and normative requirement changes require separately reviewed scope. The [concept](../../proposals/threat-analysis-rule-catalog-concept.md) defines the agreed direction: retain deterministic analyzers and add focused business authorization, process, and abuse-case investigation. Existing filenames remain stable for links.

## Outcome and scope

Extend model-assisted analysis with generic abuse cases for administrative misuse, authorization boundaries, and process integrity, supported by focused investigation questions. Cases describe attacker goals and attack chains that the Analyst checks against admitted source and context. Existing Python analyzers continue to execute their technical checks. Python retains source extraction, package admission, execution limits, validation, and result processing.

Deliver shared questions and case definitions to two explicit consumers: the on-demand Threat Analyst and the full threat-model assessment. Reuse each content type's authoritative contract through separate scope adapters. Verify delivery and usefulness in each workflow; successful assessment integration does not establish that the Analyst received or investigated the new cases.

Start with roughly eight to twelve cases covering delegated administration, tenant boundaries, support impersonation, recovery, approvals, and alternate data access. Application profiles reference shared cases and provide an initial selection; admitted capabilities and permission boundaries establish applicability. Payment questions remain examples of domain specialization. Existing STRIDE coverage and investigation of threats outside the catalog remain active.

A comprehensive catalog of Python detector meanings, automated translation of questions into Python, an executable rule language, arbitrary user regex or code, remote package downloads, and automatic repository package discovery are outside scope. Initial verification investigates attack hypotheses in code; executing attacks against a running application is a separate capability and authorization scope. The earlier source-scanner discrepancies are recorded at the end as separate producer-fix work. They are not a dependency of this feature.

## Existing implementation and contracts

| Existing surface | Reuse and required delta |
|---|---|
| `scripts/analyzers/`, `data/source-auth-checks.yaml`, `data/architecture-coverage-rules.yaml` | Keep technical detection and IDs; reuse relevant evidence without duplicating executable definitions or assuming they prove business authorization. |
| `schemas/analyst-catalog.schema.json`, `data/analyst-questions.yaml`, `scripts/contexts/resolve_analyst_catalog.py` | Reuse existing question identity, schema, provenance, authority, and local package loading. Extend only proven gaps for process-oriented assessment. |
| `schemas/abuse-cases.schema.yaml`, `data/abuse-cases/default-library.yaml` | Reuse attack-chain definitions and stable case identities; reconcile overlapping patterns and define a compatible descriptive path and application-profile references in P0. |
| `scripts/contexts/load_business_context.py` and business-context contracts | Reuse admitted business facts and sourced answers; add a bounded process projection where current fields cannot express participants, states, or expectation provenance. |
| `scripts/model/resolve_abuse_cases.py`, `match_abuse_cases.py`, `scripts/contexts/build_abuse_case_contexts.py` | Reuse case resolution, matching, and bounded candidate context through explicit adapters; model-derived business hypotheses must not require a scanner finding as their sole activation signal. |
| `agents/appsec-abuse-case-verifier.md`, abuse-case validation and promotion | Reuse evidence-chain investigation and acceptance. Review stage ordering before feeding new process hypotheses into the verifier. |
| `schemas/org-profile.schema.yaml`, `scripts/runtime/resolve_org_profile.py` | Existing `analyst.required_packages` and `analyst.default_packages` configure on-demand analysis. Add explicit assessment selection without silently expanding those fields' consumers. |
| `scripts/package_internal_plugin.py`, `scripts/smoke_test_package.py` | Verify and extend copying, relocation, schema validation, package surface inventory, and installed resolution for selected question files. |
| Context-routing catalog, bindings, budgets, and controller | Add independently selectable process/question context with bounded receivers and exact-byte receipts; no global prompt injection. |
| Finding intake, merge, `scripts/shared/_finding_state.py`, renderers and exporters | Preserve confirmation, severity, identities, and consolidation; retain structured case provenance and answer explicit user requests without requiring every template to appear in narrative output. |

The catalog loader and schema now exist; their availability does not imply that the assessment consumes them or packaging covers every new workflow. The version-1 `applies_when` vocabulary retains change-oriented names, interpreted within the Analyst's selected mode. A whole-assessment applicability adapter must map these hints to admitted process evidence; it cannot require a diff or pretend every process is a code change. Additional structured semantics require a reviewed compatible extension.

Reconcile shared package ownership with the [Threat Analyst plan](../../proposals/security-advisor-threat-analyst-implementation-plan.md#custom-questions-and-methodology-profiles). Keep Analyst job state isolated from assessment state. Share data semantics and pure admission code, not an implicit invocation of an Analyst job inside an assessment.

The [context-routing contract](../contracts/context-routing.md) currently excludes component-type and capability selectors until a resolver can enforce them. `build_abuse_case_contexts.py` projects one candidate at a time. Process grouping or broader applicability is therefore a reviewed contract change, not an existing batching capability to assume. Do not simply put multiple candidates into the current single-candidate packet.

Follow [org-profile invariants](../contracts/org-profile-invariants.md) through schema, validation, resolution, packaging, consumption, and tests. Existing `abuse_cases.add` and `abuse_cases.disable` belong to a different contract. Preserve their compatibility, but do not reuse disable semantics to let question packages remove required business investigations or suppress evidence-backed findings.

Applicable constraints include REQ-MOD-001/004/005/009, REQ-FLW-002/003, REQ-BIZ-001/003/004/005, REQ-REQ-001, REQ-RPT-001/002/006, REQ-ANA-001 through 005 and 009, REQ-TRU-001, REQ-CFG-001/002, and REQ-EVO-003 in [the requirements](../../../specs/requirements.md). Before runtime changes, propose new product promises for explicit operator approval and maintain exact bindings. This plan changes no normative requirements.

## Generic case catalog and application profiles

A catalog case describes a reusable attacker goal and concrete steps with variable roles and resources. Bind those variables to admitted implementation and context before assessing the attack path. Establish the authority or process boundary being crossed; an authorized administrative operation is not a finding merely because it is powerful. Organization-specific separation, ownership, and approval expectations need an admitted source.

| Initial case | Required capability and boundary | Relevant application profiles |
|---|---|---|
| A delegated administrator grants themselves privileges beyond their delegation. | Role assignment and a bounded set of assignable privileges or subjects. | Administration portal, identity management. |
| A tenant administrator changes users or resources in another tenant. | Tenant-specific administration and resource ownership. | Multi-tenant application, administration portal. |
| A support operator uses impersonation for actions outside their support authority. | User impersonation with defined action restrictions. | Support portal, administration portal. |
| An actor changes another account's recovery data and takes over a stronger identity. | Recovery-data changes bound to account ownership and verified authority. | Identity management, self-service portal. |
| An editor changes approved content and reuses its prior approval. | Approval bound to content, version, or state. | Content management, approval workflow. |
| A requester approves their own request despite required independent approval. | Approval operation and an evidenced separation requirement. | Approval workflow, administration portal. |
| A user retrieves restricted content through an export, share link, or alternate route. | Multiple access paths to resources with the same read boundary. | Document management, reporting application. |
| A former delegate keeps using a revoked permission through a retained session or token. | Revocable delegation and an evidenced revocation policy. | Identity management, multi-tenant application. |
| A user repeats or races an operation to exceed a one-time or cumulative entitlement. | Stateful operations with an evidenced quantity, quota, or transition limit. | Self-service portal, workflow application. |
| A user makes a privileged background worker act on resources outside the user's authority. | Delegated asynchronous work and caller-to-resource authorization binding. | Job processing, integration platform. |

Application profiles are declarative references to shared case identities. One case may belong to several profiles; profiles do not duplicate case text. Application labels are selection hints, and capability evidence decides relevance. Names and frameworks must not become mandatory matching keys. Cases outside the selected profiles remain discoverable through general threat analysis.

Each case needs actor and initial access, prerequisites, goal, crossed boundary, attack steps, expected controls, required evidence, legitimate exclusions, and unresolved conditions. Reuse the existing abuse-case contract where it fits. Its current chain steps require probe patterns and may carry classification and release-gate fields; P0 must define a compatible descriptive adapter rather than fabricate regexes, scanner findings, severity, or execution authority. Question-package version 1 remains suitable for accompanying questions. It does not silently gain case or application-profile fields.

The first end-to-end example follows delegated role assignment and attempted self-escalation. Protected controls, supported attack candidates, unresolved expectations, and inapplicable cases remain distinct. Maintain one authoritative definition for each case and question. Package-qualified question references, case templates, instantiated cases, explicit user requests, process references, and finding IDs remain separate. Multiple cases may support one finding, and one case may expose several findings; consolidation still follows evidence and root cause.

## User selection and packaged delivery

User and organization question files use `analyst-catalog.schema.json` and the same admission semantics. The [payment question package](../../../examples/analyst/payments-package.yaml) remains a domain-specific authoring example. P1 adds generic administrative and application-capability examples under the contracts agreed in P0. Case definitions and application profiles use their own compatible, validated contracts; do not pass them to the current question loader as if those content types were already supported.

Follow the [Analyst authoring guidance](../../threat-analyst.md#question-packages-and-the-threat-modeling-manifesto-profile) for one independently assessable question per entry. Interpret `applies_when` against planned design behavior, the selected change, or the inspected hypothesis scope; the proposed assessment adapter maps it to admitted process evidence. Keep the package's version-1 shape and vocabulary. Applicability hints cannot establish an organizational expectation, grant source access, or waive required coverage. Retain them in the bounded model context; contexts predating that additive field remain readable.

Confirm applicability through the policy or business-context source. A claimed provenance string is not proof that the policy applies. Store observed behavior, confirmed expectation, and provisional assumption separately. Extend structured fields only where the initial process context cannot carry their source and scope without ambiguity.

Use the existing organization profile shape for on-demand analysis:

```yaml
analyst:
  required_packages:
    - file: analysis-rules/payments.yaml
      sha256: <digest of the packaged file>
```

The digest is a placeholder, not a working configuration. A proposed layout is `org-profile/org-profile.yaml` with `org-profile/analysis-rules/payments.yaml`. This example selects questions, not an explicit case request. Retain current profile-relative containment and digest pinning. Define assessment selection and explicit case-request surfaces in P0; do not publish invented settings or flags as currently supported. An explicit user selection adds packages for an invoked run and cannot remove required organization inputs.

An organization may maintain that profile and its question files in its organization repository and supply the profile to the existing plugin packaging workflow. The built plugin must include the selected files and must not depend on that repository remaining accessible. For the Analyst, users already add a local file through `--package` with an absolute path; CI uses trusted selections through `--trusted-package`, with local files pinned by digest outside the checkout under review. The full assessment needs its own explicit additive package parameter, finalized in P0 and tested in P2/P5. Document that new parameter only when implemented; a parameter passes package data, never Python code or execution permissions.

Package builds must carry selected files, validate their contents and references, record identities, versions and digests in the package surface inventory, and preserve path resolution after relocation. Smoke-test the built plugin from a different directory with the original source profile unavailable. Test both a required organization package and an added user package. Verify existing generic copying before adding special cases, and never claim current packaging is missing functionality solely because it lacks an Analyst-named function.

No target file activates itself. Trusted configuration determines package selection and required status outside package contents. CI pins local package contents outside the checkout under review under the existing resolver contract. Installing packages or configuring defaults does not start an analysis.

Record explicit investigation requests from the authorized invocation, whether the user supplies a hypothesis or names a catalog case. Capture a stable request reference, recognizable label, admitted scope, and any selected case reference before dispatch. Package origin, organization-required authority, the existing case `source: mandatory`, and profile membership do not by themselves create a public reporting request. A user-added package remains an investigation input unless the user explicitly asks for named cases or all its cases to be individually checked and answered.

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
3. Use application profiles to propose relevant cases, bind their actors and resources to admitted capabilities, and form concrete attack hypotheses with supporting questions. Carry explicit user requests independently of optional relevance ranking. Semantic selection may propose IDs, but deterministic admission checks every reference, source scope, and receiving role. Do not make keyword or existing-finding matches the only route to a business hypothesis.
4. Build one bounded process context containing the applicable expectations, assumptions, relevant architecture/control facts, scanner evidence, selected questions, and admitted source slices. Keep full architecture and unrelated source out of focused inputs.
5. Group related questions within an existing model-assisted analysis role. Reuse prior inspected facts. Do not add one agent call per rule. The first integration reuses bounded stage calls; any additional dispatch needs measured evidence and explicit budget accounting.
6. Validate structured model proposals, evidence requests, case and question references, and coverage dispositions outside the model. Run finding candidates through existing evidence, severity, and consolidation gates. Reconcile every explicit user request with a visible outcome or reason it was not investigated. Report relevant unresolved questions and material unexamined scope.

A process can span components. Define its bounded connected scope and projection explicitly without treating a process as a new component or skipping per-component STRIDE coverage. Reconcile the timing of architecture discovery, existing abuse-case matching, and verification before scheduling the new hypotheses. If a downstream finding is required by today's matcher, add a source-supported business-candidate path instead of fabricating scanner evidence to activate it.

Proposed handoff semantics include process references, source-bound actors and transitions, expectation references with status and provenance, package/question/case references, application-profile selection reasons, explicit request references, admitted source receipts, and omissions. The response carries candidate findings, assessed controls, unresolved hypotheses, missing business facts, and per-case dispositions. The controller owns request provenance and checks that no request disappeared. Choose compatible schema extensions or a new schema-backed projection in P0 based on the affected consumers; every exchanged artifact needs a validator and owner.

Missing facts that determine whether a policy applies prompt targeted questions in interactive mode. CI returns explicit unresolved items. Independent technical analysis may continue, but required missing business evidence prevents a complete business assessment and follows the existing publication contract. Silence and model-generated guesses are not answers.

## Threat Analyst activation and scope adapter

Extend the existing `appsec/core` question package in `data/analyst-questions.yaml` with supporting authorization and process questions, refining overlapping entries rather than adding duplicates. Preserve existing entry identities for compatible refinements and update the package version. The Analyst already loads this question package on every invocation. Add explicit adapters to the shared case library and application-profile references agreed in P0; a new unregistered file is not an activation mechanism. The assessment consumes the same authoritative case and question definitions through its own selection contract. User and organization additions retain their existing authority rules.

Release the expanded core content only after the Analyst pilot passes. During evaluation, use isolated baseline and treatment package revisions rather than introducing a production bypass for required core questions. A separate built-in package would require a reviewed replacement decision covering registry entries, default selection in both workflows, versions, and migration; it is not an interchangeable P1 implementation choice.

Trace `scripts/orchestrator/analyst_controller.py` from admission through `scripts/contexts/resolve_analyst_catalog.py`, `scripts/contexts/build_analyst_context.py`, and `scripts/runtime/analyst_host.py` to result validation and rendering. Preserve the Analyst's own job, snapshot, and output contracts. Do not send its findings through assessment writers or mutate `threat-model.yaml`.

The current `select_questions` takes an authority-ordered prefix before source capture. Merely appending new questions can leave relevant additions outside the delivered prefix. Add a bounded scope-aware selection step after request/snapshot context is available and before final context admission. Keep package loading separate from applicability selection. Selection may prioritize optional questions using admitted intent and process evidence, but must preserve core and organization-required authority and record every omission. Undelivered required questions continue to make coverage incomplete under the existing contract; a relevance claim cannot silently waive that requirement. Do not solve selection by blindly increasing the question limit.

Treat `applies_when` as guidance interpreted for the selected mode, not a keyword gate that excludes design or hypothesis analysis merely because no diff exists. Test a relevant question placed after many unrelated entries, including a package set exceeding the configured limit. Demonstrate relevant optional selection, visible omissions, and incomplete required coverage when necessary. Package or selection changes must invalidate dependent answer fingerprints and contexts under existing lifecycle rules.

| Analyst mode | Input and scope | Required acceptance evidence |
|---|---|---|
| Design question | Supplied intent, design and admitted business context; no diff or existing threat model required. | Applicable business questions reach the model; assumptions and missing policy remain explicit; a design scenario is not presented as a code-confirmed vulnerability. |
| Change review | Selected comparison and admitted snapshot, with supporting evidence inside the existing read scope. | New questions reach model input and result provenance; findings retain supported change relationships; unrelated files or processes are not admitted by package text. |
| Hypothesis check | Explicit hypothesis, Git revision, and selected literal paths. | Matching business questions reach the model without a diff; supported, not-confirmed, and unresolved conclusions retain source evidence and scope; an unavailable out-of-scope control leaves the result unresolved rather than expanding access. |

For every mode, verify the actual host payload, structured case records, and report projection. Cover built-in content, a user-added package, an organization-required package, an explicit case request, a protected case, and missing evidence. A direct hypothesis is an explicit request; broader design and review invocations may also carry explicit cases once their admission contract is implemented. Design reports assess scenarios and assumptions without claiming code confirmation. Test CLI/skill input parity where supported and trusted CI package selection without interactive answers. Record Analyst quality and incremental cost separately from assessment results.

## Results, cost, and lifecycle

Keep coverage dispositions separate from confirmation: not selected, not applicable with rationale, investigated with evidence, unresolved, and omitted with reason. A model's claim that a control exists does not establish a verified control. Existing evidence-state and severity contracts decide acceptance. A question package never supplies its own completion or severity verdict.

Preserve package and template versions, content digests, question/case/process references, target bindings, evidence, dispositions, and finding links in structured analysis records through intake and consolidation. Retain multiple contributing references without changing public finding IDs. Catalog templates need no one-to-one narrative entry or public template reference. The readable report explains concrete system findings, relevant controls, unresolved questions, and material coverage limits. Internal status for an examined, protected template does not automatically become report prose.

Every explicit user request receives a compact visible answer: request label, disposition, finding links where available, and a concise explanation or missing-evidence reason. Map supported attack path, not confirmed in inspected scope, unresolved, not applicable with rationale, and not performed with reason to the existing evidence states without inventing new confirmation states. Missing source, scope exclusions, budget exhaustion, cancellation, or deduplication cannot remove a request; multiple requests may reference the same finding. Not confirmed never means safe, and a visible not-performed status does not satisfy required investigation coverage.

Keep request origin and reporting intent controller-owned and distinct from case provenance and required-input authority. Test that a package cannot hide an explicit request or mark an internal template as user-requested. Preserve the current canonical YAML abuse-case outcomes and narrower export trace obligations under REQ-RPT-006. P0 must reconcile the report projection with the existing Abuse Cases section in `data/sections-contract.yaml`, its renderer, schemas, and consumers before runtime edits. Reuse existing fields only when they represent the new semantics faithfully; otherwise version and update the affected contracts together. If normal publication is blocked, retain safe request-accounting diagnostics without publishing a complete assessment. Legacy models remain readable.

Keep ordinary Python checks free of new model calls. Additional cost belongs to selected business investigations. Enforce per-process and per-run bounds on question selection, serialized context, source reads, model steps, retries, and elapsed time. Reuse existing controller counters where they fit and define any new limits in the authoritative budget data. Do not raise global budgets speculatively.

Record selected, omitted, and grouped cases and questions, delivered context size, available token usage, latency, and cost. Optional omissions remain in structured coverage; the narrative summarizes material gaps and individually accounts for explicit requests. Required work exceeding a limit leaves the assessment incomplete. The existence of a required package does not make all of its cases or questions applicable to every process.

Bind cached contexts and results to source revision, expectation/answer provenance, package digests, policy, model, and prompt configuration. Relevant changes invalidate dependent analysis on resume. Recheck admission authority before reuse. Classify new artifacts under the [audit-artifact](../contracts/audit-artifacts.md) and [cleanup](../contracts/cleanup-whitelist.md) contracts. Keep enough provenance to explain delivered findings after cleanup, never delete user packages, and never interpret old results with silently updated package content.

## Delivery sequence and acceptance gates

Each stage covers both consumers explicitly while preserving their separate permissions, scope, state, and output ownership.

| Package | Work and affected surfaces | Acceptance evidence | Depends on |
|---|---|---|---|
| P0: Contracts and integration map | Trace both workflows; settle shared case ownership, application-profile references, descriptive adapters, explicit request admission, report projection, limits, and compatibility. Propose normative deltas where needed. | Reviewed producer/consumer and schema plan; existing probe, single-candidate, report-section, and export contracts reconciled; approved product promises before runtime edits. | None. |
| P1: Generic cases and supporting questions | Define eight to twelve capability-based cases and referencing application profiles; refine overlapping `appsec/core` questions and existing library cases; preserve compatible identities and version revised content. | Definitions and examples validate against P0 contracts; reviewer confirms authority boundaries, legitimate exclusions, and evidence needs; every entry has planned consumer mappings and evaluation variants. | P0. |
| P2: Admission and packaging | Reuse/harden loaders; add explicit assessment, profile, and case-request selection; package validated definitions with surface metadata and installed smoke coverage. | Invalid inputs fail closed; required inputs persist; request intent comes from invocation rather than package origin; installed content resolves after relocation. | P0 and P1. |
| P3: One end-to-end case in both workflows | Connect delegated-administrator self-escalation to the assessment role and Analyst mode adapters, with bounded selection, internal case records, and explicit-request answers. | Actual model inputs carry the case; protected and unresolved paths remain distinct; internal templates need no narrative row; every explicit request has a visible disposition, including omissions; late relevant entries preserve required coverage. | P2. |
| P4: Comparative pilot | Add cross-tenant administration and approval reuse after content changes; compare baseline and guided analysis across profiles and renamed cases. | Predefined quality and cost gates pass across held-out cases; outside-catalog discovery persists; incorrect application labels do not override capability evidence; no benefit attributed to scanner fixes or mocked responses. | P3. |
| P5: Default integration and delivery | Release accepted cases, profiles, supporting questions, and consumer adapters; complete report projection, provenance, lifecycle, user docs, entry-point parity, and installed smoke tests. | Explicit requests are answered, structured case trace survives consolidation and cleanup, reports avoid redundant template listings, and existing state isolation, exports, and required completion guarantees hold. | P4 acceptance in both workflows. |

The first implementation slice is P0/P1, followed by delegated-administrator self-escalation through P2/P3. The reusable abuse cases are the investigation inputs; synthetic repositories and expected outcomes are separate evidence for evaluating those inputs. A scanner documentation project or correction to `AUTHZ-002` is not on this dependency chain. No new executable rule engine or LLM replacement of technical analyzers is part of P5.

## Evaluation design

Compare the same baseline technical and model-assisted analysis with and without admitted business guidance. Keep Python detector revisions, source snapshots, surrounding context, model settings, and comparable budgets fixed. Record package, prompt, model and plugin versions, run order, input fingerprints, and costs. Separate detector corrections from this experiment.

Run and report separate comparisons for full assessments and Analyst design, review, and hypothesis modes. Share case semantics and package text, but adapt expected claims to each mode's available evidence. Passing one consumer's evaluation cannot substitute for another's delivery or usefulness evidence.

Use delegated-administrator self-escalation, cross-tenant administrative changes, and approval reuse after content changes as the initial scenarios. Supply protected, violating, unresolved, inapplicable, and renamed variants for each. Include a fully authorized administrator as a legitimate exclusion, a misleading application-profile label, and the same capability in another application type. Add a threat outside the catalog to detect narrowed discovery. Payment examples may supplement these cases without defining their generic identities.

Exercise the same case as an internal template, as an entry in an added package, and as an explicitly requested investigation. Verify that only the explicit request requires an individual visible answer, while all required structured traces remain available. Cover successful findings, evidenced controls, missing evidence, inapplicability, limits, cancellation, and multiple requests converging on one finding.

Expected outcomes come from source behavior and established business facts. A business-aware reviewer defines them before model runs, including where no policy can be inferred. Keep held-out cases separate from examples used to author the package. Adjudicate without knowing the treatment where practical. An absent deployment policy or external service must not be silently supplied to only one treatment.

Propose three paired runs per held-out case with treatment order alternated. Finalize repetitions, model, case count, total spend, and maximum added context cost before live evaluation. Report variability rather than claiming universal superiority from a small pilot.

Measure additional supported findings, false positives, missed supported threats, invented expectations, unjustified confirmation of unknown cases, selection omissions, outside-catalog discovery, tokens, latency, and cost. Distinguish selection failures from reasoning failures. Transport doubles test integration; live evaluation is required for usefulness claims.

Promotion requires no permission or evidence-gate bypass, no new false confirmations in protected or unresolved acceptance cases, no invented mandatory business rule, retention of the required outside-catalog case, and a demonstrated investigation benefit within the agreed cost budget. If evidence is insufficient, revise or defer default integration and keep existing analyzers intact.

## Verification routes

Before editing implementation paths, run `python3 scripts/check_specs.py --for <path>` and read the returned requirements, decisions, and contracts. Add a matching test module for each new script. Maintain requirement bindings, permissions metadata for new commands or Read/Write/Edit targets, and reviewed test routes when affected.

| Boundary | Relevant verification |
|---|---|
| Shared questions, cases, and profiles | Catalog and abuse-case resolution tests, exact schema validation, compatible identities, valid profile references, shared cases without duplicate definitions, and capability-based applicability independent of incidental names. |
| Analyst execution and selection | `tests/test_analyst_controller.py` and affected context, host, result, CLI/skill, and report tests; inspect actual delivered questions in all three modes, late relevant entries, budget omissions, required coverage, changed answer fingerprints, and absence of assessment writes. |
| Business facts and hypotheses | Business-context tests; `tests/test_resolve_abuse_cases.py`, `tests/test_match_abuse_cases.py`, `tests/test_build_abuse_case_contexts.py`, and affected verification/promotion tests; new process adapter tests if introduced. |
| Profile and installed distribution | `tests/test_org_profile_schema.py`, `tests/test_resolve_org_profile.py`, affected config tests, `tests/test_package_internal_plugin.py`, `tests/test_smoke_test_package.py`, and relevant packaging end-to-end cases. |
| Untrusted inputs | Unsafe YAML tags, duplicate keys, alias/depth/size limits, traversal and symlinks, forged package identity or provenance, conflicting definitions, missing required files, altered digests, and attempted removal of required questions. |
| Process routing | Authorized question/source references, component isolation, existing single-candidate contract preservation, cross-component process projection, finite work, visible omissions, prompt-injection resistance, and unchanged technical scanner dispatch. |
| Results and lifecycle | Real evidence validation, internal case trace, visible accounting for every explicit request, origin versus request-intent distinction, deduplicated findings with retained request links, unchanged structured export obligations, legacy models, changed-package resume, cache invalidation, safe cleanup, and isolated Analyst/assessment state. |

Use neutral names, equivalent variants, and protected negative cases. Replay the golden fixture under [the threat-fixture runbook](../runbooks/threat-fixture.md) when deterministic tail or source scanners change. Inspect branch and worktree test plans for mixed work, run only affected reviewed routes, audit changed routes, and lint Python when modified. Use the full suite only under repository conditions for unbounded scope or release work. Stop when required checks pass. Changelog entries belong to completed user-visible delivery, not this plan revision.

## Decisions before implementation

| Decision | Recommended starting point | Needed by |
|---|---|---|
| Assessment selection interface | Explicit additive profile/CLI selection, sharing package format and authority semantics with Analyst; no implicit cross-workflow activation. | P0. |
| Explicit case requests and report projection | Invocation-owned request intent; visible answer for every explicit case; internal catalog templates need no narrative row; existing structured outcome and export obligations persist. | P0. |
| Case and application-profile contracts | Reuse library definitions and stable references; define a compatible descriptive adapter without synthetic executable probes; profiles select by admitted capabilities. | P0. |
| Process context and receiver | Reuse a bounded existing analysis role and define a process projection; resolve stage ordering and current single-candidate constraints before dispatch changes. | P0. |
| Package ownership and reviewer | Shared case definitions and supporting questions; profiles reference cases; an AppSec or domain reviewer establishes authority boundaries and legitimate exclusions. | P1. |
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
