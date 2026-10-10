# Generic abuse cases and investigation packages implementation plan

Status: proposed implementation plan, revised 2026-10-08. The operator authorized this documentation revision. Runtime implementation and normative requirement changes require separately reviewed scope. The [concept](../../proposals/threat-analysis-rule-catalog-concept.md) defines the agreed direction: retain deterministic analyzers and add focused business authorization, process, and abuse-case investigation. Existing filenames remain stable for links.

## Outcome and scope

Move the assessment closer to threat modeling. Today, abuse cases are technical chains that the matcher binds to existing scanner findings. Business rules such as self-approval, delegated administration limits, or approval reuse after a content change cannot be expressed or checked that way. This plan adds business abuse cases that teams write in plain language, maintain next to their code, and have investigated against the source with model assistance.

Three constraints shape every package:

- **Readable and maintainable cases.** A case states actor, goal, crossed boundary, steps, expected controls, and legitimate exclusions in prose. It contains no regex, scanner IDs, severity, or gate configuration. Validation errors name the file, case, and field in terms the author can fix.
- **Deterministic first.** Python keeps every check it can decide. The model receives only the part of a case that needs knowledge of intended authority, process state, or the interplay of several operations.
- **Bounded cost.** Business investigation is an addition with a fixed ceiling, not a new per-rule fan-out. Depth, per-run caps, and reuse of existing calls keep it bounded. Cost is measured before the pilot and gated in every package.

Deliver shared questions and case definitions to two explicit consumers: the full threat-model assessment and the on-demand Threat Analyst. The assessment is the primary consumer and is piloted first. The Analyst receives its own adapter and pilot afterwards. Built-in defaults are released only after both pilots pass. Successful assessment integration does not establish that the Analyst received or investigated the new cases.

Start with roughly eight to twelve cases covering delegated administration, tenant boundaries, support impersonation, recovery, approvals, and alternate data access. Payment questions remain examples of domain specialization. Existing STRIDE coverage and investigation of threats outside the catalog remain active.

A comprehensive catalog of Python detector meanings, automated translation of cases into Python or regex, an executable rule language, arbitrary user regex or code, remote package downloads, and automatic discovery of repository question packages are outside scope. Preserve existing assessment discovery of known threats and repository abuse cases, and extend the case contract for descriptive hypotheses as specified below. Initial verification investigates attack hypotheses in code; executing attacks against a running application is a separate capability and authorization scope. The earlier source-scanner discrepancies are recorded at the end as separate producer-fix work.

## Implementation status

`dev` carries the core of P0 to P3 for the full assessment (b1727c1a, 09d8bfde, e85ddc36). Each of these packages still has open acceptance items, listed under **Open**. The comparative pilot (P4), the Analyst adapter (P5), and the default release (P6) are not started.

- **P0 producer fixes.** Repository case files are contained, size- and count-bounded, and rejected one by one with a run issue and a report line. Unknown `schema_version` values are rejected by name.
- **P1 catalog.** `data/abuse-cases/business-cases.yaml` holds ten descriptive cases. It is not loaded by default.
- **P2 admission.** Version-2 files admit `kind: descriptive` cases through `schemas/abuse-cases.schema.yaml`. Descriptive cases cannot carry probes, severity, goal impact, source, or release gates, and their signals must come from the recon vocabulary.
- **P3 deterministic pilot.** The matcher preselects descriptive cases, applies the depth caps from `data/abuse-case-limits.yaml`, and records omissions as `not_performed`. The verifier receives a descriptive projection. `finalize` admits a deciding step verdict only when its excerpt occurs within three lines of the cited source line in a runtime file. The report and canonical YAML carry business coverage, `not_performed`, and unrated cases.
- **P3 live measurement (2026-10-08).** The worktree verifier definition ran headless on Sonnet against five neutral fixtures for delegated-administrator self-escalation: violating, the same defect under renamed files and identifiers, protected, decided by an external policy service, and misleading through a false comment and an unused delegation helper. All five chain verdicts matched the expectation (`fully_viable`, `fully_viable`, `mitigated`, `inconclusive`, `fully_viable`), and every deciding step passed the excerpt admission. Each call took 6 to 8 turns, 15 to 21 s, and $0.08 to $0.10, mean $0.087. Three candidates at standard depth add about $0.26, below 1 % of the $34.93 standard-run baseline in `docs/internal/cost-model.md`.
- **P3 first assessment run (2026-10-08).** A standard juice-shop run with two repository business cases aborted Stage 1d: the candidate projection exceeded the dispatch item limit, and §9 read as checked. e85ddc36 fixes the limit, names unverified candidates in §9, the YAML, and the run issues, and routes the run back to Stage 1d once. A repeat run is pending.
- **P3 preselection and team questions (2026-10-09).** `scope_qualifier` gains `route_patterns` over route paths in `.route-inventory.json` and `detector_rules` over the `source_check_id` of existing findings. Both locate runtime source files beside `path_patterns`; required signals still gate, and a case that declares locators is a candidate only when one of them finds runtime source. `data/abuse-cases/business-cases.yaml` carries the locators of the initial-case table where a route vocabulary or a source-scanner check exists. An inconclusive, fully verified descriptive case keeps up to three `open_questions` in the canonical YAML, and the team-question selector asks the first one that is a single plain question, linked to the findings its steps bind to (AC-7). A case without a bound, anchored finding raises no question.
- **P3 juice-shop replay (2026-10-09).** Three repository business cases ran through preselection and verification at standard depth. The race on the wallet balance in `routes/order.ts` was confirmed without any register finding, the alternate-route case was confirmed and linked to an existing finding, and the delegated-administrator case was refuted because the application has no delegation. The three verifier calls cost about $0.88, about 4 % of the run. A verified case requested by the invocation now carries `requested: true` in the canonical YAML and is labelled as requested in the Abuse Cases section.
- **Cost ceiling (operator-confirmed 2026-10-09).** Business-case verification adds at most 20 % of a standard run's tokens. The ceiling is provisional for P4 and is lowered to the measured value plus margin afterwards. P4, including whether the thorough-depth verifier runs on Opus, can start; a repeat juice-shop run with business cases measures the per-case cost on a real repository first.
- **Open.**
  - P0: the caps are not operator-confirmed; `added_token_share` is not read by any gate; no product requirement or requirement binding covers the new behavior.
  - P1: overlap with AC-T-002, AC-T-003, and AC-T-004 is not reconciled; `appsec/core` questions are not refined; no reviewer has confirmed the cases; only AC-T-101 has evaluation variants.
  - P2: cases carry no provenance (path, digest) in the report or YAML.
  - P3: admission checks file and excerpt, not the component inventory. A verifier step cites only file, line, and excerpt, so the route inventory has nothing to check against. A component check needs complete component coverage first: on 2026-10-09, 21 runtime handler files of the juice-shop model, among them `routes/updateProductReviews.ts` and `routes/profileImageUrlUpload.ts`, matched no component glob, and admitting only covered files would have downgraded correctly evidenced steps; thorough depth does not escalate inconclusive candidates.
  - The fixtures are small and the cost baseline comes from a different repository. The ceiling and caps stay provisional until P4.

Deviations from the plan text below, decided during implementation:

- **Binding happens inside the verifier call.** Each admitted candidate gets one verifier call that binds and judges its steps. A separate batched binding call in the architecture stage would add a dispatch and change the architecture contract without evidence that it saves cost. `finalize` performs the deterministic admission of the binding.
- **Preselection reuses `scope_qualifier`.** Descriptive cases require `required_signals` or `path_patterns` instead of a new `applies_when` field.
- **No promotion in the pilot.** A confirmed descriptive step does not become a finding, because the case carries no classification. A descriptive case without a linked finding is reported as not rated instead of receiving the fallback risk.
- **Repository cases live beside the other team-maintained inputs.** Discovery reads `docs/security/abuse-cases/` first and the legacy `.appsec/abuse-cases/` after it, with one shared file limit; a legacy file reusing an ID from the new location is rejected.
- **Explicit requests use the existing flags.** Cases named by `--only-abuse-case` or loaded through `--abuse-case-file` bypass preselection and count against their own limit of 16. Requests beyond that limit are recorded as `not_performed` instead of stopping the run. `--only-abuse-case` keeps its restricting semantics, so library cases not named are not run. A file named with `--abuse-case-file` that discovery already loads keeps its repository origin and is not treated as requested.

## Existing implementation and contracts

| Existing surface | Reuse and required delta |
|---|---|
| `scripts/analyzers/`, `data/source-auth-checks.yaml`, `data/architecture-coverage-rules.yaml` | Keep technical detection and IDs; supply their results as preselection signals and evidence without assuming they prove business authorization. |
| `schemas/analyst-catalog.schema.json`, `data/analyst-questions.yaml`, `scripts/contexts/resolve_analyst_catalog.py` | Reuse question identity, schema, provenance, authority, and local package loading. Extend only proven gaps for process-oriented assessment. |
| `schemas/abuse-cases.schema.yaml`, `data/abuse-cases/default-library.yaml` | Reuse case identities, `scope_qualifier`, and chain verdicts; add a versioned descriptive case shape in P0. |
| `schemas/known-threats.schema.yaml`, `scripts/contexts/build_threat_modeling_context.py` | Preserve automatic, contained, size-bounded, schema-validated ingestion of `docs/known-threats.yaml` and its status values. |
| `scripts/model/resolve_abuse_cases.py`, `match_abuse_cases.py`, `scripts/contexts/build_abuse_case_contexts.py` | Reuse resolution, scope checks, and single-candidate context. Add a business-candidate path that does not require a scanner finding. Fix the discovery defects listed below first. |
| `agents/appsec-abuse-case-verifier.md`, `scripts/model/promote_verified_abuse_cases.py`, `scripts/validators/abuse_case_gate.py` | Reuse evidence-chain verification, promotion, and finalization for admitted business candidates in the pilot. |
| `scripts/renderers/team_questions.py` (decision AC-7) | Reuse as the channel for missing business facts that decide whether an expectation applies. |
| `scripts/renderers/render_abuse_cases.py`, `data/sections-contract.yaml` (`abuse_cases`) | Extend the Abuse Cases section for business candidates and explicit requests; keep the existing catalog evaluation table for probe-based cases. |
| `scripts/contexts/load_business_context.py` and business-context contracts | Reuse admitted business facts and sourced answers; add a bounded process projection only where current fields cannot express participants, states, or expectation provenance. |
| `schemas/org-profile.schema.yaml`, `scripts/runtime/resolve_org_profile.py` | Existing `analyst.required_packages` and `analyst.default_packages` configure on-demand analysis only. Add explicit assessment selection without silently expanding those fields' consumers. |
| `scripts/package_internal_plugin.py`, `scripts/smoke_test_package.py` | Verify and extend copying, relocation, schema validation, surface inventory, and installed resolution for selected case and question files. |
| Context-routing catalog, bindings, budgets, and controller | Add independently selectable case context with bounded receivers and exact-byte receipts; no global prompt injection. |

Reconcile shared package ownership with the [Threat Analyst plan](../../proposals/security-advisor-threat-analyst-implementation-plan.md#custom-questions-and-methodology-profiles). Keep Analyst job state isolated from assessment state. Share data semantics and pure admission code, not an implicit invocation of an Analyst job inside an assessment.

The [context-routing contract](../contracts/context-routing.md) currently excludes component-type and capability selectors until a resolver can enforce them. `build_abuse_case_contexts.py` projects one candidate at a time. Process grouping is therefore a reviewed contract change, not an existing batching capability.

Follow [org-profile invariants](../contracts/org-profile-invariants.md) through schema, validation, resolution, packaging, consumption, and tests. Existing `abuse_cases.add` and `abuse_cases.disable` keep their compatibility, but disable semantics must not let question packages remove required business investigations or suppress evidence-backed findings.

Applicable constraints include REQ-MOD-001/004/005/009, REQ-FLW-002/003, REQ-BIZ-001/003/004/005, REQ-REQ-001, REQ-RPT-001/002/006, REQ-ANA-001 through 005 and 009, REQ-TRU-001, REQ-CFG-001/002, and REQ-EVO-003 in [the requirements](../../../specs/requirements.md). Before runtime changes, propose new product promises for explicit operator approval and maintain exact bindings. This plan changes no normative requirements.

### Verified current behavior

The following observations were checked against the code on 2026-10-08. They correct assumptions in the earlier plan revision and constrain P0.

- **Explicit case selection already exists.** `--abuse-case-file` adds a repository-contained case file and `--only-abuse-case` restricts the run to named IDs (`docs/org-profiles.md`, `scripts/runtime/resolve_config.py`). Both force verification at any depth, and the controller fails closed when the matcher rejects them. `--only-abuse-case` also removes every other case, including mandatory library cases. P0 extends these flags as the explicit request surface instead of inventing a parallel one and decides how they interact with required inputs.
- **One invalid repository file silently drops the whole abuse-case stage.** The resolver collects errors, `match_abuse_cases.py match` exits 1 before writing `.abuse-case-matches.json`, and without explicit selection the controller records only a receipt. A descriptive file without `probe`, or a duplicate ID, therefore removes all library and repository cases from the run. A descriptive case file placed in `.appsec/abuse-cases/` reproduces this today.
- **The case schema does not reject unknown versions.** `schema_version` is an unconstrained integer, so a future version is detected only through incidental field errors.
- **Repository discovery lacks containment and size bounds.** `.appsec/abuse-cases/*.yaml` follows symlinks outside the repository and reads files without a byte limit. Known-threat ingestion and `--abuse-case-file` are contained. Discovery also ignores `.yml`, which explicit files accept.
- **Repository cases can carry authority today.** A repository case can set `release_gate.fail_on` (a fatal gate result), `source: mandatory`, and `finding.severity` for promoted steps. Descriptive cases must not inherit these fields.
- **The report lists every non-applicable catalog case.** `build_catalog_evaluation` renders a "checked, not relevant" table on purpose (user request 2026-06). Adding business templates to that table would grow the report with every catalog addition.
- **Chain verdicts already cover most dispositions.** Chains end as `fully_viable`, `partially_blocked`, `mitigated`, `inconclusive`, or `not_applicable`; steps can be `refuted` (decision AC-6). No verdict represents work that was not performed.
- **The verifier fan-out has a hard failure limit.** More than 64 candidates abort the run. Business candidates need their own lower cap rather than counting toward this abort.
- **Library cases overlap with the proposed catalog.** AC-T-002 (object authorization), AC-T-003 (role claim and algorithm confusion), and AC-T-004 (registration mass assignment) cover technical parts of the tenant, alternate-path, revocation, and self-escalation cases.

## Division of work between scripts and the model

A step belongs to Python when its invariant is decidable from syntax and local data flow within one function or route. A step belongs to the model when it requires knowledge of intended authority, process state, or the relationship between several operations. When a part of a business case later proves syntactically decidable, it moves into a detector.

Each business case runs through four steps:

1. **Preselection (deterministic).** `scope_qualifier` signals, the route inventory, recon signals, and existing detector results decide whether a case can apply and where. A case without a preselection signal reaches the model only through an explicit request.
2. **Binding (model).** The model turns the generic case into a concrete hypothesis: the operation, actor, resource, and boundary in this system, with source references. The result is structured data, never code, regex, or a probe.
3. **Admission (deterministic).** Python checks that every referenced file, route, and component exists and lies in scope, and that source receipts match. Unsupported bindings become unresolved or are dropped with a recorded reason.
4. **Verification (model).** The model checks the admitted hypothesis against source, using detector results as evidence. Accepted candidates pass the existing evidence, severity, promotion, and consolidation gates.

The model does not re-decide what a detector already decided. It cites the detector result as evidence. A detector defect it encounters becomes producer-fix work in that detector, as in the historical comparison at the end of this plan.

| Initial case | Deterministic preselection and evidence | Question only the model answers |
|---|---|---|
| A delegated administrator grants themselves privileges beyond their delegation. | Role-assignment routes from the route inventory; `AUTHZ-003`/`004`/`101`/`102`; `AUTHZ-008`; the administrative-endpoint rule in `data/architecture-coverage-rules.yaml`. | Which roles and subjects this administrator may assign, and whether the handler enforces that limit. |
| A tenant administrator changes users or resources in another tenant. | `AUTHZ-001`/`002` and the `AUTHZ-301` confirmer; tenant fields in models and queries. | Whether the checked tenant or parent authorizes the affected child resource and the administrative scope. |
| A support operator uses impersonation for actions outside their support authority. | Impersonation routes and session-switch signals. | Which actions impersonation permits and whether the effective authority is restricted. |
| An actor changes another account's recovery data and takes over a stronger identity. | Recovery and profile-update routes; authentication presence. | Whether changing recovery data requires ownership or verified authority. |
| An editor changes approved content and reuses its prior approval. | Approval and update routes on the same resource. | Whether approval binds content, version, or state, and whether a change invalidates it. |
| A requester approves their own request despite required independent approval. | Approval routes. | Whether an evidenced separation requirement exists and the handler enforces it. |
| A user retrieves restricted content through an export, share link, or alternate route. | Per-route IDOR results; export, share, and download routes for the same resource. | Whether every access path enforces the same read boundary. |
| A former delegate keeps using a revoked permission through a retained session or token. | The AC-T-003 role-claim step; session and token lifetime signals. | Whether an evidenced revocation policy exists and takes effect for live sessions. |
| A user repeats or races an operation to exceed a one-time or cumulative entitlement. | Stateful update routes; transaction and locking signals. | Whether the entitlement limit holds under repetition and concurrency. |
| A user makes a privileged background worker act on resources outside the user's authority. | Job enqueue and worker entry points. | Whether the worker re-checks the caller's authority for the target resource. |

## Case authoring format

Teams maintain business cases as files in their repository, organization profile, or a selected package. The format must be readable without knowledge of the pipeline. P0 settles the shape; the following sketch is a proposal for that review, not a supported format:

```yaml
schema_version: 2
abuse_cases:
  - id: REPO-AC-010
    kind: descriptive
    title: Restricted administrator grants themselves a role outside their delegation
    actor: Delegated administrator of one department
    initial_access: authenticated_high_priv
    prerequisites: The administrator may assign a limited set of roles.
    goal: Obtain a role the delegation does not include.
    boundary: Roles and subjects the delegation permits.
    steps:
      - Call the role-assignment operation with their own user as the subject.
      - Choose a role outside the delegated set.
    expected_controls:
      - The assignment operation checks the target role against the caller's delegation.
    exclusions:
      - Fully authorized administrators who may assign every role.
    open_questions:
      - Where is the delegation defined?
    scope_qualifier:
      required_signals: [has_role_concept]
      path_patterns: ["*role*", "*role*/*"]
```

`id`, `title`, `initial_access`, and `scope_qualifier` reuse existing vocabulary. Free-text fields are bounded in length and treated as fenced data. Descriptive cases carry no `probe`, `finding`, `severity`, `goal_impact`, or `release_gate`. Severity follows the evidence of the resulting finding under the existing policy. The loader rejects unknown versions explicitly. Each validation error names the file, case ID, and field.

P1 supplies one neutral example per initial case. P5 documents the format in the user guide with the example and the validation behavior. Application profiles are deferred until the catalog outgrows the initial set; until then, preselection signals select cases, and profiles add no applicability authority.

## Cost model and depth

Business investigation must stay within a fixed share of a standard run. P0 measures the current per-candidate tokens and latency of the abuse-case verifier and the median token usage of a standard run on the pilot fixtures. The operator then confirms a ceiling for the added cost at standard depth. The proposed starting value is at most 20 % of a standard run. P3 and P4 fail their gates when a measured run exceeds it.

| Depth | Deterministic steps | Model binding | Model verification |
|---|---|---|---|
| `quick` | Run. | Only explicit requests. | Only explicit requests. |
| `standard` | Run. | Preselected cases up to the standard cap, batched in one existing call. | Admitted candidates up to the standard cap; no escalation to a stronger model. |
| `thorough` | Run. | Preselected cases up to the thorough cap. | Admitted candidates up to the thorough cap; escalation only for inconclusive candidates with evidence. |

Further cost controls:

- **Binding in the verification call.** The verifier binds and judges a candidate in one call; no separate binding dispatch exists. Batching bindings into the architecture stage remains an option once measurement shows a benefit.
- **Bounded verification context.** Each candidate receives a fixed byte and file budget for source slices. Verification does not trigger a second repository read.
- **Separate caps.** Business candidates have their own per-depth caps below the existing 64-candidate abort. Proposed starting values are three at `standard` and eight at `thorough`, confirmed after the P0 measurement. Selection follows preselection evidence, not catalog order.
- **Explicit requests.** Requests do not count toward the optional cap. A per-run maximum applies, and requests beyond it fail visibly before dispatch.
- **Visible omissions.** Cases skipped by depth, cap, or missing preselection are recorded with their reason. Required organization cases skipped at `quick` mark business coverage incomplete; an organization that needs them sets a minimum depth in its preset.
- **No speculative limits.** Caps and budgets live in their authoritative data files and change only with measured evidence, following the repository rule on budgets and timeouts.

The pilot verifies admitted candidates through the existing abuse-case verifier, one call per candidate, because that keeps attribution of quality and cost clean. Moving single-component hypotheses into the existing STRIDE component call is a later option. It needs prompt-budget evidence and a per-case disposition in the STRIDE output before adoption.

## User selection and packaged delivery

User and organization question files use `analyst-catalog.schema.json` and the same admission semantics. The [payment question package](../../../examples/analyst/payments-package.yaml) remains a domain-specific authoring example. Case definitions use their own versioned contract; do not pass them to the question loader as if that content type were supported.

Follow the [Analyst authoring guidance](../../threat-analyst.md#question-packages-and-the-threat-modeling-manifesto-profile) for one independently assessable question per entry. Interpret `applies_when` against planned design behavior, the selected change, or the inspected hypothesis scope; the assessment adapter maps it to admitted preselection evidence. Applicability hints cannot establish an organizational expectation, grant source access, or waive required coverage.

Confirm applicability through the policy or business-context source. A claimed provenance string is not proof that the policy applies. Store observed behavior, confirmed expectation, and provisional assumption separately.

Use the existing organization profile shape for on-demand analysis:

```yaml
analyst:
  required_packages:
    - file: analysis-rules/payments.yaml
      sha256: <digest of the packaged file>
```

Replace `<digest of the packaged file>` with the SHA-256 of the packaged file; the example is not a working configuration. A proposed layout is `org-profile/org-profile.yaml` with `org-profile/analysis-rules/payments.yaml`. This example selects questions, not an explicit case request. Organization case files continue to use `abuse_cases.add`. Define assessment question-package selection in P0; do not publish invented settings or flags as supported.

An organization may maintain its profile, cases, and question files in its own repository and supply them to the existing plugin packaging workflow. The built plugin must include the selected files and must not depend on that repository remaining accessible. For the Analyst, users already add a local file through `--package`; CI uses `--trusted-package` with local files pinned by digest outside the checkout under review.

Package builds must carry selected files, validate their contents and references, record identities, versions, and digests in the package surface inventory, and preserve path resolution after relocation. Smoke-test the built plugin from a different directory with the source profile unavailable. Verify existing generic copying before adding special cases.

Question packages do not activate through their presence in the target repository. Installing packages or configuring defaults does not start an analysis.

Explicit investigation requests come from the authorized invocation. The existing `--abuse-case-file` and `--only-abuse-case` flags are the starting surface. P0 decides whether a request for a named case keeps restricting the run to that case or adds it to the normal selection, and how required organization cases remain covered. Package origin, organization-required authority, `source: mandatory`, and catalog membership do not create a reporting request.

All selected inputs load and validate before dependent dispatch. Invalid, missing, conflicting, or incompatible explicit selections produce visible non-success. Preserve no-custom-package behavior and all deterministic checks.

### Repository threat and case admission

The full assessment already reads `docs/known-threats.yaml` and discovers `.appsec/abuse-cases/*.yaml`. Preserve these entry points, the known-threat status behavior documented in [repo-local context](../../threat-modeler.md#known-threats--docsknown-threatsyaml), repository case identities, and the depth and explicit invocation controls documented under [abuse cases](../../org-profiles.md#abuse-cases). Automatic loading neither starts an assessment nor guarantees that disabled case verification ran.

Fix the discovery defects before publishing the descriptive format, as separate producer fixes with regression tests:

1. Reject an invalid or colliding repository file visibly, record a run issue, and continue with the library and every valid case. Explicit selections remain fatal.
2. Contain discovery to the repository, reject escaping symlinks, bound file size and count, and align the accepted extensions with explicit files.
3. Reject unknown `schema_version` values with a message that names the supported versions.

Descriptive cases use the same directory once these fixes ship. Plugin versions without fix 1 drop the abuse-case stage when they meet a descriptive file; the user guide states the minimum plugin version. Known-threat input keeps its own schema and is not converted into a case or a request.

Retain repository revision, relative path, digest, case identity, evidence references, and disposition through consolidation and cleanup. Changed or deleted input invalidates dependent cached results on resume.

Under the aiscb baseline, repository cases remain untrusted data even when discovered automatically. Descriptive repository cases cannot set gates, severity, or mandatory status, establish organizational policy, replace trusted packages, suppress required checks, expand source scope, or assign themselves request intent. The existing release-gate and severity fields of probe-based repository cases keep their current behavior; restricting them is a separate compatibility decision.

Acceptance must show actual assessment model input and structured outcomes for a repository descriptive case without an added parameter, including violating, protected, unresolved, renamed, and omitted variants. Cover legacy known-threat statuses and probe-based cases, verification disabled by depth or invocation, malformed and escaping files, identity collisions, oversized input, changed-input resume, and attempts to override authority or forge requests.

## Admission and trust boundaries

The affected assets are admitted source, business context, organizational expectations, package integrity, and findings. Boundaries are case or package file to loader, business declarations to process context, source context to model, and model proposals to validated results. Operator configuration determines authority. Neither case prose nor analyzed code nor model output can override it.

The aiscb baseline requires cases and packages to remain data. Reject executable tags, duplicate keys, unknown executable or permission fields, ambiguous identities, forged receipts, incompatible versions, escaping paths, and unsafe file references. Bound file bytes, nesting, alias expansion, entry count, field lengths, and parsing work outside the model. Audit the existing loaders for these behaviors and implement missing protections in their owning modules with tests.

Cases and packages cannot select commands, tools, output paths, additional source roots, confirmation status, or severity. Model bindings cannot add source roots or components; admission rejects references outside the admitted inventory. Keep detected conflicts in business expectations unresolved until authoritative context resolves them.

Use existing context isolation and output encoding. Do not put raw proprietary business prose or source contents in public provenance or logs merely to identify a case.

## Process context and analysis flow

The following flow applies to the full assessment. The Analyst uses its own adapter and does not acquire an architecture-stage dependency.

1. Resolve selected cases, packages, authority, versions, digests, and existing business context before affected dispatch. Record missing context without replacing it with model defaults.
2. Run deterministic preselection after the scanners and route inventory complete. Record selected, omitted, and capped cases with reasons.
3. Bind preselected cases in one bounded model call that already holds actors, components, and flows. Carry explicit requests independently of the optional cap.
4. Admit bindings deterministically against the component inventory, route inventory, and source receipts.
5. Verify admitted candidates within the per-depth cap. Reuse detector results and prior inspected facts as evidence.
6. Pass candidates through the existing evidence, severity, promotion, and consolidation gates. Route missing business facts to team questions. Reconcile every explicit request with a visible outcome.

A process can span components. Define its bounded connected scope explicitly without treating a process as a new component or skipping per-component STRIDE coverage. Reconcile the timing of architecture discovery, evidence verification, and abuse-case matching before scheduling binding. Do not fabricate scanner evidence to activate a business candidate.

Proposed handoff semantics include case references, preselection reasons, bound actors, operations, resources, and boundaries with source references, expectation references with status and provenance, explicit request references, admitted source receipts, and omissions. The response carries candidate findings, assessed controls, unresolved hypotheses, missing business facts, and per-case dispositions. P0 chooses compatible schema extensions or a new schema-backed projection; every exchanged artifact needs a validator and owner.

Missing facts that determine whether a policy applies prompt targeted questions in interactive mode through the existing team-question channel. CI returns explicit unresolved items. Independent technical analysis continues; required missing business evidence prevents a complete business assessment and follows the existing publication contract.

## Threat Analyst activation and scope adapter

Extend the existing `appsec/core` question package in `data/analyst-questions.yaml` with supporting authorization and process questions, refining overlapping entries rather than adding duplicates. Preserve compatible entry identities and update the package version. The Analyst already loads this package on every invocation. Add an explicit adapter to the shared case definitions; a new unregistered file is not an activation mechanism.

Release the expanded core content only after the Analyst pilot passes. During evaluation, use isolated baseline and treatment package revisions rather than a production bypass for required core questions.

Trace `scripts/orchestrator/analyst_controller.py` from admission through `scripts/contexts/resolve_analyst_catalog.py`, `scripts/contexts/build_analyst_context.py`, and `scripts/runtime/analyst_host.py` to result validation and rendering. Preserve the Analyst's own job, snapshot, and output contracts. Do not send its findings through assessment writers or mutate `threat-model.yaml`.

`select_questions` takes an authority-ordered prefix up to a limit before source capture. Appending questions can leave relevant additions outside the delivered prefix. Add a bounded scope-aware selection step after request and snapshot context is available. Selection may prioritize optional questions using admitted intent, but must preserve core and organization-required authority and record every omission. Do not solve selection by raising the question limit.

| Analyst mode | Input and scope | Required acceptance evidence |
|---|---|---|
| Design question | Supplied intent, design, and admitted business context; no diff or existing threat model required. | Applicable business questions reach the model; assumptions and missing policy remain explicit; a design scenario is not presented as a code-confirmed vulnerability. |
| Change review | Selected comparison and admitted snapshot, with supporting evidence inside the existing read scope. | New questions reach model input and result provenance; findings retain supported change relationships; package text admits no unrelated files. |
| Hypothesis check | Explicit hypothesis, Git revision, and selected literal paths. | Matching business questions reach the model without a diff; conclusions retain source evidence and scope; an out-of-scope control leaves the result unresolved. |

For every mode, verify the actual host payload, structured case records, and report projection. Record Analyst quality and incremental cost separately from assessment results.

## Results and lifecycle

Map business dispositions to existing chain verdicts instead of inventing confirmation states:

| Disposition | Existing representation |
|---|---|
| Supported attack path | `fully_viable` or `partially_blocked` |
| Protected by an evidenced control | `mitigated` |
| Not confirmed in the inspected scope | `inconclusive` with `refuted` steps |
| Unresolved | `inconclusive`; missing business facts become team questions |
| Not applicable with rationale | `not_applicable` with reason |
| Not performed with reason | No chain verdict; a coverage record with the reason |

A model's claim that a control exists does not establish a verified control. A case never supplies its own completion or severity verdict. A visible not-performed status does not satisfy required coverage.

Preserve case and package versions, digests, case and question references, bindings, evidence, dispositions, and finding links in structured records through intake and consolidation. Retain multiple contributing references without changing public finding IDs. Preserve the canonical YAML abuse-case outcomes and narrower export trace obligations under REQ-RPT-006. Legacy models remain readable.

The Abuse Cases section shows verified business candidates like existing verified cases and answers every explicit request individually. The existing "checked, not relevant" table stays for probe-based cases. Non-applicable, protected, and not-performed business templates appear as a count with material gaps, not as one row per template. Changing the section requires coordinated work on `data/sections-contract.yaml`, the renderer, schemas, and consumers.

Every explicit request receives a compact visible answer: request label, disposition, finding links where available, and a concise explanation or missing-evidence reason. Missing source, scope exclusions, caps, cancellation, or deduplication cannot remove a request. Not confirmed never means safe.

Bind cached contexts and results to source revision, expectation provenance, case and package digests, policy, model, and prompt configuration. Relevant changes invalidate dependent analysis on resume. Classify new artifacts under the [audit-artifact](../contracts/audit-artifacts.md) and [cleanup](../contracts/cleanup-whitelist.md) contracts. Never delete user cases or packages.

## Risks and mitigations

| Risk | Consequence | Mitigation in this plan |
|---|---|---|
| Cost grows with each catalog addition. | Standard runs become slower and more expensive without clear benefit. | Depth gating, per-depth caps, batched binding, bounded verification context, a measured ceiling gated in P3 and P4. |
| Most outcomes are unresolved because policies are unknown. | The report gains questions, not findings. | Measure the share of actionable outcomes in P4; route missing facts to team questions; summarize templates instead of listing them. |
| The model binds a case to the wrong operation. | False or missed findings. | Deterministic admission of references; verification reads source; renamed and misleading-label variants in the evaluation. |
| The model invents a business policy. | False findings presented as violations. | Expectations need a source; unsourced expectations stay unresolved; existing evidence gates decide findings. |
| The model repeats detector work. | Higher cost and contradictory results. | Per-case mapping of deterministic evidence; detector results enter as evidence; detector defects become producer fixes. |
| A descriptive file breaks the abuse-case stage. | All library cases silently disappear from a run. | Producer fixes before the format ships; explicit version rejection; documented minimum plugin version. |
| Repository content gains authority. | A repository case gates releases or sets severity. | Descriptive cases carry no gate, severity, or mandatory fields; admission rejects them. |
| Case prose carries instructions. | Prompt injection into binding or verification. | Fenced data, bounded fields, existing context isolation and prompt-injection tests. |
| Authors cannot maintain cases. | Cases rot or fail validation without a clear fix. | Plain-language fields, one example per case, field-level validation messages, user-guide documentation. |
| Scope grows across two consumers at once. | Long delivery before any evidence of value. | Assessment pilot first; Analyst adapter after the assessment gate; defaults only after both pilots. |

## Delivery sequence and acceptance gates

| Package | Work and affected surfaces | Acceptance evidence | Depends on |
|---|---|---|---|
| P0: Contracts, baseline, and producer fixes | Settle the descriptive case shape, binding receiver, explicit request semantics, report projection, depth behavior, and caps. Measure the verifier and standard-run baseline. Ship the three discovery fixes. Propose normative deltas where needed. | Reviewed producer/consumer and schema plan; operator-confirmed cost ceiling and caps; regression tests for the discovery fixes including a neutral variant and a negative case; approved product promises before runtime edits. | None. |
| P1: Cases, mapping, and examples | Define eight to twelve descriptive cases with the deterministic mapping and model question per case; reconcile overlaps with AC-T-002, AC-T-003, and AC-T-004; refine overlapping `appsec/core` questions. | Definitions validate against P0 contracts; a reviewer confirms boundaries, exclusions, and evidence needs; each case has one neutral example and evaluation variants. | P0. |
| P2: Admission, validation, and packaging | Admit descriptive cases from repository, organization, and explicit sources; field-level validation messages; extend explicit request flags; package validated definitions with surface metadata and installed smoke coverage. | Invalid inputs fail visibly per file; legacy files stay compatible; required inputs persist; repository data grants no authority; request intent comes from invocation; installed content resolves after relocation. | P0 and P1. |
| P3: One case end to end in the assessment | Connect delegated-administrator self-escalation through preselection, batched binding, admission, verification, gates, and report. | Actual model input carries the case; protected and unresolved paths remain distinct; explicit requests are answered; depth and cap behavior holds; measured added cost stays under the ceiling. | P2. |
| P4: Comparative assessment pilot | Add cross-tenant administration and approval reuse; compare baseline and guided runs across renamed and misleading variants. | Predefined quality and cost gates pass on held-out cases; outside-catalog discovery persists; share of actionable outcomes reported; no benefit attributed to scanner fixes or mocks. | P3. |
| P5: Analyst adapter and pilot | Add the scope-aware question selection and case adapter for design, review, and hypothesis modes. | Analyst acceptance evidence for all three modes; separate quality and cost results. | P4. |
| P6: Default integration and delivery | Release accepted cases, supporting questions, and adapters; complete report projection, provenance, lifecycle, user guide, and installed smoke tests. | Explicit requests are answered; structured traces survive consolidation and cleanup; reports avoid template listings; state isolation, exports, and completion guarantees hold. | P4 and P5. |

The first implementation slice is P0, including the producer fixes, followed by delegated-administrator self-escalation through P1 to P3. A scanner documentation project or correction to `AUTHZ-002` is not on this dependency chain. No executable rule engine or model replacement of technical analyzers is part of P6.

## Evaluation design

Compare the same assessment with and without admitted business cases. Keep Python detector revisions, source snapshots, surrounding context, model settings, and comparable budgets fixed. Record case, prompt, model, and plugin versions, run order, input fingerprints, and costs. Separate detector corrections from this experiment.

Run and report separate comparisons for the full assessment and, in P5, the Analyst modes. Passing one consumer's evaluation cannot substitute for another's evidence.

Use delegated-administrator self-escalation, cross-tenant administrative changes, and approval reuse after content changes as the initial scenarios. Supply protected, violating, unresolved, inapplicable, and renamed variants for each. Include a fully authorized administrator as a legitimate exclusion, a misleading label, and the same capability in another application type. Add a threat outside the catalog to detect narrowed discovery.

Exercise the same case as a built-in template, as an organization case, as a repository case, and as an explicit request. Verify that only the explicit request requires an individual visible answer, while all required structured traces remain available.

Expected outcomes come from source behavior and established business facts. A business-aware reviewer defines them before model runs, including where no policy can be inferred. Keep held-out cases separate from authoring examples. Adjudicate without knowing the treatment where practical.

Propose three paired runs per held-out case with treatment order alternated. Finalize repetitions, model, case count, and total spend before live evaluation. Report variability rather than claiming universal superiority from a small pilot.

Measure additional supported findings, false positives, missed supported threats, invented expectations, unjustified confirmation of unknown cases, share of actionable outcomes, selection omissions, outside-catalog discovery, tokens, latency, and cost against the ceiling. Distinguish preselection, binding, and verification failures. Transport doubles test integration; live evaluation is required for usefulness claims.

P4 also settles the verifier model at `thorough`. Run the same held-out cases on the latest Sonnet, today's default, and on Opus, both as the default model and as the escalation target for inconclusive candidates. Compare the inconclusive share, false confirmations, step misattributions, and cost per candidate. Opus becomes the `thorough` default or escalation target only when it improves one of these measures on cases whose authorization logic spans several files, within the cost ceiling. The earlier Opus comparison for STRIDE, triage, and merging found 36 % higher cost without a measured quality gain, so a gain on this verifier cannot be assumed.

Promotion requires no permission or evidence-gate bypass, no new false confirmations in protected or unresolved cases, no invented mandatory business rule, retention of the outside-catalog case, and a demonstrated benefit within the cost ceiling. If evidence is insufficient, revise or defer default integration and keep existing analyzers intact.

## Verification routes

Before editing implementation paths, run `python3 scripts/check_specs.py --for <path>` and read the returned requirements, decisions, and contracts. Add a matching test module for each new script. Maintain requirement bindings, permissions metadata for new commands or Read/Write/Edit targets, and reviewed test routes when affected.

| Boundary | Relevant verification |
|---|---|
| Cases and questions | Abuse-case resolution and catalog tests, exact schema validation, version rejection, field-level error messages, compatible identities, and capability-based preselection independent of incidental names. |
| Repository threats and cases | Known-threat context and resolver tests; per-file rejection without dropping the stage; containment, symlinks, size and count bounds; legacy statuses and probes; disabled verification; collisions; resume invalidation; request intent from invocation. |
| Preselection, binding, and admission | Deterministic preselection from signals and detector results; admission rejects references outside the inventory; binding output bounds; caps per depth; visible omissions. |
| Analyst execution and selection | `tests/test_analyst_controller.py` and affected context, host, result, CLI/skill, and report tests in all three modes; late relevant entries; required coverage; absence of assessment writes. |
| Business facts and hypotheses | Business-context and team-question tests; `tests/test_resolve_abuse_cases.py`, `tests/test_match_abuse_cases.py`, `tests/test_build_abuse_case_contexts.py`, and affected verification and promotion tests. |
| Profile and installed distribution | `tests/test_org_profile_schema.py`, `tests/test_resolve_org_profile.py`, affected config tests, `tests/test_package_internal_plugin.py`, `tests/test_smoke_test_package.py`, and relevant packaging end-to-end cases. |
| Untrusted inputs | Unsafe YAML tags, duplicate keys, alias, depth, and size limits, traversal and symlinks, forged identity or provenance, forbidden authority fields in descriptive cases, altered digests, and attempted removal of required inputs. |
| Results and lifecycle | Verdict mapping, internal case trace, visible answer for every explicit request, Abuse Cases section changes, unchanged export obligations, legacy models, cache invalidation, safe cleanup, and isolated Analyst and assessment state. |

Use neutral names, equivalent variants, and protected negative cases. Replay the golden fixture under [the threat-fixture runbook](../runbooks/threat-fixture.md) when deterministic tail or source scanners change. Run only affected reviewed routes and lint Python when modified. Changelog entries belong to completed user-visible delivery, not this plan revision.

## Decisions before implementation

| Decision | Recommended starting point | Needed by |
|---|---|---|
| Descriptive case shape | Versioned `kind: descriptive` entries in the existing case files; plain-language fields; no probe, gate, severity, or mandatory status. | P0. |
| Binding receiver | Implemented: the abuse-case verifier binds and judges each candidate in one call; deterministic admission in `finalize`. | P0. |
| Explicit requests | Extend `--abuse-case-file` and `--only-abuse-case`; decide restricting versus additive semantics and required-input coverage. | P0. |
| Depth and caps | Deterministic steps at every depth; model steps from `standard`; caps confirmed from the P0 measurement. | P0. |
| Cost ceiling | At most 20 % added tokens over a standard run; operator-confirmed 2026-10-09, provisional until P4 measures it. | P0. |
| Report projection | Keep the probe-case catalog table; summarize business templates; answer explicit requests individually. | P0. |
| Repository authority of probe cases | Keep current gate and severity behavior; decide restrictions separately. | P0. |
| Case ownership and reviewer | Shared case definitions and supporting questions; an AppSec or domain reviewer establishes boundaries and exclusions. | P1. |
| Verification receiver for scale | Abuse-case verifier per candidate in the pilot; evaluate STRIDE component context after P4. | After P4. |
| Application profiles and further topics | Introduce profiles, amounts and quotas, and cross-service cases only after relevance and cost evidence. | After P4. |

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
