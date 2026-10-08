# Trust boundary classification and figure implementation plan

Date: 2026-10-07, rechecked 2026-10-08 against commit d2446aa6. Status: largely implemented on `dev` (04d5e073 to 0bb41762); see [Implementation status](#implementation-status).

Correct evidence-losing trust boundary classification, improve finding traceability, and extend the runtime and build figures without inventing trust transitions from architectural layers. The implementation must work across repositories. Juice Shop supplies replay evidence, not production matching rules.

## Implementation status

Verified against `dev` on 2026-10-08. Commits 04d5e073, 48b197ec, c31a59e0, 0f41c4a2, 34717fbe, b8a341e5, dbdec94b, 8a24f6b9, c4ea4f76, and 0bb41762 implement the plan.

- **Classification (1.1 to 1.4).** Path containment no longer overrides a process claim; deployment zones can veto a same-process claim; embedded stores stay internal interfaces.
- **Finding traceability (2.1 to 2.3).** STRIDE findings reference boundaries, and deterministic association links only on an exact cited line with a CWE bearing on one condition.
- **Figures (3.4, 3.5, 4.1, 4.3 to 4.5).** Inferred trust changes say so in text, local markers are audited, and Figure 1b maps build boundaries to public `tb-N` identifiers.

Deliberate deviations:

- **3.1 to 3.3.** The Figure 1 overview shows network crossings only; in-process trust changes appear in the detail view and the catalogue, and the overview counts trust boundaries only (RA-15).
- **4.2.** Figure 1b shows existence confidence without a verdict.

Open:

- **1.5 and 1.6.** `transition` is still derived from `kind`, so one crossing cannot carry several transitions. A contradicting `surface` is discarded with a warning rather than rejected. The v3 boundary, assessment-input-v2, and coverage-v2 contracts are unchanged. No decision records the field precedence or the deployment-zone veto, and TB-12 still names containment.
- **2.4 and 2.5.** `boundary_traceability_gaps` has no report, QA, or export consumer, so a missing link is recorded but not shown. No test covers owner change or public renumbering.
- **Regression evidence.** No PDF or theme equivalence test for markers, no multi-repository figure test, and no documented replay of the supplied run.

## Verified findings and limits

The review inspected the current plugin working tree and the supplied Juice Shop assessment under `docs/security`. Commit d2446aa6 added the multi-repository foundations, which share the affected code. `_normalize_assessment_boundaries` in `prepare_trust_boundary_context.py` reuses `_consolidate_candidates`, `_apply_axes`, and `_consolidate`, so the classification defect also applies to nested component paths within one repository of a qualified assessment. Every package must cover the single-repository and the qualified path, following the [multi-repository handoff](handoff-headless-multi-repository-2026-10-08.md).

| Observation | Verification | Classification |
| --- | --- | --- |
| Nested component paths replace a network boundary with `kind: process` | Direct calls to `_consolidate_candidates` reproduced this with `src/**` and `src/worker/**`, and again with `packages/**` and `packages/processor/**` | Confirmed classification defect |
| A privilege transition disappears on the same path | A neutral `kind: privilege` candidate became `process`; `_apply_axes` then produced `surface: in-process` and `transition: []` | Second effect of the same defect |
| Existing controls remain distinguishable | A network candidate with disjoint source paths remained network; an existing process interface remained internal | Negative controls for the reproductions |
| A verified SQL injection lacks its applicable interface reference | The API analyst received the complete SQLite interface context but emitted an empty reference list; the final source-scan finding also lacked a reference | Confirmed traceability gap |
| The existing verdict derivation handles that reference | Adding the specific reference in memory passed reference validation and changed the interface verdict from `unconfirmed` to `refuted` | No renderer or verdict repair demonstrated |
| Same-column trust transitions lack a boundary line in Figure 1a | `_boundary_gaps` returned no gap for two application endpoints, but a gap when the target occupied the data column; overview generation removes local boundary tags | Current display limitation, consistent with its contract |
| Figure 1b has no explicit boundary mapping | Its view schema has elements and edges but no boundary references; CI elements aggregate systems rather than individual jobs | Proposed capability, not a current contract violation |

These were targeted function reproductions and artifact inspections, not a full pipeline regression run. Acceptance of a reference by the structural validator does not independently prove that its evidence refutes the stated condition. No loss of a previously present reference during merging was demonstrated in the replay.

The replay's SQLite and MarsDB accesses are represented as internal interfaces. Their absence from the diagram's trust boundary lines is not itself a defect. The published report maps API to SQLite to `tb-6` and authentication to SQLite to `tb-5`; intermediate artifacts use earlier IDs recorded in `.trust-boundary-renumber.json`. Replay checks must follow identities through that mapping rather than hardcode IDs.

## Contracts and implementation owners

Read the current routes with `scripts/check_specs.py --for <path>` before changing each affected file. This plan does not amend normative requirements. Obtain explicit operator approval if implementation requires changing a product promise in `specs/requirements.md`.

| Area | Primary owners and contracts |
| --- | --- |
| Boundary assessment and normalization | `agents/appsec-trust-boundary-analyst.md`, `scripts/contexts/build_trust_boundary_assessment_input.py`, `scripts/contexts/prepare_trust_boundary_context.py`, candidate and canonical boundary schemas including `trust-boundary-candidates-v2`, `trust-boundaries-v3`, `trust-boundary-assessment-input-v2`, and `trust-boundary-coverage-v2` |
| Boundary semantics | REQ-MOD-003, decisions TB-1 through TB-12 as applicable, `docs/threat-modeler.md`, `docs/internal/contracts/schema-invariants.md`, `scripts/shared/_boundary_interface.py` |
| Finding references | `agents/appsec-stride-analyzer-v2.md`, `scripts/model/merge_threats.py` including its qualified comparison, `schemas/threats-merged-v2.schema.json`, `scripts/model/reclassify_components.py`, boundary renumbering in `build_assessment_model`, shared reference validation and boundary verdict functions |
| Runtime figure | `scripts/renderers/figure1_dfd.py`, figure detail and composition consumers, decision RA-15 and the figure contract |
| Build figure | `scripts/model/build_supply_chain_view.py`, `schemas/supply-chain-view.schema.json`, `scripts/renderers/figure1b_svg.py`, composition and table fallback, decisions RA-29 through RA-31 |
| Regression routing | `scripts/run_tests.py`, `data/requirement-bindings.yaml`, relevant targeted tests |

## Implementation sequence

Land bounded changes in the following order. Each package must preserve current consumers or include their coordinated migration.

### 1 Correct classification without losing evidence

The violated invariant is that repository path organization cannot establish process identity or erase an evidenced trust transition. The producing locations are the analyst instruction equating one deployable with no privilege transition and the deterministic path-containment override.

1. Remove path containment as sufficient authority to force `kind: process`. Retain it only where source ownership or containment is the actual question. Review its other consumers, including ingress consolidation and deployable-root selection, before accepting a narrow fix.
2. Replace the corresponding analyst instruction. A shared repository, directory, deployment package, or container does not establish the absence of a trust transition.
3. Use evidenced invocation and deployment relationships to support runtime classification. Existing workload information can contribute but does not alone prove a shared process. Preserve uncertainty when the evidence cannot decide.
4. Preserve actual embedded-store interfaces without manufacturing an application-to-data boundary. Missing or ineffective enforcement does not remove an otherwise evidenced crossing.
5. Separate crossing surface from identity, privilege, tenant, data-origin, and operator transitions in the producer contract. The current `kind` mapping cannot represent an in-process privilege transition without loss.
6. Define canonical field precedence and backward compatibility before adding independently authored axes. Migrate legacy `kind` inputs deterministically, reject contradictory new representations, and stop overwriting validated axes from a lossy legacy field. This includes the versioned qualified contracts: `trust-boundary-candidates-v2` carries only `kind`, while `trust-boundaries-v3` derives `surface` and `transition` from it. Update downstream identity, selection, consolidation, export, and rendering consumers as required.

Do not infer a network boundary merely because evidence for a common process is absent. Do not repair this defect by changing only the rendered figure.

### 2 Improve evidence-backed finding references

The observed symptom is a refutable query-construction assumption left `unconfirmed` because a finding has no reference. The replay excludes missing analyst context as the explanation for that finding.

1. Require the analyst to check applicable candidate conditions when a finding demonstrates a mechanism at the crossing. Retain the ability to omit unsupported references.
2. Define a bounded reconciliation step for LLM and deterministic findings after their identities and owners are resolved. Reuse the existing reference validator and verdict derivation.
3. Start deterministic association only with narrowly supported mechanisms whose evidence establishes the sink, receiving resource or interface, and violated condition. Do not implement generic matching from a CWE, component adjacency, or similarity of prose.
4. Report an actionable traceability gap when a plausible association remains ambiguous. Absence of a link must not become an assertion that a control works. Do not discard the security finding to enforce optional traceability.
5. Exercise existing merge, reclassification, and renumbering preservation, including the qualified merge comparison and the boundary renumbering in `build_assessment_model`. Add new preservation logic only when a regression demonstrates a missing behavior.

The detailed evidence contract for automatic association remains an implementation design decision. The replay does not establish a general resolver for arbitrary repositories. Neither larger context budgets nor weaker reference validation is justified.

### 3 Extend Figure 1a deliberately

The existing contract intentionally uses column-gap lines and omits per-boundary IDs and legends from the overview. Local markers are a contract extension, not a repair of noncompliant rendering. Update that contract and its tests together with the display change.

1. Represent meaningful same-column transitions with a local connection or component marker. Preserve a concise overview and use the catalogue for the complete inventory.
2. Retain column lines where they communicate the modeled crossings adequately. Use local markers where one line would obscure different relationships, such as an embedded store beside a separate service. Treat possible reader confusion as a design concern, not an already proven analysis error.
3. Explain internal security interfaces briefly, with a separate count or a concise notation. Do not count them as trust boundaries or claim that an interface has effective controls.
4. Keep boundary existence, confidence, and control verdict distinct. Inferred and unresolved information must not silently become confirmed. Important distinctions must survive PDF export rather than rely on SVG tooltips alone.
5. Extend the self-check to validate the new local markers and any explicit omission or grouping explanations. The current comparison with `_boundary_gaps` cannot establish this new coverage by itself.

Layout, sorting, grouping, and collapsing must not change canonical topology, trust semantics, finding references, or severity. Do not add a mandatory application-to-data separator. Repository membership creates no boundary line or marker; repository codes on component cards remain source annotations.

### 4 Add Figure 1b boundary mapping at supported granularity

Figure 1b currently aggregates CI systems and upstream input types. Start with that granularity rather than implying an existing job-level graph. The runtime and build projections for multi-repository assessments are not yet integrated. The initial mapping targets the single-repository build view; extending it to qualified build views follows that integration.

1. Add validated references from supply-chain view elements or edges to the shared canonical boundary catalogue. Require evidence for the mapping and preserve identity through delivery renumbering.
2. Render mapped crossings locally, with the same confidence and verdict semantics as the runtime view and report. Update the table fallback, schema validation, and export behavior together.
3. Distinguish evidence for a relationship from evidence for a boundary and from evidence that its control works. An unknown complete deployment path does not invalidate an independently evidenced partial crossing. It also cannot justify invented intermediate hops.
4. Preserve separate scopes for multiple CI systems, registries, and execution environments. A generic build boundary cannot be applied to every system merely because all appear in the build column. Separate repositories do not by themselves form separate build trust scopes.
5. Keep model-wide and per-view counts explicitly scoped. A boundary appearing in more than one view remains one catalogue identity.

Job-to-job boundaries are a separate follow-up. They require structured job identities, permissions, relevant triggers and data or artifact transfers, plus evidenced mapping to canonical boundaries. Implementing those prerequisites is not part of the initial renderer enhancement.

## Regression evidence

Use neutral fixtures first, a variant with different names and paths second, and the supplied run as additional replay evidence. Keep target names and special cases out of production logic.

| Case | Required result |
| --- | --- |
| Separate services with nested source paths | Their evidenced network crossing survives normalization |
| Same mechanism with renamed directories and components | Identical semantic result |
| Same mechanism in the qualified multi-repository path | Identical semantic result; nested paths in one repository do not force `kind: process` |
| In-process privilege or tenant transition | Transition survives production, validation, exports, and visualization |
| Embedded store without an additional trust transition | Internal interface remains; no artificial network separation |
| Missing or conflicting runtime evidence | Uncertainty remains explicit |
| Two possible stores behind the same component | No reference based only on shared CWE or adjacency |
| Verified violation at one evidenced interface | Correct reference and derived verdict |
| Same weakness at another sink or with unverified evidence | No unsupported reference or refuted verdict |
| Merge, owner change, and public renumbering | Valid references retain their intended identity; invalid references are diagnosed |
| Real boundary between components in the same figure column | Local representation or an explicit, contracted grouping explanation |
| Embedded and external stores in one diagram | No blanket claim that all data accesses share a separation |
| Several CI systems with one evidenced mapped boundary | Marker applies only to the supported scope |
| Unknown artifact-to-execution relationship | No invented deployment path or control effectiveness |
| Overview, detail, SVG themes, PDF, and Figure 1b table fallback | Equivalent boundary meaning, legible notation, and correct links |

Review the appropriate boundary preparation, boundary interface, merge, component reclassification, Figure 1, Figure 1b, and supply-chain view tests, plus the qualified-path tests in `tests/test_multi_repo_boundaries.py`, `tests/test_multi_repo_builder.py`, and `tests/test_multi_repo_figures.py`. Follow routed producer and consumer selections rather than running every named family indiscriminately. Add route coverage when introducing a module or dependency, and audit changed routes.

During implementation, inspect `make test-plan BASE=origin/dev` and the worktree plan when unrelated branch work is present. Keep verification scoped to this task, following the repository rules for mixed trees. Run lint for Python changes and the applicable validators and routed tests. Replay a golden fixture if deterministic-tail behavior changes. A rendered-report repair is not proof of a permanent plugin fix.

## Completion criteria

Classification no longer loses trust changes because of repository layout. Finding association is evidence-backed and explicit about unresolved cases. Figure 1a represents the agreed overview semantics without changing the model. Figure 1b shows only boundaries that can be mapped at its supported granularity. Compatibility, negative cases, and the supplied-run replay are documented separately from implementation completion.

This plan authorizes no deployment, external publication, fixture expectation weakening, or unrelated multi-repository refactor. Implementation must preserve untrusted-input validation and load the applicable secure-coding modules before affected design or code changes.
