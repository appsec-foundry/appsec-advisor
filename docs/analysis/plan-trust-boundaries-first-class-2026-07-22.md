# Plan: First-class trust boundaries without speculative risk scoring

**Date:** 2026-07-22

**Status:** planned / not started

**Supersedes:** the implementation sequence in
`analysis-trust-boundary-first-class-2026-07-21.md` where that sequence assumes
deterministic attack paths, boundary-based likelihood changes, or automatic
weakness emission.

## Outcome

Make trust boundaries stable, validated, visible, and explicitly linkable from
findings without claiming more than the repository evidence supports.

The first release will:

1. define one canonical trust-boundary contract and normalize legacy sidecars;
2. preserve public `tb-N` IDs across incremental runs;
3. give each STRIDE analyzer a validated, bounded component-scoped boundary-context
   file containing only adjacent candidates;
4. let a finding select at most two evidence-constrained `boundary_refs[]` gaps;
5. render a compact boundary catalogue in the existing System Overview and add
   links from relevant finding cards; and
6. carry boundary references through YAML, query output, and SARIF.

The new boundary metadata will **not** weight trust boundaries, change finding
severity, create a generic `trust_boundary_violation` threat, infer a full
attack path, or treat an unknown control as an absent control. Existing,
independently evidenced rating rules such as `architectural_violation` remain
separate and unchanged.

## Decisions

| Question | Decision | Reason |
|---|---|---|
| Weight trust boundaries? | No numeric weight and no likelihood/severity multiplier. | The current model has no reliable path or deployment-reachability fact. An observed boundary control is context, not proof that a finding is unreachable. |
| Add a generic boundary-violation threat? | No. Add an evidence-backed boundary-gap reference to an existing precise finding. | Missing authZ, injection, weak trust-conferring headers, and similar mechanisms already have more useful threat/weakness classes. A generic class would duplicate them. |
| How much model complexity? | One normalized boundary object, one shared preparation step, one bounded candidate-adjacency join, and one optional evidence-backed finding link. Even `thorough` has a hard per-component candidate budget. | This delivers traceability without introducing data-flow, taint, exposure, weak context relations, and risk-scoring subsystems at once. Thorough increases evidence depth, not unbounded boundary breadth. |
| How may a boundary affect a finding? | Evidence-backed traceability and remediation scope only in this release. Weak contextual associations stay out of finding records. | Risk remains `likelihood x impact`; mitigation priority keeps its existing severity/effort/reachability/architectural-violation inputs. |
| Where is the documentation shown? | A compact `### Trust Boundaries` subsection inside §1 plus boundary links on finding cards. | §2.x Trust Boundaries is forbidden and the old numbered §6 intentionally remains absent. The §1 view is visible without restoring duplicated sections. |

## Review verdict and complexity budget

The design is useful only as a staged change. It is **low runtime complexity**
(no new agent, category, rating pass, or unbounded prompt) but **medium-high
implementation complexity** because a public cross-reference touches several
schemas and deterministic consumers.

| Scope | Value | Implementation complexity | Decision |
|---|---|---|---|
| Contract normalization, endpoint resolution, SVG correctness | Removes current drift and false exposure inference even without finding links. | Medium | Required foundation. |
| Stable IDs and bounded candidate contexts | Makes later links auditable while capping every analyzer at 2/4/6 rows. | Medium | Implement with the foundation through one shared helper. |
| Evidence-backed `boundary_refs[]` | Improves finding explanation and remediation scope. | Medium-high because merge/carry-forward validation is required. | Experimental milestone with stop/go gate. |
| §1 catalogue and finding-card row | Makes successful references useful to readers. | Medium due sections-contract, renderer, ToC, QA, and escaping. | Implement only after the reference-quality gate passes. |
| SARIF/query propagation | Preserves machine-readable parity. | Low after the canonical field exists. | Include with report rollout, not before. |
| Severity weighting, generic threats, full paths, exposure subsystem | High complexity with weak evidence. | High | Explicitly deferred. |

Do not combine all milestones into one large change. Milestone 1 must be usable
and testable without `boundary_refs`; Milestone 2 must be replayed before any
report-structure work begins.

## Code-verified starting point

The plan is based on the current implementation, not only the earlier analysis:

- The sidecar schema, Phase-7 prompt, output schema, and dispatch consumer do
  not agree. In particular, the dispatch builder reads
  `crossing_enforcement`, while current producers and schemas describe other
  field names.
- `trust_boundaries[].from` and `.to` are not currently cross-reference
  validated against `components[].id`.
- The canonical model does not persist `data_flows[]`. A component and a
  primary actor therefore do not establish which boundaries an attack crosses.
- Boundary IDs are LLM-authored and have no reconciliation or reservation path.
  Reordering Phase-7 output can change a public `tb-N` ID.
- The actual deterministic relation available today is endpoint adjacency:
  whether the finding's component touches a boundary. Adjacency is a candidate,
  not proof of traversal or violation.
- Existing finding rating validation remains `likelihood x impact`; there is no
  deterministic consumer for `actor_adjusted_likelihood`.
- Figure 1 primarily renders as SVG. The current SVG uses boundary endpoints for
  layout/exposure hints but does not provide a boundary catalogue or stable
  boundary anchors.
- The current query command exposes boundaries only as a system-level view.
  Findings, weaknesses, mitigations, and SARIF do not reference `tb-N` IDs.
- Arbitrary fields such as `weakness` survive today because the boundary schemas
  allow undeclared properties. No consumer turns that field into a validated
  weakness.

## Target contract

### Canonical boundary object

Use the same declared fields in the Phase-7 producer contract, fragment schema,
canonical YAML schema, normalizer, dispatch manifest, renderer, and query tool:

```yaml
schema_version: 2
trust_boundaries:
  - id: tb-1
    name: Public request boundary
    from: external
    to: web-api
    kind: network
    assumption: Requests are authenticated and authorized before protected operations.
    evidence:
      - file: src/security/auth.ts
        line: 42
    confidence: confirmed
    resolution_status: resolved
```

`schema_version: 2` is a top-level sidecar field, not a field repeated on each
boundary.

Contract rules:

- `id` is the stable public identifier and keeps the existing `^tb-\d+$` form;
  `name` is 1–100 characters.
- `from` and `to` are component IDs or the literal `external`. New Phase-7
  output must provide both. A compatibility path may retain an old boundary
  without endpoints, but such a boundary is not eligible for adjacency or
  finding links.
- `resolution_status` is inserted by deterministic preparation, never authored
  by the LLM. A boundary is `resolved` only when both endpoints are present and
  each is `external` or a known component; otherwise it is `unresolved` and is
  excluded from every semantic consumer.
- `kind` is a small enum: `network`, `process`, `identity`, `privilege`,
  `tenant`, `data-origin`, `third-party`, or `build`.
- `assumption` states what must remain true at the crossing. It does not state
  that the assumption is satisfied. New v2 output requires 1–240 characters.
- `evidence[]` uses canonical repository-relative file and optional positive
  line references. Absolute paths, `..` traversal, paths outside the target
  repository, URLs, and evidence-derived read/write targets are forbidden.
  A boundary carries at most five evidence locations.
- `confidence` describes confidence in the modeled boundary and assumption:
  `confirmed`, `inferred`, or `unknown`. It is not a risk weight.
- Unknown fields are rejected after legacy normalization. Legacy
  `controls`, `description`, `enforcement`, `crossing_enforcement`,
  `trust_level`, and `weakness` values are migration inputs, not canonical
  output fields.
- `from` and `to` define the crossing; a separate direction field is
  deliberately omitted. `kind` is classification metadata and is not part of
  stable-ID identity.

Boundary-local controls are deliberately omitted. The existing canonical
`security_controls[]` register remains the single source for observed controls;
the boundary stores the assumption, while evidence-backed findings show where
that assumption fails.

The boundary is an edge/interface. Existing
`components[].deployment_zones[]` remains the coarse zone model; it must not be
overloaded as a second boundary identity.

### Finding relation

Add this optional field to per-component STRIDE output, merged threats, and the
canonical threat model:

```yaml
boundary_refs:
  - boundary_id: tb-1
    rationale: The route reaches the protected operation before an object-level authorization check.
    evidence_locations:
      - file: src/routes/orders.ts
        line: 87
```

Validation rules:

- `boundary_id` must exist in the normalized boundary sidecar and canonical
  model.
- The boundary must be one of the target component's dispatch candidates.
- `rationale` is required, concise, and must describe the mechanism rather than
  restate the boundary name (20–240 characters).
- A finding has at most two unique boundary references. A boundary reference
  is optional; analyzers must not add one merely to fill the field.
- Every reference represents a concrete control gap and therefore requires one
  or more `evidence_locations[]`. Each location must
  already exist in the finding's verified evidence or consolidated instances;
  the reference cannot introduce new evidence. Unknown confidence or absent
  repository evidence permits no finding reference. Each reference carries at
  most three evidence locations.
- A reference does not mean “the complete attack path crosses this boundary.” Do
  not add `crossed_boundary_ids[]` until persisted data flows can support it.
- Consolidation unions unique references and their evidence locations. It keeps
  a reference only when the corresponding member evidence survives in the
  consolidated finding. General contextual association stays in the boundary
  catalogue and is deliberately not modeled on findings in the first release.

### Bounded analysis focus

The canonical catalogue may contain every resolved boundary, but STRIDE must
not analyze every catalogue row. Derive a per-component focus class
deterministically; do not let the LLM assign it and do not persist it as an
intrinsic risk property of the boundary:

- `primary`: explicit external entry; identity, privilege, or tenant change;
  third-party/build crossing; or a boundary already tied to verified finding
  evidence;
- `secondary`: data-origin transition or a crossing into a component handling
  sensitive data; and
- `catalog-only`: ordinary process isolation with no evidenced identity,
  privilege, provenance, exposure, or sensitive-data transition, plus every
  legacy boundary whose assumption/confidence remains unknown.

A process boundary can be promoted to `primary` or `secondary` when one of
those trust-change signals exists. `kind: process` alone is never a reason to
spend analysis budget.

Default per-component candidate budgets:

| Assessment depth | Eligible focus | Maximum candidates |
|---|---|---:|
| `quick` | `primary` | 2 |
| `standard` | `primary`, then `secondary` | 4 |
| `thorough` | `primary`, then `secondary` | 6 |

The cap is hard at every depth, including `thorough`. Rank candidates using a
stable tuple rather than a risk score:

1. a prior verified boundary reference;
2. explicit external source;
3. identity/privilege/tenant transition;
4. sensitive data-origin transition;
5. third-party/build crossing;
6. confirmed before inferred confidence; and
7. stable `tb-N` as the final tie-breaker.

`catalog-only` boundaries are not sent to STRIDE even at `thorough`; they remain
available in canonical YAML and query output. Never silently imply full
boundary coverage: persist eligible, selected, and omitted IDs plus focus
reasons. An omitted boundary does not lower any finding's severity and does not
mean the boundary is safe.

The 2/4/6 values are initial operational defaults and must be calibrated in the
Milestone-2 replay, but `thorough` must not exceed six without a separate
evidence-backed design change. Boundary selection creates no new agent calls
and no extra STRIDE categories; it adds one bounded context read to agents that
the existing component selector already dispatches.

## Verified risks and required controls

| Risk | Current-code evidence | Required mitigation | Residual risk |
|---|---|---|---|
| Adjacency is misreported as traversal or violation. | `build_stride_dispatch_manifest.py::_trust_boundaries_for` joins only on `from`/`to`/`components`; canonical YAML has no persisted `data_flows[]`. | Name the deterministic input `adjacent_trust_boundaries`; allow a finding reference only with verified gap evidence and rationale; forbid weak `context` links and `crossed_boundary_ids`. | The analyzer can still overstate the rationale; replay sampling must measure precision. |
| Boundary prose creates false precision about controls. | Phase 7 requests `enforcement: "none observed"`, the sidecar also carries free-form `controls[]`, and the canonical `security_controls[]` register already owns observed controls. | Remove boundary-local enforcement, controls, trust weights, and description from the v2 object. Keep only the trust assumption, evidence, and confidence; unknown never becomes absent. | Linking a specific existing security-control record to a boundary is deferred rather than guessed by name. |
| Boundary metadata contaminates severity or priority. | `triage_validate_ratings.py` enforces the likelihood-impact matrix; `phase-group-threats.md` separately escalates `architectural_violation` and contains existing cross-repository rules. | Make `boundary_refs` metadata-only; it cannot set `architectural_violation`, likelihood, impact, risk, CVSS, or priority. Isolate existing cross-repository/architecture rules and test that identical findings rate identically with and without boundary refs. | An analyzer may still phrase a scenario more strongly; evidence and rating QA remain necessary. |
| Structured context inflates the finding count. | The STRIDE analyzer already reasons from trust-boundary prose and requires a code/evidence basis, but nothing currently prevents a future “one finding per boundary” instruction. | State that a boundary object alone is never finding evidence; require the existing threat/evidence gates; add no deterministic boundary-threat emitter and no completeness rule requiring a finding per boundary. | Better context may legitimately change LLM recall, so fixture counts are diagnostic rather than a fixed equality gate. |
| Findings are over-consolidated because they share a boundary. | `merge_threats.py` consolidates by mechanism/object catalog and `_merge_member_metadata` currently has no boundary provenance. | Never use `boundary_id` alone as a merge key. Preserve per-member reference evidence, union refs only after an independently valid merge, and keep distinct root causes separate. | Existing heuristic/LLM consolidation still needs its current fail-closed guards. |
| Public `tb-N` references churn or are reused. | Phase 7 says IDs are LLM-chosen and `reserve_ids.py` has no boundary ID type. Multiple external integrations may also share the same `external`/component endpoint pair. | Match prior IDs conservatively: compatible authored ID first, then exact endpoint pair plus normalized name, then a unique endpoint pair. Ambiguity allocates a new ID above the prior maximum; retired IDs are never reused. `kind` is not identity. | A rename among several boundaries sharing endpoints may intentionally receive a new ID rather than risk a wrong match. |
| Contract drift produces write-only fields again. | Fragment schema, Phase-7 examples, output schema, dispatch consumer, query tool, and legacy pregenerator read different field sets. | Land producer, both schemas, normalizer, consumers, Python validation, permissions, and tests atomically; reject unknown canonical properties; maintain a contract matrix in schema invariants. | Legacy inputs remain a compatibility surface until their migration window closes. |
| Untrusted fields break prompts/Markdown or steer file access. | Repository/imported context is untrusted; the proposed catalogue would newly render boundary names/assumptions and expose evidence paths to STRIDE. The current sanitizer runs after canonical YAML construction—too late for dispatch. | Sanitize name/assumption during normalization, canonicalize evidence paths under the target repo, reject traversal/URLs, treat context files as untrusted data, and escape pipes/HTML/anchors in the renderer. Boundary strings/paths never determine commands or write targets. Keep the later sanitizer as a backstop and add injection-shaped fixtures. | Semantically misleading but syntactically safe prose still requires confidence/evidence review. |
| Prompt size and cache stability regress. | `TRUST_BOUNDARIES` is currently an inline Group-B dispatch scalar and has no dedicated size budget. | Apply the depth-aware 2/4/6 candidate cap, write validated `.dispatch-context/<component>/trust-boundaries.json` files, and pass only their Group-C paths. Keep records compact, measure file/manifest growth, and reject oversized selected records rather than silently truncating them. | Each analyzer performs one additional bounded context read. |
| Boundary focus omits a useful internal crossing. | The requested hard cap intentionally reduces breadth, and focus classification consumes producer-authored `kind`/confidence plus deterministic endpoint/component facts. | Prefer prior verified gaps, explicit external entries, evidenced identity/privilege transitions, and sensitive data-origin transitions; disclose every omitted ID/reason and keep it in YAML/query. Never interpret omission as safety. | A catalog-only or over-budget boundary can be missed by STRIDE; this is the explicit trade-off for bounded complexity. |
| Late component reconciliation leaves a component without boundary context. | `build_stride_dispatch_manifest.py` can inject security-relevant components after the Phase-3/Phase-7 inventory has been authored. | Normalize the catalogue after Phase 7, but generate component contexts only after the final component reconciliation immediately before dispatch. Use the same idempotent helper in parallel and serial paths. | A newly injected component may have no modeled adjacent boundary; it receives a valid empty context plus an audited reason, never another component's context. |
| Legacy incomplete boundaries affect reachability. | `figure1_svg.py` currently treats an empty `from` value as external; the fragment schema requires only `id` and `name`. | Classify resolution with one shared endpoint predicate; exclude unresolved legacy records from adjacency, exposure, links, and other semantic consumers. Change exposure derivation to require explicit `from: external`. | Old unresolved records remain documentation-only until a future scan resolves them. |
| The report becomes noisy or the investment has little value. | The current report does not expose stable boundary-to-finding links, so real reader usage is unmeasured. | Add a stop/go gate after Milestone 2 and cap §1 at 20 rows, ordered by referenced gaps, selected primary boundaries, confidence, and stable ID. Render omitted IDs as plain text in findings and point overflow to YAML/query output. | Teams that do not use architecture-level triage may still gain only schema quality and stable IDs. |

## Implementation sequence

### Milestone 0 — characterization and contract lock

Goal: pin the current drift and agree on the new semantics before changing
runtime output.

1. Add characterization fixtures for:
   - current `controls[]` input;
   - legacy `enforcement`, `crossing_enforcement`, `trust_level`, and
     `weakness` fields;
   - missing endpoints;
   - an endpoint that references an unknown component; and
   - two runs where boundaries are reordered and renamed.
2. Add the trust-boundary invariants to
   `docs/internal/contracts/schema-invariants.md`.
3. State explicitly in that contract that trust-boundary metadata cannot alter
   `risk`, `effective_severity`, CVSS, or mitigation priority by itself. Record
   existing independent exceptions (`architectural_violation`, requirements,
   and cross-repository coverage rules) so the new reference cannot activate
   them accidentally.
4. Add a producer/schema/consumer/validator/test matrix for every boundary
   field. Include the legacy pregenerator helpers, Figure 1 SVG, query, SARIF,
   and cleanup/permission contracts rather than treating the primary builder as
   the only consumer.

Primary drift guards:
`tests/test_new_schemas.py`, `tests/test_dispatch_manifest.py`,
`tests/test_build_threat_model_yaml.py`, and
`tests/test_incremental_two_run_e2e.py`.

### Milestone 1 — normalize the boundary model and stabilize IDs

Goal: produce one trustworthy boundary array before STRIDE dispatch.

1. Update `schemas/fragments/trust-boundaries.schema.json` to declare the target
   v2 sidecar and reject undeclared canonical fields. The deterministic
   preparer accepts legacy v1 input; only its normalized v2 output is validated
   against the strict fragment schema.
2. Mirror the normalized object in
   `schemas/threat-model.output.schema.yaml`; do not leave the canonical schema
   at `name`-only validation.
3. Replace the conflicting Phase-7 examples and prose in
   `agents/phases/phase-group-architecture.md` and the thin orchestrator wiring
   with one producer contract. Phase 7 writes the sidecar, runs deterministic
   preparation, and validates the normalized file in that order.
4. Add one idempotent `scripts/prepare_trust_boundary_context.py` with matching
   `tests/test_prepare_trust_boundary_context.py` and two operations backed by
   the same library code:
   - `normalize`, invoked after Phase 7, owns v1→v2 migration, stable IDs,
     endpoint resolution, and strict sidecar validation; and
   - `contexts`, invoked immediately before STRIDE dispatch after the final
     component reconciliation, owns focus selection and bounded files under the
     existing `.dispatch-context/` directory.
   The parallel manifest builder calls the shared `contexts` function after its
   deterministic component injections. The serial Phase-9 path invokes the
   same CLI operation. Do not implement a second selection algorithm in either
   orchestrator prompt.
5. Match prior IDs conservatively:
   - reuse an authored prior ID only when its endpoints remain compatible;
   - otherwise match exact `(from, to, normalized name)`;
   - use endpoint-only matching only when exactly one prior and one current
     boundary share that pair; and
   - allocate a new ID above the highest prior number when matching is
     ambiguous.
   `kind`, assumptions, and confidence are mutable metadata, not
   identity. Retired IDs are never reused.
6. Treat LLM-authored IDs as provisional input. Reject duplicate final IDs,
   but allow multiple named external integrations to touch the same component;
   do not collapse Stripe, GitHub, and another external peer merely because all
   currently use the literal `external` endpoint.
7. Validate endpoint cross-references in Python:
   - `external` or a known component is valid;
   - an explicit unknown component or missing endpoint sets deterministic
     `resolution_status: unresolved` and emits a warning; and
   - unresolved rows remain documentation-only and are excluded from dispatch,
     exposure inference, finding links, and every other semantic consumer.
   One malformed LLM row must not abort an otherwise valid assessment.
8. Normalize legacy fields conservatively:
   - never translate `none observed` into proven absence;
   - do not copy legacy `controls`, `description`, `enforcement`, or
     `trust_level` into v2 boundary fields; emit a migration warning instead;
   - when legacy input has no explicit assumption, write the neutral
     `Assumption not recorded in legacy model`, set confidence to `unknown`,
     and keep the row `catalog-only` until a later scan refreshes it; and
   - never turn legacy `weakness` prose into a W-NNN object.
   Any new event-log line uses `scripts/event_log.py`; concise per-row migration
   diagnostics may remain on stderr.
9. Reuse the safe string primitives from
   `scripts/sanitize_perimeter_claims.py` during normalization for boundary
   name/assumption. Enforce length bounds, strip control characters, and retain
   the prohibition on speculative perimeter-absence claims. Unsafe prose must
   be cleaned before STRIDE sees it; the existing later auto-emitter invocation
   remains a backstop for legacy models.
   Canonicalize evidence paths under the target repository and reject absolute,
   traversal, URL, and out-of-repo values before writing any context file.
10. Make `scripts/build_threat_model_yaml.py` consume only the normalized array
   and validate the resulting canonical model.
11. Update existing consumers of legacy boundary fields. In particular,
    `figure1_svg.py` must treat only explicit `from: external` as external
    exposure; a missing source must no longer be equivalent to the internet.
    Legacy pregenerator paths must use normalized fields or remain explicitly
    compatibility-only with regression coverage.
12. Register the new command/path permissions in
    `data/required-permissions.yaml` and extend
    `tests/test_check_permissions.py`.

Acceptance criteria:

- The fragment and output schemas agree field-for-field.
- Reordering never changes an ID. A rename keeps its ID when the prior match is
  unambiguous; ambiguous matches receive a new ID and warning rather than a
  potentially wrong reused ID.
- Unknown component endpoints become visible unresolved catalogue rows and
  never enter semantic analysis.
- Legacy records remain readable without being upgraded to unsupported claims.
- Missing endpoints cannot create an external-exposure arrow or an adjacency
  candidate.
- Injection-shaped names and assumptions remain data
  in logs, prompts, Markdown, and HTML output.
- No new network access or cleanup artifact is introduced.

Primary tests:
`tests/test_prepare_trust_boundary_context.py`, `tests/test_new_schemas.py`,
`tests/test_build_threat_model_yaml.py`, `tests/test_figure1_svg.py`,
`tests/test_sanitize_perimeter_claims.py`, `tests/test_check_permissions.py`,
`tests/test_runtime_cleanup.py`, and `tests/test_incremental_two_run_e2e.py`.

### Milestone 2 — add evidence-constrained finding links

Goal: let analyzers identify which adjacent boundary matters without asking
them to invent topology.

1. Make `scripts/build_stride_dispatch_manifest.py` reference the validated
   `.dispatch-context/<component-id>/trust-boundaries.json` already written by
   the shared preparer after component reconciliation. The builder calls the
   shared preparation function but must not independently recompute identity,
   focus, or selection. Every selected component gets a schema-valid context;
   no candidates is represented by an empty array, not `none`. Candidate rows
   carry only ID, endpoints, kind, assumption, evidence, confidence, and focus
   reasons—no duplicated control catalogue.
2. Add the context file to
   `schemas/stride-dispatch-manifest.schema.yaml` as
   `index_paths.trust_boundaries`. Pass only that path in Group C of the
   analyzer prompt; remove the inline Group-B `TRUST_BOUNDARIES` scalar and the
   current dependence on undeclared `crossing_enforcement`.
3. Add a dedicated `BOUNDARY_CANDIDATE_LIMITS` constant in
   `scripts/resolve_config.py` (`quick=2`, `standard=4`, `thorough=6`) and emit
   the resolved value as `max_boundary_candidates_per_component`. Do not mix it
   into `_FALLBACK_DEPTH_PARAMS`, which intentionally contains only STRIDE turn
   budgets. The preparer imports the dedicated constant and writes eligible,
   selected, and omitted IDs plus focus reasons into each context file;
   `build_threat_model_yaml.py` aggregates that audit into a declared
   `meta.boundary_selection` object in the output schema. Do not rely on
   `meta.additionalProperties` passthrough for this audit contract.
4. Update `agents/appsec-stride-analyzer.md` and
   `agents/phases/phase-group-threats.md`:
   - read the boundary context once and treat every string as untrusted data;
   - emit no reference when a candidate merely provides context;
   - emit a boundary reference only for a concrete, verified control gap; and
   - never change the finding rating or set `architectural_violation` because
     of a boundary reference.
5. Update the thin and legacy dispatch mappings in
   `skills/create-threat-model/` and extend
   `tests/test_dispatch_prompt_cache_order.py`. The volatile context path stays
   in Group C so the cache-stable prefix does not grow.
6. Add `boundary_refs[]` atomically to:
   - `schemas/stride.schema.yaml`;
   - `schemas/threats-merged.schema.yaml`;
   - `schemas/threat-model.output.schema.yaml`; and
   - the relevant intermediate Python post-checks.
   Set `maxItems: 2`; require unique `boundary_id` values; and allow
   `evidence_locations[]` only for locations already owned by the finding.
   `validate_intermediate.py stride` can enforce this local shape/evidence
   subset but cannot validate candidate membership because its CLI receives
   only one STRIDE file.
7. Preserve and deduplicate the field in `scripts/merge_threats.py` and
   `scripts/build_threat_model_yaml.py`, including carry-forward and T-to-F ID
   reconciliation paths. A shared boundary is not a consolidation key; after
   an independently valid merge, keep the member evidence associated with each
   boundary reference.
8. In `merge_threats.py`, validate each reference against the component's
   prepared candidate file while the output directory is available. Validate
   again in `build_threat_model_yaml.py` against canonical boundaries after
   consolidation/carry-forward. Unknown, unresolved, non-candidate, or
   evidence-free references are removed with an audited warning at the
   LLM→merge trust boundary while the underlying finding is preserved. The
   canonical builder then hard-fails if any invalid reference nevertheless
   survives. Optional traceability metadata must not make a valid security
   finding disappear or abort the assessment without a repair opportunity.
9. Add negative tests for invented boundary IDs, non-adjacent candidates,
   evidence-free or refuted references, duplicate refs, boundary-only threat
   evidence, and consolidation that would otherwise lose reference provenance.
10. Add regression tests proving that adding or removing `boundary_refs[]` does
   not change likelihood, impact, risk, effective severity, CVSS, or mitigation
   priority and cannot activate `architectural_violation`.
11. Add tests for deterministic focus ranking, the 2/4/6 limits,
    ordinary-process exclusion at `thorough`, overflow disclosure, and stable
    selection after input reordering.
12. Bound serialized context size by construction through the six-candidate
    maximum and schema string-length limits. Measure aggregate context growth;
    do not introduce a second runtime byte-budget subsystem unless replay shows
    those structural bounds are insufficient.

Primary tests:
`tests/test_resolve_config.py`, `tests/test_dispatch_manifest.py`,
`tests/test_validate_dispatch_manifest.py`,
`tests/test_dispatch_prompt_cache_order.py`, `tests/test_new_schemas.py`,
`tests/test_merge_threats.py`, `tests/test_build_threat_model_yaml.py`, and the
relevant cases in `tests/test_validate_intermediate.py`.

Milestone-2 exit gate:

- Replay at least one neutral fixture and the repository self-model before
  implementing report changes.
- Manually review every emitted boundary reference.
- Continue to Milestone 3 only if there are zero invented/non-adjacent IDs,
  zero evidence-free control gaps, zero boundary-only findings, and no rating
  changes attributable to `boundary_refs`.
- If the links add little decision value, ship schema normalization and stable
  IDs only; do not force the report/SARIF work to justify sunk cost.

### Milestone 3 — render and export one coherent boundary view

Goal: make the modeled assumptions and their linked findings useful to readers
without restoring the removed standalone section.

1. Add a conditional computed `trust_boundary_catalog` entry to
   `data/sections-contract.yaml` immediately after `system_overview`, modeled
   on the existing `identified_actors` subsection. Its heading is
   `### Trust Boundaries`; it is folded under §1 in the ToC and document order.
   Do not modify the LLM/pregenerated `system-overview.md`, add a numbered §2.x,
   or revive §6.
2. Implement the deterministic catalogue renderer in
   `scripts/compose_threat_model.py` and render a compact table with:
   - anchored `tb-N` ID;
   - name and endpoints;
   - kind and resolution status;
   - assumption;
   - confidence; and
   - linked finding IDs, or an explicit em dash when none are linked.
   Cap the report table at 20 rows: referenced gaps first, then selected primary
   boundaries, then other confirmed rows, all with `tb-N` tie-breaking. Point
   overflow to canonical YAML/query output. A finding links to a catalogue
   anchor only when that row is present; otherwise it renders the stable ID and
   name as plain text, so no anchor can dangle.
3. Extend the computed finding card in `scripts/compose_threat_model.py` with a
   `Trust boundary gap` row containing only evidence-backed references. Do not
   render adjacency as a finding attribute or use the generic word
   “violation.”
4. Extend `scripts/query_threat_model.py` so boundary records show their linked
   findings and finding queries show their boundary references.
5. Add `boundaryIds` to SARIF result properties in
   `scripts/export_sarif.py`; do not create a second SARIF result for the
   boundary itself.
6. Add QA checks for dangling anchors, duplicate catalogue IDs, and rendered
   references that do not match canonical YAML. Escape table pipes, raw HTML,
   link syntax, and anchor-shaped payloads in every rendered boundary field.
7. Add the `has_trust_boundaries` render condition, dispatcher wiring, ToC
   folding, and contract-integrity tests atomically. Preserve the existing
   prohibition on §2.x Trust Boundaries and the intentional §6 gap.
8. Leave Figure 1's visual layout and boundary labels unchanged in the first
   release, apart from the Milestone-1 correctness fix that requires explicit
   `from: external`. The catalogue is the canonical visible view; further
   diagram enrichment can be evaluated later without coupling correctness to
   SVG layout.

Primary tests:
`tests/test_contract_integrity.py`, `tests/test_compose_threat_model.py`,
`tests/test_query_threat_model.py`, `tests/test_export_sarif.py`,
`tests/test_sarif_validation.py`, `tests/test_qa_checks.py`, and the relevant
ToC cases in the composer tests.

### Milestone 4 — documentation, replay, and rollout gate

Goal: prove the model is stable and useful before considering any boundary-based
risk or remediation-priority logic.

1. Update `docs/threat-modeler.md` with:
   - boundary semantics and evidence confidence;
   - the difference between adjacency and an evidence-backed boundary gap;
   - the fact that boundaries do not change severity; and
   - the legacy-sidecar migration behavior.
2. Add an erratum/status note to the 2026-07-21 analysis so readers do not
   implement its disproven deterministic path join or risk modulation.
3. Add a short user-visible `CHANGELOG.md` bullet after the behavior ships.
4. Replay a neutral golden fixture via `scripts/threat_fixture.py`, following
   `docs/internal/runbooks/threat-fixture.md`, then run a two-run incremental
   replay with reordered Phase-7 output.
5. Record, for the fixture and the repository self-model:
   - invalid/dangling boundary references (target: zero);
   - ID churn across the second run (target: zero for unambiguous unchanged
     identities);
   - boundary references without verified evidence (target: zero);
   - risk or priority changes attributable only to boundary metadata (target:
     zero);
   - boundary-only findings (target: zero);
   - report row/anchor overflow behavior; and
   - dispatch-manifest, context-file, and resident-token growth.
6. Run the targeted suite first, then the repository's documented broader suite
   and separate any pre-existing failures from regressions.

## Deferred work and explicit non-goals

Do not include the following in the initial implementation:

- `crossed_boundary_ids[]` derived from actor plus component;
- full data-flow or taint/provenance analysis;
- automatic internet exposure from Dockerfile `EXPOSE` alone;
- a new `.appsec/exposure.yaml` input;
- automatic weakness emission from boundary prose;
- a generic `trust_boundary_violation` threat or weakness class;
- numeric `trust_level` deltas or control-strength weights;
- automatic up-ranking or down-ranking of finding severity;
- mitigation-priority changes; or
- Figure 1 boundary-label redesign.

A later proposal may add **boundary review priority** as a separate, explicitly
non-severity field, but only after measured link precision and evidence coverage
are available. It must never reduce a finding's risk merely because a control is
documented. A new weakness class such as `over_trusted_input` is justified only
when a deterministic, evidence-backed emitter finds a design condition that no
existing precise class represents.

## Suggested commit boundaries

1. `test/docs: lock trust-boundary semantics and legacy fixtures`
2. `feat: normalize trust boundaries and reconcile stable IDs`
3. `feat: carry evidence-constrained boundary refs on findings`
4. `feat: render and export trust-boundary traceability`
5. `docs: document trust-boundary semantics and rollout evidence`

Each commit must keep producer, schema, consumer, validation, and tests in sync;
do not land an output field in one layer with an `additionalProperties` escape
hatch in another.
