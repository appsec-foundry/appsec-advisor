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
3. merge optional, schema-validated repository declarations from
   `.appsec/trust-boundaries.yaml` without letting them suppress detected
   boundaries or alter risk;
4. give each STRIDE analyzer a validated, bounded component-scoped boundary-context
   file containing only adjacent candidates;
5. let a finding select at most two evidence-constrained `boundary_refs[]` gaps;
6. render a compact boundary catalogue in the existing System Overview and add
   links from relevant finding cards; and
7. carry boundary references through YAML, query output, and SARIF.

Figure 1 remains an architecture-and-risk summary, not the canonical boundary
view. It may append stable IDs for resolved, confirmed `from: external`
boundaries to the existing global internet-exposure legend text when doing so
requires no new node, edge, or layout calculation. The §1 catalogue remains
authoritative.

The new boundary metadata will **not** weight trust boundaries, change finding
severity, create a generic `trust_boundary_violation` threat, infer a full
attack path, or treat an unknown control as an absent control. Existing,
independently evidenced rating rules such as `architectural_violation` remain
separate and unchanged.

Trust-boundary enrichment is an optional, best-effort architecture aid. It must
not make the core STRIDE assessment materially more expensive, consume an
additional analyzer turn, expand an incremental STRIDE dispatch set, trigger a
retry, or block an otherwise valid report. When the economy gate below cannot
be met, ship normalization, stable IDs, and the deterministic catalogue without
analyzer-facing boundary contexts or `boundary_refs[]`.

## Decisions

| Question | Decision | Reason |
|---|---|---|
| Weight trust boundaries? | No numeric weight and no likelihood/severity multiplier. | The current model has no reliable path or deployment-reachability fact. An observed boundary control is context, not proof that a finding is unreachable. |
| Add a generic boundary-violation threat? | No. Add an evidence-backed boundary-gap reference to an existing precise finding. | Missing authZ, injection, weak trust-conferring headers, and similar mechanisms already have more useful threat/weakness classes. A generic class would duplicate them. |
| How much model complexity? | One normalized boundary object, one shared preparation step, one bounded candidate-adjacency join, and one optional evidence-backed finding link. Even `thorough` has a hard per-component candidate budget. | This delivers traceability without introducing data-flow, taint, exposure, weak context relations, and risk-scoring subsystems at once. Thorough increases evidence depth, not unbounded boundary breadth. |
| How may a boundary affect a finding? | Evidence-backed traceability and remediation scope only in this release. Weak contextual associations stay out of finding records. | Risk remains `likelihood x impact`; mitigation priority keeps its existing severity/effort/reachability/architectural-violation inputs. |
| Where is the documentation shown? | A compact `### Trust Boundaries` subsection inside §1 plus boundary links on finding cards. | §2.x Trust Boundaries is forbidden and the old numbered §6 intentionally remains absent. The §1 view is visible without restoring duplicated sections. |
| Show boundaries in Figure 1? | Only resolved, confirmed external-entry IDs may be appended to the existing global internet-exposure legend text. No new nodes, arrows, subgraphs, or layout rules. | This exposes the highest-value topological boundaries without turning the executive figure into an incomplete topology engine. Internal, inferred, and outbound boundaries remain in §1/§2 and machine output. |
| Allow repository declarations? | Yes, through optional `.appsec/trust-boundaries.yaml`; declarations add or clarify boundaries but cannot suppress detected rows, claim a control is effective, or affect ratings. | Deployment and tenancy intent is often not provable from source. A strict data-only input supplies that truth without becoming an instruction or risk-policy channel. |
| May boundary drift expand incremental analysis? | No. Boundary-only catalogue, declaration, ranking, or context changes recompose deterministic outputs but never add a component to the STRIDE dispatch set. | Boundary links are optional enrichment. Paying for source-clean component analysis solely to refresh them is disproportionate; a later source-triggered, full, or rebuild run refreshes the links. |
| What is the runtime cost contract? | No new agent calls, no extra analyzer model turn, unchanged full/rebuild component dispatch count, zero STRIDE dispatches for a boundary-only incremental change, and no more than 5% measured API-equivalent cost growth at the Milestone-2 rollout gate. | Structural gates prevent nonlinear retry/redispatch costs; the measured gate catches prompt and cache growth that call-count checks miss. |

## Review verdict and complexity budget

The design is useful only as a staged change. It targets **low runtime
complexity** (no new agent, category, rating pass, unbounded prompt, analyzer
turn, or incremental fan-out) but has **medium-high implementation complexity**
because a public cross-reference touches several schemas and deterministic
consumers. Low runtime complexity is an acceptance condition, not an assumption.

| Scope | Value | Implementation complexity | Decision |
|---|---|---|---|
| Contract normalization, endpoint resolution, SVG correctness | Removes current drift and false exposure inference even without finding links. | Medium | Required foundation. |
| Stable IDs and bounded candidate contexts | Makes later links auditable while capping every analyzer at 2/4/6 rows and batching the optional read into its existing Step-1 context turn. | Medium | Implement with the foundation through one shared helper. |
| Optional repository declarations | Adds deployment/ownership truth that source analysis cannot reliably infer. | Medium because provenance, conflicts, and identity precedence must be deterministic. | Include after normalization, before finding links. |
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
  layout/exposure hints and an existing `internet-exposed entry point` legend
  marker, but it does not display boundary IDs, names, or assumptions. The
  Mermaid fallback can append a boundary name to a benign edge, but it is not
  the primary report path.
- The current query command exposes boundaries only as a system-level view.
  Findings, weaknesses, mitigations, and SARIF do not reference `tb-N` IDs.
- Arbitrary fields such as `weakness` survive today because the boundary schemas
  allow undeclared properties. No consumer turns that field into a validated
  weakness.
- The architecture prompts still call trust zones “trust boundaries” and draw
  them as subgraphs, while the target object is an edge/interface. The rollout
  must distinguish zone containers from boundary crossings explicitly.
- The baseline cache persists only threat and mitigation ID high-watermarks.
  Reading the maximum active boundary ID is insufficient to prevent reuse after
  the highest retired ID disappears.
- `build_threat_model_yaml.py` currently uses truthiness for the sidecar fallback;
  an authoritative empty boundary list therefore revives prior rows.

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
    sources: [detected]
```

`schema_version: 2` is a top-level sidecar field, not a field repeated on each
boundary.

Contract rules:

- `id` is the stable public identifier and keeps the existing `^tb-\d+$` form;
  `name` is 1–100 characters.
- `from` and `to` are component IDs or the literal `external`. On `from`, the
  literal denotes inbound network ingress from outside the modeled system; on
  `to`, it denotes an outbound crossing and is not an internet entry point. New
  Phase-7 output must provide both. A compatibility path may retain an old
  boundary without endpoints, but such a boundary is not eligible for
  adjacency or finding links.
- `resolution_status` is inserted by deterministic preparation, never authored
  by the LLM. Its values are `resolved`, `unresolved`, and `conflicted`. A
  boundary is `resolved` only when both endpoints are present, each is
  `external` or a known component, and reconciliation found no incompatible
  declaration/detection identity. Missing or unknown endpoints are
  `unresolved`; incompatible identity claims are `conflicted`. Every
  non-resolved row is excluded from semantic consumers and remains visible for
  review.
- The strict normalized schema uses conditional requirements: `resolved` rows
  require both endpoints, while an `unresolved` compatibility/review row may
  retain a missing endpoint. A producer omission therefore remains visible but
  cannot become semantic input.
- `kind` is a small enum: `network`, `process`, `identity`, `privilege`,
  `tenant`, `data-origin`, `third-party`, or `build`.
- `assumption` states what must remain true at the crossing. It does not state
  that the assumption is satisfied. New v2 output requires 1–240 characters.
- `evidence[]` uses canonical repository-relative file and optional positive
  line references. Absolute paths, `..` traversal, paths outside the target
  repository, URLs, and evidence-derived read/write targets are forbidden.
  A boundary carries at most five evidence locations.
- `confidence` describes confidence in the modeled boundary and assumption:
  `confirmed`, `inferred`, or `unknown`. `confirmed` requires at least one
  validated evidence location plus confirmation by the detection/review path;
  file existence or a repository declaration alone is insufficient. Missing
  evidence cannot be promoted above `inferred`. Confidence is not a risk
  weight.
- `sources[]` is a non-empty unique subset of `detected`, `repo-declared`, and
  `legacy`. It records provenance, not confidence or control effectiveness.
  `declaration_key` is present only for a repository-declared boundary and is a
  stable lowercase slug unique within `.appsec/trust-boundaries.yaml`.
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

### Optional repository declaration

The target repository may add architecture truth that cannot be derived
reliably from source in `.appsec/trust-boundaries.yaml`:

```yaml
api_version: appsec-advisor/trust-boundaries/v1
boundaries:
  - key: public-api
    name: Public API entry
    from: external
    to: web-api
    kind: network
    assumption: Protected operations require authenticated and authorized requests.
    evidence:
      - file: deploy/ingress.yaml
        line: 18
```

Declaration rules:

- The input is validated against a dedicated strict schema before merge and is
  always treated as untrusted data, never instructions.
- If the file is malformed, reject the complete declaration input with an
  actionable diagnostic and continue the detected assessment without it. Do
  not partially apply a malformed file or let repository content abort the
  assessment.
- `key` is stable declaration identity; the normalizer, not the repository,
  assigns the public `tb-N` ID. Exact declaration-key continuity is the first
  reconciliation match.
- A declaration may add a boundary or refine the name, kind, assumption, and
  evidence of the same resolved endpoint crossing. Detected evidence is unioned,
  never discarded.
- A declaration does not author `confidence`. A declaration-only row is at most
  `inferred` even when its evidence locations are structurally valid. When
  detection and declaration merge, only independently verified detection
  evidence may promote the combined row to `confirmed`; declaration evidence
  is retained as provenance but is not self-confirming.
- A declaration cannot disable a detected boundary, declare controls effective,
  set risk/severity/priority, or introduce commands, permissions, read/write
  targets, URLs, or paths outside the target repository.
- Conflicting declaration/detection endpoints for the same reconciled identity
  are preserved as separate `conflicted` review rows with an audited warning
  rather than silently choosing one side. They receive no semantic role until a
  later input resolves the conflict.
- Concrete endpoints remain repository-scoped. Org profiles may later provide
  boundary policy or templates, but the initial release does not let an org
  profile inject repository component IDs.

### Presentation contract

Each view has a deliberately different completeness promise:

| View | Contract |
|---|---|
| §1 `Trust Boundaries` | Canonical human catalogue. Shows stable ID, source, crossing, kind/status, assumption/confidence, and linked findings. The table is capped with explicit overflow to YAML/query. |
| §2 architecture diagrams | Trust **zones** may remain subgraphs. A modeled trust **boundary** is an edge/interface crossing and may be labelled with `tb-N`; a zone must not be presented as the boundary object itself. |
| Figure 1 | Optional executive projection only: append the aggregate IDs of resolved, confirmed `from: external` rows whose target components are displayed to the existing global internet-exposure legend text. Component globe markers remain unchanged. It is never a complete boundary view. |
| Finding card | Shows only evidence-backed gaps as `[tb-N](#tb-N) — Name: rationale`; adjacency alone is never rendered. |
| YAML/query/SARIF | Complete machine-readable catalogue and valid finding relations. |

Figure 1 must not create a node, arrow, attack path, severity implication, or
layout dependency from boundary metadata. `to: external`, non-resolved or
non-confirmed rows, and internal-only boundaries are not Figure-1 ingress
annotations. Aggregate eligible IDs across displayed components, show the first
two by numeric ID plus `+N`, and keep the component globe markers unchanged. If
the existing global legend text cannot accommodate the suffix, retain the old
text unchanged.

The Figure-1 ID suffix is a non-blocking enhancement. If SVG layout checks or
fallback-renderer parity cannot be satisfied without structural changes, omit
the suffix from the release; the explicit-ingress correctness fix and the §1
catalogue still ship.

### Finding relation

Add this optional field to per-component STRIDE output, merged threats, and the
canonical threat model:

```yaml
boundary_refs:
  - boundary_id: tb-1
    origin_component_id: web-api
    rationale: The route reaches the protected operation before an object-level authorization check.
    evidence_locations:
      - file: src/routes/orders.ts
        line: 87
```

Validation rules:

- `boundary_id` must identify a `resolved`, `confirmed` row in the normalized
  boundary sidecar and canonical model. Inferred or unknown rows may guide
  bounded analysis but cannot become finding relations.
- A reference newly authored in the current STRIDE run must name one of the
  origin component's selected dispatch candidates. A carried, previously
  verified reference need not consume the current prompt budget; it remains
  valid only while the boundary still exists, remains resolved and confirmed,
  is adjacent to its origin component, and its verified evidence survives.
- `origin_component_id` is required and records which component-scoped context
  authorized the reference. It must be the analyzer component for a fresh
  reference and a registered component for carried/consolidated data.
- `rationale` is required, concise, and must describe the mechanism rather than
  restate the boundary name (20–240 characters).
- A finding has at most two unique boundary references. A boundary reference
  is optional; analyzers must not add one merely to fill the field.
- Every reference represents a concrete control gap and therefore requires one
  or more `evidence_locations[]`. Each location must
  already exist in the finding's verified evidence or consolidated instances;
  the reference cannot introduce new evidence. Boundary evidence confirms the
  modeled crossing; finding evidence confirms the concrete gap. Both are
  required, and each reference carries at most three finding evidence
  locations.
- A reference does not mean “the complete attack path crosses this boundary.” Do
  not add `crossed_boundary_ids[]` until persisted data flows can support it.
- Consolidation unions unique references and their evidence locations only when
  the result still contains at most two unique `(boundary_id,
  origin_component_id)` pairs. If an otherwise eligible merge would exceed the
  public two-reference contract or lose origin provenance, keep the findings
  separate rather than dropping a valid reference. A reference survives only
  when the corresponding member evidence survives in the consolidated finding.
  General contextual association stays in the boundary catalogue and is
  deliberately not modeled on findings in the first release.

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

The cap is hard for context sent to the current analyzer at every depth,
including `thorough`. It does not invalidate a carried verified relation merely
because more prior relations exist than fit in the current prompt. Rank current
candidates using a stable tuple rather than a risk score:

1. a prior verified boundary reference (selection preference only, not a
   carry-forward validity gate);
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
evidence-backed design change. Boundary selection creates no new agent calls,
no extra STRIDE categories, and no additional model turn. A non-empty boundary
file is read in parallel with the analyzer's other Step-1 context files in the
same assistant turn. When no candidate is selected, the manifest uses `none`
and the analyzer performs no boundary read. If the 2/4/6 caps do not pass the
cost gate, calibrate them downward; never raise them to make the feature appear
more useful.

## Verified risks and required controls

| Risk | Current-code evidence | Required mitigation | Residual risk |
|---|---|---|---|
| Adjacency is misreported as traversal or violation. | `build_stride_dispatch_manifest.py::_trust_boundaries_for` joins only on `from`/`to`/`components`; canonical YAML has no persisted `data_flows[]`. | Name the deterministic input `adjacent_trust_boundaries`; allow a finding reference only with verified gap evidence and rationale; forbid weak `context` links and `crossed_boundary_ids`. | The analyzer can still overstate the rationale; replay sampling must measure precision. |
| Boundary prose creates false precision about controls. | Phase 7 requests `enforcement: "none observed"`, the sidecar also carries free-form `controls[]`, and the canonical `security_controls[]` register already owns observed controls. | Remove boundary-local enforcement, controls, trust weights, and description from the v2 object. Keep only the trust assumption, evidence, and confidence; unknown never becomes absent. | Linking a specific existing security-control record to a boundary is deferred rather than guessed by name. |
| Boundary metadata contaminates severity or priority. | `triage_validate_ratings.py` enforces the likelihood-impact matrix; `phase-group-threats.md` separately escalates `architectural_violation` and contains existing cross-repository rules. | Make `boundary_refs` metadata-only; it cannot set `architectural_violation`, likelihood, impact, risk, CVSS, or priority. Isolate existing cross-repository/architecture rules and test that identical findings rate identically with and without boundary refs. | An analyzer may still phrase a scenario more strongly; evidence and rating QA remain necessary. |
| Structured context inflates the finding count. | The STRIDE analyzer already reasons from trust-boundary prose and requires a code/evidence basis, but nothing currently prevents a future “one finding per boundary” instruction. | State that a boundary object alone is never finding evidence; require the existing threat/evidence gates; add no deterministic boundary-threat emitter and no completeness rule requiring a finding per boundary. | Better context may legitimately change LLM recall, so fixture counts are diagnostic rather than a fixed equality gate. |
| Findings are over-consolidated because they share a boundary. | `merge_threats.py` consolidates by mechanism/object catalog and `_merge_member_metadata` currently has no boundary provenance. | Never use `boundary_id` alone as a merge key. Require `origin_component_id`, preserve per-member evidence, and keep findings separate when a merge would exceed two unique refs or lose provenance. | Existing heuristic/LLM consolidation still needs its current fail-closed guards. |
| Public `tb-N` references churn or are reused. | Phase 7 says IDs are LLM-chosen; `reserve_ids.py` has no boundary ID type; `baseline_state.py` persists only T/M high-watermarks. Multiple integrations may share one endpoint pair. | Capture the prior canonical catalogue before the sidecar is overwritten; persist `next_trust_boundary_id` in the baseline; match declaration key, compatible prior ID, endpoint+name, then unique endpoint; allocate only from the high-watermark. `--rebuild` deliberately resets both catalogue and counter. | A rename among several boundaries sharing endpoints may intentionally receive a new ID rather than risk a wrong match. |
| Contract drift produces write-only fields again. | Fragment schema, Phase-7 examples, output schema, dispatch consumer, query tool, and legacy pregenerator read different field sets. | Land producer, both schemas, normalizer, consumers, Python validation, permissions, and tests atomically; reject unknown canonical properties; maintain a contract matrix in schema invariants. | Legacy inputs remain a compatibility surface until their migration window closes. |
| Untrusted fields break prompts/Markdown or steer file access. | Repository/imported context is untrusted; the proposed catalogue would newly render boundary names/assumptions and expose evidence paths to STRIDE. The current sanitizer runs after canonical YAML construction—too late for dispatch. | Sanitize name/assumption during normalization, canonicalize evidence paths under the target repo, reject traversal/URLs, treat context files as untrusted data, and escape pipes/HTML/anchors in the renderer. Boundary strings/paths never determine commands or write targets. Keep the later sanitizer as a backstop and add injection-shaped fixtures. | Semantically misleading but syntactically safe prose still requires confidence/evidence review. |
| Prompt size, cache stability, or turn count regresses. | `TRUST_BOUNDARIES` is currently an inline Group-B dispatch scalar and has no dedicated size budget. The analyzer already reads several Group-C files in Step 1, so a separately sequenced boundary read would add a full model round-trip and re-read resident context. | Apply the depth-aware 2/4/6 candidate cap, write validated `.dispatch-context/<component>/trust-boundaries.json` files only for non-empty selections, pass only their Group-C paths, and batch all non-`none` Step-1 context reads in one parallel tool-call turn. Keep records compact, measure file/manifest/cache growth, and omit an oversized optional context with an audited reason rather than truncating it or blocking STRIDE. | The bounded tool result still grows resident context; the rollout cost gate measures that residual. |
| Boundary focus omits a useful internal crossing. | The requested hard cap intentionally reduces breadth, and focus classification consumes producer-authored `kind`/confidence plus deterministic endpoint/component facts. | Prefer prior verified gaps, explicit external entries, evidenced identity/privilege transitions, and sensitive data-origin transitions; disclose every omitted ID/reason and keep it in YAML/query. Never interpret omission as safety. | A catalog-only or over-budget boundary can be missed by STRIDE; this is the explicit trade-off for bounded complexity. |
| Late component reconciliation leaves a component without boundary context. | `build_stride_dispatch_manifest.py` can inject security-relevant components after the Phase-3/Phase-7 inventory has been authored. | Normalize the catalogue after Phase 7, but generate component contexts only after the final component reconciliation immediately before dispatch. Use the same idempotent helper in parallel and serial paths. | A newly injected component may have no modeled adjacent boundary; its manifest uses `none` plus an audited reason, never another component's context. |
| Boundary input drift creates disproportionate incremental spend. | The current actor-slice delta path proves that a context-hash change can re-dispatch a source-clean component. Applying the same rule to optional boundary context could turn one central declaration or ranking change into a near-full STRIDE run. | Normalize on every full/incremental run and fingerprint declaration inputs for deterministic recomposition, but never add a component to `SECURITY_RELEVANT_COMPONENTS` or the STRIDE dispatch set because of a boundary-only change. Generate contexts only for components already selected for fresh STRIDE analysis. Revalidate or drop carried refs deterministically; otherwise defer link enrichment until a later source-triggered, full, or rebuild run. | Boundary links may lag catalogue changes, which is acceptable for optional enrichment and must be disclosed in the selection audit. |
| A post-build component rewrite invalidates a reference. | `auto_emitter_pass.sh` runs `reclassify_components.py` after canonical YAML validation and can change both YAML and `.threats-merged.json`. | Make reclassification reconcile `origin_component_id` and adjacency atomically: retain only if the resolved boundary is adjacent to the new component and evidence survives; otherwise remove the optional ref with an audited warning. Run the boundary integrity check again after all mutations. | A corrected component can legitimately lose optional traceability; the finding itself remains. |
| Current selection drops a valid carried reference. | The prompt cap is 2/4/6, while one component may have more prior verified relations than fit in a new analyzer context. | Apply candidate membership only to refs newly authored in the current dispatch. Validate carried refs by existence, resolved/confirmed status, adjacency, origin, and surviving evidence; selection is a prompt budget, not a relation-retention policy. | A carried ref may not be re-reviewed in the current shallow run; its prior verification state stays explicit. |
| Legacy incomplete boundaries affect reachability. | `figure1_svg.py` currently treats an empty `from` value as external; the fragment schema requires only `id` and `name`. | Classify resolution with one shared endpoint predicate; exclude unresolved legacy records from adjacency, exposure, links, and other semantic consumers. Change exposure derivation to require explicit `from: external`. | Old unresolved records remain documentation-only until a future scan resolves them. |
| A valid empty catalogue revives stale rows. | `build_threat_model_yaml.py` uses `sidecar_rows or carry_forward`, so `[]` is treated as missing. | Allow an empty v2 array, distinguish missing/malformed from present-empty, and make explicit empty authoritative. Update old non-empty prose gates. | An LLM that accidentally emits empty still needs phase diagnostics, but prior rows are not silently presented as current truth. |
| Repository declarations become a suppression/risk, self-confirmation, or availability channel. | Repository configuration is untrusted and existing code has no boundary-declaration resolver. | Strict schema; additive-only merge; declaration-only confidence capped at `inferred`; stable declaration keys; provenance; conflicts become non-semantic `conflicted` rows; malformed input is rejected as a whole without aborting detection; no disable, rating, control-effectiveness, command, URL, or external-path fields. | A syntactically valid declaration can still be factually wrong and is displayed as declared provenance for review. |
| Figure 1 becomes noisy or implies full topology. | The primary SVG currently uses boundaries only for exposure/ghost hints, gives exposed components a globe, and has one global internet-exposure legend row. | Append at most two aggregate numeric `tb-N` IDs plus `+N` only to that existing legend text, solely for resolved, confirmed `from: external` rows targeting displayed components. Keep component globes unchanged; add no nodes/edges/layout and state that §1 is canonical. Degrade to the unchanged text on layout failure. | The aggregate legend does not map each ID to a component; §1 supplies that mapping. Outbound, internal, and inferred boundaries are intentionally absent. |
| The report becomes noisy or the investment has little value. | The current report does not expose stable boundary-to-finding links, so real reader usage is unmeasured. | Add a stop/go gate after Milestone 2 and cap §1 at 20 rows, ordered by referenced gaps, conflicted/unresolved review rows, selected primary boundaries, confidence, and stable ID. Render omitted IDs as plain text in findings and point overflow to YAML/query output. | Teams that do not use architecture-level triage may still gain only schema quality and stable IDs. |

## Implementation sequence

### Milestone 0 — characterization and contract lock

Goal: pin the current drift and agree on the new semantics before changing
runtime output.

1. Add characterization fixtures for:
   - current `controls[]` input;
   - legacy `enforcement`, `crossing_enforcement`, `trust_level`, and
     `weakness` fields;
   - missing endpoints;
   - an endpoint that references an unknown component;
   - an authoritative empty v2 catalogue;
   - a repository declaration that agrees/conflicts with detection;
   - two runs where boundaries are reordered and renamed; and
   - three runs where the highest ID is retired before a new boundary appears.
2. Add the trust-boundary invariants to
   `docs/internal/contracts/schema-invariants.md`.
3. State explicitly in that contract that trust-boundary metadata cannot alter
   `risk`, `effective_severity`, CVSS, or mitigation priority by itself. Record
   existing independent exceptions (`architectural_violation`, requirements,
   and cross-repository coverage rules) so the new reference cannot activate
   them accidentally.
4. Add a producer/schema/consumer/validator/test matrix for every boundary
   field. Include repository declarations, the legacy pregenerator helpers,
   both Figure-1 renderers, cross-repo slicing, query, SARIF, post-build
   component reclassification, rerender, and cleanup/permission contracts
   rather than treating the primary builder as the only consumer.
5. Replace the diagram vocabulary contractually: deployment/trust zones are
   subgraphs; trust-boundary objects are crossings between endpoints. Update the
   conflicting agent prose and add a drift test so “boundary as subgraph” does
   not return.

Primary drift guards:
`tests/test_new_schemas.py`, `tests/test_dispatch_manifest.py`,
`tests/test_build_threat_model_yaml.py`, and
`tests/test_incremental_two_run_e2e.py`.

### Milestone 1 — normalize the boundary model and stabilize IDs

Goal: produce one trustworthy boundary array before STRIDE dispatch.

1. Update `schemas/fragments/trust-boundaries.schema.json` to declare the target
   v2 sidecar and reject undeclared canonical fields. The deterministic
   preparer accepts legacy v1 input; only its normalized v2 output is validated
   against the strict fragment schema. A present v2 `trust_boundaries: []` is
   valid and authoritative; missing/malformed and present-empty are distinct.
2. Mirror the normalized object in
   `schemas/threat-model.output.schema.yaml`; do not leave the canonical schema
   at `name`-only validation.
3. Replace the conflicting Phase-7 examples and prose in
   `agents/phases/phase-group-architecture.md`,
   `agents/appsec-threat-analyst.md`, and the thin orchestrator wiring with one
   producer contract. Phase 7 writes the sidecar, runs deterministic preparation,
   and validates the normalized file in that order. Replace “boundary subgraph”
   with the zone-versus-crossing vocabulary from the presentation contract.
4. Add one idempotent `scripts/prepare_trust_boundary_context.py` with matching
   `tests/test_prepare_trust_boundary_context.py` and two operations backed by
   the same library code:
   - `normalize`, invoked after Phase 7, owns v1→v2 migration, repository
     declaration merge, stable IDs, endpoint resolution, and strict sidecar
     validation; and
   - `contexts`, invoked immediately before STRIDE dispatch after the final
     component reconciliation, owns focus selection and bounded files under the
     existing `.dispatch-context/` directory for components already selected
     for fresh STRIDE analysis. It must not expand that selection.
   The parallel manifest builder calls the shared `contexts` function after its
   deterministic component injections. The serial Phase-9 path invokes the
   same CLI operation. Do not implement a second selection algorithm in either
   orchestrator prompt.
   `normalize` receives the target repo, the just-authored sidecar, the prior
   canonical `threat-model.yaml` captured before overwrite, and the output
   directory explicitly. It reads and reserves the high-watermark only through
   the shared locked counter path; it must not infer “prior” from the file it is
   about to replace. Run it on every full and incremental execution, using the
   current Phase-7 output or the explicitly selected cached sidecar; do not skip
   repository declaration processing merely because source files are unchanged.
5. Add `schemas/trust-boundaries-repo.schema.yaml` and load optional
   `<repo>/.appsec/trust-boundaries.yaml` as data. Merge declarations additively
   before ID reconciliation, preserve `sources[]`, and use the conflict rules in
   the declaration contract. Do not add a disable list or org endpoint layer.
6. Match prior IDs conservatively and bijectively:
   - reuse an exact `declaration_key` first;
   - reuse an authored prior ID only when its endpoints remain compatible;
   - otherwise match exact `(from, to, normalized name)`;
   - use endpoint-only matching only when exactly one prior and one current
     boundary share that pair; and
   - allocate a new ID from the persisted high-watermark when matching is
     ambiguous or absent.
   `kind`, assumptions, and confidence are mutable metadata, not
   identity. Retired IDs are never reused.
7. Extend `scripts/baseline_state.py` and `scripts/reserve_ids.py` with
   `id_counters.next_trust_boundary_id`; only the deterministic normalizer may
   reserve this ID type. Bump the baseline schema version and migrate v1 state
   without discarding existing counters. Seed the counter from the prior
   counter and prior canonical `tb-N` IDs, never from an unmatched ID supplied
   by the current untrusted sidecar. Normal updates preserve it even when the
   highest row retires; `--rebuild` is the deliberate reset that permits
   reassignment. Bound the numeric suffix and add validation plus three-run
   retirement tests.
   In the same baseline migration, add a declaration-input fingerprint so a
   declaration-only change can trigger deterministic normalization and
   recomposition. Do not add per-component boundary-context hashes to the
   incremental dispatch decision; boundary drift is not an authorization to
   spend STRIDE budget on a source-clean component.
8. Treat LLM-authored IDs as provisional input. Reject duplicate final IDs,
   but allow multiple named external integrations to touch the same component;
   do not collapse Stripe, GitHub, and another external peer merely because all
   currently use the literal `external` endpoint.
9. Validate endpoint cross-references in Python:
   - `external` or a known component is valid;
   - an explicit unknown component or missing endpoint sets deterministic
     `resolution_status: unresolved` and emits a warning;
   - an incompatible declaration/detection identity sets
     `resolution_status: conflicted` on the retained review rows; and
   - every non-resolved row remains documentation-only and is excluded from
     dispatch, exposure inference, finding links, and every other semantic
     consumer.
   One malformed LLM row must not abort an otherwise valid assessment.
10. Normalize legacy fields conservatively:
   - never translate `none observed` into proven absence;
   - do not copy legacy `controls`, `description`, `enforcement`, or
     `trust_level` into v2 boundary fields; emit a migration warning instead;
   - when legacy input has no explicit assumption, write the neutral
     `Assumption not recorded in legacy model`, set confidence to `unknown`,
     and keep the row `catalog-only` until a later scan refreshes it; and
   - never turn legacy `weakness` prose into a W-NNN object.
   Any new event-log line uses `scripts/event_log.py`; concise per-row migration
   diagnostics may remain on stderr.
11. Extract a public shared perimeter-prose helper rather than importing the
   private `_sanitize_string` from `scripts/sanitize_perimeter_claims.py`.
   Normalize boundary name/assumption with context-appropriate neutral text,
   enforce length bounds, strip control characters, and retain the prohibition
   on speculative perimeter-absence claims. Unsafe prose must be cleaned before
   STRIDE sees it; the existing later auto-emitter invocation remains a backstop
   for legacy models.
   Canonicalize evidence paths under the target repository and reject absolute,
   traversal, URL, symlink-escape, and out-of-repo values before writing any
   context file. Bound endpoint/evidence-path lengths; a positive line must
   resolve inside the cited regular file when present.
12. Make `scripts/build_threat_model_yaml.py` consume only the normalized array,
    distinguish present-empty from missing, and validate the resulting canonical
    model. Update old “non-empty trust_boundaries” prose/gates. A legacy
    `--rerender` uses a display-only compatibility adapter and never makes a v1
    row semantic, assigns a new ID, or fails solely because Stage 1 was skipped;
    a fresh full/incremental run is required to produce canonical v2.
13. Update every semantic consumer of legacy boundary fields. In particular,
    `figure1_svg.py` and the Mermaid Figure-1 builder must treat only explicit,
    resolved, confirmed `from: external` as ingress; a missing, unknown, or
    declaration-only source must not become internet exposure. Update
    `slice_cross_repo_for_component.py` to consume the normalized component
    boundary view without retaining an analyzer-facing inline scalar. Legacy
    pregenerator paths must use normalized fields or remain explicitly
    display-only with regression coverage.
14. Register the new command/path permissions in
    `data/required-permissions.yaml`, keep the selection audit and any non-empty
    context files under the existing `.dispatch-context/` runtime directory,
    and update the cleanup contract if its current directory rule does not
    already cover them. Extend `tests/test_check_permissions.py` and
    `tests/test_runtime_cleanup.py`.

Acceptance criteria:

- The fragment and output schemas agree field-for-field.
- Reordering never changes an ID. A rename keeps its ID when the prior match is
  unambiguous; ambiguous matches receive a new ID and warning rather than a
  potentially wrong reused ID.
- Retiring the highest ID and adding a boundary in a later third run never
  reuses the retired ID; `--rebuild` is the tested exception.
- Repository declarations merge additively, retain provenance, and cannot
  suppress detection, self-confirm, alter Figure-1 exposure, or affect ratings.
- Changing only a repository declaration recomposes the catalogue and performs
  zero STRIDE analyzer dispatches. Boundary links for otherwise source-clean
  components may remain unchanged until a later source-triggered, full, or
  rebuild analysis.
- Unknown component endpoints become visible unresolved catalogue rows and
  never enter semantic analysis.
- Legacy records remain readable without being upgraded to unsupported claims.
- An explicit empty v2 list remains empty and does not carry old rows forward.
- A legacy rerender completes through the display-only compatibility path.
- Missing endpoints cannot create an external-exposure arrow or an adjacency
  candidate.
- Injection-shaped names and assumptions remain data
  in logs, prompts, Markdown, and HTML output.
- No new network access is introduced; every new runtime file follows the
  declared permission and cleanup/preservation contracts.

Primary tests:
`tests/test_prepare_trust_boundary_context.py`, `tests/test_new_schemas.py`,
`tests/test_build_threat_model_yaml.py`, `tests/test_figure1_svg.py`,
`tests/test_sanitize_perimeter_claims.py`, `tests/test_check_permissions.py`,
`tests/test_runtime_cleanup.py`, `tests/test_reserve_ids.py`,
`tests/test_baseline_state_coverage.py`,
`tests/test_baseline_content_unchanged.py`,
`tests/test_trust_boundaries_repo.py`, and
`tests/test_incremental_two_run_e2e.py`.

### Milestone 2 — add evidence-constrained finding links

Goal: let analyzers identify which adjacent boundary matters without asking
them to invent topology.

1. Make `scripts/build_stride_dispatch_manifest.py` reference a validated
   `.dispatch-context/<component-id>/trust-boundaries.json` written by the
   shared preparer after component reconciliation. The builder calls the shared
   preparation function but must not independently recompute identity, focus,
   or selection. Generate this file only for a component already selected for
   fresh STRIDE analysis and only when at least one candidate is selected; use
   `none` otherwise. Candidate rows carry only ID, endpoints, kind, assumption,
   evidence, confidence, and focus reasons—no duplicated control catalogue.
   Neither the preparer nor the manifest builder may add a component to an
   incremental dispatch set. Declaration-only, catalogue-only, ordering, and
   focus-ranking changes remain deterministic recomposition work. A missing,
   malformed, or oversized optional context is audited and replaced with
   `none`; it must not trigger an analyzer retry or block core STRIDE analysis.
2. Add the context file to
   `schemas/stride-dispatch-manifest.schema.yaml` as
   `index_paths.trust_boundaries`. Pass only that path in Group C of the
   analyzer prompt; remove the inline Group-B `TRUST_BOUNDARIES` scalar and the
   current dependence on undeclared `crossing_enforcement`.
3. Add a dedicated `BOUNDARY_CANDIDATE_LIMITS` constant in
   `scripts/resolve_config.py` (`quick=2`, `standard=4`, `thorough=6`) and emit
   the resolved value as `max_boundary_candidates_per_component`. Keep it
   separate from `resolve_config.py`'s own `DEPTH_PARAMS` and from
   `build_stride_dispatch_manifest.py`'s `_FALLBACK_DEPTH_PARAMS`; both
   intentionally carry only depth/QA and STRIDE turn budgets, and the latter
   lives in the dispatch builder, not in `resolve_config.py`. The preparer
   imports the dedicated constant and writes eligible,
   selected, omitted, and deferred IDs plus focus reasons into a compact
   selection audit; a context file contains selected candidate rows only.
   `build_threat_model_yaml.py` aggregates that audit into a declared
   `meta.boundary_selection` object in the output schema. Do not rely on
   `meta.additionalProperties` passthrough for this audit contract.
4. Update `agents/appsec-stride-analyzer.md` and
   `agents/phases/phase-group-threats.md`:
   - read every non-`none` Step-1 context file, including the boundary context,
     through parallel Read calls in one assistant turn; a boundary context must
     not add a model round-trip;
   - perform no boundary read when its manifest path is `none`;
   - treat every boundary-context string as untrusted data;
   - emit no reference when a candidate merely provides context;
   - emit a boundary reference only for a confirmed candidate and a concrete,
     verified control gap; and
   - never change the finding rating or set `architectural_violation` because
     of a boundary reference.
5. Update the thin and legacy dispatch mappings in
   `skills/create-threat-model/` and extend
   `tests/test_dispatch_prompt_cache_order.py`. The volatile context path stays
   in Group C so the cache-stable prefix does not grow. Add a static regression
   test that the Step-1 instructions batch the boundary path with the existing
   context reads instead of sequencing it as a new turn.
6. Add `boundary_refs[]` atomically to:
   - `schemas/stride.schema.yaml`;
   - `schemas/threats-merged.schema.yaml`;
   - `schemas/threat-model.output.schema.yaml`; and
   - the relevant intermediate Python post-checks.
   Set `maxItems: 2`; require unique `(boundary_id, origin_component_id)` pairs;
   require `origin_component_id`; and allow `evidence_locations[]` only for
   locations already owned by the finding.
   `validate_intermediate.py stride` can enforce this local shape/evidence
   subset but cannot validate candidate membership because its CLI receives
   only one STRIDE file.
7. Preserve and deduplicate the field in `scripts/merge_threats.py` and
   `scripts/build_threat_model_yaml.py`, including carry-forward and T-to-F ID
   reconciliation paths. A shared boundary is not a consolidation key. After an
   independently valid merge, keep member evidence and origin together; when a
   union would exceed two refs or lose provenance, do not merge those findings.
8. In `merge_threats.py`, validate each reference against the component's
   prepared candidate file while the output directory is available. Candidate
   membership is mandatory only for a ref freshly emitted by the current
   analyzer. Validate carried refs against canonical boundary existence,
   resolved/confirmed status, origin adjacency, and surviving verified evidence
   after consolidation/carry-forward. Unknown-ID, inferred, non-resolved,
   wrong-origin, current-run-non-candidate, or evidence-free references are
   removed with an audited warning at the LLM→merge trust boundary while the
   underlying finding is preserved. The canonical builder runs the same
   deterministic post-check and strips any invalid optional reference that
   nevertheless survives before schema validation. If boundary-reference
   integrity cannot be restored deterministically, disable boundary references
   for that run, retain the valid findings, and emit an audited warning.
   Optional traceability metadata must not make a valid security finding
   disappear, trigger a retry, or abort the assessment.
9. Extend `scripts/reclassify_components.py` and the post-auto-emitter gate. If
   a finding component changes, update reference origin only when the resolved
   boundary is adjacent to the new component and the same evidence survives;
   otherwise remove the optional reference with an audited warning. Re-run the
   boundary integrity check after the mutation and before rendering.
10. Add negative tests for invented boundary IDs, non-adjacent candidates,
   evidence-free or refuted references, inferred-boundary refs, duplicate refs,
   boundary-only threat evidence, over-cap consolidation, carry-forward beyond
   the current selection cap, and consolidation/reclassification that would
   otherwise lose reference provenance.
11. Add regression tests proving that adding or removing `boundary_refs[]` does
   not change likelihood, impact, risk, effective severity, CVSS, or mitigation
   priority and cannot activate `architectural_violation`.
12. Add tests for deterministic focus ranking, the 2/4/6 limits,
    ordinary-process exclusion at `thorough`, overflow disclosure, and stable
    selection after input reordering.
13. Bound serialized context size by construction through the six-candidate
    maximum and schema string-length limits. Measure aggregate context growth;
    do not introduce a second runtime byte-budget subsystem unless replay shows
    those structural bounds are insufficient.
14. Add incremental regression coverage proving that a change limited to
    `.appsec/trust-boundaries.yaml`, normalized catalogue metadata, candidate
    ordering, or focus ranking causes zero STRIDE dispatches. A component whose
    source is independently selected for fresh analysis receives the current
    context; carried components are not refreshed solely for optional links.
15. Compare Milestone 2 with the frozen Milestone-1 baseline through
    `scripts/measure_run.py` / `scripts/verify_run_costs.py`. Record dispatch
    count, analyzer tool-turn count, input/output/cache-write/cache-read tokens,
    API-equivalent cost, and context bytes per component. Do not infer economy
    from wall time alone.

Primary tests:
`tests/test_resolve_config.py`, `tests/test_dispatch_manifest.py`,
`tests/test_validate_dispatch_manifest.py`,
`tests/test_dispatch_prompt_cache_order.py`, `tests/test_new_schemas.py`,
`tests/test_merge_threats.py`, `tests/test_build_threat_model_yaml.py`, and the
relevant cases in `tests/test_validate_intermediate.py` and
`tests/test_reclassify_components.py`, plus the boundary-delta cases in
`tests/test_incremental_mode.py` and `tests/test_incremental_two_run_e2e.py`.

Milestone-2 exit gate:

- Replay at least one neutral fixture and the repository self-model before
  implementing report changes.
- Manually review every emitted boundary reference.
- Continue to Milestone 3 only if there are zero invented/non-adjacent IDs,
  zero evidence-free control gaps, zero boundary-only findings, and no rating
  changes attributable to `boundary_refs`.
- Full/rebuild replay must dispatch exactly the same STRIDE components as the
  Milestone-1 baseline, and a boundary-only incremental replay must dispatch
  zero STRIDE analyzers.
- Boundary loading must add zero analyzer model turns: all non-empty Step-1
  context files are read in one parallel tool-call turn, and empty boundary
  selections produce no read.
- On both the neutral fixture and repository self-model, measured
  API-equivalent run-cost growth versus the frozen Milestone-1 baseline must be
  at most 5%. Treat an inconclusive or unattributable measurement as a failed
  gate, not as evidence of economy.
- If cost growth exceeds 5%, first reduce the 2/4/6 candidate caps and replay.
  If the gate still fails, ship normalization, stable IDs, and the deterministic
  catalogue only; keep analyzer contexts and `boundary_refs[]` disabled.
- If the links add little decision value, ship schema normalization and stable
  IDs only; do not force the report/SARIF work to justify sunk cost.

### Milestone 3 — render and export one coherent boundary view

Goal: make the modeled assumptions and their linked findings useful to readers
without restoring the removed standalone section.

1. Add a conditional computed `trust_boundary_catalog` entry to
   `data/sections-contract.yaml` after the existing `identified_actors` entry,
   modeled on that subsection. Its heading is `### Trust Boundaries`; both
   computed subsections are folded under §1 through an explicit parent/folding
   rule, not a fragile “immediately follows system_overview” positional special
   case. Do not modify the LLM/pregenerated `system-overview.md`, add a numbered
   §2.x, or revive §6.
2. Implement the deterministic catalogue renderer in
   `scripts/compose_threat_model.py` and render a compact table with:
   - anchored `tb-N` ID;
   - name and endpoints;
   - kind, resolution status, and provenance source;
   - assumption;
   - confidence; and
   - linked finding IDs, or an explicit em dash when none are linked.
   Cap the report table at 20 rows: referenced gaps first, then conflicted or
   unresolved rows that need review, selected primary boundaries, and other
   confirmed rows, all with `tb-N` tie-breaking. Point overflow to canonical
   YAML/query output. A
   finding links to a catalogue anchor only when that row is present; otherwise
   it renders the stable ID and name as plain text, so no anchor can dangle.
3. Extend the computed finding card in `scripts/compose_threat_model.py` with a
   `Trust boundary gap` row containing only evidence-backed references. Render
   each as `[tb-N](#tb-N) — Name: <mechanism rationale>`; the existing finding
   location remains the evidence anchor, so do not duplicate a long evidence
   list in the card. Do not render adjacency as a finding attribute or use the
   generic word “violation.”
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
8. Keep Figure 1's visual structure unchanged. In `figure1_svg.py`, optionally
   append aggregate resolved, confirmed external-entry IDs to the existing global
   `internet-exposed entry point` legend text when their target components are
   displayed: at most two IDs in numeric order plus `+N`. Keep per-component
   globe markers unchanged. Do not render names there and do not add nodes,
   arrows, subgraphs, attack paths, or layout rules. `to: external`, non-resolved,
   non-confirmed, and internal boundaries never qualify. If the suffix cannot be
   rendered safely, keep the existing text unchanged. The catalogue remains the canonical
   visible view. Add the ID projection only when the Mermaid fallback can expose
   the same bounded external-ID set without new topology or layout behavior;
   otherwise omit the new ID annotation from both renderers. The Milestone-1
   explicit-ingress correctness fix remains mandatory either way.

Primary tests:
`tests/test_contract_integrity.py`, `tests/test_compose_threat_model.py`,
`tests/test_query_threat_model.py`, `tests/test_export_sarif.py`,
`tests/test_sarif_validation.py`, `tests/test_qa_checks.py`, and the relevant
ToC cases in the composer tests. `tests/test_figure1_svg.py` covers explicit
ingress only, unknown/missing endpoint exclusion, `to: external` exclusion,
stable multi-ID ordering/overflow, injection-safe labels, and the invariant that
the annotation creates no new edge or layout element.

### Milestone 4 — documentation, replay, and rollout gate

Goal: prove the model is stable and useful before considering any boundary-based
risk or remediation-priority logic.

1. Update `docs/threat-modeler.md` with:
   - boundary semantics and evidence confidence;
   - the difference between adjacency and an evidence-backed boundary gap;
   - the fact that boundaries do not change severity; and
   - the best-effort economy contract, including deferred boundary-link refresh
     on source-clean incremental runs;
   - the legacy-sidecar/rerender behavior;
   - the presentation-completeness contract for §1, §2, Figure 1, finding cards,
     and exports; and
   - the additive `.appsec/trust-boundaries.yaml` format, provenance, and
     conflict behavior.
2. Add an erratum/status note to the 2026-07-21 analysis so readers do not
   implement its disproven deterministic path join or risk modulation.
3. Add a short user-visible `CHANGELOG.md` bullet after the behavior ships.
4. Replay a neutral golden fixture via `scripts/threat_fixture.py`, following
   `docs/internal/runbooks/threat-fixture.md`, then run a three-run incremental
   replay with reordered Phase-7 output and retirement of the highest boundary
   ID before a new boundary is introduced. Add a boundary-declaration-only
   incremental replay and assert that it recomposes deterministic outputs with
   zero STRIDE analyzer dispatches.
5. Record, for the fixture and the repository self-model:
   - invalid/dangling boundary references (target: zero);
   - ID churn across the second run (target: zero for unambiguous unchanged
     identities);
   - boundary references without verified evidence (target: zero);
   - risk or priority changes attributable only to boundary metadata (target:
     zero);
   - boundary-only findings (target: zero);
   - report row/anchor overflow behavior; and
   - Figure-1 external-ID annotations without new nodes/edges or internal/outbound
     boundary leakage;
   - full/rebuild and boundary-only incremental STRIDE dispatch counts;
   - analyzer model-turn counts before and after boundary loading;
   - dispatch-manifest, context-file, and resident-token growth; and
   - input, output, cache-write, cache-read, and API-equivalent cost deltas from
     `scripts/measure_run.py` / `scripts/verify_run_costs.py`.
6. Run the targeted suite first, then the repository's documented broader suite
   and separate any pre-existing failures from regressions.
7. Treat the economy gate as a release gate: unchanged full/rebuild STRIDE
   dispatch count, zero boundary-only incremental STRIDE dispatches, zero added
   analyzer model turns, and at most 5% API-equivalent cost growth on both
   rollout replays. If any condition fails, release the deterministic boundary
   catalogue without analyzer contexts or `boundary_refs[]`.

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
- a general Figure 1 boundary-label/layout redesign beyond the bounded external
  ingress-ID suffix.

A later proposal may add **boundary review priority** as a separate, explicitly
non-severity field, but only after measured link precision and evidence coverage
are available. It must never reduce a finding's risk merely because a control is
documented. A new weakness class such as `over_trusted_input` is justified only
when a deterministic, evidence-backed emitter finds a design condition that no
existing precise class represents.

## Suggested commit boundaries

1. `test/docs: lock trust-boundary semantics and legacy fixtures`
2. `feat: normalize trust boundaries and reconcile stable IDs`
3. `feat: merge declared repository trust boundaries`
4. `feat: carry evidence-constrained boundary refs on findings`
5. `feat: render and export trust-boundary traceability`
6. `docs: document trust-boundary semantics and rollout evidence`

Each commit must keep producer, schema, consumer, validation, and tests in sync;
do not land an output field in one layer with an `additionalProperties` escape
hatch in another.
