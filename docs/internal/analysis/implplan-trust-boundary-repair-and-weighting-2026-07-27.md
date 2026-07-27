# Implementation plan — trust-boundary contract repair, catalogue rendering, and evidence-backed exposure weighting

- Date: 2026-07-27
- Base: `8d66de0b` (`feature/trust-boundaries-first-class`) plus the uncommitted
  working-tree changes listed below
- Primary replay: `/home/mrohr/juice-shop/docs/security`
- Comparison run: `/tmp/security`
- Related:

  - `docs/analysis/plan-trust-boundaries-first-class-2026-07-22.md`
  - `docs/internal/analysis/fixplan-scenario-and-dotpath-2026-07-27.md`

## Status and decision

The current implementation is not ready to extend with exposure weighting.
The first-class trust-boundary machinery exists, but the latest juice-shop run
did not produce one semantically valid canonical endpoint pair. Two rows are
incorrectly marked `resolved`, five are marked `unresolved`, no component
received boundary context, and no finding received a `boundary_refs[]` entry.

This plan repairs the producer and the deterministic trust boundary first. It
then fixes the catalogue and exposure presentation. Severity weighting lands
last and uses only evidence-backed `boundary_refs[]`; component adjacency alone
is not sufficient.

The implementation must preserve the original first-class-boundary contract:

- canonical `from` and `to` values are component IDs or the literal `external`;
- unresolved rows stay visible for review;
- imported strings remain untrusted data;
- T/F and `tb-N` identity remains stable across incremental runs;
- adjacency may guide bounded analysis but is not finding evidence; and
- Critical remains governed only by the existing critical-criteria gate.

## Verified current-run baseline

The latest artifacts under `/home/mrohr/juice-shop/docs/security` establish the
following baseline:

| Signal | Verified result |
|---|---|
| STRIDE findings | 64; `boundary_refs[]` entries: 0 |
| Merged findings | 70; `boundary_refs[]` entries: 0 |
| Canonical YAML findings | 66; `boundary_refs[]` entries: 0 |
| Canonical endpoint pairs | 0 of 7 semantically valid |
| Declared boundary status | 2 `resolved`, 5 `unresolved` |
| Invalid rows falsely marked `resolved` | `tb-1`, `tb-3` |
| Per-component boundary contexts | 0 files |
| Dispatch selection | every component has no eligible or selected boundary |
| Figure 1 exposure legend | old run: present; current run: absent |
| Catalogue links | em dash on all 7 rows |
| Run issues | no trust-boundary diagnostic |
| Raw severity | Critical 15, High 41, Medium 10 |
| Persisted `effective_severity` | Critical 26, High 24, missing on 16 findings |

The reported 3m05s is not an isolated Phase-7 duration. Phases 5, 6, and 7 have
the same start and end timestamps because they ran as one combined pass. Remove
the previous `34s → 3m05s (×5.4)` attribution. Any performance claim requires
separate instrumentation or must be reported for the combined Phase-5–7 pass.

### Current invalid rows

All seven rows violate the canonical endpoint contract:

| ID | Current crossing | Declared status | Required treatment |
|---|---|---|---|
| `tb-1` | `Public Internet` → `Backend API Server (port 3000)` | resolved | normalize to `external` → `backend-api` |
| `tb-2` | `Angular SPA (browser)` → `Backend API Server` | unresolved | producer must re-author the local side as `frontend-spa`; do not infer a framework alias |
| `tb-3` | `Backend API Server` → `SQLite Database` | resolved | normalize to `backend-api` → `database` |
| `tb-4` | `Backend API Server (routes/chatbot.ts)` → `External OpenAI-compatible LLM endpoint` | unresolved | normalize conservatively; explicit `external` marker may resolve the remote side |
| `tb-5` | `Angular SPA (browser)` → `Google OAuth v2 Authorization Server` | unresolved | producer must re-author the remote side as `external`; do not guess from a provider name |
| `tb-6` | `GitHub Actions Runner` → `GitHub, npm Registry, Docker Hub` | unresolved | producer must express the local component and remote side canonically |
| `tb-7` | actor role → protected endpoints | unresolved | producer must identify the enforcing component crossing; actor labels are not endpoints |

The implementation must not count `tb-1` or `tb-3` as a valid resolved baseline.
The acceptance metric starts at 0/7 semantically valid rows.

## Root causes

There is no single root cause for every symptom.

1. **Producer contract failure.** Phase 7 authored prose endpoints and authored
   deterministic fields even though its contract requires component IDs or
   `external` and reserves IDs/status/source for normalization.
2. **Execution/invariant failure.** The accepted sidecar contains invalid
   endpoints marked `resolved`. Downstream selection trusts the status first,
   then silently fails the component-membership check, so these rows are neither
   selected nor reported as deferred.
3. **Insufficient diagnostics.** Normalization warnings go to stderr and the run
   issue aggregator has no trust-boundary diagnostic input.
4. **Independent rendering defects.** Parentheses are escaped as `\(`, prose is
   hard-wrapped at arbitrary positions, and the prose fixer backticks paths
   inside catalogue narrative cells.
5. **Independent ranking persistence defect.** Ranking computes all findings but
   writes derived fields back only through the display-capped top-50 view.

## Design decisions

### Canonical fields

Do not add `from_resolved` or `to_resolved`.

- A resolved normalized row stores canonical endpoints directly in `from` and
  `to`.
- An unresolved row may retain its bounded raw `from`/`to` text so the review
  catalogue remains useful.
- `resolution_status: resolved` is valid only when both fields are either a
  registered component ID or `external`.
- Human-readable crossing labels come from `name`; no second canonical endpoint
  vocabulary is introduced.
- Resolution method, raw values, ambiguity candidates, and warnings belong in a
  separate deterministic diagnostics artifact, not the public boundary record.

This keeps existing consumers, stable-ID reconciliation, YAML, query, SARIF,
Figure 1, and finding-reference validation on one endpoint field pair.

### Conservative endpoint resolution

Resolution must be deterministic and ambiguity-safe. For each endpoint:

1. Accept exact component IDs and the literal `external`.
2. For lookup only, normalize case/spacing and strip one trailing parenthetical.
3. Match a component only when the normalized endpoint uniquely equals a
   normalized component name. Preserve the actual component ID as the result.
4. Map only narrow network-origin aliases to `external`:
   `public internet`, `internet`, `the internet`, `outside network`, and
   `untrusted network`. An endpoint beginning with the explicit adjective
   `external` may also map to `external`.
5. Do not classify actors or roles such as `attacker`, `anonymous user`, or
   `authenticated user` as `external`.
6. Do not infer externality merely from a provider or product name.
7. Do not use a longest-path-prefix heuristic. Component paths are glob
   patterns, and one evidence file can match several components.
8. If evidence-assisted matching is retained as a later fallback, require one
   unique glob-matched component, restrict it to the explicitly local endpoint,
   never use one evidence location to resolve both sides, and leave every
   ambiguity unresolved.

The producer fix is primary. Alias resolution is a compatibility backstop, not a
license for continued prose authoring.

### Exposure classification

Compute presentation exposure from canonical endpoints and status:

| Condition | Display |
|---|---|
| resolved + confirmed + `from == external` + component target | `internet-facing` |
| resolved + confirmed + component source + `to == external` | `outbound` |
| resolved + confirmed + both endpoints are registered components | `internal` |
| unresolved or conflicted | `review required` |
| resolved but not confirmed | `inferred` |

Never label an unresolved row `internal` or `outbound`.

### Rating eligibility

Exposure may elevate a finding only when the finding itself carries a validated
boundary relation. The eligible set is:

```text
finding.boundary_refs[] contains ref where
  ref.boundary_id identifies a canonical boundary with
    from == "external"
    to == ref.origin_component_id
    resolution_status == "resolved"
    confidence == "confirmed"
and finding.evidence_check not in {"refuted", "ambiguous"}
```

Component adjacency without such a reference is contextual information only and
must not affect severity. Multiple eligible external references cause at most one
rank step, not one step per boundary.

## WP-0 — Lock the regression fixtures and baseline

Before behavior changes, add a sanitized fixture reproducing the seven current
juice-shop rows, the eight component records, and the empty selection audit.
The fixture must contain only the architecture metadata required for these
tests; do not make production logic juice-shop-specific.

Add assertions for:

- two invalid rows marked `resolved`;
- five rows marked `unresolved`;
- zero semantically valid endpoint pairs;
- zero eligible/selected boundaries before repair;
- invalid-but-resolved rows not disappearing from diagnostics;
- no `boundary_refs[]` in the captured STRIDE/merged/YAML counts; and
- Figure 1's missing external marker.

This is a regression input, not an expected final output.

## WP-1 — Repair the producer and normalized endpoint contract

### 1.1 Fix Phase-7 authorship

Update `agents/phases/phase-group-architecture.md` so the Phase-7 sidecar step:

- reads the finalized `.components.json` at the phase boundary;
- gives the analyst the exact ID/name mapping without asking it to derive IDs;
- reiterates that `from`/`to` accept only those exact IDs or `external`;
- states that actor, role, port, route, provider, and protocol detail belongs in
  `name`, `kind`, `assumption`, and `evidence`, not in endpoints;
- forbids authored `id`, `resolution_status`, and `sources`;
- treats normalization as mandatory and checks its exit/result before dispatch;
- logs normal phase/step events through the existing logging standard; and
- continues fail-open for the assessment while making invalid rows visible as
  run issues.

Add agent-definition tests that pin these instructions and the normalize command
ordering.

### 1.2 Canonicalize in-place and recompute status

Refactor `scripts/prepare_trust_boundary_context.py` so normalization:

- loads component IDs and names, not IDs alone;
- resolves endpoints with the conservative algorithm above;
- writes resolved canonical values back to `from`/`to`;
- ignores authored status and recomputes it on every normalize pass, including
  cached normalized sidecars;
- never accepts `resolved` unless both endpoints satisfy the dynamic contract;
- records `conflicted` only for a real detected/declaration conflict;
- preserves unresolved raw endpoint text within existing bounds;
- remains idempotent; and
- preserves stable `tb-N` identity.

For stable IDs, normalize prior endpoints in memory with the same resolver before
matching current rows. A unique prior row that canonicalizes to the same
endpoint/name/declaration identity keeps its ID. Ambiguous migrations allocate a
new ID and emit a diagnostic. Add two-run and prior-model tests for this behavior.

### 1.3 Make the schema express the resolved invariant

Update both:

- `schemas/fragments/trust-boundaries.schema.json`; and
- `schemas/threat-model.output.schema.yaml`.

For `resolution_status: resolved`, require `from` and `to` and constrain each to
a token shape compatible with component IDs or `external`. Do not apply that
pattern to unresolved rows, because they intentionally retain reviewable raw
text. Dynamic membership in the current component set remains a deterministic
validation step.

Keep `.appsec/trust-boundaries.yaml` bounded and untrusted. Its static schema
cannot enumerate run-specific component IDs; the normalizer must apply the same
dynamic resolution and diagnostics to repository declarations.

Update schema drift, fragment validation, build-YAML, declaration, and malformed
input tests atomically.

### 1.4 Add a structured diagnostic path

Add a small contracted artifact, for example
`.trust-boundary-diagnostics.json`, containing bounded entries such as:

```json
{
  "schema_version": 1,
  "issues": [
    {
      "code": "unresolved_endpoint",
      "boundary_id": "tb-5",
      "side": "to",
      "raw_value": "Google OAuth v2 Authorization Server",
      "reason": "no exact component or explicit external marker",
      "candidates": []
    }
  ]
}
```

Requirements:

- define and validate its schema;
- bound every imported string and candidate list;
- write it atomically;
- overwrite stale diagnostics on every normalize pass;
- emit issues for unresolved, conflicted, ambiguous, and invalid-resolved rows;
- teach `aggregate_run_issues.py` to create a dedicated run issue from it;
- do not invent a new log format; any emitted log event uses
  `scripts/event_log.py`;
- update permissions and permission tests if the new target is not already
  covered; and
- test that the latest juice-shop fixture would have produced a visible run
  issue.

### 1.5 Revalidate at every downstream security boundary

Context preparation must not trust a persisted `resolution_status` by itself.
Before selection:

- verify canonical endpoint membership again;
- treat an invalid `resolved` row as ineligible and `review required`;
- include its ID in an explicit invalid/deferred audit field rather than silently
  dropping it; and
- emit/retain the diagnostic.

Apply the same reusable invariant helper in finding-reference validation,
Figure-1 exposure selection, and canonical YAML validation.

### WP-1 acceptance

- The captured current sidecar canonicalizes at least `tb-1` and `tb-3` without
  changing their IDs.
- `tb-4` resolves only if its explicit `External ...` marker is accepted by the
  narrow rule; the test must state that decision.
- `tb-2`, `tb-5`, `tb-6`, and `tb-7` remain unresolved during compatibility
  replay rather than being guessed.
- A fresh full replay, using the repaired producer, authors canonical endpoints
  for all boundaries that the component/external model can honestly express.
- No invalid endpoint pair can remain marked `resolved`.
- At least one component receives a real
  `.dispatch-context/<cid>/trust-boundaries.json`.
- The dispatch manifest points to that context.
- An unresolved row creates a dedicated run issue.
- Re-normalization is idempotent and stable IDs survive the migration.

## WP-2 — Restore downstream boundary behavior and Figure 1

With canonical `from`/`to`, update or verify every consumer rather than assuming
that Figure 1 is the only affected site:

- focus classification and candidate ordering;
- per-component context emission;
- dispatch manifest paths;
- fresh and carried `boundary_refs[]` validation;
- Figure-1 exposed component selection;
- compose fallback tier-boundary lookup;
- catalogue/query/SARIF joins; and
- incremental stable-reference cleanup.

Figure 1 acceptance:

- a resolved, confirmed `external → backend-api` row marks `backend-api` as
  exposed;
- `internet-exposed entry point` is present in the generated SVG;
- unresolved, inferred, outbound, and internal rows do not create an ingress
  marker;
- a non-exposed data tier remains indirectly reached through the application;
- the primary SVG renderer and compose fallback obey the same endpoint/status/
  confidence rules; and
- a golden fixture pins the marker and legend behavior.

Boundary-reference acceptance requires a **fresh full STRIDE replay**. A
normalize-only replay can verify contexts but cannot retroactively author
evidence-backed finding relations.

## WP-3 — Repair catalogue rendering safely

The rendering defects are independent of endpoint normalization.

### 3.1 Stop creating KaTeX delimiters

In `_safe_boundary_text`, continue escaping:

- backslashes;
- brackets;
- pipes in table mode;
- raw HTML through `html.escape`; and
- any syntax needed to prevent imported text from creating links or anchors.

Do not escape ordinary parentheses as `\(` and `\)`. Add adversarial tests for:

- `[]()` link-shaped payloads;
- HTML tags;
- pipes;
- backslashes;
- anchor-shaped text;
- nested parentheses; and
- the exact CORS assumption from the current run.

The rendered catalogue must contain no accidental `\(`.

### 3.2 Define one fixed six-column layout

Keep the stable columns:

1. ID;
2. Boundary / crossing;
3. Kind / status;
4. Assumption / confidence;
5. Source;
6. Linked findings.

Add the catalogue header to both
`compose_threat_model._FIXED_LAYOUT_TABLE_HEADERS` and
`qa_checks._FIXED_LAYOUT_SPECS`. Define explicit widths summing to 100%, inline
overflow styles, and which cells preserve structural `<br/>` separators.

Test both Markdown and PDF/HTML conversion paths. Raw HTML conversion must
preserve links and emphasis because Markdown is not parsed inside an HTML table.

### 3.3 Make prose formatting column-aware

Both `apply_fixes` and `apply_code_formatting` currently pass table rows through
the same code-token wrapper. Introduce a shared table-state helper that recognizes
the exact trust-boundary catalogue header and skips code-token wrapping only in:

- `Boundary / crossing`; and
- `Assumption / confidence`.

Do not disable escaping, link validation, or formatting in other tables or
columns. Add tests for both entry points, idempotence, rerender/autofix order, and
the exact `routes/chatbot.ts` and `app.options("*", cors())` examples.

### 3.4 Explain source without dynamic layout

Keep the Source column even when all rows have one value. Add a one-line legend:

- `detected`: derived from inspected repository evidence;
- `repo-declared`: supplied by `.appsec/trust-boundaries.yaml`; and
- `legacy`: migrated from an earlier boundary format.

Do not hide the column dynamically and do not translate the canonical enum
values.

### WP-3 acceptance

- No KaTeX delimiter is introduced by boundary prose.
- No arbitrary 44-character `<br/>` remains in narrative cells.
- Catalogue paths and expressions remain readable prose rather than partial
  monospace fragments.
- Fixed-layout HTML is structurally valid and PDF-safe.
- Imported strings cannot create HTML, links, anchors, or table columns.

## WP-4 — Show exposure without changing catalogue priority

Render the exposure label inside the existing `Kind / status` column instead of
adding a seventh column. Use the classification table in this plan.

Preserve the contractual catalogue ordering:

1. rows with linked findings;
2. conflicted or unresolved rows requiring review;
3. selected primary rows;
4. other confirmed rows; and
5. numeric `tb-N` tie-break.

Use internet-facing exposure only as a tie-breaker inside the same priority
bucket. Do not globally move an unlinked external row above a linked gap or an
unresolved review item.

Acceptance:

- `tb-1` displays `internet-facing` after canonicalization;
- outbound, internal, inferred, and review-required fixtures use distinct labels;
- sorting retains linked/review priority;
- no exposure label changes finding severity in this WP; and
- query/YAML keep canonical machine values rather than presentation labels.

## WP-5 — Repair deterministic severity persistence and auditability

This is a prerequisite for exposure weighting even though it is not caused by
trust boundaries.

### 5.1 Persist derived fields for every finding

Refactor `triage_compute_ranking.py` so the display cap on
`views.top_findings.findings_ranked` does not cap YAML persistence.

- Compute an internal update record for every finding.
- Persist `effective_severity`, breach distance, chain role, chain memberships,
  and reconciliation references for every finding.
- Keep the top-50 cap only on the ranking view.
- Recompute fields instead of using `setdefault`, so a removed chain or boundary
  can reverse a prior deterministic elevation while never lowering below raw
  risk.
- Remove stale derived fields/reasons when their cause disappears.

Add a fixture with more than 50 findings and assert that all findings receive
derived fields while only the display view remains capped.

### 5.2 Use the existing triage flag contract

Make `severity_reconciliation` a valid schema enum in
`schemas/triage-flags.schema.yaml`, matching the agent contract. Persist one
auditable flag whenever effective severity differs from raw, including the exact
eligible `tb-N` IDs for external-boundary elevation.

Do not rely on the local `_compute_effective(...).reasons` list unless it is
explicitly persisted through this contract.

Update `emit_severity_rationale.py` to render an external-boundary rationale only
from the validated reconciliation data. It must not claim that exposure caused
an elevation when a CWE cap or another rule prevented the effective value from
changing.

### WP-5 acceptance

- All 66 current juice-shop findings would have an explicit
  `effective_severity`.
- Every elevation has a matching `severity_reconciliation` flag.
- Removing an elevation cause clears stale flags and rationale.
- Existing Critical chain rationales remain unchanged.
- Schema, deterministic script, and LLM fallback instructions agree.

## WP-6 — Add evidence-backed external-boundary weighting

This deliberately revises the original plan's non-goal that boundary metadata
must not affect rating. The deviation is narrow: only a validated finding-level
relation to a confirmed external ingress may elevate effective severity.

### Ordered rule

Extend the deterministic pipeline in this order:

1. raw risk;
2. chain elevation and evidence-refutation guard;
3. one-step external-boundary elevation when the rating-eligibility predicate in
   this plan holds;
4. per-CWE severity cap;
5. critical-criteria gate; and
6. no-downgrade-below-raw invariant.

Rule:

```text
if at least one eligible external-ingress boundary reference exists:
    target = min(current_effective + 1 rank, High)
    record eligible boundary IDs in deterministic numeric order
then apply the existing per-CWE cap and Critical criteria
```

This ordering ensures exposure cannot bypass a CWE cap and cannot create
Critical. If the current value is already High or Critical, exposure does not
change it and must not produce a false elevation rationale.

### Required code and contract changes

- Build a canonical boundary index from `threat-model.yaml`.
- Validate referenced boundary existence, status, confidence, orientation, and
  `origin_component_id` before ranking.
- Reuse the same boundary-reference invariant helper used at merge/carry time.
- Pass the eligible boundary IDs into `_compute_effective` or a dedicated helper;
  do not match only on a finding's component.
- Persist a `severity_reconciliation` flag only when the exposure step actually
  increases effective severity.
- Include exposure elevation in ranking reconciliation summary counts.
- Update `agents/appsec-triage-validator.md` so deterministic and LLM fallback
  semantics remain identical.
- Update `docs/analysis/plan-trust-boundaries-first-class-2026-07-22.md` to record
  this measured, evidence-gated exception to the original non-goal.
- Update user-facing rating documentation and add a concise `CHANGELOG.md` bullet.
- Bump `analysis_version` because severity logic changes. Preserve older versions
  only as explicitly readable compatibility inputs; a full run must be
  recommended to populate evidence-backed boundary references.

Do not patch `build_changelog` merely to suppress a hypothetical whole-register
severity diff. Current finding identity does not use severity. Use
`analysis_version` as the semantic migration signal and add tests for the chosen
compatibility behavior.

### WP-6 acceptance

- Medium finding with a valid external-ingress `boundary_refs[]` entry becomes
  High when no lower CWE cap applies.
- The same component with no boundary reference is unchanged.
- A reference to an internal, outbound, inferred, unresolved, or conflicted
  boundary is unchanged.
- A wrong-origin, non-adjacent, dangling, or evidence-free reference is rejected
  before ranking.
- `refuted` and `ambiguous` findings are not exposure-elevated.
- Multiple eligible external references cause only one rank step.
- A CWE capped at Medium remains Medium.
- High stays High and never becomes Critical from exposure.
- Architecture-coverage threats and hypotheses remain non-Critical.
- Removing the boundary or reference on an incremental/rerender path removes the
  prior exposure elevation and its audit flag.
- Full juice-shop replay reports raw and effective before/after distributions,
  eligible boundary IDs, elevated finding IDs, and rejected-reference reasons.

## Integration and regression testing

### Targeted tests

At minimum, update or add coverage in:

- `tests/test_prepare_trust_boundary_context.py`;
- schema and schema-drift tests;
- agent-definition and dispatch prompt ordering tests;
- `tests/test_dispatch_manifest.py`;
- `tests/test_validate_dispatch_manifest.py`;
- `tests/test_figure1_svg.py`;
- `tests/test_compose_threat_model.py`;
- `tests/test_qa_checks.py`;
- `tests/test_apply_prose_fixes.py`;
- `tests/test_apply_prose_fixes_coverage.py`;
- `tests/test_query_threat_model.py`;
- `tests/test_triage_compute_ranking.py`;
- triage flag schema/validator tests;
- `tests/test_aggregate_run_issues.py`;
- build-YAML and incremental two-run tests; and
- permission tests when the diagnostics artifact or command surface changes.

### Incremental cases

Test:

- prose endpoints from a prior model canonicalize without T/F or `tb-N`
  renumbering;
- declaration changes invalidate or recompute affected contexts;
- carried boundary references survive only while boundary, adjacency, confidence,
  and evidence remain valid;
- invalid carried references are removed without dropping the finding;
- removed external exposure reverses only its deterministic elevation;
- normal full/incremental cleanup preserves canonical/audit artifacts according
  to the cleanup contract; and
- `--rebuild` remains the deliberate stable-ID reset exception.

### Golden replay

After targeted tests:

1. run the relevant `CONTRIBUTING.md` targeted set;
2. run `make lint`;
3. run `make test`;
4. run `make check` because this change crosses prompts, schemas, runtime,
   rendering, QA, and severity contracts;
5. replay the neutral trust-boundary fixture;
6. replay juice-shop from a clean full-run output directory; and
7. compare the current and repaired artifacts without editing fixture
   expectations to hide defects.

The replay report must include:

- semantically valid/resolved/unresolved/conflicted boundary counts;
- selected/deferred/invalid boundary IDs per component;
- context-file and manifest-path counts;
- boundary-reference count and rejection diagnostics;
- Figure-1 exposure markers;
- catalogue render checks;
- raw/effective severity distributions and missing-field count;
- exposure-elevated finding IDs with their `tb-N` evidence;
- total and combined Phase-5–7 durations; and
- overall token/cost comparison against the prior rollout budget.

## Sequence and commit boundaries

```text
WP-0 fixtures
  └─> WP-1 producer + normalization + diagnostics
        ├─> WP-2 contexts, refs, Figure 1
        └─> WP-3 catalogue rendering
              └─> WP-4 exposure presentation

WP-5 complete severity persistence/audit
  └─> WP-6 evidence-backed exposure weighting

WP-1 + WP-2 + WP-5 + WP-6
  └─> full replay and analysis-version migration verification
```

Suggested commits:

1. `test: capture broken trust-boundary endpoint regression`
2. `fix: enforce canonical trust-boundary endpoints`
3. `fix: surface trust-boundary normalization diagnostics`
4. `fix: restore boundary contexts and figure exposure`
5. `fix: render trust-boundary catalogue safely`
6. `feat: show trust-boundary exposure classification`
7. `fix: persist effective severity for every finding`
8. `feat: weight evidence-backed external boundary findings`
9. `docs: record trust-boundary rating migration`

## Interaction with current uncommitted changes

The current working tree already changes:

- `scripts/apply_prose_fixes.py` and its tests to recognize dot-directory paths
  and format Markdown prose inside styled blockquotes;
- `scripts/arch_coverage_to_threats.py` and its tests to emit the required
  deterministic `scenario`; and
- `skills/create-threat-model/SKILL-impl.md`,
  `scripts/persist_run_baseline.py`, and
  `tests/test_persist_run_baseline.py` to move run-duration persistence from an
  inline shell block into a tested deterministic writer.

Those changes are unrelated fixes and must be preserved. They do not implement
any trust-boundary WP.

The broader path recognition increases the need for WP-3's exact, column-aware
catalogue exclusion. Test WP-3 against the working-tree version of both
`apply_fixes` and `apply_code_formatting`; do not revert or weaken the dot-path
behavior.

The new baseline writer shares `.appsec-cache/baseline.json` with ID counters,
component durations, and the trust-boundary declaration fingerprint. WP-1 and
WP-6 tests must prove that normalization, migration, and run-duration
persistence preserve one another's keys. Do not use the timing fields as a
severity-migration signal; `analysis_version` remains the owner of that
decision.

## Out of scope

- Generic `trust_boundary_violation` findings.
- Severity changes based on component adjacency alone.
- Full data-flow or taint/provenance analysis.
- Guessing provider externality from arbitrary names.
- Treating actors or roles as component endpoints.
- A new public `from_resolved`/`to_resolved` vocabulary.
- Figure-1 layout redesign beyond restoring the bounded external-ingress signal.
- Reintroducing legacy `enforcement` and `weaknesses[]` fields; evaluate those in
  a separate contract proposal.
- The `ARCH-TLS-001` precision issue. It remains a separate
  architecture-coverage-rule problem.
