# Fixplan: leg-structured trust-boundary assumptions

**Status:** IMPLEMENTED (steps 0–5, uncommitted). Step 6 (pipeline re-run) not
done — every acceptance criterion below was instead verified against the
existing juice-shop model without re-running the pipeline, because leg
attribution falls back to the CWE map when a link carries no `leg`. Deviations
from the design as written are recorded in "Deviations" at the end.
**Date:** 2026-08-01
**Basis:** juice-shop run (51 threats, 7 boundaries) read against
`compose_threat_model.py`, `prepare_trust_boundary_context.py`,
`triage_compute_ranking.py`, `agents/appsec-trust-boundary-analyst.md`.
**Relation to `proposal-boundary-scoring-impact-2026-08-01.md`:** orthogonal and
downstream-compatible. That proposal fixes *how findings reach boundaries*
(mech 1 shipped: derived adjacency lives on the boundary row as
`adjacent_finding_ids`, never in `boundary_refs`; mech 3 elevation deferred).
This plan fixes *what the assumption says and how the verdict is granulated*.
It deliberately does NOT reintroduce the `link_basis` two-class ref that
proposal decided against.

## Problem — verified on the run

A trust boundary exists because the crosser cannot be trusted; the assumption
must state the conditions that resolve that distrust — validation,
authentication, authorization (user 2026-08-01). Today's assumptions state a
*mechanism occurrence* instead ("expressJwt is registered"), which is a
different claim category: the middleware can run while the boundary is wide
open. Verified consequences:

1. **The assumption suppresses linking.** tb-1's authn-only assumption gave
   authorization findings nothing to attach to: F-008 (IDOR, Critical), F-038,
   F-039 carry no `boundary_refs` although they test exactly the tb-1 crossing.
   Validation-class findings behind tb-1 (F-013, F-020/021, F-023, F-024) —
   same. 12 of 51 findings link at all.
2. **tb-2 is a false negative wearing an honesty label.** Verdict says
   "unconfirmed — none examined this crossing" while F-026 (CWE-494), F-027
   (CWE-829), F-041 (CWE-732) *are* the validation and authorization legs of
   exactly that crossing, named in the same cell as adjacent.
3. **tb-7 covers only the outbound half.** F-009's own rationale describes the
   return path ("the provider **returns** a tool call … the local executor
   accepts without validation") — the worst finding on the row is outside its
   own assumption.
4. **One verdict per row is too coarse.** "Refuted by the linked findings"
   on tb-1 hides that authn is refuted 3×, validation 1×, authorization never
   examined — and "never examined" is the most actionable statement in the
   table.
5. **Assumption text violates the analyst spec, unenforced.** tb-1 chains
   clauses with a semicolon and sanctions the gap ("unauthenticated routes are
   intentionally public") — both explicitly forbidden in
   `appsec-trust-boundary-analyst.md:135-163`; tb-3 restates its
   `enforcement_point`. The rules exist; no gate checks them.

Non-problems, checked and closed:
- F-004/F-005 both already attach to tb-3 (linking works there; only wording
  is off). F-005's duplicate ref exposed the render bug fixed in step 0.
- F-036/F-015 are not a missing "rate" leg — an authn mechanism that can be
  brute-forced establishes no identity; they belong to the authn leg.
- F-003 (CWE-400) is not a boundary question. Stays unlinked by design.
- F-029/F-030 (response disclosure) would need an egress row
  `backend-api → external`, not a fourth leg on tb-1. Out of scope here.

## Design

### D1. Legs per crossing type (the user's trio, typed by `from`/`to`)

`kind` does not discriminate (tb-1 `network` vs tb-7 `third-party`, both
`surface: network`); only `from`/`to == external` does.

| Crossing type | Legs |
|---|---|
| Ingress (`from == external`) | `validation` · `authentication` · `authorization` |
| Data-plane (both internal, `kind: process`) | `data-interpretation` (single leg — tb-4/5/6 already state exactly this) |
| Auth-verification interface (tb-3 case) | `authentication` (single leg, phrased as a property: "a token is only accepted if signed with a key only the server holds") |
| Egress (`to == external`) | `egress-content` (what may leave) · `egress-destination` (where to) · `response-trust` (the return channel is untrusted) |

Schema: `trust_boundaries[].assumption_legs: [{leg, condition}]`, each
condition obeying the existing one-sentence/testable/<180-chars contract.
`assumption` stays as the one-line rollup for consumers that don't know legs.

### D2. Verdict per leg

Extend `boundary_assumption_state` to return per-leg states from the same
inputs it reads today:
- **refuted** — a `boundary_refs` link attributed to this leg (see D3).
- **unconfirmed** — adjacency (mech-1 channel / component scan) contains a
  finding whose CWE maps to this leg, none linked.
- **clean / not-examined** — as today.
Row verdict = worst leg (refuted > unconfirmed > clean), so existing consumers
(scoring gate, §8 card) are unchanged. The §1 cell renders the legs:

```
Validierung      ✗ refuted     F-012
Authentifizierung ✗ refuted    F-017 F-040 F-042
Autorisierung    ◌ unexamined  (3 adjacent findings match, none linked — F-008 F-038 F-039)
```

### D3. Leg attribution — who says which leg a finding breaks

- **Links (`boundary_refs`)**: analyst-authored, optional `leg` field on the
  ref; validated against the boundary's declared legs. This is the ONLY input
  that can drive `refuted`, preserving the shipped mech-1 doctrine (a ref
  requires rationale + finding-owned evidence; adjacency never lives here).
- **Adjacency**: deterministic CWE→leg map, display/unconfirmed granularity
  only, zero scoring effect. Narrow families, mirroring the changelog
  `file|cwe-family` lesson: 639/862/863/285/284 → authorization;
  306/287/307/640/798(auth-context) → authentication;
  20/22/74/79/89/94/95/611/915/918/1321 → validation; 494/829 → validation
  (build); 732 → authorization (build); 209/548 → none (egress rows only).
  Unmapped CWE → leg-less adjacency, renders exactly as today.

### D4. Finding-side note (user point 2) — visibility without scoring

The §8 card's boundary line gains the leg and, when the crossing is confirmed
internet ingress, a reachability note independent of any severity change:

```
**Trust boundary gap:** [tb-1] 🌐 Public — external → backend-api ·
Bein: Authentifizierung: <rationale>
```

and for elevation (when `elevated:external_boundary(...)` actually fired,
read from `.triage-flags.json` like `emit_severity_rationale` already does):
append " — ⬆ raised this finding High → Critical". No new data source; the
flag record is the audit trail.

### D5. Assumption lint (deterministic, in `qa_checks` or the promotion step)

Reject / flag: (a) semicolon-joined clauses, (b) sanctioning clauses
(`intentionally public|by design|deliberately`), (c) Levenshtein/token overlap
with `enforcement_point` above threshold (restatement), (d) absence phrased as
assumption (`^no |none |nothing prevents`). The four failure modes are already
documented in the agent spec; this makes them enforced instead of advisory.

### D6. Explicit non-goals

- **No elevation change.** The High cap on `elevated:external_boundary`
  stays; mech 3 of the scoring proposal is deferred behind measurement, and
  `always_crit_promoted:CWE-306` already covers the unauthenticated-ingress
  Criticals on this run. D4 delivers the visibility that motivated the ask.
- No `link_basis` field on `boundary_refs` (decided against, mech 1).
- No new egress row for F-029/F-030 in this plan.
- No re-litigation of one-assumption rows tb-4/5/6 — they already conform.

## Steps

0. ✅ Renderer dedup: one link per boundary in the §8 card
   (`compose_threat_model.py` `seen_boundary_ids`, test
   `test_finding_boundary_gap_dedups_refs_to_the_same_boundary`).
   → verify: `pytest -k boundary_gap` green (done, 5 passed).
1. Schema + validation: `assumption_legs` on boundary rows, `leg` on refs,
   promotion validates leg names against the crossing type
   (`prepare_trust_boundary_context.py`).
   → verify: unit tests for each crossing type; unknown leg name rejected.
2. CWE→leg map + `boundary_assumption_state` per-leg extension; row rollup
   unchanged for legless rows (backward compatible).
   → verify: tb-2 fixture flips authorization/validation legs to
   "unconfirmed with matching adjacents"; rows without legs behave byte-identically.
3. §1 renderer: leg sub-rows in the Assumption & verdict cell; §8 card leg +
   reachability/elevation note (D4).
   → verify: golden-fragment tests; existing cell tests unchanged.
4. Analyst agent spec: per-crossing-type leg checklist replaces the
   free-form assumption instruction; keeps the four failure modes.
   → verify: spec review; next run on juice-shop produces legs for all 7 rows.
5. Assumption lint (D5) wired into the QA gate.
   → verify: tb-1's current text trips (a)+(b); tb-3's trips (c); clean texts pass.
6. Re-run on juice-shop; acceptance: F-008/F-038/F-039 visible at tb-1's
   authorization leg (at least as unconfirmed-adjacent), tb-2 legs show the
   three CI findings, tb-7 has a `response-trust` leg with F-009 attachable.

## Deviations from the design above (decided during implementation)

1. **Three crossing types, not four.** D1 listed a separate "auth-verification
   interface" type for the tb-3 case, but gave no deterministic discriminator —
   tb-3 and tb-4/5/6 are all `kind: process`, `transition: []`. Folded into
   `internal`, whose vocabulary is `data-interpretation` + `authentication` +
   `authorization`; the analyst declares the applicable subset. tb-3 declares
   `authentication` alone, tb-4/5/6 `data-interpretation` alone.
2. **Internal rows get no synthesized legs.** Ingress/egress legs follow from the
   direction, so synthesizing them asserts nothing new. "Every in-process
   interface has an authorization leg" is false, and a synthesized one would
   state a condition nobody holds. Internal rows therefore render exactly as
   before until an analyst declares legs.
3. **Row verdict is not a leg rollup.** D2 proposed worst-leg rollup;
   `boundary_assumption_state` is instead left untouched and legs are an
   additional view. A leg-less link refutes the row but names no leg, and a
   rollup would have let such a row read "clean". The row verdict is re-printed
   only when the leg view would lose it.
4. **Added: `adjacent_finding_ids` per leg, rendered as `+N adjacent`.** Not in
   the plan. The effects check showed a refuted leg swallowing every further
   finding bearing on the same condition — tb-1's validation leg reported one
   `eval` link while path traversal, XXE, SSRF and mass assignment sat behind the
   same crossing. One link is a lapse; eleven are a systemic failure, and the
   cell has to be able to say which.
5. **Lint, three changes.** (a) The semicolon threshold went 2 -> 1, overriding a
   prior deliberate "one semicolon is a clause, not a list" decision — juice-shop
   shipped a one-semicolon row that was plainly two conditions, and the old
   test's own counter-example ("Requests are authenticated; tokens are signed.")
   is the failure mode it claimed to exempt. (b) Added the sanctioning-clause
   rule. (c) FIXED a pre-existing false positive: the absence rule fired on
   "Nothing attacker-controlled reaches the provider unfiltered" — the analyst
   spec's own model answer, used verbatim by tb-7. A leading no/nothing now only
   counts as an absence when the sentence predicates no behaviour.
6. **Restatement detection NOT extended.** D5 proposed token-overlap against
   `enforcement_point` to catch tb-3. Measured: tb-3 overlaps its enforcement
   point on 2 of 4 content tokens — exactly the same ratio as tb-4, which is the
   exemplary row. No threshold separates them, so nothing was added; literal
   reuse remains the only mechanical check and the rest stays with the spec.
7. **Prompt token ceiling raised** for `appsec-stride-analyzer.md`
   (16_400 -> 16_550) for the `leg` schema line and its omit rule.

## Verified effects (juice-shop model, no re-run)

Six findings became visible at a crossing they belong to and were attached to
nothing before — including a Critical:

| Finding | Sev | CWE | now surfaces at |
| --- | --- | --- | --- |
| F-008 Insecure Direct Object Reference | Critical | 639 | tb-1 / authorization |
| F-038 Missing Authorization on Product Update | High | 862 | tb-1 / authorization |
| F-039 LLM Excessive Agency, no server-side check | High | 284 | tb-1 / authorization |
| F-026 Unauthenticated remote script execution | High | 494 | tb-2 / validation |
| F-027 Mutable GitHub Action tag | High | 829 | tb-2 / validation |
| F-041 Implicit write-all GITHUB_TOKEN | High | 732 | tb-2 / authorization |

- tb-1 authorization went from invisible to `unconfirmed` naming all three.
- tb-2 no longer reports "none examined this crossing" while three CI/CD
  findings examined it.
- tb-7 gained the `response-trust` leg and reports it refuted — F-009, whose own
  rationale describes the provider's RETURN path, was outside the old assumption.
- tb-1 validation now reads `refuted · +10 adjacent`, authentication
  `refuted · +3 adjacent`.
- 33 of 51 findings still attach to no leg. Spot-checked: correct. CWE-778
  logging, CWE-400 resource exhaustion, CWE-321/798 hard-coded keys, CWE-922
  insecure storage, CWE-598 credentials in query strings are not conditions of a
  crossing, and forcing them onto one would be the "widen until vacuous" failure
  this plan exists to avoid.

## Step A — §6 cross-reference (IMPLEMENTED)

Measured before building: coupling was rejected on evidence. Every §6 control
that maps to a leg is already graded `Missing`, `Weak` or `Partial` — there is
not one case where §6 says "fine" while a leg says "broken", so an arbitration
mechanism would fire 0x, exactly like `elevated:external_boundary`.

The real defect was that no join existed at all: `security_controls[].linked_threats`
is empty on 38 of 38 rows, and `rule_id` is present on 35 of 38 controls but on
1 of 51 findings, with an intersection of 0. §6 stated "Object-Level
Authorization (IDOR Prevention): Missing" while F-008, a Critical IDOR, hung off
no crossing — the same gap twice, no path between.

Built, deterministic, no new authored data:

- `_SECTION7_DOMAIN_LEG` maps the six unambiguous §6 domains to legs. 6.7 output
  encoding, 6.8 browser/CORS, 6.9 crypto, 6.11 operations and 6.12 real-time are
  NOT mapped — they are not conditions of a crossing.
- Each mapped domain heading gets a stable `<a id="ctrl-...">` anchor plus a
  **Dependent crossings:** line naming the crossings, their leg state and the
  finding ids — and nothing that grades the control. §6 keeps that authority.
- Each §1 leg links back as `[§6.4](#ctrl-authorization-controls)`. Number only:
  the full title would add ~40 characters to the narrowest column in the table.
- A mapped domain with no dependent crossing says so explicitly, so silence is
  never read as "not checked", and the anchor exists either way so the §1
  back-link cannot dangle.

Known limits: the mapping is DOMAIN-level. "Route-Level Authorization" and
"Object-Level Authorization" are both `authorization`, and attaching every
authz finding to both would be wrong — per-control precision needs step B.
`egress-content` and `response-trust` get no counterpart: the model has an
"AI and LLM Controls" domain but §6 has no heading for it.

## Step B — populate `linked_threats` (NOT BUILT, needs an agent run)

The secarch/architect renderer should write `security_controls[].linked_threats`;
the field is in the schema and nothing fills it. That is the only step requiring
an agent, and it is what upgrades step A from domain-level to control-level.
Verify by re-running the pipeline and checking the field is non-empty for
controls whose `assessment` prose already cites findings.

## Step C — contradiction gate (NOT BUILT, blocked on B)

Once B produces links, a `qa_checks` rule can fail when a control graded
`Adequate`/`Effective` shares findings with a leg in state `refuted`. Do NOT
build before B: with `linked_threats` empty the rule has no input and would be
the next 0x-firing hook.

## Still open

- **Architecture assessment beyond §6 does not consume legs.** `security_controls[].domain` and the
  leg vocabulary are the same taxonomy from two angles — Identity and
  Authentication / Authorization / Input Boundary Validation / Query Construction
  and Data Access map 1:1 onto authentication / authorization / validation /
  data-interpretation. Nothing links them today, so §7 can grade a control class
  while the crossing that depends on it disagrees, and neither notices. D3
  (cross-reference, no duplicated prose) is designed but unbuilt.
- **Assumption texts are unchanged** in the delivered model: the lint warns at
  promotion, so tb-1's semicolon + sanctioning clause and tb-3's restatement only
  clear on a re-authored run.
- Steps 1–5 are uncommitted.
