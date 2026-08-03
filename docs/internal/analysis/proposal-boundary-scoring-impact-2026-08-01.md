# Proposal: give trust boundaries real impact on findings and severity

**Status:** mechanisms 1+2 SHIPPED (`daa5092f`, `a158d44f`). Mechanisms 3 and 4
DEFERRED after measurement — see "Decisions after measurement" at the end, which
records the numbers and the trigger that would reverse each call. Mechanism 5 untouched.
**Date:** 2026-08-01
**Basis:** juice-shop thorough run (79 threats, 5 boundaries) read against
`triage_compute_ranking.py`, `merge_threats.py`, `prepare_trust_boundary_context.py`,
`appsec-stride-analyzer.md`. Builds on the §1 "Assumption & verdict" work (derived
per-boundary verdicts `Refuted` / `Unconfirmed` / `No finding contradicts it` in
`compose._boundary_assumption_verdict`), which is the rendering seam every mechanism
below plugs into.

## Problem — why boundaries have no effect today

Boundaries currently annotate; they never discover and never score. Three structural
reasons, all observed on the juice-shop run:

1. **Linking is optional and sparse.** `boundary_refs` is authored only by the STRIDE
   analyst, voluntarily, max 2 per finding. Config-scan / source-scan findings cannot
   carry them at all. Result: 12 of 79 findings linked; `external → ci-cd-pipeline`
   (tb-2) showed zero links while eight CI/CD findings disproved its own assumption
   ("job-level secret scoping not confirmed").
2. **The only scoring hook aims below High.** `elevated:external_boundary`
   (`triage_compute_ranking.py`, +1 step, capped at High, requires the finding's own
   validated `boundary_refs` at confirmed ingress) never fired: 11 of the 12 linked
   findings were already High/Critical; the single Medium (T-075) sits on an *egress*
   crossing. The hook is dead precisely in repos where ingress-adjacent findings are
   already severe — i.e. where boundaries know the most.
3. **The real severity driver guesses.** All 16 High→Critical upgrades came from
   `breach_distance` with reasons like `cwe_default:CWE-306` and
   `unauth_hint:server.ts` — CWE heuristics and filename hints. The information those
   heuristics approximate (how far a finding sits from the internet) exists exactly
   and evidence-backed in the boundary graph, and is not consulted.

## Mechanisms, in ROI order

### 1. Deterministic link backfill (foundation, no LLM) — SHIPPED, adapted

> Implemented differently than sketched below: `validate_finding_boundary_refs`
> requires an analyst rationale plus finding-owned evidence and strips anything
> else, so derived adjacency can never live in `boundary_refs`. It persists on
> the boundary row instead — `assumption_verdict` + `adjacent_finding_ids`.
> The `link_basis` two-class idea below was therefore not built.

Every finding has `component`; every boundary has `covers_components` + `kind`.
Derive, in a `merge_threats` pass, which crossing every finding sits behind —
including build findings ↔ `kind: build` boundaries (fixes the tb-2 blank). The
critical design point is a two-class link:

```yaml
boundary_refs:
  - boundary_id: tb-2
    link_basis: derived-component   # deterministic; renders + feeds the verdict
  - boundary_id: tb-1
    link_basis: evidenced           # analyst, file:line — ONLY these may score
```

Doctrine intact (adjacency never elevates), display and verdicts become complete.
Zero scoring risk. Prerequisite for everything below.

### 2. `breach_distance` from the boundary graph instead of CWE defaults ⭐ — SHIPPED

> Built as sketched, plus three exclusions found during verification: a heuristic
> distance of 3 is never touched (it encodes a non-network prerequisite), the graph
> may only lower, and findings whose only refs are egress rows are skipped.
> Reason format shipped ASCII: `boundary_path:external>tb-1[refuted]>component`.

The graph already exists (`external →(tb-1)→ express-backend →(tb-3)→ sqlite-database`).
Each crossing gets a state from the assumption verdict:

| boundary state            | distance contribution |
|---------------------------|-----------------------|
| refuted                   | 0 — stands open       |
| holds, `confirmed`        | +1 — holds            |
| unconfirmed / `inferred`  | +1, flagged           |

`breach_distance(finding)` = openness of the shortest external→component path. The
reason becomes auditable instead of guessed:

```
before: breach_distance_reason: cwe_default:CWE-306
after:  breach_distance_reason: path:external→tb-1(refuted by F-022,F-065)→express-backend
```

This is where boundaries first carry the *primary* rating: the 16 Critical decisions
would rest on architecture evidence, and the loop is self-correcting — fix the tb-1
gaps, the verdict flips to holds, distance rises, the elevation falls away on the next
scan. Keep the CWE default as fallback for components with no boundary path.

### 3. Verdict-driven elevation — DEFERRED after measurement (see end of document)

Rule sketch: a *refuted* **ingress** boundary elevates findings in its
`covers_components` whose attack presupposes passing that control; evidence is the
refuting findings themselves; reason `elevated:boundary_refuted(tb-N)`.

Held back for three reasons (this section is the decision record):

- **Dependency.** The verdict is link-derived; without mechanism 1 it fires on
  whatever the analysts happened to link (tb-2 would never be refuted despite eight
  contradicting findings).
- **Double-counting with 2.** Both consume the same fact (tb-N is broken) on two
  paths: 2 lowers distance (which already feeds `_apply_critical_criteria`), 3
  elevates directly. Naive coexistence upgrades one finding twice for one fact.
  Required guard: if `breach_distance_reason` already cites `tb-N(refuted)`,
  `elevated:boundary_refuted(tb-N)` must not fire for the same finding — one tb-N
  elevates exactly once. Build this guard (and the reason string) into 2's
  implementation so 3 becomes a small delta.
- **Doctrine exception.** `triage_compute_ranking.py` states: *"Component adjacency
  alone is never enough: callers pass only IDs from fully validated boundary_refs."*
  Mechanism 3 is the first exception: adjacency + evidence-backed refutation by
  *other* findings suffices. Defensible, but it must be a named decision, not a side
  effect. Additionally the predicate "attack presupposes the control" is the only
  genuinely fuzzy piece: an endpoint that is unauthenticated anyway gets no worse
  when tb-1 falls. Conservative predicate: `controls_in_place` names the boundary's
  control, `evidence_check: verified`, finding is not itself a refuter.

Two forms, decided after a measurement run of 2:

- **Minimal:** no separate rule — when the distance-driven upgrade fires because of a
  refuted boundary, the reason reads `boundary_refuted(tb-N)` instead of a path
  string. Same effect, gained auditability, double-count impossible.
- **Full:** own rule with the guards above (ingress only, `confirmed` only, verdicts
  from *evidenced* links only, +1 capped, tb-N dedupe vs 2, refuters excluded) — if
  the measurement shows 2 leaves cases behind (Medium/High behind refuted ingress
  where distance alone trips no critical criterion).

### 4. New findings, deterministic: `boundary-gap` check — DEFERRED after measurement (see end of document)

F-065 ("all five web3 routes omit `isAuthorized()`") exists only because STRIDE
happened to look. The same result is mechanical — per `kind`, a check pattern
against the assumption:

- `network` ingress: route inventory (`route_inventory` pre-pass exists) ×
  enforcement-point wrapping → every uncovered mutating route is a candidate
- `build`: workflow jobs without a `permissions:` block (overlaps config-scan —
  dedupe, don't duplicate)
- `process`/DB: raw-query census beside the ORM

Emit with `source: boundary-check`, evidence = the coverage table. Boundaries then
*generate* findings for the first time — complete and reproducible instead of
STRIDE-mood-dependent. This is also the machine-checkable form of the `check` field
idea (assumption + where to look + what refutes it).

### 5. LLM falsification pass + chain candidates (most expensive tier)

Per component, one explicit attempt to refute each adjacent `confirmed` boundary's
assumption: return `holds | refuted | inconclusive` + `file:line`; a finding only on
`refuted` **with** evidence (else phantom-finding risk — the reason the current
"adjacency is never evidence" line exists). Mark `source: boundary-check` for
measurability.

Second channel feeds an **existing** scoring mechanism: chain elevation
(`chain_role: keystone`) already runs but gets its chains only from abuse-case
analysis. Boundaries yield chain candidates deterministically: *tb-1 refuted* + SQLi
behind tb-3 ⇒ candidate "external → database" for the abuse verifier to confirm or
kill. Verified chains then elevate via the existing evidence-gated path — no new
scoring code.

## Cross-cutting

- **Measurability from day one.** The status quo IS the pattern "mechanism exists,
  never fires, nobody notices." Per mechanism a counter next to the existing
  `findings_elevated_via_external_boundary`, so a run states what each channel
  contributed.
- **Dampening question (out of scope, flagged).** Consequent logic says an *intact*
  boundary should also cap (finding behind a confirmed-holding crossing with no
  ingress path). That breaks the deliberate invariant "effective never below raw".
  Recommendation: do not touch — mechanism 2 handles most of it via distance — but
  it is the user's call, recorded here as an open decision.
- **Expected juice-shop delta:** identical severity landscape (everything relevant
  already Critical/High), but the 16 Critical reasons switch from CWE guessing to
  named paths, tb-2 shows its eight findings, and the boundary-gap check enumerates
  the web3/Socket.io surface completely. The *visible* scoring difference arrives in
  the next repo with Medium findings behind leaky ingress.

## Sequencing

1. Mechanism 1 (backfill, `link_basis` two-class) — foundation, zero risk.
2. Mechanism 2 (graph distance) — include the tb-N dedupe guard and
   `boundary_refuted(tb-N)` reason vocabulary now.
3. Measurement run → decide mechanism 3 minimal vs full (decision point).
4. Mechanism 4 (deterministic boundary-gap findings).
5. Mechanism 5 (LLM falsification + chain candidates).

---

# Decisions after measurement (2026-08-01)

Mechanisms 1+2 shipped. Both remaining candidates were then measured against the
juice-shop run instead of estimated. Both are deferred, for different reasons and
with different reversal triggers.

## What 1+2 actually delivered

Measured as an A/B on the real model (identical run, graph switched off vs on;
the control pass reproduced the shipped report exactly, so the deltas are
attributable):

- 20 findings moved from a guessed `cwe_default:*` distance to an evidenced
  `boundary_path:external>tb-1[refuted]>…` — auditable and self-correcting.
- **36 of 50 findings changed rank**, and the visible top-5 changed:
  `T-008, T-016, T-001, T-005, T-007` → `T-008, T-012, T-016, T-030, T-001`.
  T-012 (IDOR on sequential integer PKs) rose 7→2 because tb-1 is refuted: with
  auth bypassable via SQLi and JWT forgery, an IDOR behind it *is* reachable
  unauthenticated. The old rating assumed an authentication the same report
  dismantles elsewhere.
- Zero effective-severity changes. The value is ordering and justification, not
  severity — and nobody has validated the new order yet. First thing to inspect
  on the next real run.
- tb-2 now names the eight CI/CD findings behind it instead of rendering a blank.

## Mechanism 3 — verdict-driven elevation: DEFERRED (evidence not met)

Candidate set on juice-shop is **three** findings: the Mediums that fell to
distance 1 behind refuted ingress (T-066 MD5 hashing, T-076 WebSocket DoS,
T-077 web3 rate limiting). T-075 is excluded by the egress rule.

**At least one of the three would be wrong.** T-066 is Medium because exploiting
it needs the hashes, i.e. database access — a prerequisite unrelated to how
reachable the component is. A refuted tb-1 does not make MD5 worse. That is
exactly the fuzzy predicate ("attack presupposes the control") flagged when the
mechanism was written, and the first real dataset produces a false positive in it.

Building a doctrine exception ("component adjacency alone is never enough",
`triage_compute_ranking.py`) on three candidates with ≥1 false positive is not
justified. The minimal form is effectively already shipped: the reason string
documents the causal crossing, and where distance should flip severity the
`always_critical_cwes` gates already do it per CWE with explicit context.

**Reversal trigger:** a real run shows a finding below High behind a refuted
ingress that a human calls mis-rated *because* the boundary is open, and that
has no prerequisite problem of the T-066 kind. The candidate set is a one-liner
on any future model: findings with `effective_severity <= Medium` and a
`boundary_path:…[refuted]` reason.

## Mechanism 4 — deterministic `boundary-gap` findings: DEFERRED (work already done elsewhere)

Stronger claim than for 3: two of the three legs are already covered, by other
parts of the pipeline.

| Leg | Measured yield on juice-shop |
|---|---|
| **Build** | `F-042` (config-scan) covers **14 of 16** workflow files, and the two it omits *do* carry a `permissions` block. Complete and precise already. Job-level granularity (29 jobs) would be *worse* — the file is the repair unit. |
| **Process / DB** | 2 raw `sequelize.query` sites, both already covered by F-005 / F-013. Nothing to find. |
| **Network ingress** | 19 unauthenticated mutating routes, 4 without any finding — and **0 of the 4 are real**: `POST /` (dataErasure) enforces auth *inside the handler*; `POST /api/Feedbacks` is anonymous by design with captcha, its forging path already covered by T-016; `POST /snippets/verdict` and `/snippets/fixes` are tutorial endpoints. |

The check itself is trivial (set difference over two lists already in the model).
All the work sits in the exclusion logic: detecting in-handler auth (9 route files
in juice-shop do it), separating "deliberately open" from "forgotten", and
deduplicating against config-scan. That is heuristic stacked on heuristic — the
kind of code mechanism 2 was built to replace. A detector reporting 19 routes so
that 4 get reviewed, none of which hold, spends trust instead of building it.

**Caveat, stated plainly:** juice-shop is a poor test bed for this question. It is
deliberately vulnerable, carries unusual challenge infrastructure (the snippet
endpoints exist in no real application), and its finding density is high enough
that nearly every route is already touched by a finding. A normal application —
60 routes, 12 findings — could show a much wider gap between "checked" and
"found". One repository is a sample of one.

**Reversal trigger:** run the same two counts on the next repository —
unauthenticated mutating routes with no finding reference, against total finding
count. A normal-density repo showing a real gap there flips this decision;
juice-shop alone does not.

## Sequencing from here

1. ~~Mechanism 1~~ — shipped.
2. ~~Mechanism 2~~ — shipped.
3. Watch the top-5 ordering on the next real run (the one unvalidated output of 2).
4. Re-measure 3 and 4 on the next repository using the triggers above.
5. Mechanism 5 unchanged: still the most expensive tier, still unevaluated.
