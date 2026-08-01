# Proposal: give trust boundaries real impact on findings and severity

**Status:** proposed — no decision taken; mechanisms 1–2 recommended as the starting pair.
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

### 1. Deterministic link backfill (foundation, no LLM)

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

### 2. `breach_distance` from the boundary graph instead of CWE defaults ⭐

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

### 3. Verdict-driven elevation — deliberately sequenced AFTER 1+2

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

### 4. New findings, deterministic: `boundary-gap` check

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
