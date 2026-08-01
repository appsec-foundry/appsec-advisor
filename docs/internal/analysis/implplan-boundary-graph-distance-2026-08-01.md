# Implplan: mechanisms 1+2 — boundary adjacency backfill + graph-based breach distance

**Status:** ready to implement. Written for execution by a less capable model —
every insertion point, contract and expected number below has been verified
against the working tree on 2026-08-01; do NOT re-derive them, follow them.
**Parent:** `proposal-boundary-scoring-impact-2026-08-01.md` (mechanisms 1 and 2).
**Verified against:** juice-shop thorough run (`docs/security/threat-model.yaml`,
79 threats, 5 boundaries) + a simulation of the exact rule below (results in §7).

---

## 0. Verified facts — the ground you build on (do not re-verify, do not change)

| Fact | Anchor |
|---|---|
| `breach_distance` is computed ONLY in `_compute_breach_distance` (title overrides → `cwe_default_distance` (default 2) → unauth/auth route hints → amplifiers; clamped 1..3) | `triage_compute_ranking.py:186-235` |
| Semantics: 1 = internet/unauthenticated, 2 = authenticated user, 3 = privileged / out-of-band prerequisite (repo read, admin) | `data/breach-distance-patterns.yaml` header |
| The single fill site for `bd_by_id`/`bd_reason` (step 6a) | `triage_compute_ranking.py:661-674` |
| `write_outputs` overwrites `t["breach_distance"]` and `t["breach_distance_reason"]` in the yaml from `_finding_updates`, unconditionally | `triage_compute_ranking.py:1033-1041` |
| `breach_distance` feeds `_apply_critical_criteria` (`always_critical_cwes` → `required.breach_distance_max`), `_finding_score` (`+15*(4-bd)`), and the category reason tag `internet-reachable` (bd==1) | `triage_compute_ranking.py:382-430,529-534,976-977` |
| `validate_finding_boundary_refs` REQUIRES a 20–240 char `rationale` and finding-owned `evidence_locations`, caps at 2 refs, and strips everything else. **Derived links placed in `boundary_refs` would be deleted here.** | `prepare_trust_boundary_context.py:1273-1352` |
| The elevation gate reads only validated refs + `confidence=="confirmed"` + `from=="external"` + origin ∈ `{to} ∪ covers_components` | `triage_compute_ranking.py:591-631` |
| Elevation suppresses when `evidence_check ∈ {"refuted","ambiguous"}` | `triage_compute_ranking.py:459-486` |
| Schema: `trust_boundaries` items are `additionalProperties: false` → new row fields need a schema edit; `threats` items are `additionalProperties: true` → no schema edit for reasons | `schemas/threat-model.output.schema.yaml:372-424,543-547` |
| `compose_threat_model.py` already imports from `prepare_trust_boundary_context` (line 102) and derives the §1 verdict live in `_boundary_assumption_verdict` (three display strings + "Not examined") | `compose_threat_model.py` |
| Pipeline order: merge → build yaml → `compute_ranking`/`write_outputs` (mutates yaml) → compose. Compose can also run on a yaml that never saw triage (unit tests do this). | verified by reading callers |
| `query_threat_model.py` projects boundary keys at ~line 266 and renders the boundary detail at ~line 845-856 | `query_threat_model.py` |
| triage has a standalone CLI `main()` | `triage_compute_ranking.py:1244` |
| Counter tests assert `reconciliation_summary` keys | `tests/test_triage_compute_ranking.py:253-274`, `tests/test_new_schemas.py:60` |

## 1. Hard constraints — DO NOT

1. Do NOT touch `validate_finding_boundary_refs`, `_external_boundary_ids_for_finding`,
   `_compute_effective`, or the elevation/suppression logic. Mechanism 3 is a later,
   separate decision.
2. Do NOT write derived adjacency into `threats[].boundary_refs` — the validator
   deletes it (see §0) and the doctrine forbids it. Derived data lives on the
   boundary row (§4).
3. Do NOT change the meaning of distances 1/2/3, and never RAISE a distance from
   the graph. The graph may only LOWER a heuristic value, and never when the
   heuristic said 3 (a 3 encodes a non-network prerequisite — repo read, admin —
   which the graph cannot see; juice-shop T-047/T-050/T-051 secrets must stay 3).
4. Do NOT rename or reformat existing reason prefixes (`cwe_default:`,
   `unauth_hint:`, `override:`, …). The new prefix is exactly `boundary_path:`.
   ASCII only in reason strings — no `→` (reasons flow into TF-flag messages and
   tests match with `startswith`).
5. Do NOT reformat code you did not write. `scripts/prepare_trust_boundary_context.py`,
   `scripts/qa_checks.py` and `tests/test_prepare_trust_boundary_context.py` are NOT
   `ruff format`-clean; run `ruff format` only on files you fully own, and keep your
   own lines ≤120 chars so `ruff check` passes.
6. Compose keeps deriving the §1 verdict LIVE (it must work on a yaml that triage
   never touched). It must not start reading the persisted `assumption_verdict`.
7. Preserve the in-place augment guard `if "breach_distance" not in t:` at
   `triage_compute_ranking.py:672` and the unconditional overwrite in
   `write_outputs` exactly as they are.

## 2. Step 1 — shared state helper (single source of truth for "does the assumption survive")

**File:** `scripts/prepare_trust_boundary_context.py` (compose and triage both import it already).

```python
def boundary_assumption_state(row: dict, threats: list[dict]) -> tuple[str, list[str]]:
    """('refuted'|'unconfirmed'|'clean'|'not-examined', sorted finding ids).

    refuted      — >=1 threat carries a boundary_refs entry naming this row AND that
                   threat's evidence_check is not in ("refuted", "ambiguous").
                   Returns the refuting T-ids.
    unconfirmed  — no refuter, but >=1 threat's component sits in the protected set
                   {to} | set(covers_components) - {from}  (drop falsy values).
                   Returns those adjacent T-ids (they are NOT links).
    clean        — protected set non-empty, no threat in it.
    not-examined — protected set empty.
    """
```

Rules: pure function, no I/O; sort ids numerically by the `\d+` tail; a threat with
no `id` is skipped. The `evidence_check` gate mirrors the elevation suppression
(§0) so scoring and display can never disagree about "refuted".

**Tests** (append to `tests/test_prepare_trust_boundary_context.py`):
- `test_boundary_assumption_state_refuted_requires_clean_evidence_check` — linker
  with `evidence_check: "refuted"` does NOT refute; state falls through to
  unconfirmed/clean.
- `test_boundary_assumption_state_unconfirmed_counts_covered_components` — covers
  fold-ins count; `from` never counts.
- `test_boundary_assumption_state_not_examined_when_no_protected_side`.

## 3. Step 2 — compose parity refactor

**File:** `scripts/compose_threat_model.py`, function `_boundary_assumption_verdict`.

Replace its internal derivation with a call to
`prepare_trust_boundary_context.boundary_assumption_state(row, ctx.yaml_data.get("threats") or [])`
(extend the existing import at line 102). Keep the exact display strings that the
current tests assert:

| state | rendered |
|---|---|
| refuted | `**Refuted** by the linked findings.` |
| unconfirmed | `**Unconfirmed** — {n} finding(s) in the components it covers, none linked here.` |
| clean | `_No finding contradicts it._` |
| not-examined | `_Not examined._` |

The `linked_ids` parameter stays (the Linked-findings column is unchanged); the
*verdict* no longer uses it. Behavior delta (intentional, tiny): a boundary whose
only linker has `evidence_check: refuted` now renders Unconfirmed instead of
Refuted — matches scoring. juice-shop is unaffected (all 12 linkers are
`verified`).

**Tests:** existing `test_assumption_cell_states_a_verdict_derived_from_the_links`
and friends in `tests/test_compose_threat_model.py` must still pass unmodified.
Add `test_verdict_matches_shared_state_helper` — one fixture, assert the cell
verdict corresponds to the state the shared helper returns for each of the four
states.

## 4. Step 3 — the graph (mechanism 2)

**File:** `scripts/triage_compute_ranking.py`. New module-level function:

```python
def _boundary_graph_distance(yaml_data: dict) -> tuple[dict[str, int], dict[str, str], dict[str, str]]:
    """(component_id -> graph_bd 1..3, component_id -> reason, boundary_id -> state)."""
```

Construction rules (verified against the juice-shop data in §7 — implement exactly):

1. Participating rows: `resolution_status == "resolved"`, `to` truthy and `to != "external"`,
   `from` truthy. Egress rows (`to == "external"`) NEVER create edges.
2. Per-row state from `boundary_assumption_state(row, threats)` (Step 1).
   Crossing cost: `0` if state is `refuted` AND `row["confidence"] == "confirmed"`,
   else `1`.
3. Edge model (handles both consolidation flavors; min() makes spurious longer
   paths harmless): the row is traversable from any node in
   `{from} | covers - {to}`, and landing on every node in `{to} | covers - {from}`.
4. Fixpoint relaxation from `dist["external"] = 0`, tracking per node
   `(cost, [boundary ids on the best path])`; tie-break on the smaller id list
   joined as a string, for determinism.
5. `graph_bd[c] = min(3, 1 + cost)`; reason
   `boundary_path:external>tb-1[refuted]>express-backend` — the path's boundary ids
   each suffixed `[refuted]`/`[holds]`/`[unconfirmed]` (state; `holds` = confirmed
   and not refuted), then the component id. ASCII `>` separators only.

Integration — inside the existing 6a loop, directly after `d, r = _compute_breach_distance(...)`
(line 668), with `graph_bd, graph_reason, _states = _boundary_graph_distance(yaml_data)`
hoisted above the loop:

```python
component = t.get("component") or t.get("component_id")
g = graph_bd.get(component) if isinstance(component, str) else None
if g is not None and d < 3 and g < d and not _only_egress_refs(t, boundaries):
    d, r = g, graph_reason[component]
```

`_only_egress_refs(t, boundaries)`: True iff `t["boundary_refs"]` is non-empty and
every referenced row that exists has `to == "external"`. Rationale (verified case):
T-075 leaks a key on an *outbound* WSS handshake; its component is
internet-reachable but the attack needs a network-observer position — lowering it
to 1 on ingress reachability would be wrong. A finding with no refs at all is
still eligible.

Counter: count every finding where the graph changed `d`; emit as
`"findings_redistanced_via_boundary_graph"` in `reconciliation_summary` AND in
`_empty_ranking_block()` (line 953-960 — tests assert key presence).

**The mechanism-3 seam (do not remove):** the reason string carries
`tb-N[refuted]` tokens. A later verdict-driven elevation must skip any finding
whose `breach_distance_reason` already cites the same `tb-N[refuted]` — that
regex-able token is the dedupe key.

## 5. Step 4 — persist boundary annotations (mechanism 1)

1. In `compute_ranking`, build `_boundary_updates`: for EVERY boundary row (egress
   included), `{"id": ..., "assumption_verdict": state, "adjacent_finding_ids": [...]}`
   where `adjacent_finding_ids` are the state helper's ids ONLY in the
   `unconfirmed` case (cap 50); omit the key when empty. Return it beside
   `_finding_updates` (same private-underscore hand-off pattern, consumed and
   removed by `write_outputs`).
2. In `write_outputs`, apply to `yaml_data["trust_boundaries"]` rows by id, then
   write as today.
3. Schema (`schemas/threat-model.output.schema.yaml`, inside the
   `trust_boundaries.items.properties` block that is `additionalProperties: false`):

```yaml
        # Written back by triage_compute_ranking.write_outputs — derived, never authored.
        assumption_verdict: {type: string, enum: [refuted, unconfirmed, clean, not-examined]}
        adjacent_finding_ids:
          type: array
          uniqueItems: true
          maxItems: 50
          items: {type: string, pattern: "^T-\\d+$"}
```

4. `query_threat_model.py`: extend the boundary projection (~line 266) with the two
   fields (`.get(...)` — absent on pre-triage yamls) and the detail renderer
   (~line 852) with, after the Assumption line:
   `  Verdict: {assumption_verdict}` (only when present) and
   `  Adjacent findings (unlinked): T-042, T-043, ... ` (only when present).

This closes the tb-2 gap end-to-end: the yaml then records
`assumption_verdict: unconfirmed` + the eight T-ids on tb-2, queryable, without a
single change to `boundary_refs` or the elevation path.

## 6. Step 5 — new tests (exact list)

`tests/test_triage_compute_ranking.py` (follow the existing fixture style there):
- `test_graph_lowers_guessed_distance_behind_refuted_ingress` — tb-1 refuted by a
  linked finding; a second finding in a covered component drops 2→1 with reason
  `boundary_path:external>tb-1[refuted]>...`.
- `test_graph_never_touches_distance_three` — same fixture, CWE with default 3
  stays 3.
- `test_graph_skips_egress_only_findings` — finding whose only ref is a
  `to: external` row keeps its heuristic distance.
- `test_graph_multi_hop_costs_accumulate` — tb-1 holds (cost 1) + tb-3 holds
  (cost 1) → component behind both gets graph_bd 3 → no lowering of a 2.
- `test_graph_unreachable_component_keeps_heuristic` — component in no row.
- `test_no_trust_boundaries_is_a_no_op` — yaml without `trust_boundaries`:
  `bd_by_id`, reasons and counter (0) identical to today.
- `test_refuted_state_needs_clean_evidence_check` — linker with
  `evidence_check: refuted` → cost 1, no lowering.
- `test_write_outputs_persists_verdict_and_adjacent_ids` — run
  `write_outputs`, reload yaml, assert both fields (and absence of
  `_boundary_updates` in the flags file).
- `test_redistance_counter_present_in_empty_block`.

`tests/test_new_schemas.py`: extend the boundary-row fixture with both new fields →
still validates; a wrong enum value → fails.

`tests/test_query_threat_model.py`: extend the existing boundary-detail test
(line ~681) with the two new lines.

## 7. Step 6 — verification harness on the real run (expected numbers)

The simulation of exactly the §4 rules against
`/home/mrohr/juice-shop/docs/security/threat-model.yaml` produced — your
implementation must reproduce these before the task counts as done:

- States: `tb-1 refuted`, `tb-3 refuted`, `tb-2 unconfirmed` (tb-4/tb-5: refuted
  for persistence, excluded from the graph as egress).
- Graph distances: express-backend/auth/realtime-channel/web3-nft/sqlite-database
  = 1; ci-cd-pipeline = 2; angular-frontend and chat-service unreachable → fallback.
- **Exactly 20 findings drop 2→1** (all currently `cwe_default:*`):
  T-010 T-012 T-025 T-026 T-029 T-030 T-032 T-033 T-034 T-035 T-048 T-049 T-055
  T-056 T-061 T-063 T-064 T-066 T-076 T-077.
  **T-075 must NOT change** (egress-only refs exception).
- **Zero `effective_severity` changes** (verified: no `always_critical_cwes`
  context gate flips; all `breach_distance_max` gates are ≤2 and 2→1 keeps them
  satisfied).
- Counter `findings_redistanced_via_boundary_graph == 20`.

Procedure: copy the juice-shop yaml into a scratch dir, run
`compute_ranking(scratch_dir)` + `write_outputs`, diff the reloaded yaml against
the original on `(id, breach_distance, breach_distance_reason, effective_severity)`.
Then: full `python3 -m pytest -q` (baseline today: 11200 passed, 93 skipped) and
`python3 -m ruff check scripts/ tests/` clean.

## 8. Definition of done

- [ ] Shared state helper + 3 prep tests
- [ ] Compose delegates to it; all existing compose verdict tests pass unmodified
- [ ] Graph + composition rule + egress exception + counter in triage
- [ ] `_boundary_updates` persisted; schema extended; query surfaces both fields
- [ ] All §6 tests green; full suite green; ruff clean on your lines
- [ ] §7 numbers reproduced on the real yaml (20 / 0 / states as listed)
- [ ] No file outside: `prepare_trust_boundary_context.py`,
      `triage_compute_ranking.py`, `compose_threat_model.py`,
      `query_threat_model.py`, `schemas/threat-model.output.schema.yaml`,
      the four test files named above
