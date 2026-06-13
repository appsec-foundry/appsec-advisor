# Implementation Plan — B1 + B2: preserve prior threats on depth-downgrade incremental re-scan

**Status:** ✅ IMPLEMENTED 2026-06-13 (uncommitted). Decisions locked: **A** = strictly-shallower
carry; **B** = `resolved_prior_findings` via `.stride`→merge→`.threats-merged.json`; **C** = one
aggregate disclosure line in the quick-mode banner (no per-threat §8 markers). Full suite 3980 passed.

**Deviation found during verification (and fixed):** `merge_threats._assign_t_ids` restarts global
T-numbering at T-001 every run, so a carried threat re-injected with its *prior* id would collide
with a freshly-assigned one — the side-condition #2 "keep prior id verbatim" was WRONG. Carried
threats now get a fresh, collision-free id continuing after the current max. Also: the reconciler
runs **before** `build_mitigations` (not just before the threat_ids loop) so carried threats get a
§10 Mitigation Register entry.

Files: `schemas/{stride,threats-merged,threat-model.output}.schema.yaml`, `scripts/merge_threats.py`,
`scripts/build_threat_model_yaml.py`, `scripts/compose_threat_model.py`,
`agents/phases/phase-group-threats.md`, `agents/appsec-stride-analyzer.md`, tests in
`tests/test_{build_threat_model_yaml,merge_threats,compose_threat_model}.py`.

---

**Original plan (for reference) — NOTHING implemented when written.**
**Date:** 2026-06-13
**Parent:** `proposal-depth-downgrade-incremental-preservation.md`
**Bug:** A DIRTY component re-scanned at a shallower depth (`thorough/standard → quick --incremental`)
overwrites `.stride-<id>.json`; prior threats the shallow scan doesn't re-emit vanish.
The analyzer's disposition is depth-blind (`appsec-stride-analyzer.md:124`) and the
changelog builder *treats incremental as full* (`build_threat_model_yaml.py:947-948`),
so there is no deterministic reconciliation — `resolved.threats` only ever fills on
component **removal** (`phase-group-threats.md:62`).

---

## Design: two composing layers

- **B1 (LLM, advisory):** make the analyzer's prior-finding disposition **depth-aware** —
  when current depth < prior depth, a prior `status: open` finding that it cannot
  **affirmatively** show to be fixed is **carried** (emitted) instead of dropped.
  Also emit an explicit `resolved_prior_findings[]` list when it *does* confirm a fix.
- **B2 (deterministic, authoritative):** a Python reconciler in
  `build_threat_model_yaml.py` that, for **re-analyzed** components, diffs prior
  threats against the freshly-merged threats and **re-injects** any prior threat that
  (a) did not survive by fingerprint, (b) is not in the analyzer's affirmed-fix list,
  and (c) was found at a deeper depth than the current run. Records honest
  `resolved` / `changed` / `carried_forward_components` changelog buckets.

**Composition — no double-count.** B2's "lost" test is by fingerprint against the
**new** threat list. If B1 re-emits the threat, its fingerprint is present → B2 skips it.
If B1 fails to re-emit, fingerprint absent → B2 carries it. B2 is the safety net that
makes correctness independent of LLM compliance (per AGENTS.md: prefer deterministic
Python; make the LLM do less). **B2 alone fixes the bug**; B1 improves precision
(lets genuine fixes resolve instead of being conservatively carried).

### Signals already on disk (no new producers needed)
| Need | Source | Verified at |
|---|---|---|
| prior threats (id, component, cwe, title, full verdict) | `prior_yaml = _load_yaml(od/"threat-model.yaml")` | `build_threat_model_yaml.py:1029` |
| new merged threats (id, component, cwe, title) | `build_threats(merged)` output | `:365-396` |
| which components were re-analyzed | `baseline.json.stride_files[cid].sha256` vs current `.stride-<cid>.json` sha | `baseline_state.py:199,334` |
| current depth | `skill_cfg["assessment_depth"]` | used `:953` |
| prior depth | `baseline.json.last_run_depth` | consumed by §7 override `compose:1319` |

---

## DIFF 1 — schema: new `evidence_check` enum value (3 files, bidirectional)

Add `carried-unverified-shallower-depth` to the enum in all three schemas that
declare it, keeping them in lockstep (drift-guarded).

**`schemas/threats-merged.schema.yaml:161`**
```diff
-          enum: [verified, verified-prior, refuted, ambiguous, unchecked, null]
+          enum: [verified, verified-prior, refuted, ambiguous, unchecked,
+                 carried-unverified-shallower-depth, null]
```
Extend the comment block (`:151-159`) with one line:
```
          # `carried-unverified-shallower-depth` — set by the deterministic
          # incremental reconciler (or the analyzer at reduced depth) on a prior
          # threat carried forward because the current scan was too shallow to
          # re-confirm it. Triage must NOT elevate it; QA must NOT demand fresh
          # evidence for it.
```

**`schemas/threat-model.output.schema.yaml:610`** — same enum line edit (this is the
*final* report schema; a carried threat lands here).

**`schemas/stride.schema.yaml:154`** — same enum line edit (so a B1-emitting analyzer
is schema-valid).

> Also check (Editing Guidance → "Schema, fragment, or report structure"):
> `docs/internal/contracts/schema-invariants.md` — add the new enum value to any
> documented evidence_check invariant. Triage consumers
> (`triage_compute_ranking.py`, `severity-caps.yaml` logic): confirm the new value
> is treated like `unchecked`/`ambiguous` (never elevated). QA
> (`qa_checks.py` evidence-integrity check): treat it as a valid non-fresh state,
> not a missing-evidence failure.

---

## DIFF 2 — `agents/phases/phase-group-threats.md`: pass prior depth to re-dispatched analyzers

Add `PRIOR_ASSESSMENT_DEPTH` to the Group B scalar list (component-specific but
constant per run), sourced once from the baseline. Re-dispatched (dirty) components
need it; carried-forward components don't run an analyzer so it's harmless there.

**At `:206` (Group B list), append:**
```diff
- ..., `FOCUS_PATHS` (M15/M20 — see below), `EXCLUDE_PATHS` (M16 — ...)
+ ..., `FOCUS_PATHS` (M15/M20 — see below), `EXCLUDE_PATHS` (M16 — ...),
+ `PRIOR_ASSESSMENT_DEPTH` (incremental only — the `assessment_depth` of the run
+ that produced the baseline, from `.appsec-cache/baseline.json.last_run_depth`;
+ pass `none` on a full/first run. The analyzer compares it to `ASSESSMENT_DEPTH`
+ to decide the prior-finding carry-vs-drop disposition — see appsec-stride-analyzer.md
+ "Step 1 — prior-finding disposition".)
```

**In the dirty-set / dispatch-prep Bash (near `:66-82`), resolve it once:**
```bash
PRIOR_ASSESSMENT_DEPTH=$(python3 -c "import json,sys; \
  print(json.load(open('$OUTPUT_DIR/.appsec-cache/baseline.json')).get('last_run_depth') or 'none')" \
  2>/dev/null || echo none)
```

> `ASSESSMENT_DEPTH` is already an analyzer input (`appsec-stride-analyzer.md:93`).
> No new permission: reading `baseline.json` is already in-scope for Phase 9.

---

## DIFF 3 — `agents/appsec-stride-analyzer.md`: depth-aware disposition + affirmed-fix emission

**3a. Inputs (`:89-93`, "Run config") — document the new param:**
```diff
 - `ASSESSMENT_DEPTH` — `quick` / `standard` / `thorough`. Drives turn ceilings...
+- `PRIOR_ASSESSMENT_DEPTH` — `quick` / `standard` / `thorough` / `none`. The depth
+  of the baseline run (incremental only). When it is DEEPER than `ASSESSMENT_DEPTH`,
+  apply the conservative carry rule in Step 1 to prior findings you cannot confirm
+  fixed. `none` on full/first runs → no carry rule (normal disposition).
```

**3b. Rewrite the disposition at `:124`.** Current text:
> When the re-read confirms the issue still exists, set `evidence_check: "verified-prior"`.
> When the re-read shows the code changed and the issue is gone, do **not** emit the
> threat (the orchestrator's resolved-threats list captures it instead). ...

Replace the middle sentence with a three-way disposition:
```diff
-**When the re-read confirms the issue still exists**, set `evidence_check: "verified-prior"` on the emitted threat. When the re-read shows the code changed and the issue is gone, do **not** emit the threat (the orchestrator's resolved-threats list captures it instead). Threats not derived from a prior-finding re-read default to `evidence_check: "unchecked"`; the Phase 10b `appsec-evidence-verifier` updates them.
+**Prior-finding disposition (three-way):**
+1. **Still present** — the cited code still exhibits the issue → emit the threat,
+   `evidence_check: "verified-prior"`.
+2. **Affirmatively fixed** — you can point to the specific change that removes it
+   (control added, vulnerable path deleted, input now validated/encoded) → do **not**
+   emit it, AND record it in the output's `resolved_prior_findings[]` (see Output)
+   with the prior `id` and a one-line `reason`. The deterministic reconciler uses
+   this to mark it resolved instead of carrying it.
+3. **Could not confirm either way** — you did not re-read deeply enough to assert
+   present-or-fixed (typical at reduced depth, e.g. `skip_verification_greps`):
+   * if `PRIOR_ASSESSMENT_DEPTH` is DEEPER than `ASSESSMENT_DEPTH` → **carry it**:
+     emit the prior threat unchanged with `evidence_check: "carried-unverified-shallower-depth"`.
+     Absence of confirmation at reduced depth is **not** evidence of a fix.
+   * otherwise (equal/deeper current depth) → existing behaviour: do not emit;
+     the reconciler records it as resolved-not-reproduced.
+Threats not derived from a prior-finding re-read default to `evidence_check: "unchecked"`; the Phase 10b `appsec-evidence-verifier` updates them.
```

**3c. Output schema for the analyzer — add the optional `resolved_prior_findings[]`.**
In the analyzer's output-JSON section (the same block that lists `threats[]`), add a
sibling array. Mirror in `schemas/stride.schema.yaml` (top-level optional array):
```yaml
    resolved_prior_findings:
      # Prior findings this re-scan affirmatively confirmed FIXED (disposition #2).
      # Lets the deterministic reconciler resolve precisely instead of carrying.
      type: array
      items:
        type: object
        required: [prior_id, reason]
        additionalProperties: false
        properties:
          prior_id:   { type: string }       # the id from PRIOR_FINDINGS_INDEX_PATH
          cwe:        { type: [string, "null"] }
          title:      { type: [string, "null"] }
          reason:     { type: string, maxLength: 200 }
```

> B1 is advisory: if the analyzer omits `resolved_prior_findings`, B2 conservatively
> carries (over-reports) rather than loses. Quick-profile note (`:240-253`) gains a
> row stating the carry rule overrides `skip_verification_greps` for *disposition*
> (you still skip the grep, you just don't treat skipped as fixed).

---

## DIFF 4 — `scripts/build_threat_model_yaml.py`: deterministic reconciler (the authoritative fix)

### 4a. New helpers (module scope, near `_carry_forward` at `:126`)
```python
def _threat_fingerprint(t: dict) -> tuple:
    """Stable identity across runs: component + cwe + normalized title.
    Mirrors the re-dispatch fingerprint contract in phase-group-threats.md:50."""
    comp = (t.get("component") or t.get("component_id") or "").strip().lower()
    cwe = (t.get("cwe") or "").strip().upper()
    title = re.sub(r"\s*\([^()]*:\d+\)\s*$", "", (t.get("title") or "")).strip().lower()
    return (comp, cwe, title)


_DEPTH_RANK = {"quick": 0, "standard": 1, "thorough": 2}

def _depth_is_shallower(cur: str, prior: str) -> bool:
    """True iff cur is strictly shallower than prior (both known)."""
    c = _DEPTH_RANK.get((cur or "").strip().lower())
    p = _DEPTH_RANK.get((prior or "").strip().lower())
    return c is not None and p is not None and c < p


def _reanalyzed_component_ids(output_dir: Path) -> set[str] | None:
    """Components whose .stride-<id>.json changed vs the baseline hash → re-analyzed.
    Returns None when no baseline (full/first run) → caller skips reconciliation."""
    bpath = output_dir / ".appsec-cache" / "baseline.json"
    if not bpath.is_file():
        return None
    try:
        prior_hashes = (json.loads(bpath.read_text()).get("stride_files") or {})
    except (OSError, ValueError):
        return None
    changed: set[str] = set()
    for cid, rec in prior_hashes.items():
        sfile = output_dir / f".stride-{cid}.json"
        if not sfile.is_file():
            continue  # removed-component path handles this elsewhere
        actual = "sha256:" + hashlib.sha256(sfile.read_bytes()).hexdigest()
        if actual != (rec or {}).get("sha256"):
            changed.add(cid)
    return changed
```

### 4b. The reconciler
```python
def reconcile_incremental_threats(
    threats: list[dict],
    prior_yaml: dict | None,
    output_dir: Path,
    cur_depth: str,
    prior_depth: str | None,
    resolved_prior: dict[str, str],   # prior_id/fingerprint -> reason (from analyzers)
) -> tuple[list[dict], dict[str, str], list[str]]:
    """Re-inject prior threats of RE-ANALYZED components that the (shallower)
    re-scan dropped without an affirmative fix. Returns
    (threats_out, resolved_reason_by_id, carried_ids).

    Only carries when the current depth is strictly shallower than prior depth —
    at equal/deeper depth a non-reproduced prior threat is genuinely resolved.
    """
    if not prior_yaml:
        return threats, {}, []
    reanalyzed = _reanalyzed_component_ids(output_dir)
    if not reanalyzed:
        return threats, {}, []

    present = {_threat_fingerprint(t) for t in threats}
    shallower = _depth_is_shallower(cur_depth, prior_depth)
    carried: list[str] = []
    resolved_reasons: dict[str, str] = {}

    for pt in (prior_yaml.get("threats") or []):
        comp = pt.get("component") or pt.get("component_id") or ""
        if comp not in reanalyzed:
            continue                      # carried-forward component → already intact
        fp = _threat_fingerprint(pt)
        if fp in present:
            continue                      # re-emitted by the analyzer (B1) → keep
        pid = pt.get("id", "")
        if pid in resolved_prior or fp in resolved_prior:   # analyzer affirmed fix
            resolved_reasons[pid] = resolved_prior.get(pid) or resolved_prior.get(fp)
            continue
        if shallower:
            carried_threat = dict(pt)
            carried_threat["evidence_check"] = "carried-unverified-shallower-depth"
            threats.append(carried_threat)
            present.add(fp)
            carried.append(pid)
        else:
            resolved_reasons[pid] = "not reproduced at equal-or-deeper depth"
    return threats, resolved_reasons, carried
```

### 4c. Collect the analyzers' affirmed-fix list
Add a loader (sibling to the `.stride-*.json` reads merge already does) that unions
every `resolved_prior_findings[]` into `{prior_id: reason, fingerprint: reason}`.
Cleanest home: emit it from `merge_threats.py` into `.threats-merged.json` under a new
top-level key `resolved_prior_findings` (merge already globs every stride file), then
read `merged.get("resolved_prior_findings")` here. **This keeps the builder reading one
file, consistent with the existing merge→build contract.**

### 4d. Wire it in `main()` — between threat build and the per-component `threat_ids` loop (`:1071`)
```diff
+    resolved_prior = _index_resolved_prior(merged)          # from .threats-merged.json
+    prior_depth = _load_last_run_depth(od)                  # baseline.json.last_run_depth
+    threats, _recon_resolved, _carried_ids = reconcile_incremental_threats(
+        threats, prior_yaml, od,
+        skill_cfg.get("assessment_depth", "standard"), prior_depth, resolved_prior,
+    )
+
     # threat_ids per component (derived)
     for comp in components:
```
(Place AFTER triage has run — the builder runs post-triage, so a carried threat keeps
its prior, fully-triaged verdict; we deliberately do NOT re-triage at shallow depth.)

### 4e. Honest changelog — stop "treating incremental as full" (`:947-968`)
Extend `build_changelog` with optional incremental params and, when `mode != "full"`
and a baseline exists, populate real buckets instead of the full-run stub:
```diff
 def build_changelog(
     skill_cfg, threats, components, attack_surface, existing_changelog, plugin_root,
-    *, current_sha=None,
+    *, current_sha=None,
+    reanalyzed_ids=None, carried_forward_ids=None,
+    resolved_reason_by_id=None, carried_ids=None,
 ):
```
```diff
-        "reanalyzed_components": sorted({c.get("id","") for c in components if c.get("id")}),
-        "carried_forward_components": [],
+        "reanalyzed_components": sorted(reanalyzed_ids) if reanalyzed_ids is not None
+                                 else sorted({c.get("id","") for c in components if c.get("id")}),
+        "carried_forward_components": sorted(carried_forward_ids or []),
         "added": { ... },
-        "changed": {"threats": []},
-        "resolved": {"threats": [], "reason_by_id": {}},
+        "changed": {"threats": sorted(carried_ids or [])},
+        "resolved": {"threats": sorted((resolved_reason_by_id or {}).keys()),
+                     "reason_by_id": dict(resolved_reason_by_id or {})},
```
Pass `_recon_resolved`, `_carried_ids`, the `reanalyzed` set, and
(`all_components − reanalyzed`) as `carried_forward_ids` from `main()` into the
`build_changelog(...)` call at `:1083`. This finally populates the
`carried_forward_components` field that `render_completion_summary.py:300,323`
already reads (today always empty).

### 4f. Imports
`reconcile_incremental_threats` and helpers use `hashlib` and `re` — confirm both are
already imported at the top of `build_threat_model_yaml.py` (re is; verify hashlib,
add if missing).

---

## DIFF 5 — Tests (drift guards + behaviour)

| File | Add |
|---|---|
| `tests/test_build_threat_model_yaml.py` | `test_reconcile_carries_dropped_prior_threat_at_shallower_depth` (prior thorough threat in a re-analyzed comp, not re-emitted, no affirmed-fix → present in output, `evidence_check=carried-unverified-shallower-depth`, prior id kept); `test_reconcile_resolves_when_analyzer_affirms_fix` (in `resolved_prior` → absent + changelog.resolved+reason); `test_reconcile_no_carry_at_equal_depth` (quick→quick: dropped→resolved, not carried); `test_reconcile_skips_carried_forward_component` (unchanged comp's threats untouched, no double-inject); `test_reconcile_no_double_count_when_reemitted` (fingerprint present → not re-injected); `test_changelog_incremental_buckets_populated` |
| `tests/test_baseline_state.py` | `_reanalyzed_component_ids` sha-mismatch detection (changed/unchanged/missing-baseline→None) |
| schema drift test (`tests/test_schemas_*` / enum-lockstep guard) | assert the new enum value present in all three evidence_check enums |
| `tests/test_merge_threats.py` | `resolved_prior_findings[]` union into `.threats-merged.json` |
| analyzer-def drift test (if `appsec-stride-analyzer.md` content is pinned) | update the pinned disposition text |

**Live E2E (manual, post-implementation):** `thorough` then `--quick --incremental` on a
fixture with one edited security-relevant file → assert (a) count does not collapse,
(b) edited component's *unrelated* prior threats are carried with the new
`evidence_check`, (c) a genuinely-fixed finding (add a validator in the diff) resolves
with a reason, (d) changelog `resolved`/`carried_forward_components` populated.

---

## Side conditions / constraints (carried from the proposal, now pinned)

1. **No double-count (B1×B2):** guaranteed by B2's fingerprint-present skip (4b). ✔
2. **T-ID stability:** carried threat re-injected with its prior `id` verbatim (4b);
   the per-component `threat_ids` loop (`:1074`) re-derives from `t["id"]` after
   injection, so it picks up carried ids. ✔
3. **Post-triage injection:** carried threat keeps the prior run's triage verdict;
   we intentionally do not re-rank at shallow depth (matches "only change what you
   verified"). Confirm `triage_compute_ranking.py` runs before the builder (it does —
   triage writes `.threats-merged.json`, builder reads it). ✔
4. **Genuine fixes still resolve:** disposition #2 + `resolved_prior_findings`; and at
   equal/deeper depth non-reproduction → resolved (4b else-branch). Over-preserve only
   at strictly-shallower depth — the safe failure direction for a security tool. ✔
5. **Removed components untouched:** `_reanalyzed_component_ids` skips components whose
   `.stride-<id>.json` is absent; the existing removal path
   (`phase-group-threats.md:62`) still owns those. No conflict. ✔
6. **Full/first run unaffected:** `_reanalyzed_component_ids` returns None (no baseline)
   → reconciler is a no-op; `build_changelog` falls back to current full-run stub when
   incremental params are None. ✔
7. **Requirements-drop hard-abort** (`resolve_config.py:976`) is orthogonal — untouched. ✔
8. **Permissions:** new file reads are `baseline.json` + `.stride-*.json`, both already
   in Phase 9 / builder scope. Re-check `data/required-permissions.yaml` +
   `tests/test_check_permissions.py` only if the analyzer gains a NEW write (it does:
   `resolved_prior_findings` goes into the existing `.stride-<id>.json` write — no new
   target). Expected: no permission change. **Verify, don't assume.**

## Sequencing

1. DIFF 1 (schema enum) + DIFF 4 (B2 reconciler + honest changelog) + DIFF 5 tests —
   **this set alone fixes the bug deterministically.** Ship first.
2. DIFF 2 + DIFF 3 (B1 analyzer depth-awareness + affirmed-fix emission) — precision
   layer; lets genuine fixes resolve instead of being conservatively carried. Ship
   second; B2 already protects correctness in the interim.

## Open decisions for the user
- **A. Over-preserve vs strict (4b `shallower` gate):** carry only at strictly-shallower
  depth (proposed) vs carry whenever a prior threat is non-reproduced-and-not-affirmed
  at ANY depth (more conservative, changes equal-depth behaviour too). Proposed =
  minimal blast radius. Your call if you want the stricter variant.
- **B. `resolved_prior_findings` home:** emit via `.stride-<id>.json` → merge unions into
  `.threats-merged.json` (proposed, one-file-read for builder) vs a separate sidecar.
- **C. Carried-threat visibility in the report:** should a carried (`evidence_check=
  carried-unverified-shallower-depth`) threat render a visible "carried from deeper
  prior scan — not re-verified at quick depth" marker in §8, or stay silent? (Honesty
  vs noise.) Default proposed: silent in body, tracked in changelog `changed[]`.
