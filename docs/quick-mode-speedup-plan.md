# Quick-Mode Speedup — Plan (① ② ③)

Status (2026-05-31): **② IMPLEMENTED** (Critical-safe, + fixed a pre-existing
failing drift test). **① REJECTED** (marginal saving, silent coverage hole — see
risk analysis). **③ DEFERRED** — needs a new deterministic generator; investigation
showed no existing one (`pregenerate_fragments.py` items 8/9 are the two REQUIRED
LLM-authored fragments), `weaknesses` has `minItems:3`, and it swaps a prominent §1
section for generic taxonomy prose to save only ~30-60s. Awaiting explicit go.

Quick is already heavily trimmed (QA, architect, walkthroughs, attack-paths,
arch-enrichment, actor-discovery, STRIDE A/E/F, cap-3, evidence-Critical-only,
haiku-economy). Only Phase 9 STRIDE moves the wall-clock. ① + ② attack Phase 9
directly and **compound**; ③ is an independent Stage-2 win.

Combined ①+② effect on per-component STRIDE output:
`current 6 cats × 2 = 12 threats/component` → `4 cats × 1 = 4` → ~3× less
enumeration/authoring in the dominant phase.

---

## Pre-existing bug to fix in passing (found while planning ②)

`tests/test_stride_quick_profile.py:47` asserts `skip_code_examples is True`,
but `QUICK_STRIDE_PROFILE` flipped it to `False` (2026-05, R9). The drift-guard
test was **not** updated and currently FAILS:

```
FAILED test_profile_active_quick_haiku_economy — assert False is True
```

② edits this same test → fix the C-assertion + docstring (A-F header block) in
the same commit. Lines 9–10 of the docstring and line 47 assertion.

---

## ② threats/category 2→1  (smallest, do first)

**Goal:** halve per-category enumeration depth at quick.

**Edits:**

1. `scripts/resolve_config.py` — `QUICK_STRIDE_PROFILE` (~line 145):
   ```diff
   -    "max_threats_per_category": 2,     # B
   +    "max_threats_per_category": 1,     # B (was 2 — quick is a triage pass;
   +                                       #     keep only the top-severity threat
   +                                       #     per STRIDE category per component)
   ```

2. `agents/appsec-stride-analyzer.md` Step-3 Quick-mode table (line 236):
   ```diff
   -| `max_threats_per_category` | `2` | After enumerating per category, sort by severity descending (Critical > High > Medium > Low) and keep at most the top 2. |
   +| `max_threats_per_category` | `1` | After enumerating per category, sort by severity descending (Critical > High > Medium > Low) and keep only the top 1. |
   ```

3. `tests/test_stride_quick_profile.py`:
   - docstring A-F block: `B. max_threats_per_category = 1`, `C. skip_code_examples = False`
   - line 46: `assert p["max_threats_per_category"] == 1, "B: cap is 1 (quick triage)"`
   - line 47 (drift fix): `assert p["skip_code_examples"] is False, "C: code_example KEPT at quick (R9)"`

**Risk:** drops 2nd-ranked finding per category. Criticals/Highs rarely cluster
2-per-category-per-component, so loss is mostly Medium/Low. Low.

**Verify:** `pytest tests/test_stride_quick_profile.py -q` green.

---

## ① STRIDE-Subset — drop Repudiation + DoS at quick  (biggest wall-clock lever)

**Goal:** quick analyzes only **S/T/I/E** per component. R and D in a quick
triage pass almost always yield Medium/Low (audit-logging gaps, rate-limiting),
which the cap already buries. Cutting 2 of 6 letters removes ~⅓ of per-component
enumeration in the dominant phase.

**New profile flag** (`scripts/resolve_config.py → QUICK_STRIDE_PROFILE`):
```diff
+    "stride_categories": ["S", "T", "I", "E"],  # G — quick drops Repudiation
+                                                 #     + DoS (triage: both yield
+                                                 #     mostly Medium/Low, buried
+                                                 #     by the per-category cap)
```
Full/standard/thorough keep all 6 (the `else` branch in
`resolve_stride_profile` returns `{"stride_profile_label": "full"}` with no
`stride_categories` key → analyzer defaults to all 6).

**Edits:**

1. `scripts/resolve_config.py` — add `stride_categories` to `QUICK_STRIDE_PROFILE`
   (above). Already forwarded verbatim via the existing
   `stride_profile` JSON, so no resolver plumbing change.

2. `agents/phases/phase-group-threats.md:424` — the `STRIDE_PROFILE={...}`
   example line: add `"stride_categories": ["S","T","I","E"]` so the documented
   forwarded shape matches.

3. `agents/phases/phase-group-threats.md:193` — pre-dispatch echo currently
   hard-codes `Spoofing/Tampering/Repudiation/Information-Disclosure/DoS/EoP`.
   Make it reflect the active category set (drop Repudiation/DoS at quick) so
   the user-visible manifest is honest.

4. `agents/appsec-stride-analyzer.md` Step 3:
   - the closing line *"All 6 STRIDE categories … are unchanged at Quick"*
     (after the table) must change to: *"At Quick the STRIDE letters analyzed
     are restricted to `STRIDE_PROFILE_JSON.stride_categories` (default all 6
     when absent); R and D are skipped at quick."*
   - add a new row to the Quick-mode table:
     ```
     | `stride_categories` | `["S","T","I","E"]` | Enumerate only these STRIDE letters. Absent/None → all 6. Quick drops Repudiation + DoS. |
     ```
   - in the per-letter enumeration block: gate the Repudiation and DoS
     sub-sections on membership in `stride_categories`.

5. `tests/test_stride_quick_profile.py` — assert
   `p["stride_categories"] == ["S","T","I","E"]` for quick+haiku-economy, and
   assert the key is **absent** (or analyzer defaults to all 6) for the
   `full` branch.

**Risk:** loses genuine Repudiation (audit-trail) and DoS (availability)
findings. Mitigated by: (a) quick is explicitly a triage pass, (b) the
SPA-without-BFF / architectural anti-patterns are enforced under Spoofing/EoP,
not R/D, so they survive. Downstream §8 register / attack-tree are deterministic
from `threats[]`, so fewer threats just means a shorter register — no breakage.

**Verify:** run pipeline against fixture at `--quick`; confirm no
`threat_category_id` starting with the Repudiation/DoS taxonomy prefixes appears
in `threat-model.yaml`; `pytest tests/test_stride_quick_profile.py -q` green.

---

## ③ ms-architecture-assessment deterministic at quick  (Stage-2 win, no Phase-9 risk)

**Goal:** stop authoring the LLM `ms-architecture-assessment.json` at quick;
let the composer derive the §1 Architecture Assessment table deterministically.
`ms-verdict` (the headline management summary) stays LLM-authored.

**Pattern to mirror:** `_derive_attack_paths_fallback` (compose_threat_model.py
:2163) + `_derive_tier_root_causes` (:2945). The renderer
`_render_architecture_assessment` (:5819) currently calls `_load_fragment`,
which **raises FragmentError when missing** (:1413) — so the integration point
is: catch that and fall back to a deterministic builder.

**Edits:**

1. `scripts/resolve_config.py` — add resolver
   `resolve_skip_arch_assessment_authoring(depth)` mirroring
   `resolve_skip_attack_paths_authoring` (already exists ~line 530), default
   `True` at quick. Emit `skip_arch_assessment_authoring` into resolved JSON +
   env `SKIP_ARCH_ASSESSMENT_AUTHORING`.

2. `skills/create-threat-model/SKILL-impl.md` — document the new env var in the
   Stage-2 dispatch var list (next to `SKIP_ATTACK_PATHS_AUTHORING`, ~line 2426)
   and pass it on the renderer dispatch.

3. `agents/appsec-threat-renderer.md` — when `SKIP_ARCH_ASSESSMENT_AUTHORING=true`,
   skip authoring `ms-architecture-assessment.json` (the §1 authoring contract
   block at line 139 becomes conditional). Keep `ms-verdict.json` authoring.

4. `scripts/compose_threat_model.py`:
   - new `_derive_architecture_assessment_fallback(threats, comp_lookup)`:
     - `verdict_severity`: `red` if any Critical, `amber` if any High, else `green`
     - `weaknesses[]`: group threats by security domain via the existing
       attack-class / CWE→domain map (`_assign_attack_class`, :2116); one
       weakness per populated domain
     - `affected_components`: unique `threats[].component` per domain
     - `findings`: `{ref, label}` per threat in the domain
     - `description`: **templated generic prose** per domain (the tradeoff —
       see Risk)
     - `framing` / `verdict_prose`: short deterministic templates
   - in `_render_architecture_assessment` (:5845): wrap `_load_fragment` in
     try/except `FragmentError` → on miss, build via the fallback. (Same
     try/except shape the attack-paths path already uses at :2253/:2276.)

5. Tests: unit-test the new fallback (domain grouping, severity rollup,
   component derivation) like the attack-paths fallback tests.

**Risk:** deterministic `description` prose is generic and violates the
"design-review prose, not SAST line-listing" quality bar that the LLM contract
(renderer:175) enforces. The §1 table becomes more mechanical at quick. Net:
acceptable because (a) ms-verdict carries the narrative headline, (b) the
findings/components columns stay accurate, (c) it only affects quick.

**Saving:** removes one LLM authoring fragment from Stage 2 (~30–60s). No Phase-9
impact.

---

## Suggested order

1. ② (1 profile value + 1 table + test; also fixes the failing drift test)
2. ① (compounds with ②; touches profile + 2 agent docs + analyzer gating + test)
3. ③ (independent; new resolver + renderer skip + compose fallback + tests)

Each is independently shippable. ②+① give the real wall-clock win; ③ is
optional polish.
