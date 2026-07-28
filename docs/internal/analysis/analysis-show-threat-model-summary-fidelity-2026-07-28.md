# show-threat-model: summary block does not match the report it summarizes

**Date:** 2026-07-28
**Status:** implemented — see "Resolution" at the end for what shipped and what
was deliberately left alone
**Surface:** `skills/show-threat-model/SKILL.md` → `scripts/summarize_threat_model.py`
**Reference run:** juice-shop, `docs/security/` (67 threats, 8 components, standard/full)

## Summary

`show-threat-model` is documented as *"prints a rendered block verbatim"* — a
faithful, deterministic view of the delivered threat model. Measured against the
report it claims to summarize, it currently:

1. cites identifiers that do not exist anywhere in the report,
2. prints severity numbers that contradict the report's own headline,
3. omits the verdict — the one judgement the report leads with,
4. presents a "worst case" list that is not the report's worst case.

All four have the same root shape: the summarizer re-derives facts from
`threat-model.yaml` using its own rules instead of reproducing what the composer
already decided.

---

## D1 — Finding IDs do not exist in the report

`_threat_id()` (`summarize_threat_model.py:80`) returns the raw yaml id `T-NNN`.
Every user-facing label in `threat-model.md` is `F-NNN`; the composer rewrites
the visible label in `_normalize_finding_label`
(`compose_threat_model.py:900-909`, `T-NNN → F-NNN`).

`T-NNN` survives in the report only as a *hidden* HTML anchor
(`<a id="t-062">`). The only visible `T-` tokens are `AC-T-001…` — abuse-case
ids, a **different namespace**. So a reader who greps the report for `T-001`
either finds nothing or lands on an unrelated abuse case.

`query_threat_model.py:68-75` already solved this with `_display_id()` and
documents why. `summarize_threat_model.py` never adopted it.

**Fix:** apply the same `T-NNN → F-NNN` mapping in `_worst_case`, `criticals`,
and `threats_by_severity`. Keep the raw yaml id in the `--json` payload under a
separate key so machine consumers do not silently change meaning.

---

## D2 — Severity numbers contradict the report

Measured on juice-shop:

| Source | Critical | High | Medium | Total |
|---|---|---|---|---|
| `show-threat-model` today | **27** | 29 | 11 | 67 |
| Report §8 Findings Register | **15** | 40 | 12 | 67 |
| Report Management Summary "Risk distribution" | **14** | 39 | 12 | 65 |

Cause: `_severity_label()` (`summarize_threat_model.py:56-67`) ranks by
`effective_severity → risk → severity`. The composer does the opposite for the
finding inventory:

- §8 Findings Register buckets on `risk` only
  (`compose_threat_model.py:15918` — `t.get("risk") or t.get("severity")`).
- The MS "Risk distribution" line uses `_risk_distribution_counts()`
  (`compose_threat_model.py:2664-2691`), also `risk`-based, minus folded
  `insecure-practice` sites, plus `design-risk` weaknesses once at their heading
  severity.

`effective_severity` exists for abuse-chain elevation and drives §9 / ranking —
it is **not** the basis of the finding inventory. On this model it elevates 12
findings to Critical (`T-024`, `T-026`, `T-029`, `T-042`, `T-045`, `T-048`,
`T-051`, `T-052`, `T-053`, `T-054`, `T-062`, `T-070`), nearly doubling the
Critical count a reader sees anywhere else. The docstring's justification
("reflects the same numbers the model actually presents") is factually wrong.

Two further divergences in the same tally:

- The register drops `evidence_check == "refuted"` threats
  (`compose_threat_model.py:15901`); the summarizer counts them.
- The register/MS fold `insecure-practice` sites into their weakness; the
  summarizer counts them as standalone findings.

**Fix:** extract the composer's `_risk_distribution_counts()` into a shared
module (e.g. `scripts/severity_rollup.py`) and have both the composer and the
summarizer call it — one rule, one place. Add the refuted-filter to the shared
helper so both surfaces agree.

**Open decision:** which of the two report tallies the block should print.
Recommendation: mirror the **MS Risk distribution** (14/39/12, total 65),
because that is the headline a reader has in front of them, and label the line
accordingly. The `Findings   N threats across M components` line must then use
the same total, or it re-introduces the contradiction it is meant to remove.

**Side effect of the fix:** `T-062 "Container image signing via cosign or
attest-build-provenance"` currently appears under **Top Critical**. Its `risk`
is Medium; only `effective_severity` made it Critical. It is also
mitigation-shaped prose rather than a threat statement. Switching the basis
removes it from the list without a separate patch.

---

## D3 — The verdict is missing

The report opens with:

```
## Management Summary
### Verdict
🔴 Juice Shop carries fifteen critical and forty high-severity defects across
   eight system components. Hardcoded credentials, unprotected features, and
   widespread input-injection flaws mean any internet user can take full
   administrative control and extract every customer account.
```

This is the single most decision-relevant sentence in the deliverable, and it
carries a red/amber/green flag (`severity: "red"`). The overview block does not
contain it, in any form.

Root cause: **`threat-model.yaml` does not carry the verdict at all.** It exists
only in

- `.fragments/ms-verdict.json` — a Stage-2 compose input, listed in
  `runtime_cleanup.POST_QA_DIRS` and therefore deleted on a clean run, and
- the rendered `threat-model.md`.

So the semantic model is not self-describing: no consumer (`show`, `ask`,
`export`, `review`) can state the assessment's own conclusion without scraping
markdown.

**Options:**

| # | Approach | Assessment |
|---|---|---|
| A | Persist the verdict into `threat-model.yaml` from a post-compose emitter (precedent: the existing auto-emitters that enrich the yaml after `build_threat_model_yaml.py`) | **Recommended.** Fixes the gap at the producer; every consumer benefits; survives cleanup; schema-checkable |
| B | Read `.fragments/ms-verdict.json` when present | Rejected — cleanup deletes it; works only on `--keep-runtime-files` runs |
| C | Parse `### Verdict` out of `threat-model.md` | Fallback only — text scraping of a rendered artifact, exactly the pattern the repo avoids elsewhere |

Option A needs: a schema field (`meta.verdict` or a top-level `verdict` block
with `severity` / `opening` / `bullets`), an emitter, schema + compose tests, and
`--rebuild` behaviour agreed (the verdict is Stage-2 output, so a yaml rebuild
must not silently drop it — see the known "rebuild wipes enrichments" trap).

---

## D4 — "Worst case if nothing changes" is not the worst case

The block prints:

```
Worst case if nothing changes
  ⚠ T-001   Critical · frontend-spa · JWT and TOTP Tokens in Browser localStorage → M-001 (P1)
  ⚠ T-003   Critical · auth · JWT Algorithm Confusion algorithm none Accepted ...
  ⚠ T-004   Critical · frontend-spa · Derived Password from OAuth Email Claim ...
```

`_worst_case()` reads `critical_findings[]` and treats `summary` as curated
prose. In this model `critical_findings` has **55 entries — one per finding —
and every `summary` is a verbatim copy of the threat title**:

```json
{"threat_id": "T-001", "summary": "JWT and TOTP Tokens in Browser localStorage", "mitigation_id": "M-001"}
```

So the list degenerates to *"the three lowest-numbered Critical findings"*. It
is not a worst-case ranking, and it reads as three raw weakness labels rather
than an outcome.

The report's actual worst-case block is the MS blockquote — outcome-framed,
impact-first, already carrying `F-NNN` refs and verified-attack-path markers:

> - **Full admin account forgery** — Hardcoded signing credentials and a broken
>   token-validation library let any attacker mint a valid administrator session
>   without knowing any password. *(🔴 F-010, 🔴 F-003 → W-003)* — ✓ verified attack path

Same source as D3 (`ms-verdict.bullets`). **One fix serves both**: once the
verdict block is persisted, print its `bullets` here instead of re-deriving a
pseudo-ranking from `critical_findings[]`.

If the verdict is not persisted, the honest interim change is to rename the
heading (it currently over-promises) and to stop treating an uncurated
`critical_findings[]` as curated.

---

## D5 — Hand-off to the other skills

The renderer does emit the hand-off (`_NEXT_STEP_HINT`,
`summarize_threat_model.py:302-306`):

```
Ask        a question about a specific finding, coverage, or what to fix first
           → /appsec-advisor:ask-threat-model     act on findings → /appsec-advisor:review-threat-model
```

It is the **last** line of a ~50-line block, after the report path, and it is
the only line the invoking agent has an incentive to trim — `SKILL.md` tells it
to print the renderer output verbatim, but the block ends with what looks like
advisory chatter. Reported symptom: the pointer does not reach the user.

**Fix (low cost, no new data):** move the hand-off directly under `Status`,
where the user is still reading, and make `SKILL.md` state that the block is
printed *in full, including the trailing lane pointers* — the routing correction
it exists for only works if it is actually shown.

---

## Proposed order of work

| Step | Change | Verify |
|---|---|---|
| 1 | `_display_id()` in the summarizer (D1) | new test: rendered block contains `F-001`, never `T-001` |
| 2 | Shared severity rollup, composer + summarizer call it; drop refuted (D2) | new test: summarizer counts == `_risk_distribution_counts` on the e2e golden fixture |
| 3 | Persist the verdict into `threat-model.yaml` (D3) | schema test + compose test; `--rebuild` does not drop it |
| 4 | Verdict + `bullets` rendered in the block, replacing the pseudo worst-case (D3/D4) | render test against the fixture |
| 5 | Hand-off placement + `SKILL.md` wording (D5) | existing `test_render_text_names_the_ask_and_review_lanes` extended |

Steps 1, 2 and 5 are self-contained in `summarize_threat_model.py` (+ one shared
helper). Steps 3 and 4 touch the schema and the render pipeline and should be a
separate change.

Existing tests that encode the current, wrong behaviour and must be updated:
`tests/test_summarize_threat_model.py::test_severity_uses_effective_severity_precedence`
and `::test_worst_case_from_curated_critical_findings`.

---

## Resolution

All five steps landed.

**New shared module `scripts/_severity_rollup.py`.** Owns `display_id`
(`T-NNN → F-NNN`), `register_severity` (`risk → severity`, never
`effective_severity`), `register_threats`, and the Management-Summary tally.
`compose_threat_model._risk_distribution_counts` and
`._weakness_basis_breakdown` are now thin delegates, and
`tests/test_severity_rollup.py::test_composer_delegates_to_this_module` pins
that they cannot drift apart again.

**Two bases, not one.** The block prints the Management-Summary tally as its
histogram (matching the report's headline) but builds its finding *lists* from
the §8 register. Using the MS membership for the lists as well looked
consistent on paper and was wrong in practice: on the reference model it
silently dropped the Critical weak-password-hashing finding, because that site
folds into the weakness register. Everything listed is now a card the reader
can open, and a single line names the delta when the two totals differ:

```
Findings   65 findings across 8 components
           §8 register lists 67 — the headline folds practice sites into the weakness register
```

**Verdict persistence — Option A, as a post-compose emitter.** The first
attempt wrote the verdict from inside `compose.render()`, which covered every
compose path with one call site. That was wrong, and
`test_analysis_version_upgrade::test_v2_report_remains_renderable_and_is_not_rewritten`
caught it: **the composer is read-only for `threat-model.yaml`** — rendering a
v2 baseline must not mutate the semantic model, and the test asserts byte
equality to pin that.

What shipped instead follows the house pattern for yaml enrichment
(`scripts/emit_*.py`): `scripts/emit_verdict_to_model.py` runs after compose
and writes the block. `compose._build_verdict_export` still resolves the
payload — it sits next to the code that renders the same bullets, so the
persisted and rendered verdicts cannot disagree — but the composer only stashes
it on the `RenderContext`; the emitter does the writing. Call sites:
`orchestration_controller` (default path), the Stage-2 renderer agent, and the
parallel-render branch in `SKILL-impl.md`. The emitter is idempotent and
best-effort: it writes YAML only, so the documented Markdown mutation order is
untouched, and a failure leaves a complete report in place. Schema: top-level
`verdict` in `schemas/threat-model.output.schema.yaml`.

**Not changed, on purpose:**

- The refuted-filter divergence between §8 (drops refuted findings) and the MS
  Risk-distribution line (counts them). Aligning them changes what the *report*
  prints, which is a separate decision from making the overview agree with it.
  `register_threats` filters refuted, so the overview lists match §8; the
  histogram still mirrors the MS line verbatim, including this quirk.
- `critical_findings[]` still holds one uncurated entry per finding. The
  overview no longer depends on it when a verdict is present, but the field
  itself remains a copy of the threat titles.
