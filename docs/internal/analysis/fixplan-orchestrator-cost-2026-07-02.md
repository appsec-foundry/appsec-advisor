# Handoff: orchestrator cost investigation + anchor/AI bug fixes (2026-07-02)

**Purpose:** resume this work in a FRESH session after `/clear` on **Sonnet** (not
Opus). Point the new session at this file. All state below is on disk and survives
`/clear`. Context: this started from a juice-shop `create-threat-model` run that cost
~$77 and shipped 12 broken §7 anchors + a thin AI/LLM-Exposure map.

Plugin repo: `/home/mrohr/appsec-advisor` (branch `dev`). Target repo of the run:
`/home/mrohr/juice-shop`, output `docs/security/`.

---

## PART A — bug fixes (DONE, verified, NOT committed)

6 deterministic bugs found + fixed. Full plugin test suite: **8963 passed, 93 skipped**
(ran after all edits). Fresh from-scratch deliverable rebuild: **toc_closure 0 issues,
all gates green, zero manual patching**. Counterfactuals confirmed old=broken/new=fixed.

Changed source files (uncommitted, `git diff` on branch `dev`):
- `scripts/qa_checks.py` — Bug 2: `required_subsection` matcher `fullmatch`→`match`
  (the `^`-anchored contract patterns are prefixes; the `(54)`/`(52)` route-count
  suffix on §5.1/§5.2 headings broke `fullmatch` → false-positive "missing subsection"
  → forced a needless fragment-fixer repair pass).
- `scripts/compose_threat_model.py` — Bug 1a: `_linkify_section_refs` slug_map now uses
  `github_render_slug` (was `github_slug`) so bare `§N.M` prose refs into slash/&/dash
  headings resolve. Bug 1c: moved `_linkify_section_refs` to run AFTER
  `_section7_number_and_bulletize` (it was building its number→slug map from the
  pre-renumber §7 headings; an un-numbered "Threat Hypotheses" opener shifts 7.2.1…N by
  one → mislabeled/dangling anchors). Plus a `_PRELINKED_REF_RE` normalizer that repairs
  already-linked `[§N.M](#wrong)` refs from LLM-authored fragments.
- `scripts/apply_prose_fixes.py` — Bug 1d: `_rewrite_controls_covered_anchors` builds
  Controls-covered bullet anchors with `github_render_slug` (was `github_slug`) — same
  slash-heading divergence, different file (this was the source of the 6 stubborn
  `#723-oauth-google-social-login`-style dead links).
- `scripts/pregenerate_fragments.py` — Bug 1b: `_render_threat_hypotheses_table` emits an
  `<a id="threat-hypotheses-requiring-validation">` before the heading (Controls-covered
  bullet dangled because this pseudo-control had no explicit anchor). Bug 4:
  `_LLM_TOP10_RULES` LLM10 keywords add `unrate-limited`/`rate-limit`/`rate limiting`/
  `no rate limit`/`unlimited` so T-037 "Unrate-Limited LLM Chat Proxy" maps (it was
  dropped from the AI map by the `rate limit`≠`unrate-limited` gap).
- `agents/appsec-threat-renderer.md` — Bug 3: `ms-ai-exposure.json` authoring decision
  keyed off `threat-model.yaml` LLM findings (authoritative), not off a `### 7.13`
  heading in `.recon-summary.md` (which is absent when recon runs in fallback → the rich
  AI callout got silently dropped).

Root-cause family: link TARGETS must use `github_render_slug` (what GitHub renders),
NOT `github_slug` (collapsed single-hyphen); they diverge for headings with ` / `, ` & `,
` — `. `toc_closure` already verifies with render_slug.

**Open decisions:** (1) commit these? (2) add one regression test per deterministic bug
(1a/1b/1c/1d/2/4) — they slipped past 8963 existing tests. Recommended before commit.

The juice-shop deliverable (`docs/security/threat-model.md` + `-juice-shop-standard.*`
stamped copies) was rebuilt clean with the fixes; AI map now = LLM06 + LLM10 + LLM07.

---

## PART B — orchestrator cost problem (diagnosed, NOT fixed)

**Symptom:** the run cost ~$77. Not a bug from Part A; not the model tier.

**Measured facts (this run, session 20b15b3f, from `docs/security/.hook-events.log` +
`scripts/context_window_report.py` on the Claude JSONL):**
- Orchestrator session cost decomposition (Sonnet rates): **cache_read 178.6M tokens =
  $53.58 = 73%** of $73.27; cache_write 14%; output 12%; input 0.3%.
- **Peak resident context ~802k tokens, 0 compactions.**
- cache_read grew super-linearly (quadratic): 5.6M (start) → 91.5M (run end 09:35) →
  173M (10:30, after the follow-up analysis+fixing in the SAME never-cleared session).
- Same volume on **Opus ≈ $366 (5×)** — Sonnet was correct and SAVED ~$290; Haiku is too
  weak to orchestrate (skill forbids it). So the model is NOT the lever; VOLUME is.

**Root cause:** the LEGACY runtime holds `SKILL-impl.md` (343KB / ~88k tokens) resident +
accumulates ~14 sub-agent completion notifications; re-served every turn. The skill's own
cost model assumes a "thin cheap orchestrator" — the legacy runtime violates that.
`cache_read ≈ resident_context × turns`, both large → quadratic.

**Key lever (verified available):** the THIN runtime. Router test:
- default (what ran): `runtime=legacy` → loads `SKILL-impl.md` (~88k tok).
- `APPSEC_THIN_ORCHESTRATOR=1`: `runtime=thin-full` → loads `SKILL-full-runtime.md`
  (~2.2k tok) + deterministic `orchestration_controller.py`. It's rollout-gated
  ("compact runtime is rollout-gated") = a maintainer GA decision, NOT a flag to flip
  silently. Only applies to full/rebuild; incremental/special modes stay legacy.

### Investigation plan (do on FRESH Sonnet session — NO new full scan needed except Phase 4)
- **Phase 1 — Identify (cheap, deterministic, no scan):** finish attributing the 178M
  cache_read to sources. Tools: `scripts/context_window_report.py --json` on the JSONL
  under `/home/mrohr/.claude/projects/-home-mrohr-juice-shop/`; bucket tool_result sizes;
  attribute the big cache_read jumps (+42M @09:31, +68M @10:26) to specific actions;
  resolve the arithmetic (245 tool_results / ~220k unique content vs 178M cache_read →
  extended-thinking turn count? fixed per-turn overhead?). Deliverable: % split fixed
  (system+tools+skill-file) vs growing (conversation).
- **Phase 2 — Isolate (cheap):** A/B the same render under legacy vs
  `APPSEC_THIN_ORCHESTRATOR=1` via `--rerender` (NO STRIDE). Measure peak-resident +
  cache_read each. Proves the thin-runtime delta with data.
- **Phase 3 — Fix (pick by Phase-1 data):**
  1. Thin runtime → GA (close parity matrix so router picks it by default) — primary,
     maintainer call.
  2. More aggressive lazy-loading of `SKILL-impl.md` in legacy (per-stage slice, don't
     hold all 88k resident) — I can implement.
  3. Compact sub-agent completion contract (terse structured returns, bulky prose to
     disk) — I can implement; biggest lever if notifications dominate.
  4. Mid-run guardrail in `scripts/skill_watchdog.py` (warn when cache_read crosses a
     threshold; the start-only bloat detector misses in-run growth) — I can implement.
- **Phase 4 — Verify:** ONE real full scan under the fix, on Sonnet + fresh session,
  compare to baseline (peak 802k / cache_read 178M / $77). Target: orchestrator
  cache_read ↓ 3–5×.

**Process rule (learned this session):** do NOT run the investigation on Opus in a
bloated session — that reproduces the exact anti-pattern. `/clear` + `/model sonnet`
first. All needed state is on disk (JSONL transcripts, logs, plugin source, applied
fixes) — a fresh session loses nothing.

---

## RESUME INSTRUCTIONS (fresh Sonnet session)
1. Read this file.
2. `cd /home/mrohr/appsec-advisor && git diff --stat scripts/ agents/` — confirm Part A
   fixes still present (branch `dev`).
3. Decide with user: commit Part A + add regression tests? then start Part B Phase 1.
4. Part B Phase 1/2 need NO full scan — scripts + `--rerender` only.
