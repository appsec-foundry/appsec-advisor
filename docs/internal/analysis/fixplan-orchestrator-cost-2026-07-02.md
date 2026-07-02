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

---

## UPDATE 2026-07-02 (later same day) — Part A committed; Part B Phase 1 done, Phase 2 blocked

**Part A:** committed as `96b6058` on `dev` (not pushed). Regression tests per bug not
yet added (deferred by user — commit first).

### Part B Phase 1 — two corrections to the numbers above

1. **`context_window_report.py` double-counted cache_read (now fixed, `dev`
   uncommitted).** Claude Code logs one JSONL record per content block
   (thinking/text/tool_use) for a single API turn, and every block carries the
   *same* `message.usage` snapshot. The script summed `cache_read_input_tokens`
   per JSONL record instead of per unique `message.id` — in the analyzed session
   that inflated `cache_read_throughput` by **2.12×** (546 raw records → 258 real
   API turns). `peak_resident_context` was NOT affected (`max()` is dedup-proof) —
   **563,717 is correct; the "~802k" figure above was never corroborated by this
   tool and should be treated as an unverified rough estimate, not a baseline.**
   Fix: dedupe by `message.id` in `analyze_session`; regression test added
   (`test_multiple_content_blocks_per_message_are_not_double_counted`).
2. **The analyzed session silently mixed models — it was NOT all-Sonnet.** Sonnet
   ran 07:30–09:31 (157 turns = the original threat-model run). At 09:42 someone
   switched to **Opus** for the rest of the session — 101 turns through 11:11,
   which is the Part-A bug-fixing/debugging work. The "$77 / cache_read 178.6M at
   Sonnet rates" framing above conflated the two: a real chunk of that spend was
   at Opus rates, not Sonnet.

**Corrected real cost** (deduped turns, real per-model pricing — Sonnet 5
input/output $2/$10 intro through 2026-08-31 or $3/$15 standard, cache_read≈0.1×
input, cache_write(5m)≈1.25× input; Opus 4.8 input/output $5/$25, no intro,
same cache-rate formula):

| | turns | cache_read | cost |
|---|---:|---:|---:|
| Sonnet block (07:30–09:31, the original run) | 157 | 45.4M | ~$12.01 (intro) / ~$18.02 (standard) |
| Opus block (09:42–11:11, the fixing work) | 101 | 46.5M | ~$30.29 |
| **Total (this retained session)** | 258 | 91.8M | **~$42–48**, not $77 |

The $77→~$42–48 revision is NOT the legacy-runtime fix paying off — it's simply
correcting bad arithmetic (double-counted cache_read) and a bad pricing
assumption (the "Opus ≈ 5×" comparison used `verify_run_costs.py`'s stale
`opus-4-6` pricing table; real Opus 4.8 cache_read is $0.50/M vs that table's
$1.50/M — 3× too high). `verify_run_costs.py`'s `PRICING_MODELS` dict has no
`sonnet-5`/`opus-4-8` entries — flagged as a Phase-3 candidate, not fixed here.

**Arithmetic resolved** (the "245 tool_results / ~220k unique content vs 178M
cache_read" puzzle from Part B's first pass): deduped cache_read (91.8M) vs
deduped cache_creation — i.e. genuinely NEW content ever added to the
conversation (1.27M) — gives a **~72× average re-read multiplier**. This is
structural, not a bug: with 0 compactions, every token added to context stays
resident and gets re-read from cache on every subsequent turn until session end.
Rough fixed/growing split: the turn-1 baseline (~62.7k tokens — system + tools +
partial skill load) gets re-read across the other 257 turns ≈ 16.1M tokens ≈
**~17% fixed**, **~83% growing** (conversation/tool-result/subagent-notification
accumulation over the session). This confirms Part B's qualitative diagnosis
(growth, not fixed overhead, dominates) even though the dollar figures above
were wrong.

### Part B Phase 2 — blocked, not executable as written

`--rerender` **always routes to `runtime=legacy`**, regardless of
`APPSEC_THIN_ORCHESTRATOR` — `orchestration_controller.py`'s router requires
`mode in {"full","rebuild"}` AND `not rerender`
(`_runtime_for()` around line 234–245; reason string:
`"special mode retains the parity runtime"`). The cheap path (`--rerender`,
skips Stage 1/STRIDE) and the thin-eligible path (`--full`/`--rebuild`, which
triggers the expensive Stage-1 fan-out) are mutually exclusive today. A cheap
A/B of legacy-vs-thin is **not possible** without either (a) a real
`--full`/`--rebuild` run (expensive, not done — out of scope this session), or
(b) a router code change to add a diagnostic-only override (not done — would
need review as its own change).

**Decision (user, 2026-07-02): skip Phase 2, go straight to Phase 3 using Phase 1
data only.**

### Part B Phase 3 — done this session

- Fixed `context_window_report.py` dedup bug (see above); regression test added;
  full related test files green (`context_window_report` + `run_costs`, 74
  passed). Uncommitted on `dev`.
- **Thin-runtime GA recommendation (for the maintainer — this is their call, not
  implemented here):** the legacy runtime holds `SKILL-impl.md` (351,511 bytes /
  ~86k tokens) resident for the entire session and re-pays it on every turn; the
  thin runtime's `SKILL-full-runtime.md` is 8,717 bytes / ~2k tokens — roughly
  **43× smaller**. Given ~83% of this session's cache_read was growth-driven
  (not fixed-baseline-driven), thin runtime would cut the *fixed* ~17% slice
  further but wouldn't by itself fix the *growing* ~83% (conversation/subagent
  notification accumulation) — meaning thin-runtime GA (Phase-3 item 1) and the
  compact sub-agent completion contract (Phase-3 item 3, "biggest lever if
  notifications dominate") are complementary, not substitutes. Recommend GA'ing
  thin runtime AND scoping the compact-completion-contract work, in that
  priority order — but closing the parity matrix for GA is a maintainer decision
  outside this session's scope.
- Items 2 (lazy-load `SKILL-impl.md` per-stage) and 4 (mid-run `skill_watchdog.py`
  guardrail) from the original Phase-3 list were NOT implemented this session —
  open follow-ups if the maintainer wants them ahead of thin-runtime GA.

**Open decisions for next session:** commit the `context_window_report.py` fix?
add regression tests for Part A's 6 bugs (still deferred)? pursue Phase-3 items
2/4, or the `verify_run_costs.py` stale-pricing-table fix?
