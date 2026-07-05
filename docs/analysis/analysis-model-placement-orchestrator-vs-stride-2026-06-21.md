# Analysis: Model Placement — Orchestrator (Opus vs Sonnet) and STRIDE (Opus vs Sonnet)

> **⚠ CORRECTION 2026-06-22 — the STRIDE part of this analysis is unvalidated.**
> It was later verified (`_agent_model` resolution + real logs) that the
> parallel STRIDE dispatch does **not set** the agent `model` parameter, so the
> STRIDE analyzers silently fall back to their frontmatter default **Sonnet** — even
> in the runs evaluated here, STRIDE effectively ran on **Sonnet**, only triage on
> Opus. The core claim "Opus STRIDE is better **and** cheaper" therefore rests on
> runs in which Opus STRIDE was **never executed** — it is **not substantiated**.
> V3's `$9 opus` share was probably triage/merger, not STRIDE. Only a run
> with STRIDE provably running on Opus (dispatch fix + `stride_model_mismatch` gate,
> implemented 2026-06-22) allows a real measurement. The orchestrator claims (§3/§4)
> are unaffected by this.
>
> **UPDATE 2026-06-23 — this measurement is now available (§10): the A/B refutes §5a.**
> With STRIDE provably running on Opus and otherwise identical flags, Opus reasoning is
> **$40.78 vs $30.01 = $10.77 more expensive**, not cheaper. The "Opus is cheaper" thesis is wrong;
> it remains a pure quality-vs-cost trade-off. Details + severity/surface data in §10.

Status: **Analysis / recommendation — code NOT implemented.** The documentation clarifications on the
orchestration cost formula are implemented (see §8); the model default change
(`opus` for reasoning + B2d inversion) is open and tied to a verification (Stage 0).

Empirical basis: **N = 1 repo** (OWASP Juice Shop), three standard full runs from
2026-06-21. Directional claims are robust; exact percentage/cost values are
benchmark-dependent and not generalizable. Source of the raw data: the three
`/cost` outputs + run state under `~/scans2/juice-shop/{standard-opus-orchestrator,
standard-stride-orchestrator,standard-stride-orchestrator-opus-reasoning}/`.

---

## 0. TL;DR

- **Same model — the lever is *placement*, not the model.**
- **Opus on the orchestrator = burned money.** The orchestration layer is
  ~40–50 % of an Opus-driven run; running it on Opus adds roughly **+25–55 %
  to the total** (proportional, grows with run length/repo size — not a fixed amount) and
  does **not** deepen the analysis.
- **Opus on STRIDE/triage/merge = the only lever that raises quality** — and on
  this (large) repo it was even **cheaper** than pure Sonnet.
- **Recommendation:** Default `standard`/`thorough` → STRIDE on **Opus**; **disable/invert**
  the size-triggered auto-downgrade (`B2d`); deprecate `opus-cheap`.
  Sonnet STRIDE only in `quick` + explicit opt-out.

---

## 1. Experimental setup

Three runs, all `--assessment-depth standard --full`, against the same Juice Shop repo.
The directory name describes the **driving Claude Code session**, not the internal
pipeline. Internally, `orchestrator_model` is `sonnet` in all three (per matrix always
`claude-sonnet-4-6`).

| Variant | Driver session | `reasoning_model` | `stride/triage/merger` |
|---|---|---|---|
| **V1** `standard-opus-orchestrator` | **Opus** | sonnet-economy (auto) | sonnet / sonnet / sonnet |
| **V2** `standard-stride-orchestrator` | Sonnet | sonnet-economy (auto) | sonnet / sonnet / sonnet |
| **V3** `…-opus-reasoning` | Sonnet | **opus** | **opus / opus / opus** |

Important: V1 and V2 have **byte-identical internal pipeline configs** — the only
difference is the model of the driver session. That makes **V1 − V2 = effect of
Opus-as-orchestrator** and **V3 − V2 = effect of Opus-in-reasoning** (against the same
Sonnet driver session) two clean natural experiments.

Evidence that V1/V2 had no internal analysis phase on Opus — the `reasoning_label`
from `.skill-config.json`:

> sonnet-economy (auto — large repo: economy tier across all criteria-selected
> components; **Opus on merger/triage uneconomical at this scale, STRIDE stays Sonnet**)

The auto-switcher downgraded the pipeline because of repo size; `.agent-run.log`
shows **0 Opus subagents** in V1/V2 (only sonnet+haiku). In V1, the entire
Opus amount therefore went into the outer session (glue/dispatch), not the analysis.

---

## 2. Raw data

| | V1 opus-orchestrator | V2 sonnet (control) | V3 opus-reasoning |
|---|---|---|---|
| **Cost** | **$42.01** | $33.66 | **$31.78** |
| of which Opus | $21.46 | – | $9.08 |
| of which Sonnet | $20.36 | $33.66 | $22.06 |
| of which Haiku | $0.19 | – | $0.64 |
| API duration | 1h 55m | 2h 10m | 2h 05m |
| Wall duration | 1h 12m | 1h 44m | *8h 42m ⚠️* |
| **Findings** | 71 | 50 | **74** |
| Mitigations | 74 | 50 | **76** |
| Severity (C/H/M/L) | 13 / 50 / 5 / 3 | 14 / 27 / 8 / 1 | **8 / 38 / 18 / 10** |
| % Crit/High | 89 % | 82 % | **62 %** |
| "✓ verified" markers | 64 / 71 | 45 / 50 | **70 / 74 (95 %)** |
| STRIDE components | 8 (+ai-chatbot, +b2b-api) | 7 (+marsdb) | 8 (**+web3**, +llm-chat) |

⚠️ **V3 wall (8h 42m) is contaminated** — the session was idle/suspended. Only API time
and cost are reliable. V1's 1h 12m wall is conspicuously low (API-latency luck,
not structurally faster); all three API times fall in the 1h55–2h10 band.

Token deltas (from `/cost`, authoritative over the whole run):

| Sonnet consumption | V2 | V3 | Δ |
|---|---|---|---|
| output | 355.2k | 220.5k | **−38 %** |
| cache-read | 67.4m | 41.6m | **−38 % (−25.8m)** |
| input | 145.3k | 68.3k | −53 % |

---

## 3. Finding A — Opus as orchestrator: no analytical added value, high price

V1 (Opus session) delivers 71 findings against V2's 50 — but since Opus did **zero analysis**
in V1 (pipeline byte-identical to V2, 0 Opus subagents), this lead is only
attributable to (a) better orchestration/inventory judgments by the Opus session or
(b) run-to-run noise (N=1). **Qualitatively**, it turns out that Opus-as-orchestrator
does *not* fix the core weakness:

- **Severity inflation persists:** 89 % of all V1 findings are Crit/High (13 C + 50 H),
  only 8 Med/Low. Opus cannot fix this, because `triage_model` = Sonnet.

→ **$21.46 for an indirect, partly-noise effect that does not raise quality.**
Money into the glue.

---

## 4. Finding B — orchestration cost formula (proportional, not fixed)

V1 separates the cost cleanly by model, because Opus there was *only* the orchestration:

- **Orchestration (Opus) = $21.46 = 51 % of the $42.01 run.**
- Pipeline (Sonnet) = $20.36 = 48 %.

So the orchestration layer is **~40–50 % of an Opus-driven run** — not a
small item, but dominated by the long-lived session's **cache-read** (the
orchestrator re-reads the growing cached context on *every* dispatch).

**Surcharge for Opus vs Sonnet orchestration:**
- Our run: V1 − V2 = $42.01 − $33.66 = **$8.35 ≈ +25 %** on the total.
- Documentation benchmark (`docs/threat-modeler.md`): $47 (Opus session) vs $30 (Sonnet session)
  ≈ **+57 %**.

→ The surcharge is **proportional, not fixed**: it scales with run length × context
size, i.e. with repo size. On larger/longer runs the absolute surcharge grows.
Rule of thumb: **+25–55 % on the total, for zero return.** Orchestrator therefore **always
Sonnet** (Haiku is too weak — it drives JSON contracts/gates/repair loops).

**Caveat / not cleanly isolable:** V2 folds orchestration + pipeline into *one*
Sonnet amount, so the Sonnet orchestration share cannot be determined exactly. The
"+25 %" assumes V1 pipeline ≈ V2 pipeline (same Sonnet); the "5×" claim in the
old docs is the *per-token rate* (Opus ≈ 5× Sonnet), not a whole-run factor. Both
readings give the same direction, different magnitude → range rather than point value.

---

## 5. Finding C — Opus vs Sonnet for STRIDE: better AND (here) cheaper

### 5a. Cost inversion (V3 < V2)

V3 (Opus reasoning) was **cheaper** than V2 (pure Sonnet): **$31.78 < $33.66**.
Mechanics:

- The Sonnet side fell by **−$11.60** ($33.66 → $22.06), because the most churn-intensive phases
  (STRIDE/triage/merge) left the Sonnet counter: Sonnet output −38 %, Sonnet
  cache-read −38 % (−25.8m).
- Opus + Haiku added only **+$9.72**. Opus's own cache-read was only **7.0m** —
  far below the 25.8m that the same work would have generated on Sonnet, because Opus
  converges in **fewer tool iterations**.
- Net **−$1.88**.

Worked example for clarity (per-model totals from `/cost`):

```
                 V2 (all Sonnet)       V3 (STRIDE/triage/merge → Opus)
  sonnet         $33.66                $22.06        (−$11.60)
  opus           –                     $9.08
  haiku          –                     $0.64
  ───────        ──────                ──────
  Σ              $33.66                $31.78        (netto −$1.88)

  Driver = Sonnet cache-read:    67.4m  →  41.6m   (−25.8m)
```

Why `cache-read` is the driver: it is **by far the largest cost item** of the
run — in V2 roughly **~$20 of $33.66** (estimated: 67.4m tokens × ~$0.30/M Sonnet
cache-read rate; `/cost` only provides per-model totals, no per-line dollars, hence
derived). Every subagent turn re-reads the entire cached context (millions of
tokens) → more turns = more cache-read dollars. Opus does the same reasoning
phases in **fewer turns** and therefore generates only **7.0m** Opus cache-read instead of the
~25m it costs on Sonnet. The Opus surcharge (**+$9.72**) is smaller than the Sonnet
saving thus freed up (**−$11.60**) → the run ends up cheaper on balance.

Key point: the most expensive item is **cache-read**, which scales with the turn count. A
Sonnet that shoulders STRIDE "thrashes" (many re-reads/retries → lots of cache-read). Opus
is *more token-efficient* on exactly the most expensive item. **It is not "Opus < Sonnet
per token" — it is "fewer, but more decisive turns".**

Note: `estimate_duration._MODEL_FACTOR` encodes `opus: 1.40` (= 1.4× more expensive/
slower). The **cost** side of this assumption is refuted by the run; the **time** side
(Opus latency) remains plausible but is unmeasured because of the contaminated V3 wall.

### 5b. Quality (not just count)

- **Severity calibration clearly better:** V3 has 8 Critical (vs 13/14) and a
  real Med/Low tail (28 findings) instead of the 89 %/82 % Crit/High inflation of
  V1/V2. A more conservative, more prioritizable distribution — and this is **directly causal**,
  because `triage_model = opus` *is* the severity-assignment stage.
- **More verified evidence:** 70/74 (95 %) "✓ verified" vs 90 %/90 %.
- **Real new attack surface:** analyzed the custom Web3 component (wallet ownership from
  request body, Web3 endpoints without auth/rate-limit, NFT mint error leak, Alchemy RPC
  unchecked) + LLM chat (prompt injection, excessive agency). These are real
  Juice Shop challenges that V2 (pure Sonnet) misses entirely.

Quality ranking: **V3 ≳ V1 > V2.**

---

## 6. What justifies Sonnet for STRIDE at all?

Stress-test of the obvious reasons — most of them collapse:

1. **Latency (Opus ~1.4× slower):** weak. STRIDE runs parallel fan-out per
   component (default-on), the wall surcharge is *one* component's latency, not N×;
   for a ~2h run producing a periodic document, negligible. Also **unmeasured**
   (V3 wall contaminated).
2. **Small/simple repos (Sonnet cheaper, no thrash):** economically irrelevant. There
   Sonnet is *relatively* cheaper, but in *absolute* terms we're talking about ~$1.50 instead of ~$3 —
   cost optimization only pays off where costs are large, and those are the **large** repos,
   where Opus wins. (Hypothesis — untested on small repos.)
3. **Capacity / rate limit / hard cost cap:** survives — but as a **degraded
   emergency mode** for mass scans, not as a default.

Sharper still: **`opus-cheap` is allocated backwards.** It gives Opus to the
**merger** (a phase the code itself describes as "too small for Opus rates") and
lets **STRIDE — the value-generating reasoning phase — starve on Sonnet**. Opus on the
cheap, structured phase; Sonnet on the open-ended, value-determining one. This contradicts the
code's own rationale.

**Legitimate home for Sonnet STRIDE:** only **`quick`** (user-chosen fast/shallow, with
already-reduced STRIDE depth) + explicit `--reasoning-model sonnet-economy` /
`--max-cost-usd`. **Never** as an automatic, size-triggered downgrade of `standard`.

---

## 7. Current behavior in the code (`scripts/resolve_config.py`)

- **Default `standard`/`thorough`** = `opus-cheap` (`resolve_reasoning_model`, ~line 498) →
  `MODEL_MATRIX["opus-cheap"]` = **stride: sonnet, triage: sonnet, merger: opus**.
- **`LARGE_REPO_SOURCE_FILE_THRESHOLD = 400`** (line 343). Juice Shop > 400 →
  `resolve_repo_size_cap` sets `repo_size_capped = True`.
- **`resolve_default_tier_for_capped_repos` (B2d, ~line 415)** then (without explicit
  `--reasoning-model`) downgrades `opus-cheap` → `sonnet-economy` — **all Sonnet**. This
  forced V1/V2 onto the *worst* reasoning variant. The size trigger is
  **backwards**: large is exactly the regime in which Opus STRIDE pays off.
- `MODEL_MATRIX["opus"]` = stride/triage/merger **all opus** (= V3, via explicit
  `--reasoning-model opus`).

---

## 8. Recommendation & integration

### Already implemented (2026-06-21) — docs/prose only, no test pins affected
Clarification of the orchestration cost formula in four places: bare "~5×" → "+25–55 %
on the total, proportional to repo size; orchestration ≈ half an Opus run":
`docs/threat-modeler.md` (×2), `skills/create-threat-model/SKILL.md`,
`scripts/run-headless.sh` (×2).

### Open — model routing (tied to verification)

**Stage 0 — verification (before any code change):** 3×3 matrix
(small / medium / large × `sonnet-economy` / `opus-cheap` / `opus`). Closes the
missing `opus-cheap` cell on Juice Shop and isolates whether **STRIDE-on-Sonnet** is the
cost driver (or triage/merger). Confirms the *magnitude*; the *direction* is
already settled.

**Stage 1 — low-risk, directly evidenced:** delete/neutralize the B2d size downgrade (`:415`),
so large repos are not forced onto all-Sonnet. Test pins
bidirectional (`test_resolve_config.py`, `test_reasoning_model_resolution.py`,
`test_haiku_routing_per_depth.py`).

**Stage 2 — the actual lever:** Default `standard`/`thorough` → **`opus`**
(STRIDE on Opus). Deprecate/redefine `opus-cheap`. Recalibrate the `estimate_duration` anchors
after a real Opus standard run (leave `_MODEL_FACTOR` duration at 1.40 if appropriate —
only the cost assumption was wrong). Sonnet STRIDE stays for `quick` + opt-out.

No new tier needed — rather **fewer** (change the default + invert the auto-switch).

---

## 9. Limits of significance

- **N = 1 repo, one language (Node/Express), three single runs.** No variance control
  (API latency, time of day, repair/retry churn). V2 may have had more churn, which
  inflates its cache-read.
- **V3 wall contaminated** (8h idle) → duration comparison only via API time.
- **Orchestration split not exactly isolable** (V2 folds everything into Sonnet).
- **Small-repo regime untested** → the "absolutely trivial" argument is inference, not
  measurement.
- What is robust is the **direction** (Opus on reasoning raises quality and is at least
  cost-neutral on large repos; Opus on the orchestrator is pure surcharge). The
  **exact percentage values** are benchmark-dependent.

---

## 10. VALIDATED 2026-06-23 — clean A/B measurement refutes the cost thesis (§5a)

The clean measurement missing in §5a has been supplied: two runs against the same
Juice Shop repo, **identical flags** (`--rebuild --assessment-depth standard --stride-cap 2`,
same code version with dispatch fix), both **clean** (0 resumes), **same threat count**.
The only variable: the reasoning tier. For the first time, Opus STRIDE ran **provably** (12 Opus dispatches);
the Sonnet run had **0 Opus** (reasoning_model=sonnet-economy, stride/triage/merger=sonnet).

| | Opus reasoning | Sonnet-economy | Δ |
|---|---|---|---|
| **Cost (`/cost`)** | **$40.78** | **$30.01** | **Sonnet −$10.77 (−26 %)** |
| Threats | 53 | 52 | ~same |
| Opus dispatches | 12 (STRIDE+triage+merger) | 0 | — |
| Run | clean (77 min) | clean (API 2h09; wall contaminated) | — |

**Finding: §5a is wrong.** All else equal, Opus reasoning is **$10.77 more expensive**,
not cheaper. The original "cost inversion" (V3 $31.78 < V2 $33.66) was an artifact —
in V1/V2/V3, STRIDE effectively ran on Sonnet; the $1.88 difference was opus- vs sonnet-**triage/merger**
+ noise, not a STRIDE effect. Mechanics of the refutation: the dominant cost item, cache-read, sits
with the **always-Sonnet orchestrator** (in the Sonnet run ~$17.70 of $30, 59.0m tokens) — which is invariant
to the STRIDE model. Opus on the reasoning does **not lower** this block, it only **adds** its
own layer. Opus = strictly additive cost.

**§5b (quality) stands — but belongs to triage, not STRIDE, and the trade-off is real and measured.**
The cheap Sonnet-economy run shows exactly the weaknesses named in §5b, because `triage_model` is now
also Sonnet:

- **Severity inflation:** 11 Critical / 31 High / 8 Medium / **2 Low** = **81 % Crit/High** (vs. the
  opus-triage-calibrated 62 % with 10 Low). Harder to prioritize.
- **Surface gap:** **no** Web3/NFT component analyzed (the verified Opus standard run had
  one). LLM/AI chatbot surface is covered.

**`--stride-cap 2` verified (live, key-gated):** 43 STRIDE threats, **no** cap violation
(≤2 per category/component, Criticals exempt — Critical-safe holds). The 9 CI/CD threats come from
`source=architectural-anti-pattern` and correctly are **not** subject to the STRIDE cap.

**Consequence for the open default recommendation (§8 Stage 2):** The rationale "Opus STRIDE better **and**
cheaper" no longer holds — cheaper it is not. It remains a pure **quality-vs-cost** trade-off
($10.77 / +36 % for better severity calibration + Web3 surface). An Opus default is therefore **not**
covered by cost; a sensible middle ground would be **Opus on triage only** (the calibration stage) with
**Sonnet STRIDE** — unmeasured, the next test.

### DECISION 2026-06-23 — standard default → sonnet-economy (implemented)

After the A/B (§10) and a content comparison of the two runs (opus-triage vs sonnet-triage, both
sonnet-STRIDE + cap), it was decided: **`standard` defaults back to `sonnet-economy`; only `thorough`
stays Opus.** Rationale:

- **Cost:** Opus reasoning at standard is ~+$10.77 (+36 %) with no substantiated benefit → the everyday default
  optimizes for cost. This finally makes the tiers a real cost ladder (quick≈$8 / standard≈$30 /
  thorough≈$42), which resolves the initial finding "standard ≈ thorough".
- **Quality:** The content comparison showed that the difference between runs is **run variance of the
  (Sonnet) STRIDE/architecture phases** (two "identical" runs shared only ~6 of ~50 findings exactly;
  one found Web3, the other LLM). The triage-model effect was **not measurable** (0 severity diffs on the
  6 matched). Opus triage calibration is confounded under the cap. → no robust quality reason for
  an Opus default.
- **Opt-in preserved:** Opus stays available at standard (`--reasoning-model opus`), as does the middle ground
  `--triage-model opus` (per-stage flag, new). Whoever wants full coverage → `thorough` (more components/turns)
  beats the tier choice, because the gap is run variance, not the model.

§8 Stage 2 (Opus as default) is thus **rejected**. Implementation: `resolve_reasoning_model` (standard→
sonnet-economy), tests, AGENTS.md/threat-modeler.md/HELP/SKILL table, CHANGELOG.
