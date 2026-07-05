# Model Selection, Cost & Context Window

This is the single authoritative reference for **which model runs where** in the
create-threat-model pipeline, **what you (as plugin author or user) can control**,
and the **cost / context-window trade-offs**. It consolidates what was previously
scattered across `HELP.txt`, `SKILL.md`, `SKILL-impl.md`, and the internal
`docs/analysis/*model-placement*` / `*orchestrator-context*` notes.

## The two halves of a run

A run has two cost/compute halves that are controlled in **different** places:

| Half | What it is | Who controls the model |
|------|------------|------------------------|
| **Subagents** | STRIDE analyzers, triage, merger, renderer, QA, recon, config-scan, abuse-verifiers | **The plugin** — dispatched with an explicit `model=` from `MODEL_MATRIX` (`scripts/resolve_config.py`). Ships with the plugin; every user inherits it automatically. |
| **Orchestrator** | The main session that assembles/dispatches/writes the report | **The user's Claude Code session** — set via `/model` (interactive) or `run-headless.sh --model` (headless). A skill **cannot** set the model of the session it runs in; `ORCHESTRATOR_MODEL` in the config is *informational only*. |

The practical consequence: the plugin can make the **subagent** half cheap by
default for all users, but the **orchestrator** half is inherently the user's
choice (interactive) — the plugin can only advise there.

## Subagents — `MODEL_MATRIX` (author-controlled default)

`MODEL_MATRIX` in `scripts/resolve_config.py` maps each reasoning tier to the
model used for STRIDE / triage / merger. Tiers:

| Tier | STRIDE / triage / merger | When it's the default |
|------|--------------------------|-----------------------|
| `sonnet-economy` | **`claude-sonnet-4-6`** (cost-pinned) — but see the standard buy-back below | quick & standard (the everyday default) |
| `sonnet` | `sonnet` alias → latest Sonnet (Sonnet 5) | opt-in via `--reasoning-model sonnet` |
| `opus-cheap` | Sonnet STRIDE/triage, Opus merger | opt-in |
| `opus` | Opus everywhere | thorough default; opt-in elsewhere |

**Per-role model split (2026-07-05).** The `sonnet-economy` / default tiers are
*not* uniformly 4.6 — the subagents split by role, always a concrete id, never the
bare `sonnet` alias (which follows the session):

| Role | Agents | quick | standard | thorough |
|---|---|---|---|---|
| Reasoning core | STRIDE | 4.6 | 4.6 | Opus |
| Reasoning core | triage, merger | 4.6 | **Sonnet 5** | Opus |
| Quality showcase | renderer, abuse-verifier | 4.6 | **Sonnet 5** | **Sonnet 5** |
| Mechanical/contract | qa_content, qa_routine | 4.6 (qa_routine Haiku) | 4.6 (qa_routine Haiku) | 4.6 |
| Session | orchestrator | alias (= host session) | alias | alias |

STRIDE stays 4.6 (Sonnet 5 regressed recall). renderer + abuse-verifier are the
quality-showcase stages → latest Sonnet 5 at standard AND thorough, 4.6 only at the
cheap quick tier. qa_content + qa_routine are mechanical → 4.6 everywhere. The
orchestrator can't be pinned (it IS the session model). The whole split is skipped
for the explicit `sonnet` tier (`--reasoning-model sonnet`, latest Sonnet).
**Caveat:** these explicit-id pins only bite on the **headless path** (or
the hybrid-merger path) — an *interactive* run's subagents inherit the session
model regardless (the Agent-tool `model` param takes only tier aliases, and the
`sonnet` alias resolves to the session). So on an interactive scan the session
model still governs everything; the pins are effectively a headless default.

The deterministic-leaning periphery (context-resolver, recon-scanner, qa-routine,
config-scanner) is routed to Haiku via `EXTENDED_MODEL_MATRIX` — see
`resolve_extended_models`.

### Why the default is cost-pinned to Sonnet 4.6

Sonnet 5 and Sonnet 4.6 have the **same per-token price** ($3/$15), but Sonnet 5
uses a newer tokenizer that counts the **same text as ~30% more tokens**, and
runs adaptive thinking by default. Across ~18 subagents that inflates a full-scan
by roughly the difference between a ~$37 run (all-Sonnet-4.6) and a ~$60 run
(all-Sonnet-5) with no per-token price change. Pinning the default subagent model
to Sonnet 4.6 restores the cheaper token count **without violating the tier
principle** — 4.6 is still Sonnet tier (reasoning is never downgraded to Haiku),
just the previous version. Users who want Sonnet 5's quality opt in explicitly.

The pin lives in exactly one place (`MODEL_MATRIX["sonnet-economy"]`). When
`claude-sonnet-4-6` is eventually deprecated, bump the string there.

### Override precedence (highest wins)

```
--stride-model / --triage-model / --merger-model   (per-run CLI flag; choices: sonnet | opus)
  APPSEC_STRIDE_MODEL / _TRIAGE_MODEL / _MERGER_MODEL (env; accepts ANY exact model id)
    MODEL_MATRIX[tier]                                (shipped default)
```

- `--reasoning-model sonnet` — flip the whole subagent set to Sonnet 5 (quality).
- `--reasoning-model opus` — Opus reasoning (premium).
- `APPSEC_STRIDE_MODEL=claude-sonnet-5` — pin one stage to an exact model. The
  env vars accept any model string (the CLI flags only accept the `sonnet`/`opus`
  aliases). Set them in an `env` block in `settings.json` to apply automatically
  to every run without touching the invocation.

## Orchestrator — the session model

The orchestrator is the session the skill runs inside; the plugin cannot change
it.

- **Interactive** (`/appsec-advisor:create-threat-model`): set your default model
  once via `/config` / `settings.json`, or `/model` before the run. The skill
  prints a cost advisory when it detects Opus (mainly raises cost, not depth) or
  Haiku (too weak to orchestrate), plus a **repo-size-derived recommendation** (see
  below). It cannot set or override the session model — a divergent choice is
  honored by a clean abort + a `claude --model <X>` restart command.
- **Headless** (`scripts/run-headless.sh` / `claude -p`): the wrapper launches
  `claude -p --model <X>`, so here the orchestrator model **is** a real parameter
  — the author sets the wrapper default, users override with `--model`. The
  interactive recommendation prompt is skipped (`APPSEC_HEADLESS=1`).

### Repo-size recommendation (advisory)

`resolve_config.py:recommend_orchestrator_model` derives an advisory session model
from the repo's source-file count (`ORCHESTRATOR_SONNET5_FILE_THRESHOLD = 2500`):

| Repo size | Recommended session model | Why |
|---|---|---|
| **< 2500 source files** (e.g. Juice-Shop ≈ 641) | **`claude-sonnet-4-6`** | much cheaper, only very limited orchestrator benefit from a larger model, window sufficient |
| **≥ 2500 source files** (very large) | **`claude-sonnet-5`** | larger window avoids mid-run compaction (higher cost, but prevents compaction-induced finalization skips) |

The Pre-flight box shows the recommendation; interactively, when the detected
session diverges from it, an `AskUserQuestion` lets the user choose. **It is never
binding** — a user may consciously scan a large repo on 4.6 (it just proceeds), or
keep Sonnet 5 on a small repo. The threshold is calibrated *above* Juice-Shop so a
normal app recommends 4.6.

## Context window caveat — don't cheap-out the orchestrator

In the Claude Code harness the effective context window differs by model (e.g.
Sonnet 4.6 is capped well below Sonnet 5's 1M in the harness). This matters for
the **orchestrator**, which accumulates the largest context over a long run —
running it on a small-window model risks mid-run compaction / degradation on big
repos. It does **not** matter for the **subagents**: each is single-component
scoped and bounded (turn budgets, sliced taxonomy), sitting comfortably within
even the smaller window.

So the recommended split is size-dependent: **orchestrator on Sonnet 4.6 for
normal repos** (the cost win, no quality loss) and **on the large-window Sonnet 5
only for very large repos** (≥ 2500 files — where the window prevents compaction);
**subagents cost-pinned to Sonnet 4.6** except the standard buy-back stages. The
larger window is bought only where the larger context actually causes trouble.

## Benchmarks — measured effects of Sonnet 5 vs Sonnet 4.6

Two A/B runs on OWASP Juice Shop (standard depth, full scan) isolate the model
effect. **N = 1 repo** (Node/Express) — the *directions* below are reliable; exact
dollar/percent figures are benchmark-specific and do not generalize. Raw analyses:
`docs/internal/analysis/plan-model-routing-transparency-2026-07-04.md` (Sonnet-5 vs
Sonnet-4.6, per agent) and
`docs/analysis/analysis-model-placement-orchestrator-vs-stride-2026-06-21.md` (Opus
placement; §10 is the validated clean A/B).

### Cost — the session model dominates

| Session model | Total | Driver |
|---|---|---|
| **Sonnet 5** | ≈ **$60** | ~124M cache-read tokens on the long main session |
| **Sonnet 4.6** | ≈ **$30** (≈ half) | same work, ~30 % fewer tokens |

Same $/token — the gap is Sonnet 5's newer tokenizer counting the **same text as
~30 % more tokens** plus adaptive-thinking-by-default, multiplied across the
orchestrator's ever-growing cache-read (re-read on every dispatch). That cache-read
is the single biggest line item and it follows the **session/orchestrator** model.
**So the one real cost lever is running the session on 4.6; per-agent pins are
second-order.** Counter-consideration: the context-window caveat above — on very
large repos 4.6's smaller harness window risks mid-run compaction, which is why the
default recommendation still puts the *orchestrator* on the large-window model.

### Per-agent quality — where Sonnet 5 helps, where it hurts

| Agent | Sonnet 5 vs 4.6 (measured) | Verdict |
|---|---|---|
| `appsec-threat-merger` | dedup **0 vs 8** file:line collisions | **Sonnet 5** — quality buy-back |
| `appsec-triage-validator` | **10 vs 15** defensible Criticals (better calibration) | **Sonnet 5** — quality buy-back |
| `appsec-threat-renderer` / MS | outcome-first CISO framing | **Sonnet 5** — quality buy-back |
| `appsec-abuse-case-verifier` | 4.6 reintroduces `inconclusive` verdicts | **Sonnet 5** (tier default; 4.6 opt-in only) |
| `appsec-stride-analyzer` | **Sonnet 5 WORSE** — drops path-traversal, SSRF sink, prompt injection; folds the LLM chatbot | **stay on 4.6** — better recall **and** cheaper (win/win) |
| `qa_content`, orchestrator | no observed delta | 4.6 / session |
| recon / config / context | pure extraction | Haiku |

The headline is that Sonnet 5 is **not** a uniform upgrade: it improves the
*aggregation/judgment* stages (merge, triage, MS framing) but **regresses STRIDE
discovery recall** — the value stage — so STRIDE stays cost-pinned to 4.6.

### Opus (older validated A/B, §10 of the placement analysis)

Opus reasoning (STRIDE + triage + merger) was **$40.78 vs $30.01 sonnet-economy =
+$10.77 / +36 %** with no quality/coverage gain. Opus cost is **strictly additive**
— it adds its own layer without shrinking the invariant orchestrator cache-read.
Opus on the *orchestrator* is pure surcharge (+25–55 % of total) for zero analytic
value. Hence `standard` defaults to `sonnet-economy`; only `thorough` uses Opus.

### Practical recipe

Session on **Sonnet 4.6** (the cost lever) + quality buy-back only where it is
measured to pay: `APPSEC_MERGER_MODEL` / `APPSEC_TRIAGE_MODEL` /
`APPSEC_RENDERER_MODEL` = `claude-sonnet-5`. Keep **STRIDE on 4.6**. Mind the
resolution-≠-execution caveat: interactive dispatch can only pass tier aliases (so a
`sonnet` alias just inherits the session), which means exact-version pins land
reliably only via the headless path / a `settings.json "env"` block.

## Quick recipes

| Goal | How |
|------|-----|
| Cheapest full scan, all users, no user config | Ship `MODEL_MATRIX["sonnet-economy"] = claude-sonnet-4-6` (the default). |
| Best-quality subagents for one run | `--reasoning-model sonnet` (Sonnet 5) or `--reasoning-model opus`. |
| Pin one stage to an exact model | `APPSEC_STRIDE_MODEL=claude-sonnet-5` (env; any model id). |
| Cheap orchestrator, interactive | Set your session default model (`/config`) — the plugin can't do it for you. |
| Cheap + safe orchestrator, headless | `run-headless.sh --model <large-window model>` — don't default it to a small-window model on big repos. |
