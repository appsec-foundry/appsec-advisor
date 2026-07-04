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
| `sonnet-economy` | **`claude-sonnet-4-6`** (cost-pinned) | quick & standard (the everyday default) |
| `sonnet` | `sonnet` alias → latest Sonnet (Sonnet 5) | opt-in via `--reasoning-model sonnet` |
| `opus-cheap` | Sonnet STRIDE/triage, Opus merger | opt-in |
| `opus` | Opus everywhere | thorough default; opt-in elsewhere |

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
  Haiku (too weak to orchestrate). It cannot set or override the session model.
- **Headless** (`scripts/run-headless.sh` / `claude -p`): the wrapper launches
  `claude -p --model <X>`, so here the orchestrator model **is** a real parameter
  — the author sets the wrapper default, users override with `--model`.

## Context window caveat — don't cheap-out the orchestrator

In the Claude Code harness the effective context window differs by model (e.g.
Sonnet 4.6 is capped well below Sonnet 5's 1M in the harness). This matters for
the **orchestrator**, which accumulates the largest context over a long run —
running it on a small-window model risks mid-run compaction / degradation on big
repos. It does **not** matter for the **subagents**: each is single-component
scoped and bounded (turn budgets, sliced taxonomy), sitting comfortably within
even the smaller window.

So the recommended split is: **orchestrator on the large-window model** (your
session — Sonnet 5), **subagents cost-pinned to Sonnet 4.6** (the `MODEL_MATRIX`
default). The larger window sits where the larger context lives.

## Quick recipes

| Goal | How |
|------|-----|
| Cheapest full scan, all users, no user config | Ship `MODEL_MATRIX["sonnet-economy"] = claude-sonnet-4-6` (the default). |
| Best-quality subagents for one run | `--reasoning-model sonnet` (Sonnet 5) or `--reasoning-model opus`. |
| Pin one stage to an exact model | `APPSEC_STRIDE_MODEL=claude-sonnet-5` (env; any model id). |
| Cheap orchestrator, interactive | Set your session default model (`/config`) — the plugin can't do it for you. |
| Cheap + safe orchestrator, headless | `run-headless.sh --model <large-window model>` — don't default it to a small-window model on big repos. |
