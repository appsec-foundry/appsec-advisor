# Multi-repository vs single-repository assessment: cost and speed

**Date:** 2026-10-12

**Status:** Analysis. No code changed. Findings below are measured from two finished runs; conclusions are qualified by their scope.

**Question:** The new multi-repository assessment (`assess_repositories`, `scripts/orchestrator/orchestration_controller.py`) is noticeably faster and cheaper than the classic single-repository `create-threat-model` run. Which mechanisms cause the difference, and what can the single-repository runtime adopt?

## Compared runs

The two runs differ in target size and depth, so absolute numbers are not a like-for-like comparison. They are used to identify mechanisms, not to state a speed-up factor.

| | Single repository | Multi repository |
|---|---|---|
| Target | OWASP Juice Shop (246 routes, 8 components) | `insecure-multirepoapp` (small services; STRIDE source windows of 25–171 lines per component, 10 components) |
| Depth | `thorough` | `standard` |
| Models | Opus 5.5 for STRIDE, merger, post-STRIDE synthesizer; Sonnet 4.6 for every other agent; Haiku 5.5 for recon | Sonnet 5.5 for every role; Haiku 5.5 for recon |
| Wall clock | 99 min (`ASSESSMENT_START` → `ASSESSMENT_END`) | 41 min (`started_at` → publication) |
| Cost | ≈ 17.9 $ subagents (priced from `AGENT_USAGE`) + ≈ 5.4 $ orchestrator session (`SESSION_STOP` at `ASSESSMENT_END`; whether child usage is included was not verified) | 7.58 $ (`.assessment-state.json` accounting, 143 calls) |
| Findings | 79 (5 critical, 33 high, 41 medium) | 76 (2 critical, 40 high, 34 medium) |

Sources: the single run's `.agent-run.log`; the multi run's `.assessment-work/jobs/*.receipt.json` (role, calls, USD, source ranges) and `.assessment-work/host-events/*.jsonl` (per-call model, tools, usage, duration).

## Cost drivers

The multi run differs from the single run in four mechanisms. The first one dominates.

### 1. Single-shot calls instead of agentic tool loops

Every multi-run call is a `claude -p` host whose only tool is `StructuredOutput`. The controller assembles the source windows deterministically (`source_ranges` in each receipt), and every call finishes in 2 turns. The single run's agents use Read, Grep, and Bash and re-read their growing context on every tool turn.

| Measure | Single | Multi |
|---|---|---|
| Tool uses | 549 | 0 (one `StructuredOutput` per call) |
| Cache reads | 21.9 M tokens | ≈ 0.8 M tokens |
| Cache writes | 2.3 M tokens | ≈ 1.3 M tokens |

The abuse-case verifier shows the effect most clearly: 15 agents with 202 tool uses cost 3.49 $ in the single run; the multi run spent 0.17 $ on 2 jobs (5 calls). The multi target had fewer candidates, so part of this gap is target size.

### 2. No LLM orchestrator

The multi run is driven end to end by Python. The single run's orchestrator session cost ≈ 5.4 $ and adds one model turn between stages. The thin orchestrator already reduced this, but it remains a per-stage cost and latency.

### 3. Model and price tier

The single run used Opus 5.5 for STRIDE, merger, and synthesizer (5.80 $) and Sonnet 4.6 for the remaining agents. Sonnet 4.6 is more expensive per token than Sonnet 5.5 (`PRICING_MODELS` in `scripts/runtime/verify_run_costs.py`: output 15 $ vs 10 $, cache read 0.30 $ vs 0.10 $ per million tokens). Repricing the single run's subagent tokens at Sonnet 5.5 rates gives 10.49 $ instead of 17.92 $. About 40 % of the subagent cost difference is therefore a tier effect, independent of the runtime architecture.

### 4. Stages the multi run does not execute

The multi run has no architect review (7 agents, 2.25 $ in the single run), no threat-merger agent, and no abuse-case deriver agent. This is less work, with an unmeasured quality difference.

### Cost per role

| Role | Single: agents, USD | Multi: jobs (calls), USD |
|---|---|---|
| STRIDE analyzer | 8 (Opus), 5.04 | 10 (23), 1.92 |
| Abuse-case verifier | 15, 3.49 | 2 (5), 0.17 |
| Architect reviewer | 7, 2.25 | not run |
| Architecture analyst | 1, 1.97 | 11 (24), 0.99 |
| Evidence verifier | 1, 1.12 | 10 (20), 1.04 |
| Security-architecture renderer | 1, 0.97 | 1 (2), 0.97 |
| Control analyst | 1, 0.78 | 10 (21), 0.56 |
| Trust-boundary analyst | 1, 0.65 | 17 (35), 1.52 |
| Other roles | 6, 1.65 | 8 (13), 0.42 |

## Speed drivers

Parallelism does not explain the multi run's speed. Its 143 host calls ran almost sequentially: 2,118 s of summed call time in a 2,420 s run, about 15 s per call. Speed comes from short calls, and the model contributes only for output-heavy roles.

| Measure | Single (agents) | Multi (single call) |
|---|---|---|
| Output throughput | 50–73 tok/s for write-heavy agents such as the architect reviewer, measured on wall time including tool execution | 100–130 tok/s, measured on API time |
| Time per tool turn | 7–44 s, typically 10–20 s | not applicable |
| Abuse-case verifier | 71–181 s per case with 7–19 tool turns | 3.2 s per call |
| Security-architecture renderer | 662 s for 19.5 k output tokens with 15 tool turns | ≈ 99 s per call for ≈ 18 k output tokens |

- **Tool-heavy roles are dominated by turn count.** Abuse-case verifier, control analyst, trust-boundary analyst, and STRIDE need 10–20 round trips of 10–20 s each. A faster model cannot recover that; a single 3–15 s call does.
- **Output-heavy roles gain from the model.** Renderers, architecture analyst, and architect review generate many tokens. At ≈ 60 tok/s, 19.5 k tokens take ≈ 5.5 min; at ≈ 130 tok/s, ≈ 2.5 min.

The throughput figures are not strictly comparable: the single run exposes only wall time including tool execution, the multi run exposes API time. STRIDE output counts in the single log are partial (`output_partial`) and are excluded from throughput.

## Options for the single-repository runtime

1. **Move bounded roles to the host model.** Assemble source windows deterministically and call the model once with `StructuredOutput` only. Candidates, in order of measured leverage: abuse-case verifier, evidence verifier (its agent definition already describes bounded receipted source windows), architect reviewer, control analyst, trust-boundary analyst. The earlier threat-analyst evaluation found no quality benefit from exploration (`--explore`), which supports this direction for bounded roles.
2. **Revisit the Sonnet 4.6 pin.** The pin raises cost per token and lowers throughput relative to Sonnet 5.5. Decision MD-9 records that Sonnet 4.6 never delivers in combined STRIDE; whether the pin for the other roles is still required was not verified.
3. **Move more stage sequencing into deterministic code.** The multi run shows that the full sequence runs without an LLM orchestrator.
4. **Dispatch each STRIDE wave in one message.** The single log reports `wave_split_across_messages` twice. This saves turns but is a small lever.

## Verification needed before adoption

- **Quality is not compared.** Bounded windows can miss data flows across files that an exploring agent would follow. Each role change needs an A/B run on the same target and depth, graded with `eval-threat-model`. The abuse-case verifier is the recommended first candidate: largest measured gap, narrowly bounded input.
- **Separate model effect from architecture effect.** Run the single-repository pipeline on the same target with Sonnet 5.5 instead of the Sonnet 4.6 pin. The time and cost it saves is the model effect; the remaining gap to the host model approximates the architecture effect.

## Side observation

The multi run's `.assessment-state.json` reports `status: failed` although all deliverables were published and recorded with digests. The cause was not investigated; a step after `state.complete()` presumably raised.
