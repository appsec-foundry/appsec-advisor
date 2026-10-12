# Multi-repository vs single-repository assessment: cost and speed

**Date:** 2026-10-12

**Status:** Analysis. No code changed. Findings below are measured from two finished runs; conclusions are qualified by their scope.

**Question:** The new multi-repository assessment (`assess_repositories`, `scripts/orchestrator/orchestration_controller.py`) is noticeably faster and cheaper than the classic single-repository `create-threat-model` run. Which mechanisms cause the difference, what does the session LLM orchestrator contribute, and what can the single-repository runtime adopt?

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

## Role of the session LLM orchestrator

The orchestration contract already assigns control to Python: "Python controls execution and validates state. Models decide security meaning only at explicit semantic boundaries" (`docs/internal/contracts/orchestration-actions.md`). Those boundaries are the role agents, not the orchestrator. The session LLM performs the following tasks in a single-repository run:

| Task | Semantic judgment | Deterministic alternative |
|---|---|---|
| Start the agents that `orchestration_controller.py next` names | No; relay of a controller action | Python starts tool-less `claude -p` hosts, as the multi run does |
| Business-context dialog: confirm the use case from the preview, derive one business-harm question (at most two questions) | **Yes; the only judgment the orchestrator owns** | One host call produces the questions; the session only asks them |
| Task rows, banners, `AskUserQuestion`, completion summary | No | Partly; Task rows and `AskUserQuestion` are bound to the session |
| Start and stop the watchdog, re-enter through `next` after compaction | No | Python owns both |

The orchestrator has measurable cost beyond its share of the bill (≈ 5.4 $ and one model turn per stage in the Juice Shop run). Several guards exist only to correct its behavior:

- `check_stride_dispatch.py` blocks STRIDE performed inline instead of dispatched.
- The `completion_relay` gate blocks a paraphrased completion summary.
- The Stage-1 dispatch must be phrased as a command; otherwise the orchestrator backgrounds the analyst and the 600 s ceiling kills it.
- `TELEMETRY_MISMATCH code=wave_split_across_messages` reports STRIDE waves spread over several messages (twice in the Juice Shop run).
- After context compaction the orchestrator must rehydrate from the filesystem.

**Headless mode keeps the orchestrator without any of its interactive tasks.** `scripts/run-headless.sh` hands two or more `--repo` selections to `orchestration_controller.py assess` (line 236) but runs a single repository as `claude -p` with the `create-threat-model` skill. A headless single-repository run therefore pays for a session LLM that asks no questions and shows no UI.

The orchestrator cannot be removed on its own in interactive mode. Only the session may dispatch Level-0 agents, and the role agents need Read, Grep, and Bash. Removing it requires the role conversion in step 1 below first.

## Recommendation

**Make orchestration deterministic; keep the LLM for semantic roles, called as bounded single calls.** The decision separates three layers:

| Layer | Recommendation |
|---|---|
| Orchestration: sequence, dispatch, retries, gates, status | Deterministic Python controller, as in `assess_repositories` |
| Semantic roles: STRIDE, evidence, abuse-case verification, rendering, and the other role agents | LLM, called once per job with deterministically assembled source windows and `StructuredOutput` only, instead of an agent with a tool loop |
| Business-context dialog | LLM generates the questions; the session asks them |

Order of adoption:

1. **Convert the abuse-case verifier to a host call and compare it A/B.** It has the largest measured gap per role (3.49 $ vs 0.17 $) and a narrowly bounded input. Continue with the evidence verifier (its agent definition already describes bounded receipted source windows), architect reviewer, control analyst, and trust-boundary analyst. The earlier threat-analyst evaluation found no quality benefit from exploration (`--explore`), which supports this direction for bounded roles.
2. **Run headless single-repository assessments through the Python controller.** This removes the session LLM where it has no interactive task. `assess` currently requires at least two `--repo` selections and has no architect review, threat merger, or QA reviewer stage; the gap to the single-repository pipeline must be closed or deliberately accepted.
3. **Reduce the interactive session to preflight, dialog, and model selection.** The session then starts the controller as one background command, follows a progress file, and relays the finished summary unchanged.

Independent of that order:

- **Retire the Sonnet 4.6 session prompt with the orchestrator, and give every role an explicit model.** The interactive session-model question (`SKILL-full-runtime.md` §2a) and `_session_model_advisory` in `scripts/runtime/resolve_config.py` only exist because the session model drives cost. Several roles (renderer, abuse-case verifier, and others listed as "follows session") inherit the session model; without a session orchestrator they need an explicit controller-assigned model, as `assess` already does.
- **Revisit the Sonnet 4.6 economy pin separately.** The pin for STRIDE, triage, and merger in `resolve_config.py` is independent of the orchestrator. Its rationale (2026-07-04: same price per token, about 30 % fewer tokens than Sonnet 5) predates Sonnet 5.5, which the current price table lists as cheaper per token than Sonnet 4.6; the token-count difference for Sonnet 5.5 was not measured. Decision MD-9 records that Sonnet 4.6 returns no artifact from a tool-less STRIDE call, so any role converted to a host call cannot keep the pin.
- **Record the architecture choice as a decision** in `docs/internal/decisions.md` once it is made, with operator-confirmed wording.

## Verification needed before adoption

- **Quality is not compared.** Bounded windows can miss data flows across files that an exploring agent would follow. Each role change needs an A/B run on the same target and depth, graded with `eval-threat-model`.
- **Separate model effect from architecture effect.** Run the single-repository pipeline on the same target with Sonnet 5.5 instead of the Sonnet 4.6 pin. The time and cost it saves is the model effect; the remaining gap to the host model approximates the architecture effect.
- **Interactive progress and cancellation** need a replacement for Task rows and session interrupts once the controller runs as a background process.
- **Not verified:** whether `claude -p` hosts started from an interactive session are billed and permitted like subagents. The multi run shows only that they work headless.
- **Not verified:** whether the session LLM contributes judgment in Stage 3 repair and Stage 4 beyond relaying controller actions. This analysis read the ownership sections, not `SKILL-thin-stage3.md`.

## Side observation

The multi run's `.assessment-state.json` reports `status: failed` although all deliverables were published and recorded with digests. The cause was not investigated; a step after `state.complete()` presumably raised.
