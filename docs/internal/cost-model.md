# Run cost

What a run costs, how to measure it without getting a wrong number, and which
savings have already been ruled out. New measurements go in the findings log at
the bottom; the sections above are rewritten when a measurement changes them.

## Measuring a run

```
python3 scripts/cost_running_total.py <output-dir> --format json
```

Three properties of the telemetry decide whether a figure is meaningful. Getting
any of them wrong has produced a number off by a factor, more than once.

**A `SESSION_STOP` snapshot covers the session that emitted it.** Sub-agents run
in their own sessions and report through `AGENT_USAGE`. They carry the larger
half of a run, so a figure taken from the host session alone is not a run cost.

**The host session outlives the assessment.** Its counter is cumulative and keeps
growing while the user works on afterwards in the same session. The last
snapshot in the log therefore charges the run for everything that followed it.
The window closes at the last event a pipeline role wrote to `.agent-run.log`,
plus a grace window for the snapshot that reports it.

**Some agents never report usage.** The abuse-case verifiers run through a host
path that returns no per-call usage, logged as `TELEMETRY_MISMATCH
code=usage_source_absent`. Their spend is missing from every total. When
`cost_is_floor` is set, the figure is a lower bound and the banner prints `≥`.

Never compare figures across scopes. A run-to-run comparison is only valid when
both numbers came from the same window and the same set of sessions.

## Baseline

juice-shop, 2026-08-17, `--rebuild`, standard depth, seven components, one
STRIDE retry, Sonnet list prices.

| | tokens | $ | share |
|---|---:|---:|---:|
| `cache_read` | 50,287,879 | 14.48 | 41% |
| `cache_write` | 3,383,807 | 12.08 | 35% |
| output | 567,987 | 8.37 | 24% |
| **total** | | **≥34.93** | |

By actor: host session $12.80, the eight STRIDE analyzer runs $12.00, the other
ten sub-agents $10.13. Seven abuse verifiers are unmetered on top.

Cost does not follow token volume, because a `cache_read` token is priced at a
fiftieth of an output token. STRIDE is 53% of the run's `cache_read` and 34% of
its cost. Recon is the single largest context per turn at 146k and costs $0.69,
because it runs on Haiku.

## Where the cost comes from

**Context accumulates inside an agent.** Each turn adds to the context and every
later turn re-reads it, so an agent's `cache_read` grows with the square of its
turn count. Measured growth is 2,600 to 4,700 tokens per turn, on a base of the
projection plus the ~3k agent definition.

**The orchestrator is turn count, not context size.** Its 52,700 tokens per turn
is the second-lowest of any role — the thin-orchestrator design holds. It is
expensive because it takes ~556 tool calls in one session that never resets, of
which 317 complete in under a second. At least 52 are standalone `log_event.py`
calls whose only product is a log line.

**Idle time costs money.** A wait past the cache TTL forces the next turn to
re-prefill cold. In the baseline run, the first turn after a 5h09m standby wrote
352,840 cache tokens, $1.32.

## Levers

### Ruled out

**Splitting the STRIDE analyzer per category group.** The mechanism is real — two
agents of half the turns each halve the quadratic term. The ceiling is $1.88,
and $2.18 even if the fixed prelude were free. Against that it needs eight
production files including the dispatch contract, the completeness gate in
`stride_dispatch_waves.py` and the `local_id` allocation that `merge_threats.
_remap_scenario_local_refs` depends on. The baseline run also contains the
counter-experiment: `web3-nft` attempt-2 is a fresh agent on the same component
and needed 31 turns for six categories against attempt-1's 33. A second agent
re-reads the sources rather than inheriting them, so the even turn split the
estimate assumes does not happen.

**Batching components into fewer, larger agents.** The same quadratic model that
makes splitting save tokens makes batching cost them. What batching saves is one
fixed prelude per component, under 10k. It buys latency, not cost.

**`maxTurns`.** The frontmatter ceiling of 96 binds nothing. The ceiling that
reaches the model is `analysis.max_turns` in each component's `context-plan.json`
— 8 to 80 in the baseline run — and it is a soft instruction: `ci-cd-pipeline`
used 17 of 8 and `realtime-channel` 29 of 20. Lowering it does not save; it
truncates. `web3-nft` attempt-1 stopped at exactly its 33 and produced no output
at all, which cost a full retry.

**`artifact_receipts` in the dispatch payload.** 12,717 bytes per dispatch, about
3.2k tokens, re-read on each of the 241 STRIDE turns: ~0.77M `cache_read`, $0.23.
It costs a contract change.

**The deterministic QA gate.** 25+ checks, seconds of wall-clock, no model
tokens.

### Open

**Turns that produce nothing.** Every `log_event.py` call is a full model turn
that re-reads the session context to append one line. Folding them into the
adjacent script invocation is a local change with no effect on coverage.

**`cache_write`.** $12.08 of the baseline run, 35%, and never examined. Per
token it is 12.5 times the price of `cache_read`.

**The recon summary's length.** Five runs produced 477 / 530 / 500 / 513 / 513
lines against the target of 200 in `agents/appsec-recon-scanner.md`, twice on
different models with the same 513. The length comes from the mandated 7.1–7.32
sub-section structure, so a producer retry would loop against a structure that
cannot meet the target. Either the target or the structure has to change. This
is a token lever, not a cost lever: recon itself runs on Haiku, and the saving
lands in the downstream prompts the summary rides along in.

## Findings log

**2026-08-17 — the reported cost was the orchestrator session only.** A run
reported at $11.20 cost ≥$34.93. Nothing aggregated `AGENT_USAGE`:
`agent_logger.py` writes it, four scripts read it for lifecycle and durations,
none priced it. `cost_running_total.py` assumed one cumulative session per
`session_id`, but every `SESSION_STOP` in `.hook-events.log` carries the same
id — host snapshots and sub-agent one-shot totals interleaved under one
identity.

**2026-08-17 — the run window has no end marker.** `verify_run_costs.
find_run_window` keys on `ASSESSMENT_START` / `ASSESSMENT_END` and reviewer end
events; none of them fire on the thin-orchestrator pipeline, so it returns
`(None, None)` and the whole path is dead. `cost_running_total.py` had a start
and no end. Measuring the baseline run while the host session continued working
produced three different "final" figures — $12.80, $17.13, $22.53 — from the
same log within twenty minutes.

**2026-08-17 — cost scales with how much source the analyzers read.** That
reading is the product. The levers above are either efficiency at the margin or
a trade of tokens against latency; beyond them, savings come out of coverage.
