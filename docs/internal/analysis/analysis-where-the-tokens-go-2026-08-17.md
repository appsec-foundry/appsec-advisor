# Where a run's tokens actually go

Measured on the 2026-08-17 juice-shop run (`--rebuild`, standard depth, seven
components, one STRIDE retry). It answers a question context-v2 was built to
settle and did not: per-agent context came down, total cost did not.

## What the run cost, and where the figure comes from

The run's own closing summary is the authority: **$25.39** — $24.96 on
sonnet-4-6 (116.9k input, 481.3k output, 32.4M cache read, 1.8M cache write)
and $0.43 on haiku-4.5. Wall clock 6h54m against 2h42m of API time; the
difference is a wait for the 5-hour usage window to reset.

Mid-run `SESSION_STOP … cost=` is **not** that figure. It counts the
orchestrator session and reached $12.80 while the run was still rendering. The
sum of the run's 16 `AGENT_USAGE` records exceeds it in every dimension — out
341,761 vs 167,661, cache_write 2,255,047 vs 812,869, cache_read 24,818,437 vs
18,784,896 — so the session line does not contain the sub-agents.

It does not follow that the two are disjoint and additive. Adding them gives
43.6M cache reads against the 34.1M the run actually billed, so they overlap.
Neither view is the total. **Take the cost from the closing summary; treat
`SESSION_STOP` as orchestrator-only progress.**

## Method

`cache_read / tool_uses` approximates the context an agent carries per turn.
`tool_uses` is not exactly a turn count and cache behaviour is not uniform, so
these are magnitudes, not measurements.

The approximation is checked against a case where the answer is known
independently: the post-STRIDE synthesizer's projection on disk is 175,798
bytes (~44k tokens) and the derived figure is 49,472. Where the orchestrator
sends a large context, the derivation finds it.

## Where the tokens are

| | cache_read | share |
|---|---:|---:|
| STRIDE analyzers (8 runs incl. one retry) | 14.5 M | **57%** |
| Recon | 3.1 M | 12% |
| Everything else | 8.0 M | 31% |
| **total** | **25.6 M** | |

Per agent:

| Agent | turns | cache_read | ≈ context/turn |
|---|---:|---:|---:|
| phase2-recon | 21 | 3,069,688 | **146,175** |
| phase8-controls | 19 | 1,714,113 | 90,216 |
| phase3-6-architecture | 28 | 2,104,212 | 75,150 |
| phase10a-evidence | 19 | 1,360,104 | 71,584 |
| stride:api-server | 41 | 2,934,055 | 71,562 |
| stride:angular-spa | 32 | 1,902,446 | 59,451 |
| stride:auth-guard | 22 | 1,278,013 | 58,091 |
| stride:sqlite-db | 36 | 1,911,371 | 53,093 |
| stride:ci-cd-pipeline | 17 | 866,771 | 50,986 |
| phase9-merge-review | 9 | 445,255 | 49,472 |
| phase10b-root-causes | 7 | 346,308 | 49,472 |
| ms-renderer | 16 | 754,272 | 47,142 |

## The projection is not the problem

What the orchestrator actually sends a STRIDE analyzer, from
`.dispatch-context/`:

```
sqlite-db          15,303 B  ≈ 3,825 tok      angular-spa   32,658 B  ≈  8,164 tok
web3-nft           19,932 B  ≈ 4,983 tok      api-server    38,983 B  ≈  9,745 tok
realtime-channel   20,515 B  ≈ 5,128 tok      post-stride  175,798 B  ≈ 43,949 tok
auth-guard         25,223 B  ≈ 6,305 tok
```

Plus a ~3k agent definition. For `sqlite-db` that is under 7k against 53k
observed — a factor of eight. The projection works and is role-specific; it is
simply not what fills the context.

The gap is what the analyzer reads itself. Source windows from the target
repository stay in its context and are re-read on every later turn, so
`api-server` pays for its early greps 41 times. Better projection cannot reach
that, because the orchestrator does not choose those reads.

## `maxTurns` is not a lever

`appsec-stride-analyzer-v2` carries `maxTurns: 96`. The highest observed usage
is 41 (`api-server`); the rest sit between 17 and 36. Recon uses 21 of 36, the
post-STRIDE synthesizer 7 of 20. Only the merger is close, at 9 of 12.

Lowering the ceiling changes nothing until it drops below 41, and then it
truncates an analysis rather than making one cheaper. This also closes out the
cheap-STRIDE question for good: the light tier lowers a ceiling nobody reaches,
which is why a `light` component ran *longer* than a `full` one in the same
wave in two consecutive runs (589 s vs 462 s, then 480 s vs 352 s).

## What would actually reduce it

**1 — Split the analyzer per category group.** The split point already exists:
the analyzer logs `Writing STRIDE findings Spoofing+Tampering` and then
`Repudiation+InfoDisclosure+DoS+EoP`. Dispatching those as two agents gives the
second a fresh context instead of inheriting the first's source windows.

Order of magnitude: one agent whose context grows to 71k over 41 turns
accumulates ~2.9 M. Two agents of ~20 turns each, growing to ~40k, come to
about 1 M together. The cost is a second fixed prelude per component — agent
definition plus projection, under 10k — which is nothing against 14.5 M. The
change is in the orchestrator and needs no cooperation from the model, which is
what makes it worth doing first among the analyzer levers.

The arithmetic assumes context grows linearly and turns divide evenly. Neither
is measured. Split one analyzer and compare its two `cache_read` values against
`api-server`'s 2.9 M before building it out.

**2 — Recon.** 146k per turn, double every other role, and its output is the
513-line summary that then rides along in every downstream prompt. It is the
only item where cutting saves both tokens and wall-clock. Five runs have now
produced 477 / 530 / 500 / 513 / 513 lines against a target of 200, twice on
different models with the same 513 — the length comes from the mandated 7.1–7.32
sub-section structure, not from model verbosity. Enforcing the target through a
producer retry would loop against a structure that cannot meet it. Either the
target or the structure has to change, and that is a decision about how much
reconnaissance detail the pipeline wants.

**3 — Fewer, larger agents.** Seven analyzers at ~60k each exceed the single
~180k monolith context-v2 replaced. Parallelism bought wall-clock and paid in
tokens. Batching internal-only components into one call is the trade if cost
outweighs latency; it is already recorded as the real cheap-STRIDE lever.

## What to stop considering

- **Item C** (`artifact_receipts` out of the action payload): 12,717 bytes per
  dispatch, measured. Noise against 25.6 M, and it costs a contract change.
- **`maxTurns`**: see above.
- **The QA checks**: the deterministic gate runs 25+ checks in 6 seconds.

## The uncomfortable part

Cost scales almost linearly with how much source the analyzers read, and that
reading is the product. Levers 1 and 2 are genuine efficiency — the same
analysis for less. Lever 3 trades tokens for latency. Anything beyond them buys
savings with coverage.
