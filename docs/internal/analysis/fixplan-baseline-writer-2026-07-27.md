# Fixplan — move the run-end baseline writer out of the skill layer

Date: 2026-07-27 · Base: `8d66de0b` (`feature/trust-boundaries-first-class`)
Status: implemented, UNCOMMITTED · full suite GREEN (10356 passed, 93 skipped)
Companion patch: `fixplan-baseline-writer-2026-07-27.patch`

**Deliberately separate** from `fixplan-scenario-and-dotpath-2026-07-27.md` and
from the trust-boundary implementation plan. Different defect, different cause,
independently reviewable and revertible.

## The defect

The 2026-07-27 juice-shop run wrote `.appsec-cache/baseline.json` with the wrong
field names:

| written | required |
|---|---|
| `last_wall_seconds` | `last_run_seconds` |
| `last_mode` | `last_run_mode` |
| `last_depth` | `last_run_depth` |
| — | `last_run_iso` |

Measured impact — the next run on this repo would have estimated:

```
with the drifted keys :  source=parametric      total=66 min
with the correct keys :  source=last_run_cache  total=101 min
```

The report itself was unaffected; only the next-run duration estimate.

## Root cause

**A data contract lived in prose that an LLM had to reproduce by hand, and
nothing verified the result.**

The writer was ~40 lines of inline bash in `SKILL-impl.md` (lines 4434–4533),
including four exact JSON key names. The orchestrator resumed after a context
compaction, and its read window ended three lines before that block:

```
4424   ### Persist the wall-clock for next-run replay
4428   … write the just-finished run's total wall-clock + mode + depth
       into `.appsec-cache/baseline.json` …
4431 ← read window ended here
4434   ```bash                       ← the normative source starts here
```

The paragraph names three concepts — *wall-clock*, *mode*, *depth* — and reads
as complete. The field names were derived from it (`last_wall_seconds`,
`last_mode`, `last_depth`) instead of from the block below. Contributing: the
runtime prescribes reading `## Completion Summary` → `## Error Handling`
(4113–4682); only 4113–4431 was read.

### Why nothing caught it

`estimate_duration.py:307-314`:

```python
last_seconds = cache.get("last_run_seconds")
if not isinstance(last_seconds, (int, float)) or last_seconds <= 0:
    return None          # → parametric fallback, no diagnostic
```

**A misspelled key is indistinguishable from a missing one.** The cache looked
populated; the estimator behaved as if it were empty.

### It had happened before

`baseline_state.py:353-358` documents a 2026-06 instance of the same contract
failing — *"exactly the gap that left `last_run_seconds=None` in the 2026-06
juice-shop anchor caches"* — and states outright that
*"the run-end finalization in SKILL-impl.md owns the writes"*. That fix was
defensive (carry the fields forward on rewrite); it treated the symptom, not the
fact that the writer itself was unverifiable prose.

## The fix

Give the contract a single owner in code, so there are no field names left to
reconstruct.

**New `scripts/persist_run_baseline.py`** — owns the four key names as module
constants, and reproduces the original semantics exactly:

- start-epoch precedence: `.agent-run.log` `ASSESSMENT_START` → `.scan-start-epoch`
  → `--fallback-epoch` (the log form excludes permission-prompt wait time)
- `run_timing.py --net-wall-seconds` wins when smaller, so an idle run does not
  inflate the next estimate
- atomic write; merges into an existing cache (never clobbers `id_counters`,
  `component_durations`, …); tolerates a corrupt cache
- best-effort by contract: no usable start signal → reports the skip **on stderr**
  and exits 0, rather than passing silently

**`SKILL-impl.md`** — 100 lines of bash replaced by a 7-line invocation, and the
surrounding prose now states that the script owns the names and must not be
restated. That paragraph is the one that was misread; it now points at the owner
instead of describing the payload.

## Verification

`tests/test_persist_run_baseline.py`, 15 tests. The load-bearing one is
`test_written_cache_is_consumed_by_estimator` — it writes via the writer and
reads via `estimate_duration._last_run_cache`, so writer and reader can no longer
drift apart. Proven to catch the original defect: with the drifted names
re-injected, the estimator returns `None` and the test fails.

Two further guards pin the names against both consumers
(`estimate_duration.py`, `baseline_state.py`), so renaming in one place breaks
the build rather than a future run's estimate.

Remaining tests cover start-epoch precedence, net-wall smaller/larger,
non-positive duration, no-signal skip, CLI exit 0 on skip, cache-key
preservation, corrupt cache, re-run overwrite, and no leftover temp file.

End-to-end, invoked exactly as `SKILL-impl.md` now prescribes:

```
run-baseline: 8896s (full/standard) via agent-run.log:ASSESSMENT_START
{"source":"last_run_cache", ...}
```

(The inflated seconds are a test artefact — the replay runs hours after the real
run, so `now − start` is large. `_net_wall_seconds` against the real output dir
returns 6089 and would have capped it during the actual run.)

Full suite: 10356 passed, 93 skipped, 0 failed.

## Already repaired in place

`<juice-shop-output>/.appsec-cache/baseline.json` was rewritten
with the four correct keys (`last_run_seconds: 6089`) and the invented ones
removed; `estimate_duration.py` now reports `source=last_run_cache` / 101 min for
that repo.

## Not addressed

The same class remains elsewhere: `SKILL-impl.md` still carries other inline bash
blocks whose exact field names matter. This fix covers the one that broke. A
sweep for further prose-borne contracts is a separate piece of work — the
trust-boundary endpoint contract (`from`/`to` as component IDs or `external`,
specified in the agent prompt but not enforced) is the same failure mode and is
tracked in `implplan-trust-boundary-repair-and-weighting-2026-07-27.md`.
