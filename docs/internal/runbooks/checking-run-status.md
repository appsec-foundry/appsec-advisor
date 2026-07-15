# Checking run status (is a scan running? how far along?)

Answers "is a threat-model scan running against repo X, and where is it?"
**without** guessing from process lists or the repo-root `.agent-run.log`.

All three tools are **read-only**: they never analyze, write, or dispatch an
agent, and grant the skill no new permissions. Safe to run at any time,
including against a repo that is being scanned right now.

## The one gotcha: where a live run actually writes

A live run's heartbeat and progress sidecars live under the **OUTPUT_DIR**
(`<repo>/docs/security` by default), *not* the repo root.

The repo-root `<repo>/.agent-run.log` can be a **stale artifact from a prior
run**: a scan that died hours ago leaves an old log there, while a fresh scan
writing to `docs/security/` looks — to a naive tailer — like nothing is
happening. Do **not** infer liveness from that file, and do **not** grep for
processes (a run driven from another terminal/session has no distinctive
process name). Use the helpers below; they read the OUTPUT_DIR and report
heartbeat freshness.

## Snapshot: is it alive, and what is it doing right now?

```bash
python3 scripts/appsec_status.py --repo /path/to/repo --live
```

Prints the in-flight snapshot: current phase + checkpoint status,
`heartbeat_age` vs. the phase's `stall_threshold`, the active progress line
(`.appsec-progress.json`), and each active tool call (`.active-tool-calls/`)
with its age, agent, tool, and truncated input.

Read it like this:

- `heartbeat_age` well under `stall_threshold` → **alive**.
- `heartbeat_age` past the threshold, or no active tool calls and an old
  checkpoint → **stalled or dead** (a run driven from another session that
  crashed leaves no process to find, so age is the signal, not `ps`).

When the previous run ended **without** producing `threat-model.md` and no scan
is currently live, the snapshot leads with a **last-run verdict** — the same
`cutoff_cause.py` classification the in-run cut-off banners use (`api_stall` vs
`session_death` vs `budget`), plus the `--resume` recovery hint. This is the
robust surface for the plugin-fault-vs-API question: the in-run banner only
prints while the orchestrator turn survives, but this verdict renders in the
next live status turn regardless. It is suppressed while a scan is genuinely
running (lock held by a live pid) so an in-progress run is never mislabelled.
The `--json` forms carry it under the `cutoff` key (`{kind, block}`, or `null`).

Add `--json` for cron-style polling from a second terminal or the IDE:

```bash
python3 scripts/appsec_status.py --repo /path/to/repo --live --json
```

Equivalent skill form (same helper underneath):

```
/appsec-advisor:status --repo /path/to/repo --live
```

The bare `/appsec-advisor:status` (no `--live`) prints the broader
plugin/last-run overview — version, available capsules, last-run identity,
config sources, fast-path preview — rather than the in-flight snapshot.

## Follow: watch phase transitions and stalls as they happen

For a live, phase-aware tail (instead of repeated snapshots) point
`watch_run.py` at the **OUTPUT_DIR**, not the repo root:

```bash
python3 scripts/watch_run.py /path/to/repo/docs/security
python3 scripts/watch_run.py /path/to/repo/docs/security --depth thorough
python3 scripts/watch_run.py /path/to/repo/docs/security --once   # snapshot, no follow
```

It tails `.hook-events.log`, emits one line per relevant event
(`PHASE_*`, `STEP_*`, `AGENT_INVOKE`, `FILE_WRITE/EDIT`, `HEARTBEAT`,
`ERROR/FAIL`, `SCAN_*`, `ASSESSMENT_*`), and — crucially — applies a
**per-phase** silence threshold from `PHASE_DURATION_LIMITS_SECONDS`
(× `--stall-multiplier`, default 1.5). A flat threshold false-positives during
legitimately silent phases (Triage and fragment authoring each run minutes as a
single LLM call); the per-phase matrix does not. It emits a single `STALL` line
only when a genuinely stuck phase exceeds its own budget.

## Which to reach for

| Need | Use |
|---|---|
| One-shot "is it alive / what now?" | `appsec_status.py --live` |
| Same, machine-readable for polling | `appsec_status.py --live --json` |
| Continuous follow + stall detection | `watch_run.py <output_dir>` |
| Broader plugin/last-run overview | `appsec_status.py` (no `--live`) |
