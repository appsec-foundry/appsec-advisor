# Checking run status (is a scan running? how far along?)

Use the status helpers to check whether a scan is running and which phase it has reached.

The helpers only read run state. They do not analyze code, write artifacts, dispatch agents, or require new skill permissions. You can use them during an active scan.

<a id="the-one-gotcha-where-a-live-run-actually-writes"></a>
## Run-state location

A live run's heartbeat and progress sidecars live under the **OUTPUT_DIR**
(`<repo>/docs/security` by default), *not* the repo root.

The repository-root `.agent-run.log` may belong to an earlier run. Process names also do not reliably identify a scan started in another session. Use the helpers below to read the active output directory and check heartbeat freshness.

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

If the previous run produced no `threat-model.md` and no scan is active, the snapshot shows a last-run verdict and recovery hint. It uses the same `cutoff_cause.py` classifications as the in-run banner: `api_stall`, `session_death`, or `budget`. Unlike that banner, the verdict remains available after the orchestrator exits. It is suppressed while a live process holds the run lock. JSON output carries it under `cutoff` as `{kind, block}`, or `null`.

Add `--json` for cron-style polling from a second terminal or the IDE:

```bash
python3 scripts/appsec_status.py --repo /path/to/repo --live --json
```

Equivalent skill form (same helper underneath):

```
/appsec-advisor:status --repo /path/to/repo --live
```

Without `--live`, `/appsec-advisor:status` shows the plugin version, available capsules, last-run identity, configuration sources, and fast-path preview.

## Follow: watch phase transitions and stalls as they happen

For a live, phase-aware tail (instead of repeated snapshots) point
`watch_run.py` at the **OUTPUT_DIR**, not the repo root:

```bash
python3 scripts/watch_run.py /path/to/repo/docs/security
python3 scripts/watch_run.py /path/to/repo/docs/security --depth thorough
python3 scripts/watch_run.py /path/to/repo/docs/security --once   # snapshot, no follow
```

The watcher reads `.hook-events.log` and prints phase, step, agent, file, heartbeat, error, and assessment events. It emits one `STALL` line when a phase exceeds its silence threshold from `PHASE_DURATION_LIMITS_SECONDS`, multiplied by `--stall-multiplier` (default 1.5). Phase-specific thresholds allow for long LLM calls during triage and fragment authoring.

## Which to reach for

| Need | Use |
|---|---|
| One-shot "is it alive / what now?" | `appsec_status.py --live` |
| Same, machine-readable for polling | `appsec_status.py --live --json` |
| Continuous follow + stall detection | `watch_run.py <output_dir>` |
| Broader plugin/last-run overview | `appsec_status.py` (no `--live`) |
