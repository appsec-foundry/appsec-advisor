# Runbook — paid acceptance runs

Every acceptance run costs a full scan. Four pre-R10 runs were rejected after
the fact because the command line was retyped and lost a flag: resolution
produced a different depth, mode, or preservation setting than the plan
requires, and the mistake surfaced only once the scan had been paid for.

The cohort is defined once in `docs/internal/acceptance-cohort.yaml`. Generate
the invocation from it; do not retype one.

## Launch a member

```bash
python3 scripts/acceptance_invocation.py print \
    --member r10 --repo <target-repo> --output-root <acceptance-root>
```

The line it prints is the invocation, including any environment prefix the
member needs. `--output-root` receives one subdirectory per member, so two
members never share run state.

Set `APPSEC_TELEMETRY_STRICT=1` for an acceptance run. It turns a telemetry
disagreement at a semantic boundary into an abort instead of a warning, so the
run cannot pass on evidence its own producers contradict. Export it in the
environment that launches the run, so the skill's Bash sees it.

## Verify before the run costs anything

As soon as `.skill-config.json` exists in the run's output directory — before
the first model dispatch — check what resolution actually produced:

```bash
python3 scripts/acceptance_invocation.py verify --member r10 --output-dir <run-dir>
```

Exit 0 prints the cohort hash and the run is a member. Exit 1 lists every field
that resolved to something else; abandon the run and fix the invocation. This
is the whole point of the tool: a wrong run is cheap to discard here and
expensive to discover later.

## Members

| Member | Depth | Producer | What it is for |
|---|---|---|---|
| `r10` | quick | context-v2 | The single rebuild checkpoint for the full lifecycle, concurrency, claim, post-STRIDE, rendering, and cleanup path |

## Prove the host integration first

The repository gates cannot exercise the installed host's hook payloads,
background scheduling, or signal propagation. Run the canary before the paid
scan so that gap does not surface after recon and later roles have been billed:

```bash
python3 scripts/live_canary.py run   --output <canary-dir> [--max-duration 900]
python3 scripts/live_canary.py check --output <canary-dir>/run
```

It scans the bundled synthetic repository under a hard wall-clock cap with
`APPSEC_TELEMETRY_STRICT=1`, then checks five properties of what the host
actually produced: a foreground child completed, a bounded parallel pair
overlapped, a completed child reported non-zero usage, every terminal call's
turn budget was retired, and live markers were cleared. `check` reads artifacts
only, so it can also be pointed at an earlier run.

A failing property names what to fix before the cohort run. Do not launch a
paid member on a red canary.

## Record the host with the result

Capture `claude --version` alongside the acceptance evidence. Hook payload
shapes are host-version specific, and the repository gates cannot prove the
installed one. If that version has no fixture in
`tests/fixtures/hook-payloads/`, capture a sanitized one and let the replay
harness run against it before the paid run, not after.

## If a run ends badly

`scripts/terminate_run.py` runs from the headless wrapper on every non-clean
exit and brings the lock, checkpoint, lifecycle, live markers, and run issues
into one terminal state. Check with `scripts/appsec_status.py --live` against
the run directory; it should report the abort immediately rather than an
unknown phase.
