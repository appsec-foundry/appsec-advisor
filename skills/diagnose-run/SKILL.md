---
name: diagnose-run
description: >-
  Find the plugin defects behind the issues a create-threat-model run recorded.
  Reads `.run-issues.json`, re-reads each symptom next to the plugin's own code,
  and reports a `file:line` root cause per issue, or classifies it as an
  environment or expected condition. Read-only against the plugin; writes only
  `.run-bugs.json`. Requires plugin-developer mode (`APPSEC_PLUGIN_DEV=1`).
  Use it when a run offered a root-cause assessment and you deferred it, or
  when the completion summary listed Run Issues you want explained.
---

You are the **diagnose-run** skill. A finished run recorded *symptoms* in
`$OUTPUT_DIR/.run-issues.json` — "a `TOOL_ERROR` fired at log line 812". This
skill turns them into *causes* — "`scripts/merge_threats.py:412` writes a
component id the renderer cannot resolve" — by dispatching the
`appsec-run-diagnostician` agent against this repository's own code.

It never fixes anything. `/appsec-advisor:fix-run-issues` remains the only
writing path.

The run itself does not do this work: the diagnostician is a sub-agent, so its
wall-clock and tokens would land in the run's own duration and cost figures and
describe the scan plus its own diagnosis. That is why the offer comes after the
completion summary, and why this skill exists for the deferred case.

## `--help` — inline help (early exit)

If the user's arguments contain `--help` or `-h`, print this block verbatim
and exit. Do not call any tools.

```
/appsec-advisor:diagnose-run — Root-cause the issues a run recorded.

USAGE
  /appsec-advisor:diagnose-run [--repo <path>] [--output <path>]

FLAGS
  --repo <path>     Repository the run assessed (default: current working dir)
  --output <path>   Output directory of that run (default: <repo>/docs/security)
  --help, -h        Show this help and exit

REQUIRES
  APPSEC_PLUGIN_DEV=1        plugin-developer mode
  .run-issues.json           written by the run; kept on disk when a run
                             offered a diagnosis and you deferred it

WRITES
  .run-bugs.json             one verdict per issue, rendered to the console
```

## Step 1 — Parse arguments

Recognized flags (and the values consumed by `--repo` / `--output`):

  `--repo <path>`  `--output <path>`  `--help` | `-h`

Default `REPO_ROOT` to the current working directory and `OUTPUT_DIR` to
`$REPO_ROOT/docs/security`; the flags override them. Any other token is a hard
failure: print `Error: unknown argument '<TOKEN>'` followed by the flag list
above to stderr and exit `2` without touching a file.

## Step 2 — Gate

Both conditions must hold. Print the message and exit `1` when one fails.

- `APPSEC_PLUGIN_DEV=1` in the environment. Otherwise:
  `Plugin-developer mode is off (APPSEC_PLUGIN_DEV=1). A root-cause assessment
  reads the plugin's own source, which only helps if you can change it. To
  report a run problem instead, use /appsec-advisor:report-error.`
- `$OUTPUT_DIR/.run-issues.json` exists and its `issues` array is non-empty.
  Otherwise: `No recorded run issues in <OUTPUT_DIR>. A clean run has nothing
  to diagnose, and cleanup reaps the file unless a run deferred its diagnosis.`

## Step 3 — Diagnose

Delete a stale sidecar first, so a failed dispatch cannot leave the previous
run's diagnosis behind:

```bash
rm -f "$OUTPUT_DIR/.run-bugs.json"
```

Then invoke the `appsec-advisor:appsec-run-diagnostician` agent — Agent tool
`description`: `"Diagnose plugin bugs from this run"`, with
`run_in_background: false`. Do **not** end your turn until it returns. Pass in
the prompt:

- `OUTPUT_DIR=<absolute output path>`
- `REPO_ROOT=<absolute repo path>`
- `PLUGIN_ROOT=$CLAUDE_PLUGIN_ROOT`
- `ASSESSMENT_DEPTH=<the run's depth, or standard when unknown>`
- `EXAMINE_CAP=12`
- `MODEL_ID=<the model the agent runs on>`

## Step 4 — Render

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/render_run_diagnosis.py" \
    --output-dir "$OUTPUT_DIR" --plugin-root "$CLAUDE_PLUGIN_ROOT"
```

Reproduce its stdout **verbatim as response text** — the Claude Code UI
collapses Bash results, so a block that lives only in the tool output is
invisible. Never hand-author the block and never substitute the agent's
one-line return for it. The script owns the format and validates
`.run-bugs.json` against `schemas/run-bugs.schema.json`; a missing, malformed,
or schema-violating sidecar prints one stderr warning and nothing else.
