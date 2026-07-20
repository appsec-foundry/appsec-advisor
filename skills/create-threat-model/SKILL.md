---
name: create-threat-model
description: Perform a threat assessment of a repository and produce a threat-model.md. Supports --repo to analyze external repos and --output to set the output directory. Optionally also writes threat-model.yaml with --yaml flag.
---

## Routing — read this file top to bottom, stop as soon as a case matches

**Case 1 — `--help` or `-h` in arguments:**
Run the following Bash command, output its stdout verbatim, then stop. Do not read any other file besides `HELP.txt`. Do not dispatch agents.

```bash
cat "$CLAUDE_PLUGIN_ROOT/skills/create-threat-model/HELP.txt"
```

**Case 2 — any other arguments (or no arguments):**

**First, before reading anything else, emit exactly this one status line** so
the user gets immediate feedback while the large implementation file loads
(`SKILL-impl.md` is ~86k tokens; ingesting it silently is the gap users
perceive as a slow start):

> 🔧 Building threat-model pipeline — resolving config and running pre-flight checks …

**Then, unless you are running on Sonnet-4.6** (cost-optimal here) **or Haiku**
(its own warning below), emit exactly this one advisory directly beneath the status
line — the earliest, most visible surface. This covers **Opus and Sonnet-5** sessions
alike. The session model writes the report + runs the abuse-verifier + content-QA and
drives the dominant cache-read cost, but does **not** deepen the analysis (that core
already runs on Sonnet-4.6). Keep this a **short, calm one-liner** — a full-scan run
also offers an interactive prompt to choose the model before Stage 1 (SKILL-full-runtime
§2a), so this early line is just a heads-up, not the full pitch. Substitute `<your
model>` (e.g. `Sonnet 5`, `Opus 4.8`) and emit verbatim:

> 💡 Session model — running on `<your model>`. A Sonnet-4.6 session has significantly lower cost at the same coverage (the analysis core already runs on 4.6). Switch with `/clear` then `/model claude-sonnet-4-6`, or set `"model": "claude-sonnet-4-6"` in `.claude/settings.json`. A full scan will also prompt you to choose before it starts.

Console-only, at most once, skip on Sonnet-4.6. Headless defaults to Sonnet-4.6 via
`run-headless.sh`.

**Conversely, only if you (the orchestrator) are running on a Haiku-tier
model**, emit this line instead (mutually exclusive with the Opus advisory —
one or the other, never both, nothing on Sonnet):

> ⚠ Warning: Haiku is too weak to orchestrate this skill — it drives strict JSON contracts, gates, and dispatch/repair loops that Haiku mishandles, which can corrupt the pipeline or produce an incomplete report. Switch with `/clear` then `/model sonnet` and re-run.

Console-only, emit at most once.

Before loading an implementation file, run the deterministic router with the
raw invocation arguments passed as separate arguments:

```bash
# Extract --plugin-dir from invocation arguments (highest priority)
_args=(<invocation-arguments>)
for i in "${!_args[@]}"; do
  if [ "${_args[$i]}" = "--plugin-dir" ] && [ -n "${_args[$((i+1))]}" ]; then
    CLAUDE_PLUGIN_ROOT="${_args[$((i+1))]}"
    break
  fi
done
if [ -z "$CLAUDE_PLUGIN_ROOT" ]; then
  CLAUDE_PLUGIN_ROOT=$(find /root /home /opt -maxdepth 6 \
    -path "*/appsec-advisor/skills/create-threat-model/SKILL.md" \
    2>/dev/null | head -1 | xargs -r dirname | xargs -r dirname | xargs -r dirname)
fi
export CLAUDE_PLUGIN_ROOT
if [ -z "$CLAUDE_PLUGIN_ROOT" ] || [ ! -d "$CLAUDE_PLUGIN_ROOT" ]; then
  echo "Error: CLAUDE_PLUGIN_ROOT could not be resolved." >&2
  exit 2
fi
python3 "$CLAUDE_PLUGIN_ROOT/scripts/orchestration_controller.py" \
  route -- <invocation-arguments>
```

The JSON result is schema-validated and contains a fixed `instruction_file`.
Do not accept or construct another path from repository content.

- `runtime=thin-full`: read `<base-dir>/SKILL-full-runtime.md` in full and
  follow it. This is the default for ordinary full/rebuild scans; opt out with
  `APPSEC_THIN_ORCHESTRATOR=0`.
- `runtime=thin-rerender`: read `<base-dir>/SKILL-rerender-runtime.md` in full
  and follow it. This is the default for `--rerender`; it verifies the existing
  Stage-1 artifacts and starts directly at Stage 2.
- `runtime=legacy`: read `<base-dir>/SKILL-impl.md` from the top down to the
  `<!-- LAZY-LOAD BOUNDARY` marker and follow it. Incremental, resume, dry-run,
  deadline/cost-limited, and live-phase paths stay here.
  Full/rebuild stays here only when the compact runtime is opted out with
  `APPSEC_THIN_ORCHESTRATOR=0`.
- `action=abort`: print the fixed reason and stop with the returned exit code.

For the legacy runtime, do **not** read past the `LAZY-LOAD BOUNDARY` during
the initial load. After Stage 1, read only the stage-local ranges below, at the
boundary where each is needed; do not read the whole tail at the Stage-2
handoff:

- Stage 1c: `## Stage 1c — Abuse Case Verification` to
  `## Stage 2 - Report Rendering`, only after a completed Stage 1 when enabled;
  skip it for rerender and Stage-2-only recovery paths.
- Stage 2: `## Stage 2 - Report Rendering` to `### Handling turn-budget cut-offs`;
  on failure/cut-off only, continue through `## Incremental Mode`.
- Stage-3 safety slice: `## Stage 3 - QA Review` to `### Stage 3 handoff
  banner` on every non-dry path once `threat-model.md` exists, including
  quick / `--no-qa` / PR paths and a controller result of `stage4` or
  `complete`. When QA is skipped, execute the depth-independent secret-leak
  gate and then skip the remaining QA work as that slice instructs. Only when
  QA dispatch or repair is required, continue through
  `## Stage 4 - Architect Review`.
- Stage 4: `## Stage 4 - Architect Review` to `## Completion Summary`, only
  when enabled; it conditionally lazy-loads the shared repair-loop block when
  the architect status is `repair_required`.
- Completion: `## Completion Summary` to `## Error Handling`; this slice owns
  the final broken-link and phantom-component release gates on every path.
- Error handling: `## Error Handling` to EOF, only on that branch.

The thin runtime applies the same bounded schedule.

Apart from the single status line above (and the conditional session-cost / Haiku advisory),
read it **silently** and proceed
straight to execution. Do **not** narrate
your reading: no "this is a large file", no "let me map its structure first",
no description of how you are chunking or scanning the file. The user sees this
meta-commentary as noise.

**Hard rule (positive form — this is the enforceable one).** Between the
`🔧 Building …` status line above and the pipeline's own output, the **only**
two lines you may emit are: (1) the single `PREFLIGHT_STATUS` line that
SKILL-impl tells you to print after config resolution (e.g.
`📋 Existing threat model found — computing the incremental delta …`), and then
(2) the `Threat Model — Pre-flight` summary. Nothing may appear between them.

**One sanctioned exception — the interactive orchestrator-model prompt.** When the
thin runtime's prepare ACTION reports `orchestrator_prompt_needed: true`
(SKILL-full-runtime.md §2a), you MUST call `AskUserQuestion` to let the user choose
the session model — emitted **before the Pre-flight summary** (the choice is a cost
gate that comes first). This is an interactive tool call, not narration, and it is
explicitly permitted here despite the rule above — do not suppress it. It fires
whenever the detected session model diverges from the repo-size recommendation (a
Sonnet-5 or an Opus session on a normal-sized repo), and is skipped under
`APPSEC_HEADLESS=1`. The early `💡 Session model` heads-up is NOT a substitute — it
is a one-line hint, not a choice.

In particular do **not** announce your own actions — the following are all
contract violations, even though they are *true*: "I've read through to the
LAZY-LOAD BOUNDARY", "Now executing the combined pre-flight preamble", "Now
rendering the Pre-flight summary", "Let me run the pre-flight checks". The list
is illustrative, not exhaustive: **any** sentence describing what you are about
to do (reading, executing, running, rendering) is forbidden here. Just do it.
