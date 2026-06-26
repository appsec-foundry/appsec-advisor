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

**Then, only if you (the orchestrator) are running on an Opus-tier model**, emit
exactly this one advisory line directly beneath the status line — otherwise emit
nothing extra. The session model you started with only assembles and writes the
report; it does **not** deepen the security analysis itself, so Opus here mostly
multiplies cost (~5x) without finding more:

> ⚠ Heads-up: running on Opus mainly increases cost, not depth — the model picked here only writes up the report, it doesn't find more threats. Orchestration is ~half of an Opus-driven run, so this adds roughly +25–55% to the run's total (a proportional share that grows with repo size, not a fixed amount). For a deeper assessment, put the threat analysis itself on Opus with `--reasoning-model opus`, and/or widen coverage with a thorough scan via `--assessment-depth thorough`. You can safely continue this run on a cheaper model.

This advisory is console-only — never write it to any file or report artifact,
emit it at most once, and skip it entirely on non-Opus models. (Headless
`--model opus` runs also get a deterministic pre-launch warning from
`scripts/run-headless.sh`; a duplicate there is harmless.)

**Conversely, only if you (the orchestrator) are running on a Haiku-tier
model**, emit this line instead (mutually exclusive with the Opus advisory —
one or the other, never both, nothing on Sonnet):

> ⚠ Warning: Haiku is too weak to orchestrate this skill — it drives strict JSON contracts, gates, and dispatch/repair loops that Haiku mishandles, which can corrupt the pipeline or produce an incomplete report. Switch with `/clear` then `/model sonnet` and re-run.

Console-only, emit at most once.

Then read `<base-dir>/SKILL-impl.md` (base-dir is on the `Base directory for this skill:` line in the invocation header) from the top **down to the `<!-- LAZY-LOAD BOUNDARY` marker** (~60% in, immediately before `## Stage 2 - Report Rendering`) — do **not** read past that marker during this initial load. Follow those instructions to run Stages 1 and 1c. The Stage 2 / 3 / 4 / Completion / Error-Handling sections below the marker are read just-in-time at the Stage-2 handoff (an instruction right above the marker tells you exactly when) — deferring them keeps the pre-flight resident context roughly a third smaller, which avoids the auto-compaction that otherwise fires just before the STRIDE dispatch.

Apart from the single status line above (and the conditional Opus/Haiku advisory),
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
In particular do **not** announce your own actions — the following are all
contract violations, even though they are *true*: "I've read through to the
LAZY-LOAD BOUNDARY", "Now executing the combined pre-flight preamble", "Now
rendering the Pre-flight summary", "Let me run the pre-flight checks". The list
is illustrative, not exhaustive: **any** sentence describing what you are about
to do (reading, executing, running, rendering) is forbidden here. Just do it.
