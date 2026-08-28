---
name: status
description: Read-only overview of the AppSec plugin — version, available features, last-run identity, and configuration sources. Does not analyze or modify anything.
---

You are printing a status overview for the AppSec plugin. This skill is **read-only** — do not analyze the repository, do not write files, do not dispatch sub-agents.

The helper below owns the whole command: the flag surface, the defaults, the
`--help` text, the rejection message for an unknown flag, and the formatting of
every line it prints. You run it and reprint what it says. Nothing in this
skill is yours to decide.

## Step 1 — Run the helper

Pass the user's arguments through unchanged. Do not parse, validate, correct,
expand, reorder, or drop any of them, and do not resolve `--repo` or `--output`
defaults yourself. Quote each argument exactly as the user typed it, so a shell
metacharacter inside one stays inert:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/appsec_status.py" "<arg1>" "<arg2>" …
```

With no arguments, run the script with none. Capture the exit code and
propagate it; `2` means the helper rejected an argument and already printed why.

If the helper cannot run at all (missing file, empty stdout), that is the
status: print the command you ran and its stderr verbatim, and stop. Never
answer from your own knowledge of the plugin instead — a summary written here
looks like a working status report and hides a broken installation.

## Step 2 — Reprint the output

The user cannot see Bash tool output. Reprint the script's stdout **verbatim**
in a fenced code block in your text response: every line, from the first to the
last, including every table and every line inside it. Do not summarise,
shorten, reorder, re-align, or drop a section — the Versions table in
particular is what a reader compares between two machines, so a missing line
there is a wrong answer. Add no commentary before or after the block.
