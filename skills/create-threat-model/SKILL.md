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
Read `<base-dir>/SKILL-impl.md` in full (base-dir is on the `Base directory for this skill:` line in the invocation header), then follow all instructions in that file to run the assessment.
