---
name: update-threat-model
description: >-
  Explains how to update an existing threat model after a code change: rerun
  create-threat-model, which re-analyzes only changed components when the
  previous model can be carried, or pass --full to reassess everything.
---

This command never dispatches another skill or agent and never mutates run
state.

If the arguments contain `--help` or `-h`, print
`$CLAUDE_PLUGIN_ROOT/skills/update-threat-model/HELP.txt` verbatim and stop.

For every other invocation, print this text and stop without reading
repository content or dispatching an agent:

```text
Update the threat model with /appsec-advisor:create-threat-model. A rerun without a mode flag, or with --incremental, re-analyzes only the components whose files changed and carries the rest from the previous model; it is refused before any change when the previous model cannot be carried. Pass --full to reassess every component while preserving history, or --rebuild for a clean start. No run state was changed and no agent was dispatched.
```
