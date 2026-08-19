---
name: update-threat-model
description: >-
  Reports that incremental threat-model updates are unavailable in the compact
  runtime and directs the user to a full or rebuild assessment.
---

Incremental updates have no compact runtime and must not dispatch another skill
or mutate run state.

If the arguments contain `--help` or `-h`, print
`$CLAUDE_PLUGIN_ROOT/skills/update-threat-model/HELP.txt` verbatim and stop.

For every other invocation, print this error and stop with exit code 2 without
reading repository content or dispatching an agent:

```text
Incremental threat-model updates are not supported by the compact runtime. Run /appsec-advisor:create-threat-model --full to reassess while preserving history, or add --rebuild for a clean start. No run state was changed and no agent was dispatched.
```
