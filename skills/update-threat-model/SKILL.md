---
name: update-threat-model
description: Incrementally update an existing docs/security/threat-model.md to reflect code changes since the last assessment.
---

Invoke the `appsec-plugin:appsec-threat-analyst` agent to update an existing `docs/security/threat-model.md` in the current repository.

Before starting the analysis, read the existing `docs/security/threat-model.md` at the repository root. Use it as the baseline:
- Preserve findings that are still valid and unchanged
- Update sections where the code has drifted from what the threat model describes
- Add new threats, components, or diagrams for code that did not exist when the model was last generated
- Remove or mark as resolved any threats that no longer apply
- Carry over known exceptions and accepted risks unchanged unless the underlying code has changed

At the top of the updated document, add or refresh a "Last Updated" line and append an entry to a `## Revision History` section at the end of the file:

```
| Date | Author | Summary of changes |
|------|--------|--------------------|
| <date> | appsec-threat-analyst | <one-line summary> |
```

Pass along any arguments the user provided as focus areas or scope constraints (e.g., "re-evaluate the auth service", "new payment integration added"). If no arguments were given, do a full re-evaluation of all sections.

Use the current working directory as the repository root unless the user specified a different path. If no `docs/security/threat-model.md` exists, notify the user and suggest running `/appsec-plugin:create-threat-model` instead.
