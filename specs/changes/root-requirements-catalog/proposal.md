# Root requirements catalog

The operator approved the complete English requirement list grouped by topic with REQ-ID bullets, followed by its placement in the repository root, in the implementation request on 2026-10-12.

Move the normative catalog from `specs/requirements.md` to `requirements.md` and use the approved wording. Keep technical paths, decisions, and exact test evidence in `data/requirement-bindings.yaml`. Update the parser, development approval guard configuration, documentation links, and test routes together.

Merge REQ-MOD-005 into REQ-MOD-001 and REQ-ANA-006 into REQ-ANA-005, retaining their implementation bindings and retiring their IDs. Split existing compound promises into the approved topic bullets and bind newly explicit lifecycle, audit, scope, and execution requirements to their existing producers and evidence. Coverage labels describe the available evidence, not a claim that this catalog migration implements new runtime behavior.

The previous catalog remains available in Git history; historical proposals retain their original paths. No duplicate normative catalog remains under `specs/`.
