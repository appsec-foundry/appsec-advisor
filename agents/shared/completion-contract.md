# Shared Completion Contract

All create-threat-model pipeline agents (orchestrator + sub-agents) MUST follow this contract for their final assistant message — the text the agent produces on its last turn, as opposed to anything it writes to disk.

## Why this exists

The orchestrator never re-reads a sub-agent's prose. It reads the artifact file(s) the sub-agent wrote (`.stride-<id>.json`, `.recon-summary.md`, etc.) and the harness-generated `<usage>` block. A sub-agent's final assistant message is returned verbatim by the Agent/Task tool and lands permanently in the orchestrator's conversation — it is never evicted (no mid-run compaction) and gets re-read from cache on every subsequent turn for the rest of the run. A prose recap of findings there is pure duplication: the same content already lives in the file, and the orchestrator has no code path that reads it back out of the message. On a full run this duplication compounds — STRIDE analyzers and abuse-case verifiers fan out one agent per component/candidate, so a wordy final message multiplies by fan-out width, not just once.

## The rule

Your final assistant message MUST be exactly this shape and nothing more:

```
Wrote <N> <artifact_noun> to <path>. <one-sentence outcome>.
```

- `<N>` — a count (findings, threats, checks, fixes — whatever the agent's own `.md` file calls its unit of output).
- `<path>` — the artifact path you wrote, relative to `$OUTPUT_DIR`.
- One sentence, no more — a verdict-level outcome (e.g. "All checks passed", "3 findings flagged Critical", "Repaired 2 broken anchors"), not a walkthrough of how you got there.

**Do not include:** individual finding titles, severities, or descriptions; restated reasoning or step-by-step recap; bulleted summaries; anything the orchestrator would have to read to know what you found. If the orchestrator (or a human) needs that detail, it's already in the file you wrote — that's the whole point of writing it there first.

This does not change what you write to disk — full detail still goes in the artifact file per each agent's own instructions. It only shortens what you say back on your last turn.
