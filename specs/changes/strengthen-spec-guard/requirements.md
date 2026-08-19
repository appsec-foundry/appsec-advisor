# Sourced constraints

## SPEC-GUARD-001 Protect the complete specification tree

Source: operator request; `ai-secure-coding-baseline` upstream
`scripts/spec_guard.py`.

- Native writes, identifiable shell writers, and recognizable mutating MCP tools
  targeting `specs/` request explicit approval.
- Missing configuration, malformed matched input, and internal guard failures
  block rather than allow the call.
- Reads and mutations outside `specs/` remain unaffected.

## SPEC-GUARD-002 Do not pre-approve unrelated contributor actions

Source: operator request; `AGENTS.md` → Secure by Default.

- The checked-in project settings contain only the specification edit prompt.
- Plugin runtime permissions remain solely in `data/required-permissions.yaml`.
