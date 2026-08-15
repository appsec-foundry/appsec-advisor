# Sourced constraints

## ALIGN-001 Contracts describe implemented boundary behavior

Source: `docs/internal/contracts/orchestration-actions.md` and
`scripts/orchestration_controller.py`.

- Required handoffs fail closed.
- Optional enrichments degrade only where their boundary contract says so.
- Recon signals receive one producer retry, STRIDE keeps its separate persisted
  two-attempt budget, and other producers follow their boundary contract.

## ALIGN-002 Model ownership is layered

Source: `docs/model-selection.md` and `scripts/resolve_config.py`.

- The session model controls the orchestrator and remains the primary cost
  lever.
- The pipeline centrally routes subagents and agents never select their own
  model.

## ALIGN-003 External context is not finding evidence

Source: `AGENTS.md` and decision `FE-4`.

- A cross-repository mismatch may seed a hypothesis.
- A finding and any CVSS score require target-repository evidence.

## ALIGN-004 Spec changes require a user decision

Source: operator request.

- Every recognized direct or shell write to `specs/requirements.md` or
  `docs/internal/decisions.md` returns `permissionDecision: ask`.
- The project settings wire the hook for every supported write tool and Bash.
- There is no environment-variable bypass.

## ALIGN-005 Source references stay resolvable

Source: `specs/README.md`.

- Markdown documents named by a requirement source must exist.
- A `document → section` reference must resolve to a current heading.
