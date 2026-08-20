# Sourced constraints

## SPB-001 The normative specification contains product behavior only

Source: operator request and `specs/README.md`.

- Keep requirement IDs, titles, and stable user-recognizable outcomes in the
  normative catalog.
- Keep paths, tests, decisions, budgets, retries, model names, stage names, and
  implementation ownership outside the normative catalog.

## SPB-002 Technical bindings remain deterministic

Source: the existing `check_specs.py --for` and requirements-hook workflow.

- Preserve file-to-requirement lookup through a validated binding file.
- Resolve guards to exact pytest node IDs and label their evidence as direct,
  partial, or advisory.
- Retire removed requirement IDs and reject their reuse.

## SPB-003 Approval follows normative meaning

Source: operator request.

- Ask for explicit approval before changing `specs/requirements.md`.
- Do not require a special specification approval for proposals, archives, or
  technical binding maintenance.

## SPB-004 Agent instructions route to authoritative contracts

Source: `AGENTS.md` opening contract.

- Keep repository-wide working rules in `AGENTS.md`.
- Replace duplicated runtime mechanics with links to their authoritative
  decisions, contracts, data, schemas, and tests.
