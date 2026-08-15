# Sourced constraints

This change introduces no plugin behavior. Its constraints come from existing
repository sources and from what the operator asked for.

## SDD-001 Leave the decision register in place

Source: operator decision; `docs/internal/decisions.md` states that the register
governs and that a rationale document does not.

- `decisions.md` stays where it is, in its format, with its own guard test.
- A catalog entry cites a decision ID as its source instead of restating the
  behavior.
- Changing a decision still goes through `decisions.md`.

Acceptance: no decision row moves, and every decision ID cited by the catalog
exists in the register.

## SDD-002 The catalog explains and binds, it does not legislate

Source: `AGENTS.md` — a contract states the rule a consumer must satisfy; the
same rule applied to this file.

- Normative text stays in code, `schemas/`, `data/`, and the contracts.
- An entry adds only what those do not carry: the plain sentence, the files it
  governs, and the guard.

Acceptance: every entry names a source that exists and adds no obligation its
source does not carry.

## SDD-003 A requirement names a guard or admits it has none

Source: `docs/internal/decisions.md` — guard column with its two documented
placeholders.

- An entry names a test function or a pytest node id, or states
  `— (no guard written)` or `— (guard not located)`.
- The check fails on a guard no test defines.
- An entry may not claim both a guard and an absence.

Acceptance: a renamed, misspelled, or deleted guard fails the check, and an
unguarded requirement is visible as unguarded.

## SDD-004 The check is free and deterministic

Source: `Makefile` — the `check` target is the continuous gate and calls no
model; `CONTRIBUTING.md` separates it from the manual full run.

- The check calls no model, starts no scan, and reads no network.
- It runs inside `make check` and as an ordinary pytest module.

Acceptance: `make check` gains one step and stays offline.

## SDD-005 An agent does not write the requirements

Source: operator request; `docs/internal/decisions.md:6` and `AGENTS.md:21` ask
that a decision change go to the operator first.

- Writes to `specs/requirements.md` and `docs/internal/decisions.md` are denied
  by a hook rather than discouraged in prose.
- The denial names what to do instead: propose the change to the operator.
- `APPSEC_SPEC_EDIT=1` is the operator's own override, following the precedent
  of `APPSEC_PLUGIN_DEV` in `scripts/plugin_write_gate.py`.

Acceptance: an `Edit` or `Write` against either file is denied without the
variable, and allowed with it.

## SDD-006 Nothing here ships to an install

Source: `hooks/hooks.json` is the plugin's hook registry and is packaged;
`.claude/settings.json` is this checkout's own configuration.

- The development hook is registered only in `.claude/settings.json`.
- `hooks/hooks.json` is unchanged.

Acceptance: a packaged build carries no requirements hook.
