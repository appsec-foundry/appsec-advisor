# Tasks

## Slice 1 — the CI gate reads entries, not path names

- [x] Compare the decision register against its base revision and require a proposal only for a changed row, a removed row, or a change to the rules around the rows (`scripts/check_specs.py`).
- [x] Hold the register like the catalog when no base revision can be read, so an unresolvable comparison fails closed (`scripts/check_specs.py`).
- [x] Keep `specs/requirements.md` held for any change, since the operator approves a requirement's ID as well as its text (`scripts/check_specs.py`).
- [x] Guard the addition, the change, the removal, the relaxed rule, the missing base revision, and the catalog's asymmetry (`tests/test_check_specs.py`).
- [x] State the rule where a reader looks for it (`specs/README.md`).

## Slice 2 — the development hook stops asking for additions

- [ ] Apply `requirements-hook.patch`. It changes `scripts/requirements_hook.py`, its tests, and one sentence in `specs/README.md`. The hook and `scripts/spec_guard.py` are `Edit`-denied in `.claude/settings.json` so the guard cannot rewrite itself, which also means an agent cannot apply this: run `git apply specs/changes/gate-the-change-not-the-path/requirements-hook.patch` from an ordinary terminal.
- [x] Verify the patch before handover: `git apply --check` passes, and the patched hook runs 41 tests green against a symlinked copy of the repository.

## Slice 3 — the register says what belongs in it

- [x] Add the entry rule to the register header (`docs/internal/decisions.md`).
- [x] Trim the incident narratives from `OR-16` through `OR-22` to the pointer the header asks for, after verifying each narrative survives at the code it names.
- [x] Move `OR-22`'s reasoning into the docstring of the module that pins it, since nothing else recorded it (`tests/test_hook_payload_contract.py`).
- [x] Lift the pinned 15 and 60 minutes out of `OR-17`'s decision text into the function that owns them.
- [x] Repair the Orchestration table: two blank lines had split it into three rendered tables, and `OR-17` sat after `OR-19`.

## Open

- [ ] Decide whether the three requirement texts that drifted into mechanism are trimmed: `REQ-RPT-003`'s closing sentence about one inline-code format across report sections, `REQ-RPT-006`'s artifact field shapes, and `REQ-CFG-003`'s six-clause specification of a maintenance command. Each is a normative change and needs the operator's wording approval before it is written.
- [ ] Review the 70 register rows that no binding, test, script, agent, contract, or changelog entry cites, and retire the ones whose named guard already states the rule and fails on it. Retiring a decision is the case the operator approves, so this is a reviewed list, not a sweep.
