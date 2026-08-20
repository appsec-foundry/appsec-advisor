# How the plugin changes

`requirements.md` is the approved product specification. It contains only
stable behavior a user would recognize and must stay readable in one sitting.

Implementation bindings live separately in `data/requirement-bindings.yaml`.
They connect each requirement to affected paths, technical decisions, source
documents, and exact pytest node IDs without making those volatile details part
of the specification.

- `requirements.md` — current normative product requirements.
- `changes/<name>/` — proposals and work records for requirement changes.
- `archive/<date>-<name>/` — completed change records.

## What belongs in the specification

A sentence belongs in `requirements.md` when a person using the plugin would
recognize it as a promise and would be let down if it broke. The requirement
states the outcome, not the mechanism used to produce it.

Roles, step order, retries, model names, budgets, paths, test names, internal
limits, and fallback algorithms do not belong there. Non-obvious architectural
choices belong in `docs/internal/decisions.md`; shapes and vocabularies belong in
schemas and data files; implementation details belong in code and contracts.

## Who approves what

The operator approves a requirement's ID, title, and normative text. Creating a
proposal or changing a technical binding uses the normal code-review process and
does not require a separate specification permission prompt.

An incompatible implementation change updates and receives approval for the
requirement before the implementation lands. Requirement IDs are never reused;
removed IDs are recorded in the bindings file.

## Requirement format

```markdown
## Section name

### REQ-CLN-001 — Short title

The stable product requirement in one or two short sentences, without paths,
tests, internal components, or implementation parameters.
```

## Technical bindings

`data/requirement-bindings.yaml` is validated against
`schemas/requirement-bindings.schema.yaml`. Each active requirement has one
binding with:

- `applies_to` — repository-relative paths or globs used by `--for` and the edit hook;
- `decisions` and `documents` — technical context for maintainers;
- `guards` — exact pytest node IDs;
- `coverage` — `direct`, `partial`, or `advisory` evidence.

`direct` means the named tests exercise the requirement's central behavior.
`partial` is honest supporting evidence for a broader product promise.
`advisory` means no deterministic guard currently proves it.

Bindings may change during an implementation refactor without changing or
reapproving the product requirement. Review still checks whether their paths and
tests remain complete and semantically relevant.

## Enforcement

`python3 scripts/check_specs.py` validates the catalog, the binding schema,
retired IDs, referenced paths and decisions, and exact test node IDs.

`python3 scripts/check_specs.py --for <path>` prints the requirements and guard
coverage bound to a file. The development hook supplies the same context before
a supported direct file edit.

`python3 scripts/check_specs.py --changed-against <ref>` requires a changed
proposal when the normative catalog or decision register changes. It records the
change process but cannot prove that a person approved it.

`scripts/spec_guard.py` asks before an identifiable mutation of the normative
`specs/requirements.md` file. It does not hold proposals, archived records, or
technical bindings.

`scripts/requirements_hook.py` surfaces applicable requirements and separately
holds the decision register. Both hooks are development-only and do not ship in
the plugin.

Structural checks cannot determine whether a test truly proves a product
promise. The coverage classification and code review must state that limitation
instead of implying stronger enforcement.
