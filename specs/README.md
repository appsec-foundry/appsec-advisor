# How the plugin changes

[requirements.md](../requirements.md) in the repository root is the approved product specification. It states user-visible behavior in short English bullets grouped by topic. This directory retains proposals and change records.

Implementation bindings live separately in `data/requirement-bindings.yaml`.
They connect each requirement to affected paths, technical decisions, source
documents, and exact pytest node IDs without making those volatile details part
of the specification.

- [`../requirements.md`](../requirements.md) — current normative product requirements.
- `changes/<name>/` — proposals and work records for requirement changes.
- `archive/<date>-<name>/` — completed change records.

## What belongs in the specification

A sentence belongs in `requirements.md` when a person using the plugin would
recognize it as a promise and would be let down if it broke. The requirement
states the outcome, not the mechanism used to produce it.

Roles, step order, retries, model names, budgets, paths, test names, internal limits, and fallback algorithms do not belong there. Shapes and vocabularies belong in schemas and data files; implementation details belong in code and contracts. Derive these technical obligations and their tests from the requirements through the bindings.

The [decision register](../docs/internal/decisions.md) records only long-lived, cross-cutting technical choices that requirements leave open and whose reversal would have significant consequences. Its admission rule requires the chosen approach, alternative, reason and consequences. Bug fixes, scanner rules, algorithms, local implementation details and invariants already explained by contracts or tests do not need entries. A code change or a new test alone never requires a decision. Retiring duplicate entries does not move their details into requirements.

## Who approves what

The operator approves a requirement's ID and normative text. Creating a proposal or changing a technical binding uses the normal code-review process and does not require a separate specification permission prompt.

Before adding or changing a requirement or decision, show the operator its exact wording and a plain-language summary and obtain confirmation of both, as required by `AGENTS.md`. Retiring a decision also needs approval. Changes to existing decision entries or the register's rules require a proposal; the structural checker permitting an additive row without one does not replace operator confirmation.

An incompatible implementation change updates and receives approval for the
requirement before the implementation lands. Requirement IDs are never reused;
removed IDs are recorded in the bindings file.

## Requirement format

```markdown
## Section name

- **REQ-CLN-001:** The tool must provide the stated user-visible behavior.
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

`python3 scripts/check_specs.py --changed-against <ref>` requires a changed proposal when the normative catalog changes at all, and when the decision register changes an entry it already had, drops one, or changes the text around its entries at all. A diff that only adds decision rows passes, because the text around them states how every later decision is made. Without a readable base revision the register is held like the catalog. The check records the change process but cannot prove that a person approved it.

`scripts/spec_guard.py` asks before an identifiable mutation of the root `requirements.md` file. It does not hold proposals, archived records, or technical bindings.

`scripts/requirements/requirements_hook.py` surfaces applicable requirements and separately
holds the decision register. Both hooks are development-only and do not ship in
the plugin.

Structural checks cannot determine whether a test truly proves a product
promise. The coverage classification and code review must state that limitation
instead of implying stronger enforcement.
