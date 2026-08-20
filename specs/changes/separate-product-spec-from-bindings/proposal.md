# Separate the product specification from technical bindings

## Problem

The requirements catalog mixes stable product promises with paths, document
headings, decision references, and test names. Routine refactors therefore
rewrite a protected specification even when the behavior a user relies on does
not change. The catalog also contains runtime mechanisms and unsupported
incremental behavior that are not current product requirements.

`AGENTS.md` repeats exact runtime contracts despite defining itself as a map to
their authoritative sources. The resulting copies can disagree with the
controller and decision register.

## Goal

Keep only stable, user-recognizable behavior in `specs/requirements.md`. Move
technical ownership and guard evidence to a schema-validated binding file, make
guard strength explicit, narrow special approval to normative specification
text, and turn `AGENTS.md` back into a routing document.

## Approved scope

The operator approved this migration after reviewing the current catalog and
guard chain on 2026-08-20.

## User-visible effect

There is no runtime behavior change. Maintainers can refactor paths and tests
without requesting approval for an unchanged product requirement, while edits
to the normative specification still require an explicit decision.
