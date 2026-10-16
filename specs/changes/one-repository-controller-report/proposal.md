# Deliver a one-repository controller run as a single-repository model

## Problem

The experimental `create-threat-model2` skill launches the controller for one
repository. The controller always published the qualified version-2 contract,
which every follow-on tool (publish, review, eval, change detection, analyst
context) refuses as a combined model, and it required an output outside the
checkout, so the report could not sit in `docs/security` beside the
repository's inputs.

## Goal

Change MR-3 so that publication converts the model back to the qualified
version-2 contract only when the assessment covers several repositories. A
one-repository run publishes its version-1 workspace model after the same
qualified checks (MR-8), writes to `docs/security` inside its checkout without
reading that directory as source (MR-6), and an interactive launch without a
budget flag gets a depth-derived hard budget (MR-7).

## Non-goals

- Changing the contract or behavior of an assessment of two or more repositories.
- Deleting files in `docs/security` that the controller did not write.
- Replacing `create-threat-model`; that follows Phase 3 of
  `docs/internal/analysis/implplan-deterministic-single-repo-controller-2026-10-12.md`.
