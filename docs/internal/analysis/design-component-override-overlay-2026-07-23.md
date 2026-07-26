# Design — user component-override overlay (`.appsec/components.yaml`)

**Status:** backlog / design sketch. **Not started.**

## Problem

STRIDE selection is parametrized by component attributes — `deployment_zones`
(→ `_is_exposed`), `handles_sensitive_data` (→ crown-jewel), type (→ `_is_datastore`
/ `_is_cicd`). These are **recon-authored** and land in `.components.json`, which is a
**derived artifact regenerated every full run** (`build_stride_dispatch_manifest.py`
writes it from Analyst-A). When recon mis-tags a component — e.g. an internal SQL DB
marked non-sensitive — the wrong component gets analyzed, and a user hand-edit to
`.components.json` is **silently wiped** on the next run. There is no supported way for
a user to correct recon's judgment or pin a run's coverage.

This is the **user-driven generalization of D1** (the `_is_datastore` type-anchor catches
one under-tagging heuristically; the overlay lets the user catch *any* mis-tagging).

## Shape

A thin, separate **input** file merged *over* the recon output, never editing the derived
artifact. Mirror the existing 3-layer override pattern of `.appsec/actors.yaml`
(`resolve_actors.py`).

- **File:** `<repo>/.appsec/components.yaml` — per component: overridable `exposed` /
  `deployment_zones` / `sensitive` / `component_type`.
- **Merge point:** after recon writes the component inventory, **before**
  `select_stride_components`.
- **Match key:** `canonical_id` (`classify_component._to_canonical`), **not** the raw
  LLM-authored id — ids drift between runs. **Warn on any overlay entry that matches no
  component**, or the override rots silently.
- **Logging:** every applied override emitted via `scripts/event_log.py`.

## The one hard rule — override direction (fail-safe)

- **Escalation** (mark *more* critical/exposed → *more* coverage): allow freely.
- **De-escalation** (mark *less* → *less* coverage, saves cost): **explicit + logged +
  surfaced in the report**, never silent. A user must not be able to quietly create a
  whole-component blind spot; the tool records it as a user decision. Matches the repo's
  fail-safe philosophy (exposure-unknown → included; ceiling sheds only proven-internal).

## Recommended slice (don't build it all at once)

**Escalation-only** first: overlay can only raise coverage, applied at the merge point,
canonical-id match, unmatched-entry warning, event-logged. This is small (schema + merge
+ log + test) and dodges the two expensive parts:

- **De-escalation** → the report-surfacing-heavy, security-sensitive part (new producer
  emitter + compose/QA contract). Defer until real demand.
- **Incremental invalidation** → escalation is always safe (more coverage), so no
  force-full is needed; a de-escalating overlay change would need requirements-toggle-style
  invalidation. Defer with de-escalation.

## Scope boundary (avoid a third half-overlapping override system)

Distinct from `org-profile` (org-wide criticality policy) and `.appsec/actors.yaml`
(threat actors). This layer overrides **per-component attributes** only. Position it
explicitly against those two or the three blur together.

## Full-build surface (for later, if it grows past the slice)

Schema · resolver/merge · event-log · **report-surfacing of de-escalations** (producer
emitter, bidirectional per AGENTS.md §4) · incremental-invalidation detection ·
`required-permissions.yaml` (new read target) · docs · tests.
