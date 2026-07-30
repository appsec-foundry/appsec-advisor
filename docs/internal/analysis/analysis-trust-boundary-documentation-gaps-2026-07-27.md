# Trust-boundary documentation review — 2026-07-27

Scope: the documentation surface of the trust-boundaries-first-class feature
after it merged into `dev` (`e728f03e`). Every claim below was checked against
the producer, not against another document. Nothing is applied yet.

**Re-verified 2026-07-30.** All nine findings still held. Line references were
refreshed against the current tree, and D6 was corrected: the merge guard covers
five consolidation paths, not four.

**Applied 2026-07-30.** D1–D7 are fixed. D8 and D9 are code, not documentation,
and remain open: D8 still needs a fixture before anyone changes the ranking, and
D9 is an unrelated duplicate definition. The line references below describe the
state at review time and are no longer exact for the documents that were edited.

## Summary

The internal contract is in good shape. `docs/internal/contracts/schema-invariants.md`
§4h describes the catalogue, the reference invariant, the ID allocation rule, and
the single severity exception, and it agrees with the code everywhere it was
checked.

The user-facing surface has one factual error, three stale or imprecise
statements, and two behaviors that changed what a reader sees in a report but
appear in no user-facing document. One design question surfaced during the check
and is recorded separately because it is not a documentation fix.

## D1 — Analyzer candidacy does not require `confirmed` (factual error)

`docs/threat-modeler.md:423`

> Only resolved, confirmed crossings may become analyzer candidates or Figure 1
> exposure context.

The Figure 1 half is correct: `figure1_svg.py:469` requires
`confidence == "confirmed"`.

The analyzer half is wrong. Candidate selection in
`prepare_trust_boundary_context.py:961-964` admits a boundary on two conditions —
`resolution_status == "resolved"` and `boundary_endpoints_valid`. Confidence
never gates admission; it enters only as the sixth of seven sort keys
(`:984`), so it breaks ties and nothing more.

The internal contract already states this correctly: schema-invariants.md:108-112
lists analyzer context under the `resolved` requirement alone. So the user doc
contradicts both the code and the contract.

Fix: split the sentence. Analyzer candidacy requires a resolved row with valid
endpoints; Figure 1 exposure additionally requires `confirmed`. Worth naming the
consequence in the same place, because it is the part a reader acts on: a
reference to an `inferred` row is discarded at merge
(`prepare_trust_boundary_context.py:1146`), so an inferred candidate can occupy
an analyzer slot but can never produce a surviving link.

## D2 — Stale count in the repo-local context intro

`docs/threat-modeler.md:363`

> Two optional files add team-owned context.

The section now has three subsections: `docs/business-context.md`,
`docs/known-threats.yaml`, and `.appsec/trust-boundaries.yaml`. The trust-boundary
subsection was added without updating the intro.

The following sentence — "Neither file can suppress a finding" — has the same
problem and is worth rewording rather than renumbering, since the constraint
applies to all three.

## D3 — "Candidate files" names the wrong object

`docs/threat-modeler.md:448`

> Candidate files are bounded by assessment depth (2/4/6 for quick/standard/thorough)

`BOUNDARY_CANDIDATE_LIMITS` (`resolve_config.py:253`) caps **boundaries per
component**, written as rows into exactly one file per component
(`<component>/trust-boundaries.json`). The file count is not what depth controls.

Fix: "at most 2/4/6 candidate crossings per component".

## D4 — Shipped feature still listed as roadmap

`README.md:297`, under `## Roadmap`

> Make trust boundaries stable and directly linkable from findings, including
> the violated assumption and attacker impact.

This is what the merge delivered: stable `tb-N` anchors, `boundary_refs[]` on
findings, and `assumption` on the canonical row. Remove the bullet. The
`.appsec/components.yaml` bullet directly below it is still genuinely open and
should stay.

## D5 — No route to the declaration file from the configuration inventory

`docs/configuration.md:9-13` is the canonical table of configuration files and
scope. It lists `config.json`, `config.local.json`, and the requirements-catalog
config. It does not mention `.appsec/trust-boundaries.yaml`, and the README
documentation table (`README.md:246-256`) has no row that routes to repo-local
context files at all.

A reader who wants to declare a boundary can only find the syntax by already
knowing it lives in `docs/threat-modeler.md`. The cheapest fix is a row in the
README table pointing at *Repo-local context*, plus a cross-reference from
configuration.md rather than a second copy of the schema.

## D6 — Consolidation behavior changed and is undocumented for users

`merge_threats.py:1703` — `_can_merge_boundary_refs` refuses a merge when the
union of `(boundary_id, origin_component_id)` pairs exceeds two. It guards all
five consolidation paths: `_dedupe_exact` (`:914`), `_consolidate_config_checks`
(`:1028`), `_consolidate_by_group` (`:1277`), `_dedupe_evidence` (`:1352`), and
`_apply_decisions` (`:1899`, `:1930`).

This is visible in a report: findings of the same mechanism at different
crossings now stay as separate rows where they previously collapsed into one.
It is documented internally (schema-invariants.md:137-141) but appears in no
user-facing document, and `CHANGELOG.md` does not mention it under *Changed*.

Per the changelog policy in AGENTS.md this qualifies — a reader could notice the
difference in output. One bullet, no root cause.

## D7 — The selection mechanics from `5022f589` are undocumented

The commit changed which crossings reach an analyzer at all — the largest
practical effect of the feature. None of it is in `docs/threat-modeler.md`:

- **Evidence-file ownership** admits a component that implements a crossing
  without being an endpoint (`:969-970`, `_evidence_owners` at `:772`). This is
  what makes an egress boundary such as `backend-api -> external` analyzable.
- **Parent inheritance** gives a role-folded component its container's
  candidates, and only when its own list is empty (`:989-1004`).
- **Coverage redistribution** swaps an uncovered crossing in against one that
  another component already covers, keeping the per-component cap exact
  (`:1011-1046`); when nothing is displaceable, the gap is reported instead of
  hidden.
- **Quick depth takes `primary` focus only** (`:973`), which narrows candidates
  further than the cap of 2 alone suggests.

Not all of this belongs in a user document. The two items a reader can act on
are the depth-dependent narrowing at quick and the coverage warning — the rest
is contract material and would be better placed in schema-invariants.md §4h,
which currently describes the reference invariant but not the selection rule.

## D8 — Design question, not a documentation fix

Candidate ranking (`:978-986`) sorts `from == "external"` above confidence.
Reference validation (`:1146`) then requires `confirmed`. At quick depth the cap
is 2, so two `inferred` external crossings can take both slots on a component
and every reference to them is guaranteed to be dropped at merge — the slot is
spent, the link cannot survive.

This was not observed in a run; it follows from reading the two rank keys
against the validator. If it is real, the fix is in the ranking or in the
eligibility filter, not in prose. Worth a fixture before deciding.

## D9 — Duplicate function definition

`prepare_trust_boundary_context.py` defines `_glob_probe` twice, at `:607` and
`:820`, with identical bodies and differing docstrings. The second shadows the
first. Ruff `F811` does not fire because the first definition is used in
`_contained_in` before the redefinition, so `make lint` stays green.

Unrelated to documentation; noted because it was found during the check.

## Suggested order

1. D1 — the only statement that is wrong rather than incomplete.
2. D4, D2, D3 — small, self-contained corrections.
3. D6 — one changelog bullet.
4. D5, D7 — routing and the selection rule; needs a decision on what belongs in
   the user doc versus §4h.
5. D8, D9 — separate from the documentation work.
