# Proposal — promote Threat Hypotheses to real Findings before re-enabling §6.2's table

**Status:** OPEN. The "Threat Hypotheses Requiring Validation" table was
**disabled** in the rendered report 2026-07-03 (user request) — see
`scripts/pregenerate_fragments.py::_render_threat_hypotheses_table` (function
kept, call site removed) and `data/sections-contract.yaml`'s
`structural_heading_exemptions` (kept, dormant). This doc is the resume-work
record for whoever picks this back up.

**User framing (verbatim intent):** the underlying idea — architecture-derived
hypotheses that are plausible but not yet source-to-sink proven — is valuable
and belongs in the backlog. But a table of unlinked hypotheses with no
Findings attached is not report-ready. Before the table goes back in the
report, each hypothesis needs an actual Finding derived from it and linked in
— not just a bare "here's a maybe" row.

## What was actually broken (proximate bug, already understood)

The renderer read `h.get("evidence")` / `h.get("validation_objective")`, but
`threat_hypotheses[]` entries (built by `build_threat_model_yaml.py::
build_threat_hypotheses` from `.architecture-coverage.json`) carry that content
under `positive_signals[]` instead — a field-name mismatch. Every row rendered
`_?_` / `_pending validation objective_` regardless of how much real evidence
existed. `positive_signals[]` in the juice-shop run actually had rich,
concrete file:line + code-snippet evidence (e.g. 8 signals for the XSS
hypothesis) that never reached the table.

Renaming the field read is a real fix, but the user's ask goes further than
that — see below.

## What "done" looks like (user's actual bar)

Not just: fix the field mismatch so Evidence/Validation columns populate.

Instead: each unpromoted hypothesis that has enough evidence to be actionable
should be **promoted to a real Finding** (a `threats[]` entry with an F-NNN /
T-NNN id) — not left in a separate, disconnected "hypotheses" limbo table.
The report should link the Finding, not just describe the hypothesis.

This machinery already partially exists and should be the starting point,
not reinvented:

- `scripts/arch_coverage_to_threats.py` — promotes `proof_state=confirmed`
  hypotheses into `threats[]`; hypotheses with `proof_state` in
  `{control-derived, ...}` stay unpromoted. Read this file first — it may
  already do most of what's needed, or may reveal why promotion isn't
  happening for hypotheses that plausibly should qualify (juice-shop's XSS
  hypothesis had 8 concrete positive_signals — worth checking why that one,
  specifically, never got promoted on a real run).
- `scripts/qa_arch_coverage.py` — validates rule-id coverage across
  `threat_hypotheses[]` / `security_controls[]` / `threats-merged[]`; any
  promotion-criteria change likely needs a matching QA rule update.
- `validate_intermediate.py::_check_threat_hypotheses_invariants` — schema
  gate for `threat_hypotheses[]`; extend if the promoted-linkage shape changes.

## Open questions for whoever designs this

1. What's the promotion bar? `proof_state` already has a taxonomy
   (`control-derived`, `confirmed`, …) — does "has ≥N concrete
   `positive_signals[]` with no `negative_signals[]`/`exculpatory_signals[]`"
   become an additional automatic-promotion criterion, or does this stay a
   human/LLM judgment call per hypothesis?
2. Once promoted, does the resulting Finding cite the hypothesis's
   `source_hypothesis_id` for traceability (so a reader can see "this finding
   started life as an architecture hypothesis, not a STRIDE pass")?
3. What happens to hypotheses that never get enough evidence to promote —
   do they get silently dropped, or does a genuinely-thin, no-longer-generic
   version of the table survive for the honestly-unresolved remainder? (The
   original table's real defect wasn't "hypotheses are bad" — it was
   "displaying unlinked, evidence-less hypotheses as if they were actionable
   register content.")

## Do NOT do

- Do not just rename `evidence` → `positive_signals` in the renderer and
  re-enable the table. That fixes the display bug but not the actual ask
  (linked Findings, not a disconnected hypothesis list).
- Do not touch the underlying `threat_hypotheses[]` data pipeline, promotion
  logic in `arch_coverage_to_threats.py`, or QA coverage checks in
  `qa_arch_coverage.py` as part of the 2026-07-03 disable — those were left
  intentionally untouched; they're a separate, working mechanism.
