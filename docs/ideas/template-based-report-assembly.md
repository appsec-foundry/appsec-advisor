# Template-Based Report Assembly

Status: **Idea — not committed to implementation.** Step 1 (resolver
scaffolding) already exists on disk but is not wired into the runtime.
Decision on whether to proceed is deferred.

## Problem

Phase 11 currently writes `threat-model.md` from memory based on a
~1500-line prompt spread across the orchestrator and phase-group files.
Consequences:

- **Structural drift between runs** — heading numbering, separator
  placement, TOC formatting, section order can vary slightly per run.
- **QA reviewer exists mostly as a janitor** — about half of its 10 checks
  are structural patch-ups (anchor verification, placeholder removal,
  linkification, section-presence assertion).
- **Cross-run report diffs are noisy** — layout drift drowns out content
  drift, making PR-based threat-delta review painful.
- **Single output format** — HTML, PDF, JSON-for-audit-tooling would each
  require re-running the LLM with a modified prompt.

The migration below would turn implicit structural rules (encoded in
prompts) into explicit structural rules (encoded in code).

## Option 3 — Fragment-based template

**Idea:** A canonical `threat-model.template.md` with `{{include: …}}`
markers. The orchestrator writes one fragment file per section
(`08-threat-register.md`, `04-assets.md`, …) to `$OUTPUT_DIR/fragments/`.
A deterministic Python resolver assembles the final report at the end
of Phase 11.

**Runtime layout:**

```
plugin/templates/threat-model.template.md    # ~30 lines, checked in
plugin/scripts/render_threat_model.py        # deterministic resolver
plugin/scripts/render_threat_model_schema.py # fragment ID constants
$OUTPUT_DIR/fragments/NN-*.md                # runtime artefacts
$OUTPUT_DIR/threat-model.md                  # produced by resolver
```

### Pros

- **Strongest consistency guarantees** — section presence, order, and
  heading structure are mechanically enforced.
- **Multi-output-format becomes feasible** — swap the template for
  HTML/PDF/JSON assembly without touching the orchestrator.
- **Single-point-of-edit for layout** — change the template once, every
  future report picks it up.
- **QA reviewer can shrink** — structural checks become obsolete over
  time; reviewer focuses on content correctness.
- **Parallelisable fragment writes** — minor turn-budget relief in
  large assessments.

### Cons

- **Coupling quadruple** — template, schema, orchestrator prompt, and
  resolver must stay in sync. A drift in any one breaks all future
  runs at once.
- **Harder failure mode** — if the resolver crashes after the LLM has
  done all its work, there is no report at all (vs. today's partial
  markdown which can be manually rescued). `--lenient` mitigates but
  does not cure.
- **Debugging spans two layers** — bugs can originate in fragment
  content, template structure, or orchestrator write paths. Triage is
  slower.
- **Cognitive load for contributors** — the plugin's mental model
  grows from "agents write markdown" to "agents write fragments, a
  resolver assembles from a template, validated by a schema".
- **Migration phase is hybrid** — between Step 2 and Step 6, some
  sections are fragmented and others live in a `99-rest-*.md`
  catch-all. Half-finished migrations are worse than either extreme.
- **Cross-fragment references are harder** — Section 2's "Linked
  Threats" column references T-IDs assigned in Section 8. Today this
  is intra-prompt copy; tomorrow it is inter-fragment coupling.
- **Irreversible after Step 5/6** — rollback becomes cheaper than
  continuing only within the first two steps.

## Variant C — Single template with inline placeholders

**Idea:** One `threat-model.template.md` file with named HTML-comment
markers (`<!-- SECTION_8_HERE -->`). The orchestrator writes **a single**
`threat-model.md` against the template, same as today, but using the
template as a skeleton instead of producing layout from memory. A
simple Python script verifies every marker was substituted (no markers
left in the final output).

### Pros

- **Much smaller footprint** — 1 template file, 0 fragment files,
  ~10-line validator script. Checked-in surface area: 2 files vs. 3+
  in Option 3.
- **Orchestrator workflow unchanged** — still writes one file, still
  one Phase-11 Write call. No new coupling between phases.
- **No hybrid migration phase** — switch over in one step: add template,
  update Phase 11 to write against it, add a validator call.
- **Layout centralised** — the template file documents the canonical
  structure in one place, same as Option 3.
- **Trivial rollback** — revert the Phase 11 prompt change, delete the
  template file. 10 minutes of work, any time.
- **No cross-fragment reference coupling** — T-ID cross-references stay
  intra-file, same as today.

### Cons

- **Weaker enforcement than Option 3** — the validator can only check
  that markers were replaced, not that each section's content is
  well-formed. An LLM that writes Section 8 in the Section 4 slot
  would pass the marker check.
- **LLM might damage markers** — HTML comments are more robust than
  `{{…}}` but not bulletproof. A sloppy run could emit
  `<!-- SECTION_8HERE -->` (typo) and the validator would flag it as
  unfilled.
- **No multi-format benefit** — because the orchestrator writes
  Markdown directly into the template, there is no structured
  intermediate representation to re-render as HTML or PDF.
- **Less parallelisation headroom** — still one monolithic Write call
  per assessment.
- **QA reviewer simplification is smaller** — section-presence check
  can go, but anchor/linkify/placeholder checks stay.

## Variant C vs. Option 3 — decision matrix

| Concern | Option 3 | Variant C |
|---|---|---|
| Cross-run consistency | strong | moderate |
| Multi-format support (HTML/PDF/JSON) | yes | no |
| Coupling surface | 4 things in sync | 2 things in sync |
| Contributor cognitive load | high | low |
| Migration complexity | 6+ steps | 1 step |
| Rollback cost | grows over time | flat |
| QA reviewer shrinkage | substantial | small |
| Failure-mode hardness | hard (all-or-nothing) | soft (same as today) |
| Fragment management burden | real | none |

## Decision criteria

Pick **Option 3** if:

- Multi-format output (HTML, PDF, machine-readable audit export) is on
  the roadmap within the next 6–12 months.
- Cross-repo / cross-team report comparison is a concrete use case.
- Reducing QA-reviewer turn budget is a priority.
- You are willing to commit to finishing Steps 2–6 within a few weeks
  and not leaving the plugin in a hybrid state.

Pick **Variant C** if:

- The main pain point is structural drift between runs, nothing else.
- Current plugin is otherwise stable and you want a minimal-surface
  fix.
- You want a change you can ship in one commit and trivially revert.
- Multi-format support is not on the roadmap.

Pick **neither** (stay with current approach) if:

- Reports today are good enough; humans read them and act on them.
- No consumer depends on machine-parseable output.
- QA reviewer rarely reports structural fixes (signal that the
  problem being solved is small).
- Team bandwidth is better spent on content quality (better STRIDE
  catalogues, more CWE coverage, refined risk heuristics) than on
  architectural polish that is invisible to report readers.

## Current state on disk

Step 1 of the Option 3 plan was already implemented as a dormant
scaffolding layer. These files exist but are **not** invoked by the
runtime:

- `plugin/templates/threat-model.template.md` — MVP passthrough
  template with a single `{{include: 99-full-body.md}}` marker
- `plugin/templates/fragments/README.md` — fragment contract docs
- `plugin/scripts/render_threat_model.py` — pure-Python resolver with
  `{{include: …}}` / `{{include?: …}}` support, `--lenient` flag, and
  full CLI
- `plugin/scripts/render_threat_model_schema.py` — shared fragment ID
  constants
- `tests/test_render_threat_model.py` — 18 unit + CLI + template
  self-check tests (all passing)
- `tests/fixtures/render/` — roundtrip fixtures

The orchestrator and phase-group files are **untouched** — the runtime
behaviour is identical to before Step 1. The scaffolding can be
deleted with no runtime impact, or activated later with a
`phase-group-finalization.md` rewrite.

## References

- Prior analysis: see conversation history for the full Vor/Nachteile
  discussion and the Step 2 migration plan design
- Related existing analysis: `docs/threat-model-consistency-analysis.md`
