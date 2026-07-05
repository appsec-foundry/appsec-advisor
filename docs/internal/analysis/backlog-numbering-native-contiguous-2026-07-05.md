# Backlog — rework section numbering to be natively contiguous

**As of:** 2026-07-05 · **Priority:** medium · **Status:** open

## Problem

Section numbering is **not natively contiguous**. `compose_threat_model.py`
still emits the legacy scheme where §6 (Use Cases) was retired, so the composed
document runs §1–§5, §7–§11 with a gap. Contiguous §1–§10 (Security
Architecture = §6, Findings = §7, Abuse = §8, Mitigation = §9, Out of Scope =
§10) is only achieved by a **last-mile cosmetic relabel**
(`renumber_sections_display.py`) run after all gates, plus a §7 mirror at
`.appsec-cache/threat-model.canonical7.md` that the machinery reads back.

That workaround (landed 2026-07-05, commit `b80b848`) makes the delivered
`threat-model.md` correct, but the underlying numbering is still §7-based
everywhere internally:

- the section contract (`data/sections-contract.yaml`) keys on §7.x titles;
- `qa_checks.py` matches §7.x subsection titles verbatim (method_whitelist,
  domain_required_rules, finding_routing, control_subsection_coverage);
- the architect LLM authors §7.x headings;
- the composer's quick-depth carry-forward extracts `## 7.` verbatim;
- ~dozens of scripts + tests reference "7.x" / `#7-security-architecture`.

So we now maintain **two numbering realities** (§7 internal / §6 delivered) and
a mirror file to bridge them. This is fragile: any consumer that reads the
persisted §6 file expecting §7 breaks, and the quick-carry round-trip
(standard → quick re-run) has only been unit-verified, not full-e2e verified.

**Why the display-relabel is inherently fragile (the mechanism to eliminate).**
The TOC is a markdown **ordered list** keyed on each section's literal number.
CommonMark renderers (VS Code preview, GitHub) ignore the literal numbers and
renumber ordered-list items **by position**. So the moment the list is
non-contiguous — the retired-§6 gap (`5.`, `7.`, `8.` …), or a conditionally
omitted section (a `--quick` run that drops a top-level section) — the rendered
number drifts from both the literal number and the plain-text subsection
numbers: `7. Security Architecture` renders as "6." while its `7.1` children
stay "7.1". `renumber_sections_display.py` papers over this only for the
fixed §7→§6 remap; a *conditional omission* still reopens a gap that no fixed
remap closes. Native contiguous numbering (or position-derived numbering) is
the only durable fix. (Related: the HTML-`href` anchor form of the relabel was
itself a latent bug — fixed 2026-07-05, commit d81b1c4 — a symptom of the
relabel having to chase every reference form by hand.)

## Goal

Make the pipeline emit **contiguous §1–§10 natively**, end to end — Security
Architecture is §6 in the contract, the templates, the LLM prompts, qa_checks,
and the composed output alike. Then delete `renumber_sections_display.py`, the
`.appsec-cache/threat-model.canonical7.md` mirror, the snapshot preference for
it, and the §6/§7 dual-numbering notes in `SKILL-impl.md`.

## Why it was deferred (the coupling that must be done together)

The 2026-07 session deliberately avoided the full rename because it is a large,
tightly-coupled, all-repo change with real collision risk (a prior session at
commit `64029a2` reached the same conclusion). A correct rework is bidirectional
and must land as one atomic change (AGENTS.md §4):

1. `data/sections-contract.yaml` — renumber §7.x → §6.x, §8→§7 … §11→§10;
   confirm the retired-§6 gap machinery (preserve block, `md_section_number`)
   is updated.
2. `qa_checks.py` — every literal §7.x / §N title match, anchor regex
   (`#7-security-architecture`), and posture/section-integrity check.
3. `compose_threat_model.py` — heading emission, `_extract_section_verbatim`
   (quick-carry top_level_number), cross-ref emitters
   (`#7-security-architecture`, "See §7"), Figure back-links.
4. Agent prompts — `agents/**` that author or reference §7.x headings.
5. Snapshot / preserve chain — `snapshot_preserved_sections.py`,
   `preserve_lib.py`, `restore_preserved_sections.py`.
6. `SKILL-impl.md` — drop the mirror + renumber steps entirely.
7. Tests + golden fixtures — ~90 references; regenerate
   `tests/fixtures/e2e/golden/threat-model.md` to native §6.

## Acceptance criteria

- `compose_threat_model.py` output has no numbering gap and no "numbering is
  non-contiguous" note — with **no** post-compose relabel step.
- `renumber_sections_display.py` and the `.canonical7.md` mirror are removed.
- Full suite + e2e golden green; a standard → quick incremental re-run
  preserves §6 Security Architecture verbatim (real e2e, not just unit).

## Related

- Interim workaround: memory `project_section6_canonical_section7_mirror_2026-07-05`
  and commit `b80b848`.
- Prior "don't rename, it's too coupled" decision: commit `64029a2`.
