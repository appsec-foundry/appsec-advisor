# Which analysis frame is visible in a finding — 2026-08-16

Two changes that came out of the same question: the LLM lens now asks four
questions the OWASP Top 10 does not ask, and none of them carries an OWASP ID,
so nothing in the report says where such a finding came from. Part A settles
what those four questions are allowed to claim. Part B is the larger and more
useful half: the STRIDE category is on every threat and rendered in three
places, but not in the Findings Register, where CWE and the OWASP Top 10 sit.

PHANTOM-B itself stays out of the report. It is the mnemonic that produced the
questions, not a classification a reader can act on. Its provenance is recorded
in `proposal-stride-check-catalogue-2026-08-14.md` and belongs there.

## Verified state

Findings Register card, `_build_threat_card`
(`scripts/compose_threat_model.py:14973`, layout comment at `:15011`):

```
**Classification:** Insecure Client-Side Storage · [CWE-922](…) · [OWASP A04:2025](…) · walkthrough [Walkthrough §3.5](#…)
```

Category name, CWE, OWASP Web Top 10 (derived from the CWE taxonomy), optional
walkthrough link. No STRIDE, no OWASP LLM ID.

Where STRIDE does appear:

| Place | Form | Producer |
|---|---|---|
| §3 walkthrough closing line | `STRIDE: Information Disclosure` | `scripts/walkthrough_renderer.py:1598` |
| §7 weakness rows | `(T·I)` | `scripts/compose_threat_model.py:9284` |
| §8 header | `**STRIDE Coverage:** Spoofing: 11 · …` | `data/sections-contract.yaml:1489` |
| SARIF | `stride` tag | `scripts/export_sarif.py:127` |
| Threat Dragon | threat type | `scripts/export_threat_dragon.py:388` |

So a finding shows its STRIDE category only when it happens to have a
walkthrough or to sit in a §7 weakness row. The value itself is enum-controlled
title case (`Spoofing` … `Elevation of Privilege`, `triage_validate_ratings.py:53`),
with a legacy `stride_category` fallback that compose already handles.

Where the OWASP LLM ID appears: `owasp_llm_ids` / `owasp_asi_ids`
(`schemas/stride.schema.yaml:192`) survive merge, YAML and SARIF (as
`owasp-llm:` tags), and in Markdown they are used **only** as the grouping key
of the Management-Summary callout "AI/LLM Exposure"
(`scripts/pregenerate_fragments.py:6220`). They are never printed on the finding
itself.

One more fact that matters for part A: an LLM-surface threat carrying no
`owasp_llm_ids` and matching no title rule triggers a diagnostic on stderr
(`scripts/pregenerate_fragments.py:6249`). It is stderr only — no Run Issue, no
gate — but its wording states an analyzer contract violation.

## Part A — what the four questions may claim

Two of the four map onto a Top 10 category without distortion, two do not.

| Question (lens file table) | STRIDE | OWASP LLM ID | Reason |
|---|---|---|---|
| Which data classes reach the model? | I | `LLM02` | Sensitive Information Disclosure is exactly this. |
| Does an approval-required action run unattended? | E | `LLM06` | Excessive Agency is exactly this. |
| Is a behavioural limit only prompt text? | T | none | A statement about control strength, not an injection finding. It applies to whichever category the guardrail was meant to cover. |
| Is a model-driven action reconstructable? | R | none | The Top 10 has no audit slot. LLM09 is Misinformation; the catalogue already maps hallucination there, and the word "audit" appearing in its check text is not a second meaning. |

Rejected: forcing all four. An "LLM09 Misinformation" badge on a missing-audit
finding is a wrong label in a user-facing callout, and it collides with the
hallucination mapping the catalogue already made.

### Edits

`agents/shared/owasp-llm-top10.md`:

1. Add an `OWASP ID` column to the four-question table with `LLM02`, `LLM06`,
   and `—` twice.
2. Scope the sentence below the table. It currently reads "In the `scenario`
   field, explicitly reference the OWASP LLM ID" and now stands after a table
   whose rows mostly have none — as written it invites an invented ID. It must
   say that the two ID-less questions produce STRIDE findings and get no OWASP
   LLM ID.

Cost: two table cells and one clause. No schema, code, or test change.

Effect: two more finding classes reach the AI/LLM Exposure callout; two
deliberately do not.

### Open point

A finding from "behavioural limit only prompt text" will almost always contain
the word `prompt` in its prose and carry no `owasp_llm_ids`, which is exactly the
stderr diagnostic's trigger. That makes it a guaranteed false positive on every
LLM repository, and the diagnostic's message ("the analyzer is contractually
required to tag what this lens produced") would then be wrong.

Options:

- Leave it. Stderr only, no gate, visible to whoever reads the run log.
- Narrow the trigger so a threat whose `stride` is `Repudiation` or `Tampering`
  and whose title matches no rule is not reported. Cheap, but it weakens the
  diagnostic for the real case it was built for.
- Give the lens a way to say "checked, no Top 10 category applies" — a marker
  field on the threat. Honest, but it is new schema vocabulary for one warning.

Recommendation: leave it and revisit once a real run shows how loud it is. The
diagnostic is a log line, not a gate, and the third option costs a schema field.

## Part B — STRIDE in the Classification line

The report calls itself code-derived STRIDE threat modeling, prints a STRIDE
coverage distribution above the register, and exports the category to SARIF and
Threat Dragon. The Markdown finding card is the one place the reader cannot see
it. That is the actual inconsistency — not the missing PHANTOM-B reference.

### Proposed form

```
**Classification:** Insecure Client-Side Storage · STRIDE: Information Disclosure · [CWE-922](…) · [OWASP A04:2025](…)
```

STRIDE sits directly after the category name: both answer "what kind of
weakness", while CWE and OWASP are external references. Full word, not the
letter — the `(T·I)` shorthand in §7 works because a legend sits under that
table; a card has none.

Against it: a finding with a walkthrough then states its category twice, in §3
and in §8. That is two different sections, and §8 is the register a reader
consults on its own, so the repetition is acceptable.

### Change trace

| Step | File | Change |
|---|---|---|
| Producer | `scripts/compose_threat_model.py` `_build_threat_card` (`:14939` block 7) | Read `t.get("stride") or t.get("stride_category")`, insert as `refs_parts[1]` when non-empty |
| Layout comment | same file `:15011` and `:14546` | Add the field to both skeleton comments |
| Contract | `data/sections-contract.yaml:1502` | Update the card skeleton comment and add `stride` to `card_fields` |
| Consumer | none | `card_fields` has no code consumer today; it is documentation |
| Validation | none required | No QA check parses the Classification line; `Classification` is already in the QA label allowlist (`scripts/qa_checks.py:8273`) |
| Tests | `tests/test_compose_threat_model.py` | Assert the rendered card carries `STRIDE: <category>` after the category name, and that a threat without `stride` renders the line unchanged |

### Edge cases

- Threat without `stride`: omit the segment, never render an empty one or `n/a`
  (the §3 line's `n/a` is its own choice and should not spread).
- `stride_category` legacy key: same fallback compose already uses at `:16656`
  and `:18731`.
- Consolidated findings: unaffected, one category per threat.
- PDF and HTML: the card is prose, not a table, so no column-width work.

Risk is low; the value is already on the object and enum-constrained, and
nothing downstream parses this line.

## Not doing

- No PHANTOM-B string in any report, schema, or export.
- No new provenance or lens field on a threat. The four questions are LLM-lens
  output either way, and STRIDE plus CWE already tell the reader what the
  finding is.
