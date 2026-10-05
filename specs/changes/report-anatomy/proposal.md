# Report anatomy as an approved specification

## Problem

The structure of `threat-model.md` can change without anyone deciding that it should. `specs/requirements.md` says what a finding and a mitigation must achieve (`REQ-RPT-003`, `REQ-RPT-005`) but not which sections the report has or which fields a finding card or a mitigation block carries. The structure lives in `data/sections-contract.yaml` (1,609 lines, mixing structure, renderer detail, and history) and in `scripts/renderers/compose_threat_model.py`. QA checks that the report matches the contract; nothing holds the contract or the renderer to an approved shape. `spec_guard` protects only `specs/requirements.md`.

The four descriptions of the finding card that exist today already disagree:

- `card_fields` in `data/sections-contract.yaml` lists `root_cause` as a fixed field. The renderer emits it only when the analysis authored one.
- The §8 intro text in the rendered report says every card has the same fixed fields including Root cause. Most cards have none.
- The docstring of `_build_threat_card` describes a table-cell layout with separate Impact and Attack Walkthrough fields. Impact is folded into Issue and the walkthrough link moved into Classification.
- The emitted fields Violates, Weakness, Trust boundary gap, and Instances appear in none of the three descriptions.

The mitigation block has no contract at all beyond the P1–P4 group headings. The §10 intro text names Why, How, and Verification as optional, while `scripts/validators/validate_mitigation_quality.py` requires steps and verification for P1 and P2.

The Management Summary contract still lists Architectural Anti-Patterns and Security Principles as optional subsections; `_render_management_summary` retired both on 2026-07-14. The contract also defines Top Mitigations as two subsections, Prioritized and Follow-up, with a Priority column; the renderer emits one table `| # | Component | Mitigation | Addresses | Effort |` without those subsections. Comments in the contract call the Mitigation Register §9 and the Weakness Register §6; the headings are §10 and §7.

The golden report `tests/fixtures/e2e/golden/threat-model.md` is rendered by the current code, but from the thin, partly hand-written fragments of `tests/fixtures/e2e/frozen-run`. Its Assets table and finding cards therefore show older or sparser shapes than a real run produces, and it cannot serve as the reference for the report's structure.

The Management Summary prompts still describe the retired Top Mitigations layout: `agents/shared/ms-template.md` and `agents/shared/qa-ms-checks.md` instruct two sub-tables under Prioritized and Follow-up Mitigations, which the composer no longer renders and `tests/test_compose_threat_model.py` asserts are absent. Prompt text is plugin runtime input, so it is corrected separately.

A recomposition of `tests/fixtures/e2e/_last-run` with the current code renders the §7b link in the Management Summary as `[§7](#7-weakness-register)b`. The cross-reference linker matches `§7` inside `§7b`. This is a renderer defect independent of this proposal.

## Goal

A reader can see in one short document what the report contains, in which order, and how a finding, a mitigation, and a weakness are built. A change to that shape fails a test until the document is changed with operator approval.

## Non-goals

- Fixing ranking, selection limits, prose style, diagram geometry, or the content of §6 control families. Those stay in their contracts and change through ordinary review.
- Replacing `data/sections-contract.yaml`. It remains the renderer's source; the new document is the approved, human-readable statement it must agree with.
- Restructuring `specs/requirements.md`.

## Proposal

1. Add `specs/report-anatomy.md` with the content of the draft in this folder.
2. Protect it like `specs/requirements.md`: `scripts/spec_guard.py` asks before a mutation, and `scripts/check_specs.py --changed-against` requires a proposal when it changes.
3. Add one requirement in the Report section that binds the product promise to the document, for example: "REQ-RPT-009 — The report follows its approved anatomy. The report's outline, Management Summary blocks, and the fields of findings, mitigations, and weaknesses follow `specs/report-anatomy.md`."
4. Add a drift test, `tests/test_report_anatomy.py`. It regenerates the deterministic fragments of two frozen runs with the current pre-generator, renders them with the current composer, and compares headings, table headers, and the fields of findings, mitigations, and weaknesses against the document. It also compares the chapter order and the §6 subsections with the contract. It fails when a required part is missing, when a part appears that the document does not list, or when the order differs, and never requires an optional part. The frozen runs are `tests/fixtures/report-anatomy/quick-run`, a copy of a full synthetic-repository run at quick depth with weaknesses, a requirements catalog, and an LLM surface, and `tests/fixtures/e2e/frozen-run` for §3. `tests/fixtures/e2e/_last-run` is not used directly because every full E2E run overwrites it.
5. Correct the drift listed above in the contract comments, the stale `card_fields`, the retired MS entries, the docstring, and the §8 and §10 intro texts, so that all of them agree with the approved document.

## Open decisions

1. Required finding fields. The current renderer emitted Root cause on none of 13 findings in the recomposed run, and emits Evidence only when evidence was recorded. The draft describes both as optional, which is today's behavior. Making either required is a renderer change.
2. Numbering gaps. When §7 is absent the report jumps from §6 to §8. Fixed numbers keep anchors such as `#8-findings-register` stable. The draft keeps fixed numbers with gaps.
3. Untested parts. Neither frozen run renders §6 content or abuse-case scenarios. §6 is held through the contract; abuse-case scenarios are described but not checked until a fixture contains one.

## Risks

- The document, the requirement, and the hook change no runtime code.
- `card_fields` and the contract comments are read by no code. The retired MS entries in `optional_subsections` are asserted by `tests/test_compose_threat_model.py` and `tests/test_contract_integrity.py`, and the Top Mitigations `sub_sections` are read by the composer; both need review before they change.
- Correcting the §8 and §10 intro texts changes rendered output, so tests that pin that text change with it.
- The drift test guards the renderer against unintended structural change. It does not catch an LLM-authored section that deviates in a live run; the existing QA gates remain responsible for that.
