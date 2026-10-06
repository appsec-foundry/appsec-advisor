# Tasks

## Slice 1: drift test

- [x] Freeze a rich run as `tests/fixtures/report-anatomy/quick-run`; use `tests/fixtures/e2e/frozen-run` for §3.
- [x] Add `tests/test_report_anatomy.py`: regenerate deterministic fragments, render, and compare headings, tables, and fields against `report-anatomy.md`, plus chapter order and §6 subsections against the contract, with negative cases for each kind of drift.
- [x] Route the test in `scripts/run_tests.py`.

## Slice 2: align the existing descriptions

- [x] Align `data/sections-contract.yaml` with the document: `card_fields`, the unused `triage_notes` entry, a note on the two retired Management Summary entries that stay listed because their sections are still used, the Top Mitigations sub-tables and columns, and section numbers in comments.
- [x] Align the `_build_threat_card` docstring and the §8 and §10 intro texts with the document.

## Slice 3: approval and protection

- [ ] Decide the open decisions in `proposal.md`.
- [ ] Approve the wording of `report-anatomy.md` and of the new Report requirement.
- [ ] Move the approved document to `specs/report-anatomy.md` and add the requirement to `specs/requirements.md` with its binding in `data/requirement-bindings.yaml`, guarded by the drift test.
- [ ] Point `ANATOMY` in `tests/test_report_anatomy.py`, the contract comments, the `_build_threat_card` docstring, and the fixture README to the moved document.
- [ ] Extend `scripts/spec_guard.py` and `scripts/check_specs.py --changed-against` to hold `specs/report-anatomy.md` like the requirement catalog.

## Separate

- [ ] Extend the frozen runs with §6 content, an abuse-case scenario, an accepted risk, and a composition warning, so the test checks those parts too.
- [ ] Fix the cross-reference linker that renders the §7b reference in the Management Summary as `[§7](#7-weakness-register)b`.
- [ ] Remove the retired Prioritized and Follow-up Mitigations layout from `agents/shared/ms-template.md` and `agents/shared/qa-ms-checks.md`.
