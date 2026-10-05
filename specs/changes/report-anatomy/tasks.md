# Tasks

## Slice 1: drift test

- [x] Freeze a rich run as `tests/fixtures/report-anatomy/quick-run`; use `tests/fixtures/e2e/frozen-run` for §3.
- [x] Add `tests/test_report_anatomy.py`: regenerate deterministic fragments, render, and compare headings, tables, and fields against `report-anatomy.md`, plus chapter order and §6 subsections against the contract, with negative cases for each kind of drift.
- [x] Route the test in `scripts/run_tests.py`.

## Slice 2: align the existing descriptions

- [ ] Align `data/sections-contract.yaml` with the document: `card_fields`, retired MS entries in `optional_subsections`, the Top Mitigations `sub_sections`, and section numbers in comments. Review `tests/test_compose_threat_model.py`, `tests/test_contract_integrity.py`, and the composer's use of `sub_sections` first.
- [ ] Align the `_build_threat_card` docstring and the §8 and §10 intro texts with the document, and update the tests that pin those texts.

## Slice 3: approval and protection

- [ ] Decide the open decisions in `proposal.md`.
- [ ] Approve the wording of `report-anatomy.md` and of the new Report requirement.
- [ ] Move the approved document to `specs/report-anatomy.md` and add the requirement to `specs/requirements.md` with its binding in `data/requirement-bindings.yaml`, guarded by the drift test.
- [ ] Extend `scripts/spec_guard.py` and `scripts/check_specs.py --changed-against` to hold `specs/report-anatomy.md` like the requirement catalog.

## Separate

- [ ] Fix the cross-reference linker that renders the §7b reference in the Management Summary as `[§7](#7-weakness-register)b`.
