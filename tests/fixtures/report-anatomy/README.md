# Report anatomy fixture

`quick-run/` is a frozen copy of a full `create-threat-model` run against `tests/fixtures/e2e/synthetic-repo` at quick depth, with a requirements catalog and an LLM surface. It holds only the inputs the composer reads: `threat-model.yaml`, the run's fragments, the skill configuration, the triage flags, and the resolved requirements. Local paths are replaced with `/plugin`.

`tests/test_report_anatomy.py` regenerates the deterministic fragments from this model, renders the report, and checks it against `specs/changes/report-anatomy/report-anatomy.md`. Refresh the copy only when the model schema changes in a way the current composer can no longer read.
