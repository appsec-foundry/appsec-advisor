# Tasks

- [x] Refuse `--context` when the resolved producer is not context-v2, naming
      the producer and the working flag combination
      (`scripts/resolve_config.py`).
- [x] Emit `Business Context File` in the context artifact's header table,
      carrying the file that was read
      (`scripts/build_threat_modeling_context.py`, and the same row in the
      `appsec-context-resolver` template).
- [x] Derive the report's context sources from that field instead of naming
      `docs/business-context.md` unconditionally
      (`scripts/orchestration_controller.py`).
- [x] Record `meta.business_context_source` beside the digest
      (`scripts/build_threat_model_yaml.py`).
- [x] Tell a cleaned-up run-only source apart from an edited context in the
      incremental note (`scripts/resolve_config.py`).
- [x] Approve the reworded `REQ-BIZ-003` and the guard on `REQ-MOD-008`.
- [x] Apply both entries to `specs/requirements.md`.
- [ ] Guard the citation half of `REQ-MOD-008`: a finding that rests on a
      supplied document names it as its source. Blocked on the evidence shape
      tracked in `changes/state-what-the-model-is-for`.
- [ ] Decide whether the STRIDE analyzer prompt should state how a component's
      business context bears on impact. Today the only instruction is the
      `description` in `schemas/stride-analyst-context.schema.json`.
