# Tasks

- [x] `specs/README.md` — format, sources rule, what is enforced and what is not.
- [x] `specs/requirements.md` — 32 requirements across purpose, the finding
      model, roles, flow, depth and rescans, context, requirements mapping,
      business context, cost, report, trust, and configuration.
- [x] `scripts/check_specs.py` — validation and the `--for <path>` lookup.
- [x] `tests/test_check_specs.py` — one test per rejected reference.
- [x] `scripts/requirements_hook.py` — denies the catalog and the register
      through `Edit`/`Write` and through a shell command that could write to
      either, and attaches the governing requirements to every other edit.
- [x] `check_specs.py --changed-against <ref>` — a held file changed with no
      change directory fails.
- [x] `tests/test_requirements_hook.py`.
- [x] `make check` runs `scripts/check_specs.py`.
- [ ] Operator wires the hook into `.claude/settings.json` (`PreToolUse`,
      matcher `Edit|Write|NotebookEdit|Bash`). Not writable from a session.
- [x] `AGENTS.md` names the catalog, the `--for` lookup, and that neither file
      is the agent's to edit.
- [ ] Operator wires `--changed-against` into `.github/workflows/tests.yml`.
- [ ] Close the 7 requirements that carry no guard, or record why they cannot
      have one: REQ-PUR-001, REQ-PUR-002, REQ-MOD-005, REQ-FLW-002, REQ-INC-002,
      REQ-BIZ-002, REQ-RPT-002.
- [ ] Resolve the 27 decision rows whose guard names a file rather than a test,
      and triage the 25 that name none.
