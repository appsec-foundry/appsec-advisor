# Handoff: legacy retirement and appsec-analyzer transition

Status: open, 2026-10-17. Working record for the transition described in [the security assessment concept](../../proposals/application-security-assessment-concept.md). Target release 0.6.0-beta.5; the release happens only after the operator approves the completed work. Nothing is pushed; the tag `archive/create-threat-model` is local only.

## Done

| Commit | Change |
|---|---|
| `2d55fa1b` | Controller writes the `.gitignore` rule for a report folder in the checkout before admitting its source |
| `785c7e94` | Free-text focus is refused instead of dropped |
| `6368a4b6` | The controller skill has its own business-context dialog file |
| `a99bf64a`, `9872b1b7`, `4ab5f8ce` | `create-threat-model2` became `create-security-assessment`, then `appsec-analyzer` |
| `ff195737` | Session action protocol removed from the controller (12,331 → about 4,800 lines) |
| `6b87f4c3` | 33 legacy-only scripts removed |
| `a1c8984d` | Agents fragment-fixer, qa-reviewer, config-scanner and context-resolver removed; context template moved to `templates/threat-modeling-context.md` |
| `21d32256` | `run-headless.sh` sends every assessment to the controller; without `--repo` the current directory is the repository |
| `a886d531` | `skills/create-threat-model/` removed; `appsec-analyzer` is the packaged required skill, banner and status command |
| `96f43cda` | Seven protocol-only schemas removed |
| `9d299be8` | REQ-TRU-002 guarded at `redact_known_secrets.py`; `postscan_secret_check.py` removed |
| `44014dec` | Decisions `OR-7`, `CE-5` and `IN-3` retired, `OR-1` reworded for controller-launched roles (operator-approved, `specs/changes/retire-session-protocol-decisions/`) |
| `34099dcb` | `REQ-USE-004` keeps only history preservation, `REQ-FLW-009` promises refusal of a narrowed focus (operator-approved, `specs/changes/drop-incremental-and-focus-promises/`) |
| `b0409fd9` | A new scan over a completed assessment needs no `--rebuild` and continues its changelog; `--rebuild` resets it (operator chose this over "every rerun starts over") |
| `921c299e` | Lost guards replaced: a new controller guard for REQ-MOD-002 (weaknesses regrouped after ranking); existing controller-path tests bound to REQ-BIZ-010, REQ-FLW-006, REQ-MOD-004, REQ-PUR-001. REQ-BIZ-005 needed none: its controller guards cover the dialog handoff, same-run use, unsafe saves and kept context; the two-question limit is dialog prose only |
| `e7e8aee6` | Incremental reconciliation removed from the model builder with its tests and routes (unreachable: the controller always writes `mode: full`) |

Operator decisions taken in this work: incremental updates dropped for now; free-text focus refused; rerender and the QA reviewer not rebuilt; legacy agents removed and `config_scanner_model` / `context_resolver_model` accepted without effect; main skill named `appsec-analyzer`; consumer skills keep the `*-security-assessment` names from the concept.

## Open, in order

1. **Legacy resolver.** `resolve()` and `main()` in `scripts/runtime/resolve_config.py` have no caller outside tests; the controller uses only `resolve_assessment()`, `build_parser()` and shared constants and helpers. Remove them with everything only they use, including the incremental mode rules (`resolve_incremental_mode`), the incremental part of `resolve_business_context` and its baseline readers, and their tests (among them the former `IN-3` guards). Check each function's callers before deleting it; the operator chose to do this as its own step.
   - The builder's `_output_mode` still maps a `mode: incremental` to the public mode; it only matters for old configurations and can go with the resolver.
   - `docs/internal/analysis/proposal-depth-downgrade-incremental-preservation.md` describes the removed reconciler; keep it as a dated analysis.
2. **Documentation.** `docs/headless-mode.md`, `docs/threat-modeler.md`, `docs/model-selection.md`, `README.md` and `docs/internal/contracts/context-routing.md` still describe the legacy skill, its modes and flags. Rewrite them together with B and C so names and paths change once. `APPSEC_TELEMETRY_STRICT` is read by no script any more but still appears in `agents/shared/logging-standard.md`, `docs/internal/runbooks/acceptance-cohort.md` and `scripts/live_canary.py`.
3. **B: consumer skill renames** (`ask-`, `show-`, `triage-`, `export-`, `eval-security-assessment`, `security-assessment-health`, `update-threat-model` removed), plus about 160 files that mention `create-threat-model` in text. Internal caller IDs such as the `create-threat-model` caller in `requirements/fetch_requirements.py` are separate; decide whether they rename.
4. **C: artifacts and storage** — `security-assessment.*` basenames, external default destination, permissions, migration with `--migrate-legacy` / `--ignore-legacy`.
5. **Changelog** for the user-visible changes, after B and C.

## Known state

- `tests/test_run_tests.py::test_modules_on_the_golden_fixture_replay_route_to_it` fails on a clean `HEAD` as well (`scripts/shared/_remote_url.py` lacks the `test_threat_fixture` route).
- `tests/test_context_routing.py::test_catalog_runtime_bindings_and_schemas_are_packaged` cannot run in the sandbox: it copies dot files the sandbox denies.
- `CHANGELOG.md` carries an uncommitted edit from another session; never stage it with this work.
- Other sessions commit documentation to `dev` in parallel; check `git log` before any history operation.

## Working rules the operator set

- Run only the checks a change requires, and name what each one exercises. No broad module sweeps and no `make audit-test-routes` for small route additions.
- Verify reported gaps against the code before fixing them; the legacy inventory overstated several (secret check, requirements check).
- Prune tests at function or method level; never delete a class or helper because one member referenced removed code. Check module-level imports of deleted modules too.
- Stage explicit paths; `git rm` leaves deletions staged for the next commit.
