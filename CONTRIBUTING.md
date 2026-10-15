# Contributing

Agent and skill definitions are Markdown files. Python handles validation, rendering, exports, and runtime checks.

Read [`AGENTS.md`](AGENTS.md) before changing runtime behavior, schemas, prompts, or report output. It maps each type of change to the contracts and tests that must stay aligned.

## Submitting changes

Open an issue before substantial changes so the approach can be agreed before implementation. Typos and small fixes can go directly to a pull request.

1. Describe the problem and proposed behavior in an issue.
2. Open a focused pull request against `dev` and link the issue.
3. Run the relevant tests and lint checks.
4. Complete the pull request template.

Maintainers are listed in [`.github/CODEOWNERS`](.github/CODEOWNERS) and review all changes to `main`. For security issues, follow [Reporting security issues](#reporting-security-issues).

## Dev environment setup

Use isolated environments instead of installing development tools into the system Python.

**ruff** (linter/formatter):
```bash
pipx install 'ruff>=0.11.13,<0.13'   # needs: sudo apt install pipx
```
Use the pinned range so local results match CI.

**Test dependencies:**
```bash
python3 -m venv .venv
.venv/bin/pip install -r tests/requirements-test.txt
```

The `Makefile` uses `.venv/bin/python3` automatically.

**Claude Code sandbox:** `.claude/settings.json` turns the sandbox on, because the
pipeline reads untrusted target repositories. Two things need an unsandboxed retry:
PDF export (mermaid drives a headless Chrome over a local socket) and any write to
`.git/config`, `.github/`, or `.claude/`, which the sandbox denies by default.

## Commands

### Tests

```bash
make test-quick                    # shared base drift guards
make test-group GROUP=report        # focused report and export tests
make test-for FILES="a.py b.py"     # only the named files' routed tests; refuses a full-suite fallback
make test-plan BASE=origin/dev      # explain the selection without running tests
make test-changed BASE=origin/dev   # branch and local changes plus requirement guards
make test-plan BASE=HEAD            # explain only staged, unstaged, and untracked work
make test-full                     # complete suite without coverage
make check                         # lint, validators, and complete suite
make test                          # complete suite with coverage
make coverage                      # complete suite with HTML coverage report
```

Test dependencies: `tests/requirements-test.txt` (pytest, pytest-cov, pyyaml, jsonschema, jinja2).

Choose one full-suite command for the required gate. `make check` already includes `make test-full`; running `make test` afterward is only useful when coverage measurement is also required. Focused tests do not use the global coverage threshold.

CI runs lint and validators once, then the complete suite on Python 3.10, 3.11, and 3.12. Only Python 3.12 measures coverage. All pushes to `dev` and `main` and pull requests targeting those branches retain these checks, including documentation changes.

#### Manual full-run (end-to-end) test

Run the manual end-to-end check when a change needs evidence from live model behavior or Claude Code integration, such as agent dispatch, phase interaction, or host hook delivery. Deterministic renderer, schema, and scanner changes use the targeted tests and fixture replay below unless they also change that integration. Run the prescribed live checks at release boundaries.

> [!IMPORTANT]
> This check calls Claude Code and consumes model budget. The synthetic quick fixture typically costs about $0.30–1.00 with API billing or 30–50% of a Pro five-hour usage window. It is not part of the normal CI suite.

```bash
make e2e-full
```

or, from inside a Claude Code session in this repository:

```text
/e2e-full
```

The driver runs the full pipeline against a clean synthetic repository and checks output schemas, evidence, exports, security boundaries, and expected findings.

Additional targets cover specific paths:

| Target | Purpose |
|---|---|
| `make e2e-full-standard` | Include the full QA stage. |
| `make e2e-full-thorough` | Include QA and architecture review. |
| `make e2e-full-repair` | Verify report repair after a deliberate corruption. |
| `make e2e-full-eval` | Add the semantic-quality evaluation. |

`make e2e-fixture-suite` checks all external language and architecture fixtures. It requires the sibling `appsec-advisor-fixtures` checkout.

Use `make e2e-full-keep` to rerun assertions against the previous E2E output without another model call.

The deterministic assessment controller has its own checks:

| Target | Purpose |
|---|---|
| `make test-controller` | Offline, no model cost, about 80 seconds: one in-process single-repository controller run over a small web application (a browser client calling its own API through guarded, public and unresolved routes), so route inventory, client-to-API flows, the architecture gate, abuse matching and publication run on real structure. Run it after any controller or deterministic-stage change. |
| `make e2e-controller` | Offline, no model cost, about two minutes with `pytest-xdist` installed: complete controller runs through `scripts/run-headless.sh` and the real CLI transport against `tests/e2e/fake_claude.py`, with injected rate-limit, overload, text-answer and login failures and a `--resume` after a stopped run. |
| `make e2e-controller-live` | One live quick controller run with the real `claude` CLI on the synthetic repository, or on `REPO=<path>`, bounded by `BUDGET` (default 3 USD); it checks that a valid model was published and prints the host event logs for diagnosis. |

Cross-repository behavior has a separate driver. See the [cross-repository fixture runbook](docs/internal/runbooks/e2e-cross-repo-fixture.md).

#### Targeted tests before finishing a non-trivial change

Follow the [verification rules in AGENTS.md](AGENTS.md#verification) to select checks for changed behavior, affected consumers, and applicable contract or security invariants. Review candidates with `python3 scripts/run_tests.py --list --path <path>` for each changed file, including requirement guards from `scripts/check_specs.py --for <path>`. Routes and bindings aid selection; they are neither a mandatory minimum nor a complete dependency graph.

| Change | Local checks |
|---|---|
| Documentation or examples | Applicable document, example, and contract validators. |
| Python behavior | Affected module and consumer tests, applicable validators, and lint and format checks. |
| Agent or skill prompts | Applicable prompt and contract checks, plus tests for affected behavior. Markdown under `agents/` or `skills/` is runtime input. |
| Rendering, report structure, or exports | Affected producer, consumer, and contract checks. Replay a golden fixture for deterministic-tail changes. |
| Scanner or heuristic | Affected scanner and consumer checks, neutral regression cases, and a golden fixture replay. |
| Impact that cannot be bounded to focused checks | State why the impact cannot be bounded, then run `make check`. |
| Release | `make release-check` and the prescribed live E2E checks. |

For the current task, the combined command below applies only when all routed tests and all validators are required. For smaller selections, invoke the required validators and exact pytest selectors directly.

```bash
make validate test-for FILES="scripts/example.py tests/test_example.py"
```

`test-for` selects only the named files, so unrelated local changes and branch commits add no tests. `validate` still checks the whole working tree. When a named file has no reviewed route or needs the full suite, `test-for` exits with code 2 and names the reason. Report it and assess the actual impact before selecting further checks.

For a complete branch, inspect the Git-based selection and run the combined command only when its entire selection is required:

```bash
make test-plan BASE=origin/dev
make validate test-changed BASE=origin/dev
```

The selection includes commits since the merge base with `BASE` and all staged, unstaged, and untracked files. `BASE` defaults to the local `origin/dev` reference; the runner does not fetch it. `make test-plan BASE=HEAD` excludes branch commits but still includes all local tasks. Use named paths to isolate one task in a mixed working tree. An invalid reference fails before pytest starts. Routes select reviewed producer and consumer modules; changed test modules run directly, and requirement bindings retain exact pytest selectors. A clean comparison runs no tests because `make validate` owns shared drift checks.

Source routes cover explicitly reviewed producers, consumers, prompts, schemas, templates, and repository documents. Routes for multiple changed source files are united. Unknown paths, shared inputs without a reviewed route, and deleted files fall back to the full suite. Every Python script has a reviewed route or an explicit full-suite reason in `scripts/run_tests.py`. The plan lists every changed path that requires this fallback, so repairing one route does not conceal another missing route. Review the plan against the behavior changed; an existing route does not prove that a new dependency is covered. Full compatibility and coverage runs remain in CI while the local selection is evaluated.

For Python changes, run Ruff lint and format checks on the affected files. Use `make lint` only when its global scope over `scripts/`, `tests/`, and `hooks/` is required. Multiple consumers or a routing fallback alone do not justify a full suite; use `make check` only at release boundaries or when impact cannot be bounded to focused checks. Reuse successful checks until relevant source, contracts, dependencies, or the test environment changes, or failures require a rerun. Stop when required checks pass.

Group membership and source routes live in [`scripts/run_tests.py`](scripts/run_tests.py). The groups are `quick`, `prose-formatting`, `report`, `scanner`, `prompts`, `runtime`, `incremental`, `e2e`, `qa-repair`, `findings`, `config`, `requirements`, `baseline`, `packaging`, `context`, `trust`, `shared`, `tooling`, and `integration`. The `e2e` group retains the frozen-run replay without model calls; `integration` covers other deterministic integration tests and drivers. Manual live-run assertions have a separate role and are not added to focused groups.

When adding or renaming a test, update its exact membership or its justified manual role. When adding a Python script, give it a measured producer and consumer route or a justified entry in `FULL_SUITE_SOURCES`; the routing tests reject silent gaps. When changing a producer or consumer, review the source routes and the tests at that boundary. `make validate` checks the inventory and rejects unassigned tests, stale paths, and invalid routes. File assignment prevents omission but does not prove semantic coverage. Do not infer sufficient coverage from filenames or Python imports alone; tests also invoke subprocesses and read schemas, templates, and prompts.

Run `make audit-test-routes` after adding or changing a source route. It runs every test module under coverage, including subprocesses, and records the repository files each test reads. It fails when a route misses a test that executes the routed script, uses one of its module-level constants or classes, or reads the routed file. It also reports routed tests without a measured dependency; remove them only when they were not skipped or failed during the measurement and do not stop a subprocess with a signal other than SIGTERM. The audit runs eight test modules in parallel by default; `python3 scripts/audit_test_routes.py --jobs <n>` sets another number.

```bash
make test-group GROUP=scanner
python3 scripts/run_tests.py --list report  # inspect the selected files
python3 scripts/run_tests.py report -x -q   # forward pytest options
scripts/run-tests.sh group report          # same selection with dependency setup
scripts/run-tests.sh changed origin/dev -q # changed-file selection
scripts/run-tests.sh pattern 'golden' -q    # explicit pytest name filter
```

`scripts/run-tests.sh quick` and `make test-quick` use the same selection. The wrapper prefers `.venv`, then an installed system interpreter, then `.venv-tests`; it installs test dependencies into `.venv-tests` if needed. A missing group name fails before dependency setup. Unknown names passed through `group` fail. The legacy `scripts/run-tests.sh <pattern>` form retains pytest's `-k` filtering: `scripts/run-tests.sh scanner` is a name filter, while `scripts/run-tests.sh group scanner` selects the reviewed group.

#### Deterministic end-to-end (no LLM)

`tests/test_e2e_pipeline.py` renders a frozen run and compares the Markdown and SARIF output with committed golden files.

After an intentional renderer, contract, or exporter change, inspect the diff and regenerate the goldens:

```bash
APPSEC_UPDATE_GOLDEN=1 python3 -m pytest tests/test_e2e_pipeline.py -k golden
```

Do not edit golden output by hand to hide a producer defect.

Do not run tests before a change to capture a baseline. When a selected test fails, rerun only the failing tests at the merge base in a temporary worktree. Replace `<failing test ids>` with the pytest node IDs from the failed run, and omit tests whose file does not exist at the merge base; they belong to the current change. Use `HEAD` instead of the merge base when the selection used `BASE=HEAD`.

```bash
base_dir=$(mktemp -d)
GIT_LFS_SKIP_SMUDGE=1 git worktree add -d "$base_dir" "$(git merge-base origin/dev HEAD)"
(cd "$base_dir" && python3 -m pytest <failing test ids> -q)
git worktree remove --force "$base_dir"
```

The same failure at the reference revision is pre-existing; a comparable passing run establishes a regression. A missing or skipped test provides no baseline. Tests that read git-ignored local data, such as `tests/fixtures/e2e/_last-run`, skip in the worktree. Do not normalize or hide new failures. When targeted tests fail outside touched files, report failing test names and error heads instead of stale global counts.

### Validation scripts

```bash
python3 scripts/validators/validate_config.py .              # config schema validation
python3 scripts/validators/validate_intermediate.py <file.json>  # intermediate file schema
```

### Development utilities

```bash
python3 scripts/mock-server.py [port]             # mock REST endpoints: context + requirements (default 4444)
./scripts/run-headless.sh --repo /path --output /out --yaml --sarif
python3 scripts/requirements/harvest_requirements.py           # regenerate fallback requirements YAML (use --format all for spec exports)
python3 scripts/threat_fixture.py freeze --run /out --into tests/fixtures/golden/<name> --repo /path
python3 scripts/threat_fixture.py replay --fixture tests/fixtures/golden/<name> --repo /path
python3 scripts/runtime/diagnostic_bundle.py collect --run /out --into . --repo-root /path  # user → maintainer
python3 scripts/runtime/diagnostic_bundle.py inspect --bundle appsec-diag-<id>.tgz          # maintainer triage
```

`threat_fixture.py` captures and replays completed runs without another scan. See the [threat fixture runbook](docs/internal/runbooks/threat-fixture.md).

`runtime/diagnostic_bundle.py` creates a scrubbed bundle for maintainer triage. Inspect every bundle before sharing it.

## Repository layout

| Path | What it is |
|------|-----------|
| `.claude-plugin/plugin.json` | Claude Code plugin manifest |
| `.claude/settings.json` | Contributor permission settings; `data/required-permissions.yaml` remains authoritative |
| `agents/` | Agent definitions (Markdown with YAML frontmatter) |
| `agents/shared/` | Shared standards (logging format, validation routines) |
| `skills/` | User-invocable skills, one directory per skill (e.g. `create-threat-model`, `audit-security-requirements`, `status`, `publish-threat-model`, `export-threat-model`) |
| `hooks/` | Hook definitions + configurable steering keywords |
| `schemas/` | YAML/JSON schemas for intermediate files and output |
| `templates/` | Report templates (management summary, sections) |
| `data/` | Requirements, policy, and rule data |
| `scripts/` | Domain packages plus maintainer tools and shell entry points; see the [script layout](scripts/README.md). |
| `tests/` | Pytest suite: agent definitions, integration, steering, SARIF, schemas |
| `examples/` | Example requirements catalogs, blueprints, abuse cases, and audit outputs |
| `docs/` | User and maintainer documentation |
| `config.json` | Plugin config (external context, pricing, logging) |

## Agent definition format

All agent `.md` files require YAML frontmatter with `name`, `description`, `tools`, `model`, and `maxTurns`. `tests/test_agent_definitions.py` enforces these constraints including turn-budget ceilings. Run that test after any frontmatter change.

## Code style

Python code in `scripts/`, `tests/`, and `hooks/` is linted and formatted with [ruff](https://docs.astral.sh/ruff/). The configuration lives in `pyproject.toml`. CI runs:

```bash
ruff check scripts/ tests/ hooks/
ruff format --check scripts/ tests/ hooks/
```

For Python changes, run both checks on the affected files before opening a pull request. Use the directory-wide commands above when their full scope is required under the [verification rules](AGENTS.md#verification). `ruff check --fix` and `ruff format` can apply most fixes. Keep rule exceptions scoped and documented in `pyproject.toml`.

## Type hints

Add type hints to new public functions. `mypy` is not currently enforced.

## Adding components

When adding a new section to the generated threat model, see [`docs/internal/runbooks/adding-a-section.md`](docs/internal/runbooks/adding-a-section.md). It covers the five registry maps that must stay aligned. Their contracts are documented in [`docs/internal/contracts/schema-invariants.md` §4f](docs/internal/contracts/schema-invariants.md#4f-fragment-registry-maps--single-source-of-truth).

## Reporting security issues

Do not open public issues for vulnerabilities. Use a [GitHub Security Advisory](../../security/advisories/new). See [`SECURITY.md`](SECURITY.md).
