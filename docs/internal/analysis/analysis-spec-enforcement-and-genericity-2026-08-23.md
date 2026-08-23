# Spec-driven development: what is enforced, and how generic the catalog is

Read-only audit of `specs/`, `data/requirement-bindings.yaml`, `scripts/check_specs.py`,
the two development hooks, `make check`, and `.github/workflows/tests.yml`.
Measured at commit `2ab1877b`.

## Summary

The separation works and the catalog is generic. Enforcement is real but narrow:
it proves *structure and references*, not *conformance*. The only mechanism that
can fail a run because behavior contradicts a requirement is the guard test —
and those tests run in `make check` regardless of the spec layer.

## What is actually enforced

| Mechanism | Where it runs | What it can fail on |
|---|---|---|
| `check_specs.py` | `make check`, CI (every push/PR) | binding schema, duplicate/malformed IDs, requirement without binding, binding without requirement, active-and-retired ID, `applies_to` pattern matching nothing, unknown decision ID, missing document, coverage/guard mismatch, guard node that does not exist |
| `check_specs.py --changed-against <base>` | CI, pull requests only | `specs/requirements.md` or `docs/internal/decisions.md` changed with no `specs/changes/*/proposal.md` in the same diff |
| `scripts/spec_guard.py` | `PreToolUse`, local dev only | asks before Write/Edit/MultiEdit/NotebookEdit, recognizable shell writes, and MCP mutations that target `specs/requirements.md` |
| `scripts/requirements_hook.py` | `PreToolUse`, local dev only | asks before edits to `docs/internal/decisions.md`; otherwise injects the governing requirements as context |
| guard tests (65 distinct nodes, 33 files) | `make check`, CI | the actual product behavior |

`check_specs.py` never asserts that an implementation still satisfies a
requirement. `specs/README.md` states this limitation and does not overclaim.

## Genericity: confirmed empirically

`0361a758` (2026-08-20) split the normative catalog from the technical bindings.
Since that commit:

- 51 commits total, 33 of them touching `scripts/`
- `specs/requirements.md`: **0** changes
- `data/requirement-bindings.yaml`: 1 change
- `specs/changes/`: 0 changes

Before the split, technical churn did reach the catalog — `e67be532`
("replace legacy stage slices with thin runtimes") and `c240a276`
("cut over to the compact generation") both edited requirement text for what
were purely internal cutovers. That class of edit now lands in the bindings.

The 25 requirement texts contain no path, test name, script name, model name, or
internal limit. `TECHNICAL_FIELD_RE` in the checker blocks reintroducing
`**Applies to:** / **Source:** / **Guard:**` lines into the catalog.

Verdict: the catalog is generic enough. Nothing needs to change here.

## Gaps

Ordered by how much they weaken the claim "spec-driven".

### 1. Two bindings miss a surface their own requirement text names

Of 238 files under `scripts/`, 42 match an `applies_to` pattern. That ratio is
not itself a defect: the bindings deliberately name the module that *owns* a
promise, not every file that touches it. The uncovered remainder is helpers,
exporters, repair, logging, and orchestration plumbing.

Two bindings are genuinely short of what their requirement promises:

- **REQ-RPT-002** promises anchors stay consistent "across the reports,
  **exports**, and follow-on tools". `applies_to` names `merge_threats.py`,
  `build_threat_model_yaml.py`, `query_threat_model.py`, `review_threat_model.py`
  — none of `export_sarif.py`, `export_threat_dragon.py`, `export_html.py`,
  `export_pdf.py`, all four of which emit anchors.
- **REQ-FLW-003** promises invalid data "stops the run instead of producing an
  apparently complete report". `applies_to` names `orchestration_controller.py`,
  `validate_intermediate.py`, `schemas/**`. `compose_threat_model.py` is the
  publishing step and is bound only to REQ-REQ-001, although a failed
  `compose --strict` is exactly this requirement's failure mode.

Separately: for an unbound path `check_specs.py --for` prints nothing and exits
0. AGENTS.md instructs agents to run it before changing a file, so the
instructed step is a silent no-op indistinguishable from "checked, nothing
applies". Making it say `no requirement is bound to this path` costs three
lines and removes that ambiguity.

### 2. Bash edits bypass requirement surfacing

`requirements_hook.decide()` handles `Bash` only to protect the decision
register. Its requirement-surfacing branch is reachable only from
`Edit|Write|MultiEdit|NotebookEdit`. An agent editing with `sed -i` or a
heredoc — which some operating modes actively prefer — never sees the
requirements for the file it is changing. `spec_guard.py` does cover shell
writes, so the *approval* gate on the catalog itself has no such hole.

### 3. The proposal gate accepts any proposal

`unapproved_changes()` is satisfied by any changed path matching
`specs/changes/*/proposal.md`, related or not, tracked or untracked. It also
runs on pull requests only, so a direct push to `dev` skips it entirely.
`specs/README.md` already says the check "records the change process but cannot
prove that a person approved it" — the CI-trigger restriction is the part not
stated.

### 4. REQ-RPT-002 is classified `advisory` although guards exist

Public finding anchors are `advisory` (no guard), while
`tests/test_compose_depth_scoped_crossrefs.py::TestSection6BackLink::test_every_emitted_anchor_is_injectable`
and `tests/test_export_threat_dragon.py::test_title_carries_the_report_anchor_not_the_yaml_id`
exercise exactly the cross-artifact anchor consistency the requirement promises.
The other two advisory entries (REQ-PUR-001, REQ-PUR-002) are purpose statements
where `advisory` is honest.

### 5. Two requirements rest on a single guard

REQ-BIZ-002 and REQ-MOD-001 each name one test node. Both are `direct`, so the
catalog claims the central behavior is proven by one assertion.

## Status

Gaps 1, 4, and the `--for` no-op were closed in the same commit that added this
document: the four exporters and `compose_threat_model.py` joined the two short
bindings, REQ-RPT-002 moved from `advisory` to `partial` with its two existing
anchor guards, and `--for` now prints `No requirement is bound to <path>.`
Coverage went from 15/7/3 to 15/8/2.

Gap 2 is tracked separately. Gap 3 stays open: no reliable join exists between a
proposal and the requirement it proposes, and extending the CI trigger from
`pull_request` to `push` only pays off if requirement changes actually reach
`dev` without a pull request.

## Not a gap

- Bindings churn is the intended volatile surface; renaming a bound test or
  script fails `check_specs.py` by design.
- 19 retired IDs are recorded and blocked from reuse.
- Neither hook ships to users: they live in `.claude/settings.json`, not
  `hooks/hooks.json`.
