# Supply-chain checks — Python & npm gap analysis (2026-07-19)

> **Status: implemented 2026-07-19.** All findings below were reproduced against
> synthetic fixtures before any edit, then fixed in
> `scripts/assess_supply_chain_controls.py` with paired regression tests in
> `tests/test_assess_supply_chain_controls.py` (83 pass). The only deferred item is
> **C2** (adding cooldown / Trusted Publishing / dependency-review as *new*
> sub-controls), which would change the nine-row contract — the cooldown signal was
> instead folded into the existing Dependency-management row. Section headings are
> kept in the past tense of the original analysis for traceability; see
> "Implementation notes" at the end for what each fix became.

Scope: the **deterministic §8 scorecard** (`scripts/assess_supply_chain_controls.py`, 9
sub-controls) and the **IAC layer** (`data/config-iac-checks.yaml`). The recon/LLM layer
(`recon_patterns.py` Cat 14/15/17/26/27/28) is out of scope except where the scorecard
under-uses what recon already detects.

Every finding below was verified against code, not inferred. Line refs are to HEAD.

---

## P0 — structural

### S1. `ADEQUATE` is unreachable for the whole domain

`_eval_dep_management` (`assess_supply_chain_controls.py:350-356`) returns only `PARTIAL`
or `MISSING` — there is no `ADEQUATE` branch. `_derive_overall:430` requires *all* nine
sub-controls `ADEQUATE`, so the `overall_effectiveness == Adequate` branch is dead code.
A perfectly-hardened repo caps at `Partial`.

Fix: grade Dependabot/Renovate properly instead of hand-waving. `repo_root` is already
available — parse `.github/dependabot.yml` for `package-ecosystem` entries and compare
against the ecosystems actually detected in the repo (npm ⇔ `package.json`, pip/uv/poetry ⇔
`pyproject.toml`/`requirements*.txt`). Full ecosystem coverage + `open-pull-requests-limit`
> 0 → `ADEQUATE`; partial coverage → `PARTIAL`. Same for `renovate.json`.

### S2. Five of nine controls are recon-text-only; four read the repo

Asymmetry: `_eval_action_pinning`, `_eval_container_hygiene`, `_eval_dependency_confusion`,
`_eval_postinstall` take `repo_root` and read files. `_eval_ci_install:130`,
`_eval_cve_scanning:359`, `_eval_sca_tooling:393` take **only** `recon` text.

Consequence: if `.recon-summary.md` is absent or terse, `_load_recon:56` returns `""` and
those three grade `MISSING` on a repo whose `.github/workflows/*.yml` plainly contains
`npm ci` and `pip-audit`. `_eval_action_pinning:176-195` already assembles the workflow
text — it should be hoisted into a shared `_ci_text(recon, repo_root)` helper and fed to
all three. This is the single highest-yield change.

---

## P1 — npm

### N1. `npm install` alongside `npm ci` still scores `ADEQUATE`

`_eval_ci_install:149-153` returns `ADEQUATE` on the *first* deterministic match and never
looks for mutable commands. One workflow with `npm ci` + another with `npm install` → clean
`ADEQUATE`. Contrast `_eval_action_pinning:222-229`, which correctly models pinned/mutable
mix as `PARTIAL`. Apply the same three-state shape here — this is directly the "npm install
usage" case.

### N2. `.npmrc registry=` to the **public** registry scores `ADEQUATE`

`_eval_dependency_confusion:278` returns `ADEQUATE` for any `registry\s*=` line. That
matches `registry=https://registry.npmjs.org/`, which is the default and provides *zero*
dependency-confusion protection. Only a `@scope:registry=` line, or a `registry=` pointing
at a non-npmjs host, is evidence. False `ADEQUATE` on a very common config.

### N3. Recon-text `@\w+/` heuristic manufactures `PARTIAL`

Same function, `:264-272`. `_has(recon, r"@\w+/")` fires on any mention of a scoped package
(`@types/node` in a dependency listing) and `r"\.npmrc"` fires on the literal filename in
prose. Nearly every npm repo gets undeserved "partial protection". Merely *consuming* a
scoped package is not a control; the control is registry pinning for that scope. Drop both
patterns.

### N4. `_eval_postinstall` misses monorepos and the `prepare` hook

`:293-303` reads only `<repo_root>/package.json` and only the keys
`postinstall`/`preinstall`/`install`. Meanwhile `recon_patterns.scan_postinstall:901` does
`rglob("package.json")` and checks five keys including **`prepare`** — the hook that
actually executes on install of a git dependency. Workspace packages under `packages/*` are
invisible to the scorecard. Align with the recon key list and walk the tree.

Also `:305` — `ignore_scripts` is detected via `_has(recon, ...)` only, even though
`repo_root` is in hand and recon Cat 17 already parses `.npmrc` for `ignore-scripts=`.

### N5. `npm audit` blocking-detection is both too narrow and too trusting

`_eval_cve_scanning:361-369` requires `--audit-level=(high|critical)` to count as blocking.
But `npm audit` exits non-zero *by default*, and `snyk test`, `osv-scanner`, `pip-audit` all
fail-closed by default too — so plain invocations are under-graded to `PARTIAL`.

The opposite error matters more: `npm audit || true` and `continue-on-error: true` are not
detected at all, so a deliberately non-blocking gate grades as blocking. Detect the
suppressors; that direction is the one that produces a falsely reassuring report.

---

## P1 — Python

### Y1. Hash-pinned `requirements.txt` scores `MISSING` on lockfile pinning

`_eval_lockfile:91-123` is existence-only over a filename list. The pip-native integrity
story is `pip-compile --generate-hashes` → a `requirements.txt` full of
`--hash=sha256:...`, with **no** lockfile by any of the listed names. That repo scores
`MISSING`, which under `_derive_overall:428` caps the entire domain at `Weak`. Fix: if any
`requirements*.txt` contains `--hash=sha256:`, credit it.

### Y2. Modern Python deterministic-install commands are unmatched

`_eval_ci_install:131-147` matches `--require-hashes` but not:

- `uv sync --frozen` / `uv sync --locked` / `uv pip sync` — currently the most common
  Python CI install and a plain false negative
- `pip-sync` (pip-tools)
- `poetry install --sync`, `poetry check --lock`
- `pipenv install --deploy`

`uv.lock` is credited as a lockfile (F6, fixed 2026-06-06) but the command that *enforces*
it is not — inconsistent.

### Y3. Zero Python dependency-confusion coverage in the scorecard

`_eval_dependency_confusion` is entirely npm-shaped. Recon already detects
`--extra-index-url` (the canonical pip confusion vector, cf. PEP 708) per
`project_supply_chain_coverage_map`, but the scorecard ignores it. Missing: `pip.conf` /
`pip.ini` `extra-index-url`, `PIP_EXTRA_INDEX_URL`, `pyproject.toml`
`[[tool.uv.index]]` + `index-strategy = "unsafe-best-match"`, poetry
`[[tool.poetry.source]]` with `priority = "supplemental"`. A pure-Python repo can only
escape `MISSING` if the recon text happens to contain the word "artifactory" or "nexus".

### Y4. Python install-time code execution is not graded

`_eval_postinstall` is npm-only. `recon_patterns.scan_postinstall:952-966` already finds
`setup.py` install-time shell escapes (`cmdclass=`, `os.system`, `subprocess.*`); the
scorecard never consults it. Nor are non-PEP-517 build backends considered.

### Y5. No Python ecosystem in the IAC layer at all

`data/config-iac-checks.yaml` has `iac_type` values: `Dockerfile`, `github_workflow`,
`docker_compose`, `dependabot`, `renovate`, `npm_config`. There is **no** `pip_config` /
`python_config`. The three Dependabot ecosystem checks (`:207`, `:219`, `:231`) cover
`npm`, `github-actions`, `docker` — not `pip`, `uv`, `gomod`, `maven`. A pure-Python repo
gets no IAC dependabot credit, and the two `npm_config` checks (`:324`, `:336`) are inert.

---

## P2 — cross-ecosystem, lower yield

- **C1** `_eval_container_hygiene:236-241` reads only `<repo_root>/Dockerfile` — misses
  `Dockerfile.*`, subdirectory Dockerfiles, and docker-compose, all of which
  `recon_patterns.scan_container_images:856` already walks. In a multi-stage Dockerfile a
  single digest-pinned `FROM` scores `ADEQUATE` even if three other stages use `:latest`;
  it should aggregate per-`FROM` into pinned/mixed/mutable like N1.
- **C2** Cooldown / `minimumReleaseAge` (G1), Trusted Publishing vs long-lived
  `NPM_TOKEN`/`TWINE_PASSWORD` (G2), and `actions/dependency-review-action` (G5) are
  detected in the recon layer but were never wired into the nine scorecard controls — this
  is the open follow-up recorded in `project_supply_chain_coverage_map`. G1 in particular
  is the top 2025 defense (Shai-Hulud, chalk/debug) and applies to both npm and uv/pip.
- **C3** Dead code: `_section` (`:65`) is unused and its regex is broken — `rf"^#{1, 4}"`
  is an f-string replacement field, so it renders as the literal `#(1, 4)` and never
  matches. `tests/test_assess_supply_chain_controls.py:122` pins the broken behaviour
  rather than fixing it. `uses_latest` (`:248`) is computed and never read.
- **C4** The `pip\s+install\b(?!\s+--require-hashes)` lookahead (`:148`) only inspects the
  immediately-following token, so `pip install -r req.txt --require-hashes` reads as
  mutable. Harmless today (the deterministic branch wins first) but wrong if reordered.

---

## Suggested ordering

1. S2 (shared `_ci_text` helper) — unblocks N1, N5, Y2 with one refactor
2. N1 + Y2 — the "npm install / uv sync" grading the question started from
3. N2 + N3 + Y3 — dependency confusion is the least trustworthy control today
4. S1 — makes `ADEQUATE` reachable
5. Y1, N4, Y4, C1 — remaining false negatives
6. C2 (G1 cooldown first), Y5, C3

Each is producer-side in `assess_supply_chain_controls.py` / `config-iac-checks.yaml` with
paired tests in `tests/test_assess_supply_chain_controls.py`. No contract change: the
`.supply-chain-assessment.json` shape (`schema_version: 1`, nine named sub-controls) stays
as-is — unless C2 adds controls, which *would* be a contract change (schema + consumer +
`docs/phase-group-architecture.md` sub-control list together, per AGENTS.md §4).

---

## Implementation notes (2026-07-19)

**Shared plumbing.** `_ci_text(recon, repo_root)` concatenates the recon summary with every
`.github/workflows/*.y{a,ml}`, `.gitlab-ci.yml`, `Jenkinsfile`, and `azure-pipelines.yml`;
`_iter_files()` walks the repo for manifests while skipping `node_modules`, `.venv`,
`vendor`, `dist`, and friends. `_eval_ci_install`, `_eval_cve_scanning`, and
`_eval_sca_tooling` gained a `repo_root` parameter and route through it, resolving S2.

**Grading-shape changes** (row semantics, not row names):

| Finding | Before | After |
| --- | --- | --- |
| N1 | `npm ci` + `npm install` → Adequate | three-state mix → **Partial** |
| N2 | public `registry=` → Adequate | requires scope-pin or non-public host → **Missing** |
| N3 | any `@scope/` in prose → Partial | heuristic removed → **Missing** |
| N4 | root `package.json`, 3 keys | repo-wide walk, 6 keys incl. `prepare`, `setup.py` |
| N5 | `npm audit \|\| true` → Adequate | suppressor detection → **Weak** |
| N5 | plain `pip-audit` → Partial | fail-closed-by-default list → **Adequate** |
| Y1 | hashed `requirements.txt` → Missing | credited → **Adequate** |
| Y2 | `uv sync --frozen` → Missing | 7 Python installers → **Adequate** |
| Y3 | no Python coverage | `--extra-index-url` / unsafe index-strategy → **Weak** |
| S1 | Adequate unreachable | ecosystem-coverage + cooldown → **Adequate** reachable |
| C1 | first `FROM` in root Dockerfile | every `FROM` in every Dockerfile, aliases excluded |

`Weak` is now reachable per row, so `_derive_overall` treats it as a domain cap exactly like
`Missing`. This is contract-valid without a schema edit — `Weak` was already in the
`sub_controls[].effectiveness` enum at `schemas/fragments/security-controls.schema.json:72`.

**Dead code removed:** `_section` (never called; its `rf"^#{1, 4}"` heading pattern was an
f-string replacement field that rendered as the literal `#(1, 4)`) and the unused
`uses_latest` local. The two tests that pinned `_section`'s degenerate behaviour were deleted
rather than migrated.

**Not done — Y5.** `data/config-iac-checks.yaml` still has no `pip_config` / `python_config`
`iac_type`, and its Dependabot ecosystem checks still cover only npm / github-actions /
docker. Adding a Python `iac_type` touches the IAC check-runner and its own contract, so it
is left as a separate change rather than smuggled into a scorecard fix.
