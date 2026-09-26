# Release runbook

Follow these steps in order to release `appsec-advisor`. The [reference](#reference) covers branches, version formats, validation gates, and CI.

## Prerequisites

- You are on `dev` with the work for this release finished and committed.
- `claude` CLI is on `PATH` (the end-to-end step needs it).
- Authenticated for the LLM run: `claude /login` (subscription) **or** `ANTHROPIC_API_KEY` set.
- **First release only:** the `dev` branch must exist. See [Appendix: create `dev`](#appendix-create-the-dev-branch-first-release-only).

## Checklist

```
[ ] 1. Sync the latest signed baseline and commit any updates
[ ] 2. Curate Unreleased, align pyproject.toml + plugin.json + badge, promote to a dated CHANGELOG.md heading
[ ] 3. make release-all          # deterministic gate, then live e2e (stops if gate fails)
[ ] 4. Merge dev → main, tag, push
[ ] 5. Verify GitHub release was created by the tag workflow
[ ] 6. Reopen dev for development (next .dev version marker)
```

## Steps

### 1. Sync the bundled baseline

Run `make baseline-sync` first, before the changelog is curated. It fetches and verifies the latest signed baseline release, then updates the bundled fallback and modular bundle when the id is unchanged. If it exits with `ACTION NEEDED` because the published id changed, review that release and rerun with `make baseline-sync ACCEPT_ID=<published-id>` to update the fallback, modular bundle, configured id, and README together. Commit any changes on `dev`; do not tag a commit with an older fallback by skipping this step.

A new baseline id reaches every user who installs or updates the baseline, so add one `Changed` bullet under `## Unreleased` that names the new id. A refresh under the same id needs no entry.

The sync uses the network and changes tracked files, so it runs during release preparation rather than inside the offline `release-check` that CI reruns on the immutable tag. If the source cannot be verified, resolve that before releasing.

### 2. Curate the changelog and bump the version

Entries under `## Unreleased` accumulate one change at a time, so review them as a whole before promoting them. Apply the `CHANGELOG.md` rule in `AGENTS.md` to the complete list:

- Remove bullets that describe internal implementation, refactors, tests, documentation, or maintainer tooling rather than a change users notice.
- Merge bullets that describe the same user-facing outcome, including across `Added`, `Changed`, and `Fixed`, into one short sentence.
- Move each remaining bullet to the category that fits the released result: new capability under `Added`, changed behavior under `Changed`, removed behavior under `Removed`, and corrected defects under `Fixed`. A defect in a feature added in the same release is not a `Fixed` entry; fold it into that feature's bullet.
- Order bullets within each category by user impact, most significant first.

Then set the release version in `pyproject.toml`, `.claude-plugin/plugin.json`, and the README version badge, and move the curated notes into the dated matching `CHANGELOG.md` heading. Keep the `## Unreleased` heading empty; `check_release_meta.py` rejects both a missing heading and remaining notes. Commit all metadata changes together:

```bash
git commit -am "release: 0.6.0b1"
```

> Step 3 fails at `check_release_meta.py` until the release metadata is committed.

### 3. Run the tests

Run the deterministic checks followed by the live LLM assessment. The assessment starts only if the checks pass:

```bash
make release-all
```

This is equivalent to running both gates in sequence:

```bash
make release-check   # ruff, format, config, fragment-registry drift, full pytest+coverage, check_release_meta
make e2e-full        # live LLM pipeline against the bundled fixture (~10–15 min, ~30–50% of a Pro 5h window)
```

Fix failures before continuing. See [Troubleshooting the gate](#troubleshooting-the-gate).

Optional, depending on what you changed:

| Command | When to use it |
|---------|----------------|
| `make e2e-full-standard` | You changed Stage-3 QA, actor discovery, enriched §7, or standard-depth routing. |
| `make e2e-full-thorough` | You changed thorough-depth routing or the Stage-4 architect review. |
| `make e2e-full-repair`   | You touched the QA / Re-Render Loop; this builds a standard seed and verifies a real fragment-fixer repair. |
| `make e2e-full-eval`     | You changed threat-generation prompts or severity/coverage logic and want the adversarial semantic-quality gate. |
| `make e2e-fixture-suite` | You changed language/framework detection or recall logic and have the external fixture checkout available. |

### 4. Merge into `main` and tag

```bash
git checkout main
git merge --no-ff dev
git tag -a v0.6.0-beta.1 -m "0.6.0 beta 1"
git push origin main --follow-tags
```

### 5. Verify the release

Pushing the tag triggers `.github/workflows/release.yml`: it re-runs
`make release-check` on the tagged commit, then creates the GitHub release (with
the prerelease flag for a beta or RC). Confirm the release appears on GitHub and
the workflow is green.

GitHub refuses to mark a prerelease as "latest", so a beta published this way leaves the previous release showing as latest. When the beta *is* the recommended version, clear the prerelease flag and promote it with the REST API:

```bash
id=$(gh api repos/<owner>/<repo>/releases/tags/v0.5.0-beta --jq .id)
gh api -X PATCH repos/<owner>/<repo>/releases/$id -f prerelease=false -f make_latest=true
```

### 6. Reopen `dev` for development

Set `version` to the next dev marker:

```bash
git checkout dev
# set version to e.g. 0.5.0.dev0 in pyproject.toml, commit
```

---

## Reference

### Branch model

- `dev`: day-to-day development. It stays ahead of `main` between releases.
- `main`: releases and release tags.

When a release is ready, merge `dev` into `main` and tag the merge commit on
`main`. A tag points at a commit, not a branch, so once it lands on `main` it's
reachable from both branches and never needs re-tagging.

### Version formats

A `-beta.N` suffix marks the Nth pre-release of the version in front of it, so
`0.6.0-beta.1` is followed by further betas, optionally an `-rc.N`, and then the
stable `0.6.0`. The tags `v0.4.0-beta` and `v0.5.x-beta` predate this rule: there
`-beta` labelled the release line itself, which is why those lines have no stable
release.

The same version appears in five places, using PEP 440-equivalent spellings:

| Where | Format | Example |
|-------|--------|---------|
| `pyproject.toml` | PEP 440 | `0.6.0b1` |
| `.claude-plugin/plugin.json` | SemVer-style, PEP 440-equivalent | `0.6.0-beta.1` |
| README version badge | plugin.json spelling, `-` escaped as `--` | `version-0.6.0--beta.1-orange.svg` |
| Git tag | leading `v` | `v0.6.0-beta.1` |
| `CHANGELOG.md` heading | version + date | `## 0.6.0-beta.1 (2026-08-22)` |

`scripts/check_release_meta.py` normalizes these before comparing, so `0.6.0b1`
and `0.6.0-beta.1` count as equal. It also rejects pending `Unreleased` content
and validates the plugin's analysis-version compatibility declaration.

The README badge is the exception: it must equal `plugin.json` at all times, not only at a release, so `tests/test_marketplace_manifest.py` checks it on every run of the suite rather than at the release boundary.

### The two gates

- **`make check`**: lint, format, configuration validation, drift guards, and the complete test suite. Run it for the changes that require the full gate in [Contributing](../CONTRIBUTING.md#targeted-tests-before-finishing-a-non-trivial-change).
- **`make release-check`**: `make check` plus `check_release_meta.py`, which verifies the version, tag, and changelog. Run it before tagging; CI repeats it on the tag. An ordinary development commit fails the release-metadata check.
- **`make release-all`**: `release-check` followed by `e2e-full`. It stops if the first gate fails.

### Troubleshooting the gate

`make release-check` stops at the first failure. Identify the stage from its error and fix the producer. Lint and formatting support automatic repair. For other failures, correct the source; do not relax schemas, patch generated output, or weaken tests to pass the gate.

| # | Stage | Symptom | Fix |
|---|-------|---------|-----|
| 1 | `ruff check` | `file:line` + rule code (e.g. `F401`) | `make fix` (runs `ruff check --fix`), or fix manually. Don't silence with `# noqa` unless justified. |
| 2 | `ruff format --check` | `Would reformat: …` | `make fix` (runs `ruff format`). Never hand-format `resolve_config.py`; it is intentionally excluded in `pyproject.toml`. |
| 3 | `validate_config.py` | config/YAML schema error | Correct the offending field. Fix the producer, don't loosen the schema. |
| 4 | `check_fragment_registry.py` | registry maps out of sync | Align all registry maps. See [`adding-a-section.md`](internal/runbooks/adding-a-section.md) and `schema-invariants.md §4f`. |
| 5 | `pytest` + coverage | failing tests or coverage below floor | Separate pre-existing failures from new ones. Run a single file with `pytest tests/test_x.py -v --tb=short`. Add tests for new code; don't lower the floor. |
| 6 | `check_release_meta.py` | version/plugin manifest/tag/changelog mismatch or unpromoted notes | Expected on a development commit. For a real release, reconcile all [version formats](#version-formats) and promote `Unreleased`. To check only code health, run `make check` instead. |

**Auto-repair:** `make fix` handles stages 1–2 (`ruff check --fix` + `ruff
format`) and then prints what stages 3–6 still need from you. It deliberately
does **not** touch the semantic stages.

After `make fix`, rerun `make release-check` to verify all stages:

```bash
make fix             # repair lint + format automatically
make release-check   # re-check; fix any remaining stage 3–6 failure by hand
```

**Triage helper (maintainer dev tool).** Every `make release-check` run captures its full output to `.cache/release-check.log` (gitignored). When the gate fails, run the project-local slash command `/triage-release-check`: it reads that log, identifies the first red stage, and recommends the producer-side fix using the table above. It proposes changes and applies them only when requested. It is a `.claude/commands/` dev command (like `e2e-full`), **not** part of the shipped plugin.

### What CI does

- **Test workflow**: every push and PR to `main` and `dev`: lint, format, config validation, fragment-registry drift, full pytest across Python 3.10–3.12, Codecov upload.
- **Release workflow**: only on a `v*` tag: runs `make release-check` and publishes the release.

Run the live end-to-end assessment manually before tagging. CI excludes it because it is non-deterministic and consumes model budget.

### Pre-release snapshots

To hand out a testable build before the real release, tag the current tip of
`dev`:

```bash
git checkout dev
git tag -a v0.5.0-alpha.1 -m "0.5.0 alpha 1 snapshot"
git push origin v0.5.0-alpha.1
gh release create v0.5.0-alpha.1 --prerelease --target dev --notes "Snapshot for testing."
```

The tag stays on the `dev` line and won't appear on `main` until that commit is merged for a release. The same tag then becomes reachable from `main` without being recreated.

### Appendix: create the `dev` branch (first release only)

A fresh clone has no `dev` branch. Create it once from `main`, push it, and make
it the default branch on GitHub:

```bash
git branch dev
git push -u origin dev
# GitHub > Settings > Branches: set default branch to dev
```

Optionally protect `main` so it only receives merges. Both branches start at the
same commit and diverge with the first version bump.
