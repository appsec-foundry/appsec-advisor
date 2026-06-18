# Release Runbook

Step-by-step procedure to cut a release of `appsec-advisor`. Follow the steps in
order. Reference material (branch model, version formats, gate internals, CI) is
at the bottom.

## Prerequisites

- You are on `dev` with the work for this release finished and committed.
- `claude` CLI is on `PATH` (the end-to-end step needs it).
- Authenticated for the LLM run: `claude /login` (subscription) **or** `ANTHROPIC_API_KEY` set.
- **First release only:** the `dev` branch must exist — see [Appendix: create `dev`](#appendix-create-the-dev-branch-first-release-only).

## Checklist

```
[ ] 1. Bump version in pyproject.toml + matching CHANGELOG.md heading, commit both
[ ] 2. make release-all          # deterministic gate, then live e2e (stops if gate fails)
[ ] 3. Merge dev → main, tag, push
[ ] 4. Verify GitHub release was created by the tag workflow
[ ] 5. Reopen dev for development (next .dev version marker)
```

## Steps

### 1. Bump the version

Edit `version` in `pyproject.toml`, write the matching `CHANGELOG.md` heading
(see [Version formats](#version-formats) — the three spellings must agree), then
commit both together:

```bash
git commit -am "release: 0.4.0b0"
```

> Until this commit exists, step 2 will fail at `check_release_meta.py` — that is
> the intended signal that the tree is not a release yet.

### 2. Run the tests

One command runs the cheap deterministic gate first and only proceeds to the
expensive LLM run if it passes:

```bash
make release-all
```

This is equivalent to running both gates in sequence:

```bash
make release-check   # ruff, format, config, fragment-registry drift, full pytest+coverage, check_release_meta
make e2e-full        # live LLM pipeline against the bundled fixture (~10–15 min, ~30–50% of a Pro 5h window)
```

Fix anything either gate reports before continuing.

Optional, depending on what you changed:

| Command | When to use it |
|---------|----------------|
| `make e2e-full-standard` | You changed pipeline depth/fidelity and want a higher-fidelity run than `quick`. |
| `make e2e-full-repair`   | You touched the QA / Re-Render Loop (`appsec-fragment-fixer`). |

### 3. Merge into `main` and tag

```bash
git checkout main
git merge --no-ff dev
git tag -a v0.4.0-beta -m "0.4.0 beta"
git push origin main --follow-tags
```

### 4. Verify the release

Pushing the tag triggers `.github/workflows/release.yml`: it re-runs
`make release-check` on the tagged commit, then creates the GitHub release (with
the prerelease flag for a beta or RC). Confirm the release appears on GitHub and
the workflow is green.

### 5. Reopen `dev` for development

Set `version` to the next dev marker:

```bash
git checkout dev
# set version to e.g. 0.5.0.dev0 in pyproject.toml, commit
```

---

## Reference

### Branch model

- `dev` — all day-to-day work. Stays ahead of `main` between releases.
- `main` — releases only. Tags live here.

When a release is ready, merge `dev` into `main` and tag the merge commit on
`main`. A tag points at a commit, not a branch, so once it lands on `main` it's
reachable from both branches and never needs re-tagging.

### Version formats

The same version appears in three places, each with its own format:

| Where | Format | Example |
|-------|--------|---------|
| `pyproject.toml` | PEP 440 | `0.4.0b0` |
| Git tag | leading `v` | `v0.4.0-beta` |
| `CHANGELOG.md` heading | version + date | `## 0.4.0-beta — 2026-06-13` |

`scripts/check_release_meta.py` normalizes these before comparing, so `0.4.0b0`
and `0.4.0-beta` count as equal — but a real mismatch still fails.

### The two gates

- **`make check`** — the everyday gate: lint, format, config validation, drift
  guards, full test suite + coverage floor. CI runs it on every push and PR to
  `main` and `dev`. Must pass on every commit.
- **`make release-check`** — `make check` plus `check_release_meta.py`, which
  confirms version, tag, and changelog agree. Run it locally before tagging; CI
  re-runs it on the tag. It *fails* on an ordinary dev commit (no version bump
  yet) — that failure is the intended signal that the tree isn't a release.
- **`make release-all`** — convenience target: `release-check` then `e2e-full`,
  stopping if the gate fails. The full pre-release test sequence in one command.

### What CI does

- **Test workflow** — every push and PR to `main` and `dev`: lint, format,
  config validation, fragment-registry drift, full pytest across Python
  3.10–3.12, Codecov upload.
- **Release workflow** — only on a `v*` tag: runs `make release-check` and
  publishes the release.

The end-to-end run is deliberately not in CI — it's non-deterministic and costs
money. It stays the one manual step you run before tagging.

### Pre-release snapshots

To hand out a testable build before the real release, tag the current tip of
`dev`:

```bash
git checkout dev
git tag -a v0.5.0-alpha.1 -m "0.5.0 alpha 1 snapshot"
git push origin v0.5.0-alpha.1
gh release create v0.5.0-alpha.1 --prerelease --target dev --notes "Snapshot for testing."
```

The tag stays on the `dev` line and won't appear on `main` until that commit is
merged for a real release — at which point the same tag becomes reachable from
`main` without being recreated.

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
