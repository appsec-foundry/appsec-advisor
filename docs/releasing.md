# Releasing

How to cut a release of `appsec-advisor`.

## Branch model

- `dev` — all day-to-day work. Stays ahead of `main` between releases.
- `main` — releases only. Tags live here.

When a release is ready, merge `dev` into `main` and tag the merge commit on `main`. A tag points at a commit, not a branch, so once it lands on `main` it's reachable from both branches and never needs re-tagging.

## Version spellings

The same version appears in three places, each with its own format:

| Where | Format | Example |
|-------|--------|---------|
| `pyproject.toml` | PEP 440 | `0.4.0b0` |
| Git tag | leading `v` | `v0.4.0-beta` |
| `CHANGELOG.md` heading | version + date | `## 0.4.0-beta — 2026-06-13` |

`scripts/check_release_meta.py` normalizes these before comparing, so `0.4.0b0` and `0.4.0-beta` count as equal — but a real mismatch still fails.

## The two gates

- **`make check`** — the everyday gate: lint, format, config validation, drift guards, full test suite + coverage floor. CI runs it on every push and PR to `main` and `dev`. Must pass on every commit.
- **`make release-check`** — `make check` plus `check_release_meta.py`, which confirms version, tag, and changelog agree. Run it locally before tagging; CI re-runs it on the tag. It *fails* on an ordinary dev commit (no version bump yet) — that failure is the intended signal that the tree isn't a release.

## First release only: create the `dev` branch

A fresh clone has no `dev` branch. Create it once from `main`, push it, and make it the default branch on GitHub:

```bash
git branch dev
git push -u origin dev
# GitHub > Settings > Branches: set default branch to dev
```

Optionally protect `main` so it only receives merges. Both branches start at the same commit and diverge with the first version bump.

## Cutting a release

Cheap deterministic checks run before the expensive LLM run, so most problems surface before any budget is spent.

**1. Finish the work on `dev`.** Commit directly or merge feature branches into `dev`.

**2. Bump the version.** Edit `version` in `pyproject.toml`, write the matching `CHANGELOG.md` heading, commit both together:

```bash
git commit -am "release: 0.4.0b0"
```

**3. Run the deterministic gate** and fix anything it reports:

```bash
make release-check
```

**4. Run the end-to-end pipeline** against the bundled fixture. It uses the LLM and costs ~30–50% of a Pro 5-hour window — that's why it runs after the cheap gate:

```bash
make e2e-full
```

**5. Merge into `main` and tag:**

```bash
git checkout main
git merge --no-ff dev
git tag -a v0.4.0-beta -m "0.4.0 beta"
git push origin main --follow-tags
```

Pushing the tag triggers `.github/workflows/release.yml`: it re-runs `make release-check` on the tagged commit, then creates the GitHub release (with the prerelease flag for a beta or RC).

**6. Reopen `dev` for development.** Set `version` to the next dev marker:

```bash
git checkout dev
# set version to e.g. 0.5.0.dev0 in pyproject.toml, commit
```

## Pre-release snapshots

To hand out a testable build before the real release, tag the current tip of `dev`:

```bash
git checkout dev
git tag -a v0.5.0-alpha.1 -m "0.5.0 alpha 1 snapshot"
git push origin v0.5.0-alpha.1
gh release create v0.5.0-alpha.1 --prerelease --target dev --notes "Snapshot for testing."
```

The tag stays on the `dev` line and won't appear on `main` until that commit is merged for a real release — at which point the same tag becomes reachable from `main` without being recreated.

## What CI does

- **Test workflow** — every push and PR to `main` and `dev`: lint, format, config validation, fragment-registry drift, full pytest across Python 3.10–3.12, Codecov upload.
- **Release workflow** — only on a `v*` tag: runs `make release-check` and publishes the release.

The end-to-end run is deliberately not in CI — it's non-deterministic and costs money. It stays the one manual step you run before tagging.
