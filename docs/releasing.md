# Releasing

How to cut a release of `appsec-advisor`.

The project develops on a long-lived `dev` branch and keeps `main` for releases only. Day-to-day work lands on `dev`, which stays ahead of `main` between releases. When a release is ready, `dev` is merged into `main` and the release is tagged there. A tag points at a commit rather than a branch, so once the tagged commit reaches `main` it is reachable from both branches and never has to be tagged twice.

## Version conventions

A release carries the same version in three places, written slightly differently in each. The `version` field in `pyproject.toml` must be valid PEP 440, so a beta reads `0.4.0b0`. The Git tag uses the friendlier form with a leading `v`, as in `v0.4.0-beta`. The `CHANGELOG.md` heading pairs the version with a date, as in `## 0.4.0-beta — 2026-06-13`. These spellings mean the same thing, and `scripts/check_release_meta.py` normalizes them before comparing, so it treats `0.4.0b0` and `0.4.0-beta` as equal but still rejects a genuine mismatch.

## The two gates

Two make targets guard a release. `make check` is the everyday gate: lint, format, config validation, the drift guards, and the full test suite with its coverage floor. CI runs it on every push and pull request to `main` and `dev`, and it has to pass on every commit.

`make release-check` is the release gate. It runs everything in `make check` and then confirms that the version, tag, and changelog agree, using `check_release_meta.py`. Because it is a superset, every drift and code-health guard runs a second time on the exact commit being released. You run it locally before tagging, and CI runs it again on the tag itself. On an ordinary dev commit it fails, because there is no version bump or changelog entry yet, and that failure is the intended signal that the tree does not describe a release.

## First release only: create the dev branch

A fresh clone has no `dev` branch yet. Create it once from the current `main`, push it, and make it the default branch on GitHub so that new work and pull requests target it:

```bash
git branch dev
git push -u origin dev
# GitHub > Settings > Branches: set the default branch to dev
```

You may also want to protect `main` so it only ever receives merges. After this both branches point at the same commit, and they start to diverge with the first version bump.

## Cutting a release

The steps are ordered so the cheap, deterministic checks run before the expensive LLM run, which means most problems surface before any budget is spent.

Start by finishing the work on `dev`, either by committing to it directly or by merging feature branches into it. Then prepare the release on `dev`: bump the `version` in `pyproject.toml`, write or complete the matching `CHANGELOG.md` heading, and commit the two together.

```bash
# edit pyproject.toml + CHANGELOG.md
git commit -am "release: 0.4.0b0"
```

Run the deterministic gate locally and fix anything it reports before going any further:

```bash
make release-check
```

Once that is green, run the end-to-end pipeline against the bundled fixture. It uses the LLM and costs roughly 30 to 50 percent of a Pro five-hour window, which is exactly why it comes after the cheap gate rather than before it:

```bash
make e2e-full
```

When you are happy with the result, merge into `main` and tag it:

```bash
git checkout main
git merge --no-ff dev
git tag -a v0.4.0-beta -m "0.4.0 beta"
git push origin main --follow-tags
```

Pushing the tag triggers `.github/workflows/release.yml`, which re-runs `make release-check` on the tagged commit and then creates the GitHub release. When the version is a pre-release such as a beta or release candidate, the release is published with the prerelease flag set. Finally, switch back to `dev` and set the `version` to the next development marker, for example `0.5.0.dev0`, before carrying on.

## Pre-release snapshots

To hand out a testable build before the real release, tag the current tip of `dev`:

```bash
git checkout dev
git tag -a v0.5.0-alpha.1 -m "0.5.0 alpha 1 snapshot"
git push origin v0.5.0-alpha.1
gh release create v0.5.0-alpha.1 --prerelease --target dev --notes "Snapshot for testing."
```

The snapshot tag stays on the `dev` line and does not appear on `main` until that commit is later merged in for a real release, at which point the same tag becomes reachable from `main` without being recreated.

## What CI does

The test workflow runs on every push and pull request to `main` and `dev`. It covers lint, format, config validation, fragment-registry drift, the full pytest matrix across Python 3.10 to 3.12, and the Codecov upload. The release workflow runs only on a `v*` tag, where it executes `make release-check` and publishes the release. The end-to-end run is deliberately left out of CI, because it is non-deterministic and costs money, so it stays the one manual step you run yourself before tagging.
