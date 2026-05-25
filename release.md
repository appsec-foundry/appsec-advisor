# Release Plan: appsec-advisor 0.4.0-beta — first public release

> **Canonical version source:** `.claude-plugin/plugin.json` →
> `scripts/plugin_meta.py plugin-version`. Already at `0.4.0-beta`.
> The historical version-reset work (0.9→0.6→0.4) is done; this document
> covers the actual shipping procedure.

---

## Status snapshot (verified 2026-05-25)

| Item | State |
|---|---|
| `.claude-plugin/plugin.json` `version` | `0.4.0-beta` ✅ |
| `README.md` Status line | `0.4.0-beta` ✅ |
| `CHANGELOG.md` top section | `## 0.4.0-beta — 2026-05-25` ✅ |
| Test fixtures (`tests/fixtures/...`) | `0.4.0-beta` ✅ |
| Agent SARIF template (`agents/appsec-threat-analyst.md`) | `0.4.0-beta` ✅ |
| Examples (`examples/threat-modeler/*.md`) | `0.4.0-beta` ✅ |
| Git remote | **none** (no `origin`) — must add before push |
| Git tags `v*` | **none** — this is the first |
| `main` branch | exists at older HEAD (5 commits behind current branch) |
| Working tree | **dirty**: 26 modified files (must commit/stash) |

---

## What "ship 0.4.0-beta" actually requires

Three concerns, in order:

1. **Branch topology** — current work branch becomes `dev`; `main` becomes the release-only branch the tag points at.
2. **Release-artifact hardening** — the shipped plugin must NOT carry developer-only surfaces (auto-repair hints, plugin-internal error displays). Verify gates below.
3. **Tag + GitHub release** — once 1 + 2 are clean, tag `v0.4.0-beta` on `main`, push, create GH prerelease.

---

## Concern 1 — Branch topology

**Goal:** rename `fix/threat-model-prose-quality` → `dev`; align `main` to the release commit; keep ongoing work on `dev`.

### 1.1 Seal the working tree

26 files are modified (tests, fixtures, examples, agents, scripts, README, CHANGELOG, dev.md). The release tag must point at a clean, committed tree.

```bash
git status -s             # confirm count = 26
git diff --stat           # eyeball what's actually changing
# Commit on the current branch BEFORE renaming:
git add -A
git commit -m "chore(release): seal working tree for 0.4.0-beta cut"
```

If any of the 26 files contains in-progress work that should NOT ship in
0.4.0-beta, surface it now — once tagged, only forward motion.

### 1.2 Capture baseline test status

```bash
pytest tests/ --tb=no -q 2>&1 | tee /tmp/pre-release-tests.log
```

Per CLAUDE.md §9 the baseline carries ~74 known failures. The post-release
count must be **equal or lower**. New failures = a regression introduced
by the seal commit and must be fixed before tagging.

### 1.3 Rename current branch → `dev`

```bash
# Currently on fix/threat-model-prose-quality.
git branch -m dev                         # local rename
# (If a remote tracking ref exists later, also push :old + push -u dev.)
```

### 1.4 Align `main` to the release commit

`main` already exists locally; it is 5 commits behind `dev`. Two options:

**Option A — fast-forward main to dev (recommended; preserves history):**
```bash
git checkout main
git merge --ff-only dev
```

**Option B — merge dev into main with a merge commit (use only if you want
a visible "release cut" commit on main):**
```bash
git checkout main
git merge --no-ff dev -m "release: 0.4.0-beta"
```

Pick A unless there is a reason to want a merge commit on `main`.

### 1.5 Make `main` the default release branch in tooling

After publishing the GitHub repo (1.7 below):
- Set `main` as the default branch on GitHub.
- Open all future PRs from `dev` (or feature branches) → `main`.
- Tag releases on `main` only.

### 1.6 (Optional) Add a remote

No `origin` is configured today. Before pushing, create the GitHub repo:

```bash
gh repo create <owner>/appsec-advisor --public --source . --remote origin --push
# This pushes both main and dev.
```

If you prefer to push without `gh`:
```bash
git remote add origin git@github.com:<owner>/appsec-advisor.git
git push -u origin main dev
```

---

## Concern 2 — Release-artifact hardening

The shipped plugin must not expose **auto-repair mode** or **plugin-internal
error displays** to end users. Verification matrix:

| Surface | Where | Today | Required for 0.4.0-beta |
|---|---|---|---|
| `APPSEC_PLUGIN_DEV=1` env var (turns on fix-suggestions + `/appsec-advisor:fix-run-issues` hints in completion summary's Run Issues block) | `.claude/settings.json`, `.claude-plugin/plugin.json`, any shipped YAML/JSON/shell | **Not set** in any shipped file (verified via `grep -rn 'APPSEC_PLUGIN_DEV'`). Default `plugin_dev=False` in `render_completion_summary.py`. | **Stay unset.** Add a pre-tag grep guard (2.1). |
| Run Issues block in completion summary (issue *titles* like "Agent exceeded maxTurns" — visible even with `plugin_dev=False`) | `scripts/render_completion_summary.py:1069` `render_run_issues()` | Shows issue titles always; suppresses fix hints only when `plugin_dev=False`. | **Hide the entire block in shipped builds** — see 2.2. |
| `/appsec-advisor:fix-run-issues` skill (auto-applies fixes to plugin-internal `.run-issues.json`) | `skills/fix-run-issues/SKILL.md` | Shipped → user-invokable via slash command. | **Exclude from the 0.4.0-beta plugin package** — see 2.3. |
| `REPAIR_MODE` Stage-2 re-render loop (internal QA→analyst quality loop) | `agents/appsec-threat-analyst.md`, `agents/appsec-qa-reviewer.md`, `skills/create-threat-model/SKILL-impl.md` | Internal quality mechanism. **Not** user-facing — never surfaces as "auto-repair" to end users. | **Keep as-is.** This is not what "no auto-repair mode" refers to. |
| Plugin-developer banners (e.g. `MAX_TURNS` banner from `scripts/budget_watchdog.py`) | Internal `.budget-critical` marker; surfaced only in dev mode banners | Off by default. | **Verify** no shipped settings file enables verbose/debug banners. |

### 2.1 Pre-tag grep guard

Before tagging, run from repo root:

```bash
# Must return ZERO matches in shipped paths:
grep -rn 'APPSEC_PLUGIN_DEV=1' \
  --include='*.json' --include='*.yaml' --include='*.yml' \
  --include='*.sh' --include='*.toml' --include='Makefile' \
  --exclude-dir=.git --exclude-dir=__pycache__ \
  --exclude-dir=tests --exclude-dir=docs \
  .

# Documentation references in skills/SKILL-impl.md and scripts/ are fine —
# they describe the flag, they do not set it.
```

Any hit outside `tests/`, `docs/`, `skills/*/SKILL-impl.md`, `scripts/`,
and `release.md` itself is a blocker.

### 2.2 Hide the Run Issues block in shipped builds

Two acceptable approaches — pick one:

**Approach A — gate the entire block on `plugin_dev`** (minimal code change):

In `scripts/render_completion_summary.py:1069` `render_run_issues()`,
return `[]` early when `plugin_dev=False`. Update the test
`test_render_completion_summary.py::test_fix_suggestions_hidden_by_default`
to assert *no* lines (not just no fix-related lines).

```python
def render_run_issues(data, plugin_dev: bool = False) -> list[str]:
    if not plugin_dev:
        return []   # release builds: never surface plugin-internal issues
    # ... existing body unchanged ...
```

**Approach B — introduce `APPSEC_RELEASE=1` release-mode env var**
(more flexibility, more surface):

Add a parallel flag to `--plugin-dev` that explicitly suppresses every
plugin-internal block (Run Issues, Health, dev hints). Wire it through
`SKILL-impl.md` Phase-12 invocation. Higher cost; defer unless someone
wants fine-grained control.

**Recommendation:** Approach A. The current default already hides the
*useful-for-devs* hints; flipping the *titles* under the same gate is a
one-line change and keeps the surface coherent (`plugin_dev=False` ⇒
nothing plugin-internal leaks).

### 2.3 Exclude `fix-run-issues` skill from the 0.4.0-beta package

This skill consumes `$OUTPUT_DIR/.run-issues.json` — a plugin-internal
artifact — and applies fixes to plugin internals (agent maxTurns bumps,
etc.). It is developer machinery, not an AppSec user feature.

**Option X — physically exclude during packaging.** If the plugin ships
via Claude Code plugin marketplace, add `fix-run-issues` to a packaging
ignore list. There is no current ignore mechanism in `.claude-plugin/`,
so:

```bash
# Move out of skills/ during the release cut and restore on dev branch:
git checkout main
git rm -r skills/fix-run-issues
git commit -m "release: exclude fix-run-issues skill from 0.4.0-beta package"
# Don't repeat on dev — it stays available for plugin developers there.
```

**Option Y — keep but mark dev-only.** Leave the skill in the package
and add a top-of-SKILL.md banner: "Plugin-developer skill. Not part of
the public 0.4.0-beta surface." Cheaper, less clean.

**Recommendation:** Option X. The skill mutates the plugin's own agent
files — shipping it to end users invites support questions and accidental
edits. The skill stays on `dev` and ships in a later release when
hardened (or never; it can remain a dev-loop tool).

### 2.4 Verification before tag

```bash
# 2.4.1 — version-aware paths print the expected version
python3 scripts/plugin_meta.py plugin-version            # → 0.4.0-beta

# 2.4.2 — no APPSEC_PLUGIN_DEV setter in shipped files
grep -rn 'APPSEC_PLUGIN_DEV=1' \
  --include='*.json' --include='*.yaml' --include='*.yml' \
  --include='*.sh' --include='*.toml' --include='Makefile' \
  --exclude-dir=.git --exclude-dir=__pycache__ \
  --exclude-dir=tests --exclude-dir=docs .

# 2.4.3 — fix-run-issues skill removed from main (only if Option X taken)
test ! -d skills/fix-run-issues

# 2.4.4 — Run Issues block hidden by default (test gate)
pytest tests/test_render_completion_summary.py::TestRenderRunIssues -q

# 2.4.5 — full suite drift check
pytest tests/ --tb=no -q 2>&1 | tee /tmp/post-release-tests.log
diff <(grep -E 'failed|passed' /tmp/pre-release-tests.log) \
     <(grep -E 'failed|passed' /tmp/post-release-tests.log)
# Failure count must be ≤ baseline. New failures = a 2.x change broke something.

# 2.4.6 — smoke run on a small repo, confirm no plugin-dev hints in summary
# (Manual; eyeball the Completion Summary output.)
```

---

## Concern 3 — Tag + GitHub release

Only after Concerns 1 and 2 are green.

```bash
git checkout main
git log -1 --oneline       # sanity — should be the release commit

git tag -a v0.4.0-beta -m "First public beta release

See CHANGELOG.md for details. This is a pre-1.0 release; prompts,
schemas, scripts, defaults, and report formats may change between
releases."

# If origin exists (added in 1.6):
git push origin main
git push origin v0.4.0-beta

# GitHub release (prerelease):
gh release create v0.4.0-beta \
  --prerelease \
  --title "0.4.0-beta — first public release" \
  --notes-file CHANGELOG.md
```

If `CHANGELOG.md` is too long for a release body, extract the
`## 0.4.0-beta — 2026-05-25` section into `/tmp/release-notes.md` first
and pass `--notes-file /tmp/release-notes.md`.

---

## Post-release

Immediately on `dev`:

```bash
git checkout dev
# Bump to a -dev marker so HEAD is distinguishable from the tagged release:
# .claude-plugin/plugin.json: "version": "0.4.1-beta-dev"
git add .claude-plugin/plugin.json
git commit -m "chore: bump dev version to 0.4.1-beta-dev"
```

If `fix-run-issues` was excluded from `main` (Option X), it stays on
`dev` only — do **not** restore it to `main` until a later release
deliberately ships it.

---

## Risk notes

1. **Two divergent trees: `main` (release) vs `dev` (active work).** The
   `fix-run-issues` skill — if excluded via Option X — exists on `dev`
   but not on `main`. Any future merge `dev → main` must explicitly
   decide whether to re-include or keep excluded. Document the decision
   in the next release.md cut.

2. **Run Issues suppression hides regressions.** If Approach A in §2.2 is
   taken, end users no longer see issue titles like "Agent exceeded
   maxTurns" in the completion summary. The data is still in
   `.run-issues.json` for log inspection, but a casual user won't notice
   degradation. Mitigation: keep `.run-issues.json` writing in place and
   ensure `threat-model-health` skill (separately shipped) surfaces
   serious issues.

3. **No CI configured.** Pre-tag verification (§2.4) is manual. Any
   command skipped = a regression slips through. The first GitHub
   release is also the first moment to wire up CI (`pytest tests/` on
   PR + on tag).

4. **`baseline.json` carry-forward.** `tests/fixtures/e2e/frozen-run/.appsec-cache/baseline.json`
   pins `plugin_version: "0.4.0-beta"`. Future bumps must move this
   fixture in lockstep with `plugin.json`, or `test_incremental_mode.py`
   diverges from real producer output.

5. **No remote yet = no public review surface.** Add `origin` *before*
   tagging, not after. A tag pushed to a remote that didn't exist at
   tag-time has confusing provenance in `git reflog`.

---

## TL;DR cheat sheet

```bash
# 1. Seal the tree on current branch
git status -s                                                # 26 → 0 after commit
git add -A && git commit -m "chore(release): seal working tree for 0.4.0-beta cut"
pytest tests/ --tb=no -q 2>&1 | tee /tmp/pre-release-tests.log

# 2. Rename to dev, FF main
git branch -m dev
git checkout main && git merge --ff-only dev

# 3. Harden release artifact
#    - one-line edit in scripts/render_completion_summary.py (§2.2 Approach A)
#    - git rm -r skills/fix-run-issues   (§2.3 Option X)
#    - update test_render_completion_summary.py to assert empty block
git add -A && git commit -m "release(0.4.0-beta): hide plugin-dev surfaces"

# 4. Verify
python3 scripts/plugin_meta.py plugin-version                # → 0.4.0-beta
grep -rn 'APPSEC_PLUGIN_DEV=1' --exclude-dir=.git --exclude-dir=tests --exclude-dir=docs .
pytest tests/ --tb=no -q 2>&1 | tee /tmp/post-release-tests.log

# 5. Tag + release
gh repo create <owner>/appsec-advisor --public --source . --remote origin --push
git tag -a v0.4.0-beta -m "First public beta release"
git push origin v0.4.0-beta
gh release create v0.4.0-beta --prerelease --title "0.4.0-beta — first public release" --notes-file CHANGELOG.md

# 6. Bump dev marker
git checkout dev
# edit .claude-plugin/plugin.json → "0.4.1-beta-dev"
git commit -am "chore: bump dev version to 0.4.1-beta-dev"
```
