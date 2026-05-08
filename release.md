# Historical Draft: Version Reset to 0.6.0-beta

> This is a historical planning note, not the authoritative current release
> plan. The canonical plugin version is read from `.claude-plugin/plugin.json`
> via `scripts/plugin_meta.py`.

> **Scope:** Reset the plugin version from `0.9.0-beta` to `0.6.0-beta` before
> the first public GitHub release. No `0.7.x`–`0.9.x` artifacts have been
> published yet, so this is a free relabel — but it touches canonical sources,
> tests, fixtures, and an embedded SARIF template inside an agent prompt.

---

## Why

`0.9.0-beta` overstates maturity given the open roadmap items (CI test against
reference repo, MCP auth, ~74 baseline test failures). Resetting to
`0.6.0-beta` for the first public release better matches actual readiness and
leaves natural headroom for `0.7.x` / `0.8.x` / `0.9.x` / `1.0.0`.

Alternatives considered: `0.9.0-beta.1`, `0.9.0-rc0`. Both keep the misleading
"close to 1.0" signal. Going to `0.6.0-beta` makes the maturity reset
deliberate and visible.

---

## Pre-flight (do these first)

1. **Working tree must be clean.** As of today there are uncommitted changes
   in `agents/phases/phase-group-architecture.md`, `data/posture-actor-labels.yaml`,
   `schemas/threat-model.output.schema.yaml`, `scripts/compose_threat_model.py`,
   `scripts/pregenerate_fragments.py`, `templates/fragments/security-posture-diagram.md.j2`,
   `tests/test_pregenerate_fragments.py`, plus untracked
   `data/actor-styling.yaml`, `scripts/mermaid_actors.py`. Either commit or
   stash them — do not let the version bump ride on top of unrelated work.

2. **Branch:** `git checkout -b chore/version-reset-0.6.0-beta`

3. **Capture baseline test status** so new failures stand out:
   ```bash
   pytest tests/ --tb=no -q 2>&1 | tee /tmp/pre-bump-tests.log
   ```

---

## Tier 1 — Canonical sources & public-facing (must change)

| File | Line | Change |
|---|---|---|
| `.claude-plugin/plugin.json` | 3 | `"version": "0.9.0-beta"` → `"version": "0.6.0-beta"` |
| `README.md` | 5 | badge `version-0.9.0--beta-orange` → `version-0.6.0--beta-orange` |
| `README.md` | 10 | `**Status:** 0.9.0-beta.` → `**Status:** 0.6.0-beta.` |
| `scripts/plugin_meta.py` | 6 | docstring example `"0.9.0-beta"` → `"0.6.0-beta"` |
| `scripts/plugin_meta.py` | 281 | argparse help `(e.g. 0.9.0-beta)` → `(e.g. 0.6.0-beta)` |
| `CHANGELOG.md` | 242 | rename header + insert reset note (manual, see below) |

**CHANGELOG note (insert above the renamed header):**
```markdown
> **Note:** Versions 0.7.x–0.9.x existed only in development and were never
> publicly released. The version was reset to 0.6.0-beta for the first public
> release to better reflect actual maturity. Subsequent releases follow normal
> SemVer (0.6.1-beta, 0.7.0-beta, …).
```

Renamed header line: `## 0.6.0-beta — 2026-05-05`

> CLAUDE.md no longer contains the version string after the recent rewrite —
> nothing to do there. README4.md and README3.en.md have been removed —
> nothing to do there either.

---

## Tier 2 — Tests, fixtures, and the embedded SARIF template (must change)

These are the spots that make the test suite (or real SARIF output) drift if
you forget them.

| File | Line(s) | Change |
|---|---|---|
| `agents/appsec-threat-analyst.md` | 572, 573 | both `"0.9.0-beta"` → `"0.6.0-beta"` (SARIF tool block — embedded in the LLM prompt; if you skip this, real runs emit `0.9.0-beta` and the SARIF test passes only against the fixture, not actual output) |
| `tests/test_sarif_validation.py` | 177, 178 | both `"0.9.0-beta"` → `"0.6.0-beta"` |
| `tests/test_haiku_routing_per_depth.py` | 204 | `"plugin_version": "0.9.0-beta"` → `"0.6.0-beta"` |
| `tests/test_incremental_mode.py` | 1222 | docstring `0.9.0-beta and 0.9.0 should be…` → `0.6.0-beta and 0.6.0 should be…` |
| `tests/test_incremental_mode.py` | 1223 | `--baseline 0.9.0-beta --current 0.9.0` → `--baseline 0.6.0-beta --current 0.6.0` |
| `tests/fixtures/e2e/frozen-run/threat-model.yaml` | 3, 24 | both `"0.9.0-beta"` → `"0.6.0-beta"` |
| `tests/fixtures/e2e/frozen-run/.appsec-cache/baseline.json` | 9 | `"plugin_version": "0.9.0-beta"` → `"0.6.0-beta"` |
| `tests/fixtures/compose/threat-model.yaml` | 3, 24 | both `"0.9.0-beta"` → `"0.6.0-beta"` |

---

## Tier 3 — Optional cosmetic cleanup

- `examples/threat-modeler/*.md` (5 files: `threat-model.md`,
  `threat-model-juice-shop-standard.md`, `threat-model-juice-shop-standard2.md`,
  `threat-model-juice-shop-thorough.md`, `threat-model-vulnerable-app-standard.md`,
  `juiceshop.md`) carry the version inline. They are dated snapshots — leaving
  them at `0.9.0-beta` is defensible. Replace only if you want strict
  consistency.

---

## Bump script (review-only — do NOT run blind)

```bash
#!/usr/bin/env bash
# bump-version-to-0.6.0-beta.sh
# Run from repo root. Review every change with `git diff` before committing.
set -euo pipefail

OLD="0.9.0-beta"
NEW="0.6.0-beta"
OLD_BADGE="0.9.0--beta"   # README badges URL-encode the dash
NEW_BADGE="0.6.0--beta"

# --- Tier 1: canonical sources ---
sed -i "s/\"version\": \"${OLD}\"/\"version\": \"${NEW}\"/" .claude-plugin/plugin.json
sed -i "s/${OLD_BADGE}/${NEW_BADGE}/g; s/${OLD}/${NEW}/g" README.md
sed -i "s/\"${OLD}\"/\"${NEW}\"/g; s/(e\.g\. ${OLD})/(e.g. ${NEW})/g" scripts/plugin_meta.py

# CHANGELOG.md: manual edit. Rename "## 0.9.0-beta — 2026-04-23" to
# "## 0.6.0-beta — 2026-05-05" and add the reset Note block above it.
# Don't sed this — you want eyes on the wording.

# --- Tier 2: agent SARIF template + tests + fixtures ---
sed -i "s/${OLD}/${NEW}/g" \
  agents/appsec-threat-analyst.md \
  tests/test_sarif_validation.py \
  tests/test_haiku_routing_per_depth.py \
  tests/test_incremental_mode.py \
  tests/fixtures/e2e/frozen-run/threat-model.yaml \
  tests/fixtures/e2e/frozen-run/.appsec-cache/baseline.json \
  tests/fixtures/compose/threat-model.yaml

# --- Tier 3: examples (uncomment to apply) ---
# sed -i "s/${OLD}/${NEW}/g" examples/threat-modeler/*.md

# --- Verify no stragglers ---
echo "=== Remaining ${OLD} references ==="
grep -rn "${OLD}" \
  --include="*.json" --include="*.md" --include="*.py" \
  --include="*.yaml" --include="*.yml" \
  --exclude-dir=.git --exclude-dir=__pycache__ \
  . || echo "None — clean."

# --- Sanity-test the version-aware paths ---
python3 scripts/plugin_meta.py plugin-version
pytest tests/test_sarif_validation.py \
       tests/test_haiku_routing_per_depth.py \
       tests/test_incremental_mode.py -x -q
```

---

## Verification checklist

After running the script (and the manual CHANGELOG edit):

- [ ] `python3 scripts/plugin_meta.py plugin-version` prints `0.6.0-beta`
- [ ] `grep -rn "0\.9\.0-beta" --exclude-dir=.git --exclude-dir=__pycache__ .`
      returns only intentional historical references (e.g. examples if you
      skipped Tier 3)
- [ ] `pytest tests/test_sarif_validation.py tests/test_haiku_routing_per_depth.py tests/test_incremental_mode.py -q`
      green
- [ ] `pytest tests/ --tb=no -q 2>&1 | tee /tmp/post-bump-tests.log` —
      compare with `/tmp/pre-bump-tests.log`. Failure count must be **equal
      or lower**. New failures = a hardcoded version was missed.
- [ ] `python3 scripts/validate_config.py` passes
- [ ] Fresh dry-run of the skill against a small repo: confirm
      `threat-model.md` and the SARIF output both report `0.6.0-beta`

---

## Commit & release

```bash
git add -A
git commit -m "chore: reset version to 0.6.0-beta for first public release

Versions 0.7.x–0.9.x existed only in development and were never publicly
released. Resetting to 0.6.0-beta to better reflect actual maturity at the
first public release."

# Open PR against main, get CI green, merge.

# After merge:
git checkout main && git pull
git tag -a v0.6.0-beta -m "First public beta release"
git push origin v0.6.0-beta

gh release create v0.6.0-beta \
  --prerelease \
  --title "0.6.0-beta — first public release" \
  --notes-file CHANGELOG.md   # or a trimmed release-notes file
```

After tagging, immediately on `develop` (or whichever working branch you use
next):

```bash
# .claude-plugin/plugin.json: "version": "0.6.1-beta-dev"
# So nobody confuses dev HEAD with a tagged release.
```

---

## Risk notes

1. **Embedded SARIF template in agent prompt** (`agents/appsec-threat-analyst.md:572-573`).
   If you forget this, real SARIF output emits `0.9.0-beta` while the test
   fixture expects `0.6.0-beta`. The unit test passes (it only validates the
   fixture), but real consumers see a mismatch. This is the single most likely
   place for the bump to look complete and not be.

2. **Baseline test failures** (~74 per CLAUDE.md §9). Capture the count
   *before* the bump. After the bump, the count must be ≤ the baseline. Any
   new failure points at a hardcoded version reference that was missed.

3. **`baseline.json` carry-forward.** The fixture
   `tests/fixtures/e2e/frozen-run/.appsec-cache/baseline.json` is the
   incremental-mode anchor. Tests that exercise incremental upgrades compare
   `plugin_version` strings — fixture and producer must move together.

4. **No GitHub release exists yet.** That is the only reason this reset is
   safe. Once `v0.6.0-beta` is tagged and pushed, future versions must move
   forward only.
