# Plan: Session banner redesign

Date: 2026-07-29 · Status: implemented on dev (2026-07-30) · Origin: review of the live
SessionStart banner; goal is clearer structure, no color glyphs, object-local
commands, and org-packaging awareness.

## Goal

Rewrite the `SessionStart` status banner (`scripts/session_banner.py`) so that:

1. It is obvious **who** is speaking (plugin identity + help).
2. **Threat model** and **coding baseline** are separate domains with fixed labels.
3. The next command sits **on the object it acts on**, not in a trailing action row.
4. There are **no color/emoji status glyphs**.
5. Commands, baseline identity, and optional lines remain correct under
   **org packaging** (namespace rewrite, skill toggles, custom baseline, headline).

The banner stays decoration, not a contract: failures stay silent; it must not
delay or break session start.

## Current banner (problems)

Example:

```text
SessionStart:startup says: 🔴 threat model · 67 threats (27 CRITICAL, 29 high) · 27 Jul 2026 10:01 UTC
⚪ AI Secure Coding Baseline not installed · /appsec-advisor:install-baseline
/appsec-advisor:review-threat-model · /appsec-advisor:help · appsec-advisor 0.5.2-dev
```

Issues:

- Claude Code already prefixes the first line with `SessionStart:startup says: `;
  plugin identity is buried on the last line.
- Severity is parenthetical after the total count; the decision signal is late.
- Traffic-light glyphs rely on color, add noise, and are redundant once labels
  and `CRITICAL` exist.
- `review-threat-model` is global footer while `install-baseline` is object-local
  → asymmetric and unclear.
- Long product name "AI Secure Coding Baseline" burns width; bare `baseline`
  collides with run/cache baseline terminology.
- Always-on commands and OK prose train users to ignore the right-hand side.

## Target layout

Three lines max in the common case:

```text
[<headline> · ]<plugin-name> <version> · <help-cmd if packaged>
threat model · <facts> · <tm-cmd if warranted and packaged>
coding baseline · <facts> · <install-cmd if warranted and packaged>
```

Rules:

| Line | Role | Content |
|---|---|---|
| 1 | Who + global help | Identity (and optional org `banner.headline`); `help` only here |
| 2 | Threat model domain | Always labeled `threat model`; facts; one primary command when needed |
| 3 | Coding baseline domain | Always labeled `coding baseline` when the line is shown; command only on problem |

No fourth "actions" row. No glyphs. No "or ask …" hints.

### Naming

| Term | Where |
|---|---|
| `threat model` | Fixed banner label |
| `coding baseline` | Fixed banner label (not bare `baseline`, not full AI product name) |
| secure-coding baseline / AI Secure Coding Baseline | Docs, help, README |
| `baseline.id` (e.g. `aisec-0.1`, `acme-sec-1.0`) | Shown when installed / mismatched |
| `baseline.name` | Longer prose in skills/docs; avoid long names in the banner line |

### Org packaging (must remain correct)

| Lever | Banner impact |
|---|---|
| Namespace rewrite | All `/…:` commands use packaging-rewritten literals via existing skill helpers |
| `banner.headline` | Prepended on line 1 only; never mixed into threat-model facts |
| `banner.enabled: false` / `APPSEC_BANNER` | Silence entire banner (user env outranks) |
| `banner.url` | Still not printed here; help skill owns it |
| `baseline.id` / `name` / sources | From resolved `config.json`; never hardcode `aisec-0.1` |
| `baseline.enabled: false` | Drop baseline line entirely |
| `skill_toggles` / missing skill dirs | Offer a command only if `_has_skill` / `_skill_command` says so |
| Hook removed from surface | No banner at all |

Headline + identity: avoid stacking `headline · name · version` awkwardly. Prefer one
clear product string on line 1 (headline when set, else manifest name) plus version
and help.

## Threat model line

### Facts (order)

1. Optional foreign project name when `meta.project != repo.name`
   (`threat model · acme-api · …`).
2. Severity first when present: `N CRITICAL`, then `N high` (omit zero levels).
3. Total count: `N total` (or `no findings` when zero).
4. Short date from `generated`: `27 Jul 2026` (drop clock by default; UTC clock
   only if same-day distinction proves necessary later).
5. Commit drift: `+N commits` when knowable and N > 0.

Do **not** show assessment depth. Do **not** put commands on this line when the
model is calm (see below).

### Command mapping (one primary)

| Condition (first match) | Command |
|---|---|
| Scan active | `status` |
| No `threat-model.yaml` | `create-threat-model` |
| Incompatible `analysis_version` | `create-threat-model --full --rebuild` |
| Stale (commits since generated ≥ `STALE_COMMITS`, today 20) | `update-threat-model` (fallback: `create --incremental`) |
| Any Critical or High | `review-threat-model` |
| Else (calm) | **no command** |

Stale wins over review: refresh before re-triage.

### Calm vs pressure examples

**Pressure (Critical/High):**
```text
threat model · 27 CRITICAL · 29 high · 67 total · 27 Jul 2026 · /appsec-advisor:review-threat-model
```

**Stale:**
```text
threat model · 8 high · 41 total · 12 Jun 2026 · +31 commits · /appsec-advisor:update-threat-model
```

**Calm:**
```text
threat model · 12 total · 27 Jul 2026
```

**Missing model:**
```text
threat model · none in docs/security/ · /appsec-advisor:create-threat-model
```

**Scan running:**
```text
threat model · scan in progress · /appsec-advisor:status
```

**Incompatible:**
```text
threat model · analysis v3 incompatible · /appsec-advisor:create-threat-model --full --rebuild
```

Outside a git repo with no model file: omit the threat-model line (today’s
behavior); still allow baseline + identity.

## Coding baseline line

Independent of the threat model. Reports whether the **expected** secure-coding
baseline is loaded into assistant context—not merely whether a file exists on disk.

### When to show the line

| Baseline check | Line |
|---|---|
| `disabled` / not configured | omit |
| check error | omit (threat model still shown) |
| `missing` | show + `install-baseline` if skill present |
| `other` (wrong/unexpected id) | show expected vs found + install if skill present |
| present on disk but not loaded | show `not installed · on disk in …` + install if skill present |
| `installed` and id OK | **omit line** (preferred, quieter) |

Visible-OK alternative (rejected as default, keep as optional later if product
wants constant confirmation): `coding baseline · aisec-0.1` with no command.

### Examples

```text
coding baseline · not installed · /appsec-advisor:install-baseline
coding baseline · not installed · on disk in CLAUDE.md · /appsec-advisor:install-baseline
coding baseline · expected acme-sec-1.0 · found other · /acme-appsec:install-baseline
```

If the install skill was stripped but baseline is missing, show state without a
dead command:

```text
coding baseline · not installed
```

## Full composed examples

Upstream plugin, pressure + missing baseline:

```text
appsec-advisor 0.5.2-dev · /appsec-advisor:help
threat model · 27 CRITICAL · 29 high · 67 total · 27 Jul 2026 · /appsec-advisor:review-threat-model
coding baseline · not installed · /appsec-advisor:install-baseline
```

Calm + baseline OK (quiet):

```text
appsec-advisor 0.5.2-dev · /appsec-advisor:help
threat model · 12 total · 27 Jul 2026
```

Org package:

```text
ACME AppSec Advisor 1.2.0 · /acme-appsec:help
threat model · 4 high · 22 total · 27 Jul 2026 · /acme-appsec:review-threat-model
coding baseline · not installed · /acme-appsec:install-baseline
```

Outside repository, baseline missing:

```text
appsec-advisor 0.5.2-dev · /appsec-advisor:help
coding baseline · not installed · /appsec-advisor:install-baseline
```

Outside repository, baseline OK:

```text
appsec-advisor 0.5.2-dev · /appsec-advisor:help
```

## Decision trees

### Threat model

```text
scan running?                     → scan in progress + status
no threat-model.yaml?             → none … + create
incompatible analysis_version?    → incompatible + rebuild create
else:
  facts = severity* + total + date + (+commits if >0)
  command =
    stale?                        → update
    critical or high?             → review
    else                          → (none)
```

### Baseline

```text
disabled / unconfigured / error?  → no line
installed expected id?            → no line (default)
missing / other / unloaded?       → line + install command if skill exists
```

## Implementation sketch

Primary file: `scripts/session_banner.py`  
Tests: `tests/test_session_banner.py`  
Docs touchpoints if behavior is user-visible: `docs/org-profiles.md` (session banner
section), possibly a short note in README only if the banner is described there.

Likely code shape:

1. Drop `GLYPH_*` and `_line` glyph prefixing; join plain segments.
2. `build_banner`:
   - line 1 = identity (+ headline) + help via `_skill_command(HELP)`
   - line 2 = threat-model status from refactored `_status_line` (facts + optional cmd)
   - line 3 = baseline from `_baseline_line` only when actionable/problem
3. Remove `build_actions` footer (or reduce it to help-on-line-1 only).
4. Move identity off the old action row onto line 1.
5. Reorder threat facts: severity → total → date → commits.
6. Shorten date helper default to date-only.
7. Calm path: no review command.
8. Baseline summary composition: fixed label `coding baseline`; id from config;
   do not lead with long `baseline.name`.
9. Keep `_skill_command` / `_has_skill` gates; keep namespace literals whole for
   packaging rewrite and `check_namespace_leaks`.
10. Keep `baseline_check.summary` either thin (state only) or adapt banner-side
    composition so the banner owns labels/commands (preferred: banner composes).

### Explicit non-goals

- ANSI colors
- Multi-command menus per line
- Restoring question hints (`or ask "…"`)
- Showing assessment depth
- Network update checks
- Printing `banner.url` on the status line
- Changing STALE_COMMITS threshold (unless product asks)

## Test plan

Update/extend `tests/test_session_banner.py`:

- Line order: identity+help → threat model → baseline (when present)
- No emoji/glyph codepoints in output
- Severity-before-total ordering
- Calm model: no review command
- Stale: update command, not review
- Critical/high: review command
- Missing model / running scan / incompatible analysis
- Baseline missing/other shows install; installed omits line
- Baseline disabled omits line
- Stripped skills never appear as commands
- Packaged namespace / custom baseline id / headline (existing packaged-root patterns)
- Outside repository behavior
- `APPSEC_BANNER` and `banner.enabled` suppression unchanged
- No ANSI escapes

Run: `python -m pytest tests/test_session_banner.py` then the usual targeted lint if
touched.

## Rollout

1. Implement + tests on `dev`.
2. Manual eyeball in a repo with model, without model, baseline on/off.
3. No CHANGELOG entry unless the banner is treated as user-visible product behavior
   worth noting; if yes, one short bullet: session banner regrouped (identity,
   threat model, coding baseline; no status glyphs).

## Open choices (resolve while implementing)

1. **Installed baseline visibility** — default **omit** (this plan). Alternative:
   always show `coding baseline · <id>`.
2. **Date time component** — default **date only**. Keep time if operators rely on
   same-day reruns.
3. **`+N commits` before stale threshold** — show from first commit (current code)
   vs only when stale. Prefer keep-from-first so silence ≠ "unknown".
4. **Headline vs manifest name** — single identity string policy when both exist.
5. Whether `baseline_check.summary()` stays command-free and banner-owned labels
   wrap it, or summary is rewritten to return structured fields.

## References

- `scripts/session_banner.py` — current implementation and constraints
- `scripts/baseline_check.py` — baseline status / summary
- `docs/org-profiles.md` — `banner` and `baseline` packaging
- `schemas/org-profile.schema.yaml` — field contracts
- `scripts/package_internal_plugin.py` — resolves banner/baseline into `config.json`,
  namespace rewrite, skill policy
