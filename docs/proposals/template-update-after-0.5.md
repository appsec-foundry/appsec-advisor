# Template update after the 0.5 release

Small follow-up plan for the example packaging repo
`/home/mrohr/appsec-advisor-packaging-template` (its own Git repo). **Only run
this once appsec-advisor 0.5 is tagged** — before that, it breaks the build.

## Why only after 0.5

On a real build, the template validates its profile against the pinned
upstream (`APPSEC_ADVISOR_REF`). The root schema is `additionalProperties:
false` — a 0.4 validator rejects `hooks:` / `gate:` / `fail_on` / `url_allowlist`.
So: **first raise the pin to the 0.5 tag, then add the fields.**

## Steps

1. **Raise the pin** — `APPSEC_ADVISOR_REF` to the 0.5 tag (CI variable or local
   default). Run `scripts/upstream-check.sh` against the new ref
   (drift check).
2. **Tighten compatibility** — in `org-profile/org-profile.yaml`
   `compatibility.core` from `">=0.4 <0.6"` to `">=0.5 <0.6"`. That way an
   accidental 0.4 pin fails with a clear compat message instead of a
   schema rejection.
3. **New fields as a showcase in the profile** (`org-profile/org-profile.yaml`):
   - `policy.url_allowlist: [security.example.internal, raw.githubusercontent.com]`
   - `security_coach:` with `enabled_by_default: true` plus one `topics` example
     (trigger → guidance + requirement IDs), matching the Acme context.
   - on the `ci-standard` preset: `requirements.gate` (`mode: enforce`, `gate_on: fail`,
     `priority_floor: MUST`) and `guardrails.fail_on: high`.
4. **Org hooks as the core showcase** (the actual "one central plugin" story):
   - New script `org-profile/hooks/guard.py` (small no-op PreToolUse hook,
     analogous to the fixture in appsec-advisor).
   - `hooks:` block in the profile:
     ```yaml
     hooks:
       block-risky-bash:
         event: PreToolUse
         matcher: Bash
         command: python3 ${CLAUDE_PLUGIN_ROOT}/org-profile/hooks/guard.py
     ```
   - **No template script change needed** — the upstream packager copies
     `org-profile/` in full and merges the `hooks:` block itself. `package-local.sh`
     just wraps it.
5. **Docs in the template** — if `README.example.md` / `AGENTS.md` / `CLAUDE.md` list
   the profile fields, add the four new ones briefly (point to the upstream doc
   `docs/org-profiles.md`, don't duplicate).

## Verify

- Build `make` or `scripts/package-local.sh` against the 0.5 upstream.
- Check in the build: `hooks/hooks.json` contains the org hook under `PreToolUse`;
  `.claude-plugin/package-surface.json` lists it under `hooks.org`.
- Run `smoke_test_package.py` on the build (green).
- `tests/run.sh` (the template's own shell tests) green — they stub the upstream,
  should remain untouched.

## Effort

Small: one new script + profile additions + optionally template docs. No
code, no test logic in the template. The risk is solely in the pin ordering
(steps 1–2 before 3–4).
