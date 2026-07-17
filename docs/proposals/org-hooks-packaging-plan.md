# Implementation plan — roll out org-owned hooks via the plugin

> **Status: done** (2026-07-17). All items built; tests green. Event set
> complete, org hooks included-by-default (exclude-able). See CHANGELOG for details.


**Goal:** A company declares its own Claude Code hooks in the org-profile; the
packager places the scripts + hooks.json entries into the branded artifact and
records them (org-owned) in `package-surface.json`. A central plugin bundles
everything, full flexibility — without sacrificing auditability.

**Pattern:** mirrored 1:1 on `mcp.servers` (org-supplied executable surface,
`${CLAUDE_PLUGIN_ROOT}` paths, tracked in the surface manifest, smoke-test-verified).

---

## The crux (first, because it drives the design)

`package_internal_plugin.py:_hook_id()` **and** `smoke_test_package.py:_hook_id()`
derive the hook ID solely from `/scripts/<name>`. Org hooks under
`/org-profile/<name>/hooks/` return `None` there → they are invisible to:
- `apply_hook_policy` (unconditionally keeps `hook_id is None`, never gates it),
- `write_surface_manifest` (not in the manifest),
- the smoke test (`_registered_hook_ids` + `check_surface_manifest`).

**Consequence:** Org hook IDs must not be derived from the command, but instead
come from the **declaration** and be carried explicitly through all three
layers. This is the guiding decision of the plan.

---

## Declaration (schema)

Profile-wide `hooks:` block (not preset-scoped), map `id → {event, command, matcher?}`:

```yaml
hooks:
  block-risky-bash:
    event: PreToolUse
    matcher: Bash                                   # nur PreToolUse/PostToolUse
    command: ${CLAUDE_PLUGIN_ROOT}/org-profile/hooks/guard.py
```

Scripts live under `org-profile/hooks/` — `overlay_org_profile()` copies the
whole profile folder to `build/org-profile/` anyway.

Schema rules (`schemas/org-profile.schema.yaml`, new top-level `hooks`):
- `propertyNames` `^[a-z0-9][a-z0-9_-]{0,62}$`, `additionalProperties:false` per hook.
- `event`: enum `[UserPromptSubmit, PreToolUse, PostToolUse, Stop, SubagentStop, Notification, SessionStart, SessionEnd, PreCompact]`.
- `command`: string, required. `matcher`: string, optional.
- `maxProperties` (e.g. 32) as a runaway backstop.

---

## Contract changes (bidirectional)

### 1. Schema — `schemas/org-profile.schema.yaml`
New `hooks` block as above.

### 2. Validation — `scripts/validate_org_profile.py` (new `_check_hooks`, mirror `_check_mcp`)
Structural checks that JSON Schema cannot express:
- `command` **must** start with `${CLAUDE_PLUGIN_ROOT}/org-profile/` (org script
  in the profile folder) — reject host paths, absolute paths, `..`.
- The resolved script **must exist** under the profile directory
  (reuse `_resolve_under`, against the path remainder after `${CLAUDE_PLUGIN_ROOT}/org-profile/`).
- `matcher` only for `PreToolUse`/`PostToolUse`.
- ID must not collide with the upstream IDs (`security-coach`, `agent-logger` reserved).
- Add a line to the doc listing above (`validate_org_profile.py:8-16`).

### 3. Packager — `scripts/package_internal_plugin.py`
- **`_org_profile_hooks(build) -> dict`** — reads `hooks` from the overlaid profile
  (analogous to `_org_profile_mcp_servers`, `:415`).
- **Extend `apply_hook_policy`** (`:367`):
  - `available = _available_hook_ids(build) ∪ set(org_hooks)` — org IDs become
    part of the keep set, so that `plugin_surface.hooks` include/exclude **also
    gates** them.
  - After filtering the upstream hooks: merge kept org hooks into `filtered_events`.
    One outer entry per hook `{matcher?, hooks:[{type:"command", command}]}`
    under `event`.
  - Extend the return value: `{"included", "removed", "events", "org": [{id, event, command}]}`
    (only kept org hooks).
- Ordering is already correct: `overlay_org_profile` runs before
  `apply_package_surface_policy` (MCP reads the same overlaid profile state).

### 4. Surface manifest — `write_surface_manifest` (`:449`)
The `hooks` dict now carries `org: [...]` — **no signature change** (the hooks dict
is already passed through). The manifest lists org hooks separately from the
upstream `included/removed`. No manifest entry, no org hook — a hard condition.

### 5. Smoke test — `scripts/smoke_test_package.py:check_surface_manifest` (`:129`)
For each `hooks.org` entry, check:
- the `command` appears in the built `hooks/hooks.json` under the declared `event`,
- the referenced script exists under `org-profile/` in the build.
New helper `_commands_for_event(root, event)` scans hooks.json. If a declared
org hook is missing (or vice versa) → `_die`.

### 6. `required-permissions.yaml`
**No change.** This is build time; the org hooks run in the packaged artifact
as Claude Code hooks (org surface, tracked in the manifest), not through the
upstream permission contract of the skills.

---

## Docs (brief, same pattern as the MCP section)

- **`docs/internal-plugin-packaging.md`** — new section "Bundle your own hooks"
  next to the MCP section: `hooks:` example, script under `org-profile/hooks/`,
  `${CLAUDE_PLUGIN_ROOT}` rule, package-surface entry, smoke test.
- **`docs/org-profiles.md`** — short `## Hooks` section (declaration +
  one sentence: runs at the Claude Code event level, cannot change findings/severity/schemas;
  tracked in the surface manifest).
- Precedence/trust in one sentence: org hook code is org-trusted (their artifact);
  the analysis pipeline stays core-owned.

---

## Tests

- **`tests/test_org_profile_schema.py`**: valid `hooks` block; invalid `event`;
  `command` without `${CLAUDE_PLUGIN_ROOT}`; `matcher` on `Stop`; ID collision with `agent-logger`.
- **`tests/fixtures/org-profiles/acme/`**: `hooks` block + tiny
  `hooks/guard.py` (no-op, prints `{}`).
- **`tests/test_package_internal_plugin.py`**: org hook lands in the built
  hooks.json under the event **and** in the surface manifest (`hooks.org`);
  `plugin_surface.hooks` exclude removes it again.
- **`tests/test_smoke_test_package.py`** (if present): org hook verification
  green; tampered manifest (hook missing from hooks.json) → error.
- If `_check_hooks` lives in its own validator test: reject missing-script /
  host-path / reserved-id.

---

## Open design points (confirm briefly before building)

1. **Event allowlist** — full Claude Code set (above) or a narrower safe subset?
   Proposal: full set (they are the org's hooks).
2. **Only `type: command`** for org hooks (no other hook types). Proposal: yes.
3. **package-policy default** — org hooks **included** by default (like
   MCP servers), exclude-able. Proposal: yes.
4. **Reserved IDs** — `security-coach`, `agent-logger` locked. Proposal: yes.

---

## Order & verify

1. Schema + `_check_hooks` → `test_org_profile_schema` green.
2. Packager merge + surface → `test_package_internal_plugin` green.
3. Smoke test → green, including the negative case.
4. Fixture integration: build a package with an org hook, inspect `hooks.json` + `package-surface.json`.
5. Docs.
6. `make test` / `make lint`.
7. Manual: package the acme fixture, check `hooks/hooks.json` (org entry) + `package-surface.json` (`hooks.org`); run `smoke_test_package.py`.

## Effort / risk
Bigger than Gate/Coach: touches the packager, validator, smoke test, schema, docs,
tests. Risk concentrates in the ID-tracking layer (the crux above) — if org IDs
are not carried through all three layers, a hook silently goes unaudited.
Therefore: build and test the packager + surface + smoke test **together**,
not separately. Recommendation: worktree.
