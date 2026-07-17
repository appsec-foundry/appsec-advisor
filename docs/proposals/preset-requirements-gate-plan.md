# Implementation plan — make gate policy packageable in `preset_requirements`

**Goal:** An org should be able to package the requirements gate policy (`--gate` on/off, `--gate-on`,
`--priority-floor`) **per preset** in the org-profile, instead of passing it on every
CI run via CLI. Affects **both** requirements skills
(`verify-requirements` diff-scoped, `audit-security-requirements` full-repo).

Status quo (verified):
- `schemas/org-profile.schema.yaml:394` `preset_requirements` only knows `enabled`.
- Both skills parse `gate_mode`/`gate_on`/`priority_floor` **only from CLI**,
  hard defaults `false` / `fail` / `MUST`
  (`skills/audit-security-requirements/SKILL.md` Step 1a,
  `skills/verify-requirements/SKILL.md:74-76`).
- `scripts/requirements_gate.py:61-69` takes `--priority-floor`/`--gate-on` as args,
  default `MUST`/`fail`.
- `resolve_org_profile.flatten_preset()` (`:183-230`) today surfaces only
  `check_requirements = requirements.enabled` from the requirements preset.
- `resolve_config._apply_org_profile` reads `defaults` selectively via `.get()` and
  passes the blob through as `org_profile_defaults` → the new key is **not** a
  regression risk for `create-threat-model` (verified `:1851-1852`).

---

## Design decision (please confirm)

Two semantics for the packaged gate policy:

**A. Default seed (recommended, v1):** Preset provides the *default* values; an
explicit CLI flag still overrides them. Precedence
`CLI > Preset > Hard default`. Simple, mirrors the character of
`gate_on`/`priority_floor` as per-run knobs, no new locking mechanism.

**B. Governance lock (optional, later):** an additional `enforce: true` that —
analogous to `policy.disable_opus` (OR-combined, not disableable) — **forces** the
gate so a developer cannot disable it via CLI.

→ **Recommendation: implement A now**, note B as a documented follow-up.
The plan below implements A.

---

## Contract change (bidirectional: producer + schema + consumer + validation + tests)

### 1. Schema — `schemas/org-profile.schema.yaml`

Extend `$defs/preset_requirements` (currently only `enabled`):

```yaml
preset_requirements:
  type: object
  additionalProperties: false
  properties:
    enabled:
      type: boolean
    gate:
      type: object
      additionalProperties: false
      description: |
        Default gate policy for this preset, consumed by both requirements
        skills (verify-requirements, audit-security-requirements). Per-run CLI
        flags (--gate / --gate-on / --priority-floor) still override these.
      properties:
        mode:
          enum: [advisory, enforce]     # advisory = exit 0; enforce = gate (like --gate)
        gate_on:
          enum: [fail, partial]
        priority_floor:
          enum: [MUST, SHOULD, MAY]
```

No required fields → v1 profiles and presets without `gate` stay unchanged
(behavior: advisory/fail/MUST). No `api_version` bump needed (purely additive,
optional).

### 2. Producer — `scripts/resolve_org_profile.py`

In `flatten_preset()` (after `:217 check_requirements`) add a **nested** block
to `defaults` — only when the preset sets it, otherwise `None`, so the
skills fall back to their hard defaults:

```python
_gate = (requirements.get("gate") or {})
defaults["requirements_gate"] = {
    "mode": _gate.get("mode"),                 # advisory | enforce | None
    "gate_on": _gate.get("gate_on"),           # fail | partial | None
    "priority_floor": _gate.get("priority_floor"),  # MUST|SHOULD|MAY | None
} if _gate else None
```

The key lands in `.org-profile-effective.json` under `defaults.requirements_gate`.
`create-threat-model` ignores it (only `.get()` of known keys).

### 3. Consumer — both SKILL.md (Step 1a gate resolution)

Both skills already emit `.org-profile-effective.json` via
`resolve_org_profile.py --emit-file` and know `$AUDIT_OUTPUT_DIR` /
output dir. **After** the emit and **before** the gate call, read the preset
defaults and apply them only where the CLI flag was **not** set:

```bash
EFFECTIVE="$OUTPUT_DIR/.org-profile-effective.json"
if [ -f "$EFFECTIVE" ]; then
  # only seed each when the CLI flag was not explicitly passed
  read PRESET_GATE_MODE PRESET_GATE_ON PRESET_FLOOR < <(python3 - "$EFFECTIVE" <<'PY'
import json,sys
d=(json.load(open(sys.argv[1])).get("defaults") or {}).get("requirements_gate") or {}
print(d.get("mode") or "", d.get("gate_on") or "", d.get("priority_floor") or "")
PY
)
  [ -z "$GATE_ON_SET" ]      && [ -n "$PRESET_GATE_ON" ] && GATE_ON="$PRESET_GATE_ON"
  [ -z "$PRIORITY_FLOOR_SET" ] && [ -n "$PRESET_FLOOR" ] && PRIORITY_FLOOR="$PRESET_FLOOR"
  [ -z "$GATE_MODE_SET" ] && [ "$PRESET_GATE_MODE" = "enforce" ] && GATE_MODE=true
fi
```

State the precedence rule in the prose of both Step 1a:
**explicit CLI flag > active preset > hard default (advisory / fail / MUST)**.
The `*_SET` markers are set during CLI parsing in Step 1a (prose addition:
"remember whether the user passed the flag explicitly").

Optional (recommended for transparency): show a line in the startup banner
`Gate     : enforce · gate-on=partial · floor=SHOULD (from preset ci-standard)`
when a preset provides the policy — otherwise omit it.

The gate call itself (`requirements_gate.py "${GATE_ARGS[@]}"`) stays unchanged;
it receives the already-resolved values.

---

## Documentation ("document everything cleanly")

1. **`docs/org-profiles.md`** — in the `presets.<name>.requirements` section,
   document the new `gate.{mode,gate_on,priority_floor}` fields, including
   precedence (CLI overrides) and a CI preset example.
2. **`docs/internal-plugin-packaging.md`** — add a `gate:` block to the
   `ci-standard` preset example (currently `:181-186`) and mention in prose
   that the gate policy is now packageable (previously CLI-only).
3. **`docs/security-requirements-audit-skill.md`** — extend the precedence chain
   with "active preset provides gate defaults".
4. **Both `SKILL.md` `--help` blocks** — note at `--gate/--gate-on/--priority-floor`:
   "default can come from the active preset; the flag overrides it".
5. **`AGENTS.md`** — check the Editing Guidance table; if an
   org-profile/requirements row exists, point it at the new gate surface.
6. **CHANGELOG / `check_release_meta.py`** — entry "preset requirements gate
   policy" (additive, not breaking).

---

## Tests

- **`tests/test_org_profile_schema.py`**: (a) preset with a valid `gate` block
  validates; (b) invalid `gate_on: yes` / `priority_floor: HIGH` /
  `mode: block` is rejected; (c) `additionalProperties` in the gate block is
  rejected.
- **`tests/test_resolve_org_profile.py`**: `flatten_preset` surfaces
  `defaults.requirements_gate` correctly from a preset; preset without gate →
  `requirements_gate is None`.
- **`tests/fixtures/org-profiles/`**: a fixture with a CI preset (`enforce`,
  `partial`, `SHOULD`) and a preset without gate.
- **`tests/test_resolve_config_org_profile.py`**: regression guard —
  `create-threat-model` stays unaffected by the new `defaults` key (green).
- Skills are prose → no unit tests; precedence is covered via the
  resolve/flatten layer. If needed, a small integration test that emits the
  effective JSON from a fixture profile and checks the gate block.

## `data/required-permissions.yaml`

No new Bash command / write target / sub-agent dispatch — the skills already call
`resolve_org_profile.py`, `requirements_gate.py`, etc. **No
change** (double-check during implementation).

## Order & verify

1. Extend schema → `tests/test_org_profile_schema.py` green.
2. `flatten_preset` + fixture → `tests/test_resolve_org_profile.py` green.
3. Both SKILL.md Step 1a + `--help` + precedence prose.
4. Docs 1–6.
5. `test_resolve_config_org_profile.py` (regression) + targeted subset + `make test` / `make lint`.
6. Manual smoke: fixture profile with CI preset → `audit-security-requirements --status`
   shows gate banner; `--gate-on fail` on the CLI overrides preset `partial`.
