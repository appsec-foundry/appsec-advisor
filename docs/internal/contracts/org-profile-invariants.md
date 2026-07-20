# Org-profile invariants

This document maps org-profile changes across schema, resolution, packaging, runtime consumption, and tests. `schemas/org-profile.schema.yaml` is the structural source of truth; this file owns the cross-layer routing rules.

## Change paths

Every org-profile field must have a declared layer and follow that layer's complete path.

### Build-time packaging blocks

Blocks that change the packaged plugin surface span:

- `schemas/org-profile.schema.yaml`
- `scripts/validate_org_profile.py`
- `scripts/package_internal_plugin.py`
- `scripts/smoke_test_package.py`
- `tests/test_package_internal_plugin.py`
- `tests/test_smoke_test_package.py`

For example, org-declared `hooks` are merged into the built `hooks/hooks.json`, recorded under `hooks.org` in `package-surface.json`, and smoke-verified. Preserve declared org hook IDs; do not derive them from `/scripts/<name>` as upstream hook IDs are.

### Preset fields

Fields consumed as preset defaults span the schema, `scripts/resolve_org_profile.py::flatten_preset`, every consuming skill or runtime, and `tests/test_org_profile_schema.py` / `tests/test_resolve_org_profile.py`.

For example, `requirements.gate` is seeded into both requirements skills and remains CLI-overridable.

### Profile-level fields

Profile-level policy consumed by a hook or guard bypasses `flatten_preset`. It flows through `resolve()` into `.org-profile-effective.json` under `defaults` and is read directly by the consumer.

Examples include `security_coach.topics` consumed by `scripts/security_steering.py` and `policy.url_allowlist` consumed by `scripts/_url_guard.py`. Relevant guards include `tests/test_security_steering_units.py` and `tests/test_url_guard.py`.

### Preset guardrails

Preset guardrails consumed by the orchestrator do pass through `flatten_preset`. For example, `guardrails.fail_on` is resolved into the effective profile and seeded by `scripts/run-headless.sh`; an explicit CLI value wins.

## Packaging verification

After an org-profile schema or packaging change, build and smoke-test the example package. Confirm the org packaging example still builds cleanly and that `package-surface.json` records the intended surface.

User-facing profile behavior is documented in `docs/org-profiles.md`; packaging details live in `docs/internal-plugin-packaging.md`.
