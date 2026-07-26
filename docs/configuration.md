# Advanced Configuration

Most users do not need to edit plugin configuration. The default configuration supports an interactive threat-model run after the permissions setup in the main README.

The root [`config.json`](../config.json) controls four independent runtime concerns: external business context, prices used for local cost calculation, event-log behavior, and the pointer to a packaged organization profile. Requirements catalogs have their own configuration and are documented in the [Requirements Audit reference](security-requirements-audit-skill.md).

## Configuration files and scope

| File | Purpose | Behavior |
|---|---|---|
| `config.json` | Committed plugin and package defaults | Canonical configuration read by the full runtime. Internal packaging writes the organization-profile pointer here. |
| `config.local.json` | Git-ignored local values for external context, pricing, or logging | Selected as a complete file by the context resolver, event logger, and cost verifier when present. It is not merged with `config.json`. |
| `skills/audit-security-requirements/config.json` | Default requirements-catalog source | Separate from the root runtime configuration. |

`config.local.json` is deliberately limited in scope. It can supply `external_context`, `pricing`, and `logging` to the consumers listed above. Organization-profile resolution, packaging, security steering, and static status summaries continue to read the committed `config.json`.

Because the local file replaces the root file for its participating consumers, include every locally customized block that those consumers need. Do not put an organization-profile pointer only in `config.local.json`; it will not activate the profile.

## External context

The optional `external_context` block points the context resolver at a REST service that provides business context for the repository under assessment.

```json
{
  "external_context": {
    "enabled": true,
    "rest_url": "https://context.example.com/appsec"
  }
}
```

`rest_url` must be an `http://` or `https://` URL with a host, or `null`. Set `enabled` to `false` to disable the integration explicitly. With `enabled: true` and `rest_url: null`, the assessment continues without external REST context.

The endpoint receives a JSON request from the context-resolver phase. Treat its response as untrusted context, and do not place credentials directly in a committed URL. A git-ignored `config.local.json` can hold a sensitive internal endpoint, subject to the file-selection behavior described above.

## Pricing

The `pricing` block supplies USD prices per one million tokens for local run-cost calculation and event summaries.

```json
{
  "pricing": {
    "input_per_1m": 3.0,
    "output_per_1m": 15.0,
    "cache_write_per_1m": 3.75,
    "cache_read_per_1m": 0.3
  }
}
```

These values do not select a model and do not change provider billing. Model routing and assessment-depth guidance live in [Model Selection, Cost & Context Window](model-selection.md). Each configured price must be a non-negative number.

When `config.local.json` exists, the event logger and cost verifier read pricing from that file instead of `config.json`. Missing individual price fields fall back to their built-in values.

## Logging

The `logging` block controls persistent verbose hook output and the maximum event-log size.

```json
{
  "logging": {
    "max_log_bytes": 5242880,
    "verbose": false
  }
}
```

- `verbose` mirrors event output to stderr. Prefer the `--verbose` command-line flag for a single run.
- `max_log_bytes` controls log rotation and must be an integer of at least 1024 bytes.

When `config.local.json` exists, the event logger reads the logging block from that file instead of `config.json`.

## Organization profile

The `organization_profile` block activates a packaged profile and optionally overrides its default preset.

```json
{
  "organization_profile": {
    "enabled": true,
    "path": "../org-profile/org-profile.yaml",
    "default_preset": null
  }
}
```

This block must be in `config.json`; it is not read from `config.local.json`. Relative paths are resolved from the plugin root. When `enabled` is `true`, `path` must point to a profile.

For a single run, command-line flags and environment variables can select or disable a profile without changing the committed configuration:

```text
/appsec-advisor:create-threat-model --org-profile /path/to/org-profile.yaml
/appsec-advisor:create-threat-model --preset release-review
/appsec-advisor:create-threat-model --no-org-profile
```

See [Organization Profiles](org-profiles.md) for profile structure, presets, validation, and the complete precedence rules. See [Internal Plugin Packaging](internal-plugin-packaging.md) for producing an organization-specific plugin.

## A complete local file

The local file is not a partial merge over `config.json`. If one local file should configure external context, pricing, and logging together, include all three blocks:

```json
{
  "external_context": {
    "enabled": true,
    "rest_url": "https://context.example.com/appsec"
  },
  "pricing": {
    "input_per_1m": 3.0,
    "output_per_1m": 15.0,
    "cache_write_per_1m": 3.75,
    "cache_read_per_1m": 0.3
  },
  "logging": {
    "max_log_bytes": 5242880,
    "verbose": false
  }
}
```

`config.local.json` is git-ignored by the repository. Keep credentials out of both configuration files; use the authentication mechanism expected by the external service instead.

## Validation

After changing the committed plugin configuration, validate it from the plugin root:

```bash
python3 scripts/validate_config.py .
```

The validator checks `config.json` and, when the skill is present, `skills/audit-security-requirements/config.json`. It rejects unknown root keys and invalid field types. It does not currently validate `config.local.json`.
