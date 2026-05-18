# Org Profiles

Org profiles let AppSec teams ship Acme-flavoured defaults — presets,
requirements source, optional markdown context, skill toggles — alongside
the plugin **without forking the core**. Profiles are validated and
resolved deterministically before Stage 1 of any scan; they never inject
agent instructions and never replace renderer / QA / schema pipelines.

This page documents the MVP scope. The contract is fixed at
`api_version: appsec-advisor.org-profile/v1`. Future fields will land
behind a new `api_version` rather than mutating the v1 surface.

## What an org profile can and cannot do

**Can**

- set default `assessment_depth`, output toggles (SARIF / PDF / pentest
  tasks / SCA), guardrails (wall time, cost cap, tracing), quality
  knobs (QA review, architect review, walkthroughs, enrichment) per
  preset
- declare a single requirements source URL, the default active state
  for create-threat-model, and a separate standalone-audit toggle
- attach 1–3 short markdown files as untrusted reference data for the
  context resolver (organisation background, SSO, platform, etc.)
- enable a default-on Security Coach with a `max_requirements_per_topic`
  cap
- soft-disable optional user-facing skills with a human-readable reason

**Cannot**

- define free-form severity policy or override CVSS eligibility
- override `quick` / `standard` / `thorough` semantics
- inject agent instructions or prompt overrides
- override schemas, QA gates, permissions, or any renderer template
- ship remote markdown context, signed packages, or arbitrary scripts

The MVP is intentionally narrow. See `custom.md` for the full design and
the explicit "Bewusst spaeter" list.

## Packaging

Two layouts are supported:

```
internal-appsec-advisor/
  appsec-advisor/                       # upstream core, not forked
    config.json                         # sets organization_profile.path
    schemas/org-profile.schema.yaml     # core-owned
    scripts/validate_org_profile.py     # core-owned
  org-profile/
    org-profile.yaml
    context/
      organization.md
      sso.md
      platform.md
```

or, bundled directly in the plugin tree:

```
appsec-advisor/
  org-profiles/
    acme/
      org-profile.yaml
      context/
        organization.md
        sso.md
        platform.md
```

The plugin's `config.json` carries the pointer:

```json
{
  "organization_profile": {
    "enabled": true,
    "path": "../org-profile/org-profile.yaml",
    "default_preset": null
  }
}
```

`organization_profile.path` is resolved relative to the plugin root when
not absolute. `default_preset: null` means "use the profile's own
`default_preset`."

## CLI and environment

`create-threat-model` accepts three new flags:

| Flag | Meaning |
|------|---------|
| `--org-profile <path>` | use this profile instead of the packaged default |
| `--preset <name>` | use this preset instead of the profile default |
| `--no-org-profile` | ignore the packaged or env-pointed profile |

For tri-state output toggles:

| Flag | Meaning |
|------|---------|
| `--no-sarif` | disable SARIF even if a preset enables it |
| `--no-pdf` | disable PDF even if a preset enables it |
| `--no-pentest-tasks` | disable pentest-tasks even if a preset enables it |
| `--no-sca` | disable SCA scan even if a preset enables it |

Environment variables mirror the CLI for headless / CI use:

```
APPSEC_ADVISOR_ORG_PROFILE=/abs/path/to/org-profile.yaml
APPSEC_ADVISOR_PRESET=release-review
APPSEC_ADVISOR_NO_ORG_PROFILE=1
```

Precedence (highest wins):

```
1. core defaults
2. packaged default org profile from config.json
3. APPSEC_ADVISOR_ORG_PROFILE / APPSEC_ADVISOR_PRESET / APPSEC_ADVISOR_NO_ORG_PROFILE
4. --org-profile / --preset / --no-org-profile
5. values from the selected preset
6. direct CLI flags (--sarif, --no-requirements, --max-cost, …)
```

Steps 2–4 only choose which profile and preset are active. Step 5 layers
preset values as structured defaults; step 6 direct flags always win.

## Schema overview

The schema lives in `schemas/org-profile.schema.yaml`. Highlights:

```yaml
api_version: appsec-advisor.org-profile/v1
organization:
  id: acme
  name: Acme Corp
  profile_version: 2026.05.1
compatibility:
  core: ">=0.0 <999.0"
default_preset: ci-standard
requirements:
  source:
    requirements_yaml_url: "https://security.acme.example/appsec-requirements.yaml"
    label: "Acme AppSec Requirements"
    fail_mode: cache_fallback
  create_threat_model:
    default_active: true
    quick_default_active: false
llm_context:
  documents:
    - id: sso
      path: context/sso.md
      purpose: identity_ecosystem
      max_bytes: 50000
skill_toggles:
  publish-threat-model:
    enabled: false
    reason: "Publishing is restricted to the AppSec release job."
presets:
  ci-standard:
    base_mode: standard
    outputs:
      yaml: true
      sarif: true
    requirements: { enabled: true }
    quality: { qa_review: auto }
    guardrails: { max_wall_time: 1h, max_cost_usd: 20, tracing: true }
```

Semantic rules enforced by `scripts/validate_org_profile.py` on top of
JSON Schema:

- `default_preset` must exist in `presets`.
- `compatibility.core` must accept the current plugin version.
- `llm_context.documents[].path` must stay under the profile directory
  and may not traverse symlinks that escape it.
- `presets[].context.document_ids[]` must reference declared documents.
- `target.repo == profile_default` requires `target.repo_path`.
- `target.output_dir` may only use the tokens `{repo_name}`,
  `{repo_slug}`, `{preset}`, `{date}`, and may not resolve into `.git/`.
- `requirements_yaml_url` must not embed credentials and must be http/s.
- `skill_toggles` keys must be known user-facing skill names; disabled
  toggles must carry a reason.

## Markdown context

`llm_context.documents` is the loader's input. Each document is:

- read from the profile directory only (no remote sources in MVP)
- size-checked against `max_bytes` (default 50_000, hard cap 200_000)
- secret-scanned for AKIA / GitHub / Slack tokens, PEM keys, and
  password/secret-like assignments
- hashed with SHA-256 for cache invalidation
- wrapped with an explicit *untrusted reference data* preamble before
  it reaches any agent context

The loader emits `.threat-modeling-context.md` (wrapped markdown) and
`.org-context-manifest.json` (sha256 + bytes + loaded/skipped reasons).

## Skill toggles

User-facing skills can be soft-disabled with a reason. The plan
distinguishes three categories:

- **User skills** (e.g. `export-threat-model`, `publish-threat-model`): blocked
  with the reason printed. Exit code 30.
- **Help-only**: `--help` still renders even when the skill is disabled.
  Exit code 10.
- **Operational / repair skills** (`status`, `check-permissions`,
  `clean-run-state`, `fix-run-issues`, `threat-model-health`): the org
  profile can warn but never hard-blocks them. Exit code 20.

Each skill calls `scripts/check_skill_enabled.py <skill>` at the top of
its preflight. With no active org profile the script always returns
"enabled" so legacy invocations are bit-identical.

## Security Coach

`security_coach.enabled_by_default: true` in the profile activates the
coach without requiring `APPSEC_COACH=1` or
`hooks/steering_keywords.json` `enabled: true`. Precedence stays
strict — the environment variable still wins, including as a kill
switch (`APPSEC_COACH=0`).

`security_coach.max_requirements_per_topic` overrides the static
default (3) for per-prompt requirement injection.

## Status output

`/appsec-advisor:status` adds an *Org Profile* section when a profile is
active or merely configured:

```
Org Profile
-----------
  Status         active
  Organization   acme
  Version        2026.05.1
  Path           /workspace/internal-appsec-advisor/org-profile/org-profile.yaml
  Preset         ci-standard (base: standard)
  Requirements   Acme AppSec Requirements
  LLM context    organization, sso, platform
  Disabled skills publish-threat-model
```

When the resolver has not yet emitted `.org-profile-effective.json`, the
status view falls back to the static pointer in `config.json` and shows
"configured (not yet resolved)".

## Compatibility note

The packaged plugin has `organization_profile.enabled: false` by
default. Until a team explicitly flips it on or passes `--org-profile`,
the resolver behaves exactly as before — every existing CLI flag,
preset-free invocation, and downstream artefact stays bit-identical.

## Examples

Use a different preset for a single run:

```
/appsec-advisor:create-threat-model --preset release-review
```

Scan an external repo with an AppSec preset:

```
/appsec-advisor:create-threat-model --preset appsec-verification --repo ../payments-api
```

Force a specific profile for a single run:

```
/appsec-advisor:create-threat-model --org-profile ./security/org-profile.yaml --preset ci-fast
```

Ignore the packaged profile for one run:

```
/appsec-advisor:create-threat-model --no-org-profile
```

Override requirements for one run:

```
/appsec-advisor:create-threat-model --requirements https://security.example.test/r.yaml
/appsec-advisor:create-threat-model --no-requirements
```
