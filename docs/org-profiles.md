# Org Profiles

Org profiles package organization-specific presets, requirements, context, actors, and skill settings without changing the core plugin.

The current format is `api_version: appsec-advisor.org-profile/v2`. Version 1 profiles continue to work and inherit the default actors.

See the [packaging runbook](internal-plugin-packaging.md) to bundle a profile in a company-branded plugin.

## What an org profile can and cannot do

**Can**

- set per-preset defaults: scan depth, outputs (SARIF / PDF / pentest tasks), quality knobs (QA, architect review, walkthroughs), and guardrails (wall time, cost cap)
- gate CI on failing requirements (`requirements.gate`) or on new threats at a chosen severity (`guardrails.fail_on`)
- apply profile-wide policy: an Opus ceiling (`policy.disable_opus`) and a remote-fetch allowlist (`policy.url_allowlist`)
- declare a single requirements source URL, the default active state for create-threat-model, and a separate standalone-audit toggle
- attach 1–3 short Markdown files with organization, identity, or platform context
- enable a default-on Security Coach, and define its baseline and its own steering topics (triggers → guidance + requirement IDs)
- bundle its own Claude Code hooks that run at the event layer (`hooks`)
- soft-disable optional user-facing skills with a human-readable reason

**Cannot**

- define free-form severity policy or override CVSS eligibility
- override `quick` / `standard` / `thorough` semantics
- inject agent instructions or prompt overrides
- override schemas, QA gates, permissions, or any renderer template
- ship remote markdown context, or code that runs inside the analysis pipeline (bundled hooks run only at Claude Code's event layer, and are listed in the package surface)

## Packaging

The [packaging runbook](internal-plugin-packaging.md) creates a self-contained plugin. The layouts below are for a manual setup.

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

`organization_profile.path` is resolved relative to the plugin root when not absolute. `default_preset: null` means "use the profile's own `default_preset`."

## CLI and environment

`create-threat-model` accepts these profile flags:

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

Profile and preset selection happen before preset values are applied. Direct command-line flags always win.

## Schema overview

The schema lives in `schemas/org-profile.schema.yaml`. Highlights:

```yaml
api_version: appsec-advisor.org-profile/v2
organization:
  id: acme
  name: Acme Corp
  profile_version: "2026.05.1"
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

These rules apply in addition to the schema:

- `default_preset` must exist in `presets`.
- `compatibility.core` must accept the current plugin version.
- `llm_context.documents[].path` must stay under the profile directory and may not traverse symlinks that escape it.
- `presets[].context.document_ids[]` must reference declared documents.
- `target.repo == profile_default` requires `target.repo_path`.
- `target.output_dir` may only use the tokens `{repo_name}`, `{repo_slug}`, `{preset}`, `{date}`, and may not resolve into `.git/`.
- `requirements_yaml_url` must not embed credentials and must be http/s.
- `skill_toggles` keys must be known user-facing skill names; disabled toggles must carry a reason.

## CI gates

Two gates turn a run's outcome into a CI exit code. Each stays advisory until a
preset opts in, and each is overridden by its own command-line flag.

The requirements gate fails when graded requirements come back FAIL — or PARTIAL
too, if you ask for it. It covers both `verify-requirements` and
`audit-security-requirements`.

```yaml
presets:
  ci-standard:
    requirements:
      enabled: true
      gate:
        mode: enforce          # default: advisory (exits 0)
        gate_on: partial       # default: fail
        priority_floor: SHOULD # default: MUST
```

Overridden by `--gate` / `--gate-on` / `--priority-floor`.

The severity gate fails a headless run that adds threats at or above a level.
Interactive runs never gate.

```yaml
presets:
  ci-standard:
    guardrails:
      fail_on: high            # critical | high | medium
```

Overridden by `--fail-on`.

## Policy

`policy:` sits above the presets and applies to every run.

```yaml
policy:
  disable_opus: true
  url_allowlist: [security.acme.example, raw.githubusercontent.com]
```

`disable_opus` downgrades every Opus selection to Sonnet — a cost or compliance
ceiling. The profile can only turn it on: `--no-opus` and `APPSEC_DISABLE_OPUS`
add to it, but nothing switches it back off for a run.

`url_allowlist` limits where the tool fetches from — the requirements catalog and
related-repo threat models. A host matches exactly or as a dotted subdomain, and
a listed internal host is allowed even on a private address. Unlisted
related-repo URLs still hit the full SSRF block (loopback, RFC1918,
cloud-metadata).

## Branding

Cover-page fields for the PDF and HTML report, shared across presets:

```yaml
branding:
  report_title: "Security Assessment"
  contact_name: "AppSec Team"
  contact_email: "appsec@acme.example"
  logo: context/logo.png       # local path or https URL
```

Each field has a matching flag (`--report-title`, `--contact-name`,
`--contact-email`, `--logo`) that wins for one run. Whatever you leave out uses
the default cover.

## Actors

Use the `actors:` block to add actors or disable default actor classes:

```yaml
actors:
  inherit_defaults: true              # keep plugin's 9 default actor classes (default)
  disable: []                          # explicitly deactivate by ID (with audit)
  add: actors/*.yaml                  # glob for custom actor definition files
```

Actor definition files live in `org-profile/<name>/actors/` (parallel to `context/`). Each file contains a top-level `actors:` array of actor objects:

```yaml
# org-profile/acme/actors/insiders.yaml
actors:
  - id: ACT-E-01
    label: acme-privileged-contractor
    access: [internal-network, ci-cd-secrets, staging-env]
    trust_positions: [contractor-internal-authority]
    capabilities:
      sophistication: medium
      tooling: [off-the-shelf]
      dwell_time: weeks
      surface_reach: [local, lateral]
    motivation: financial
    heatmap_slug: repo-read
    description: "External contractor with temporary elevated access."
```

Rules:

- Custom actors are merged with plugin defaults. Matching IDs update the default actor.
- `access[]` describes reachable deployment zones; `trust_positions[]`
  describes the actor's stable credential, authority, control, possession, or
  membership position. Declare both so discovery can reject semantic
  duplicates.
- A repository cannot re-enable an actor disabled by the organization profile.
- A disabled actor requires `disable_reason`.

With `inherit_defaults: false`, use `replaces: ACT-D-NN` to identify the default actor class covered by each custom actor.

## Markdown context

Each `llm_context.documents` file:

- must be inside the profile directory
- must fit `max_bytes` (default 50,000; maximum 200,000)
- is scanned for common secret formats
- is treated as untrusted reference data

## Skill toggles

User-facing skills can be disabled with a reason:

- **User skills** (e.g. `export-threat-model`, `publish-threat-model`): blocked with the reason printed. Exit code 30.
- **Help-only**: `--help` still renders even when the skill is disabled. Exit code 10.
- **Operational / repair skills** (`status`, `check-permissions`, `clean-run-state`, `fix-run-issues`, `threat-model-health`): the org profile can warn but never hard-blocks them. Exit code 20.

Without an active org profile, all skills remain enabled.

Skill toggles block commands at runtime. To remove a skill or hook from the package, use `org-profile/package-policy.yaml` as described in the packaging runbook.

## Security Coach

`security_coach.enabled_by_default: true` activates the coach for the team. `APPSEC_COACH=0` still disables it for one session.

`security_coach.max_requirements_per_topic` overrides the static default (3) for per-prompt requirement injection.

### Your own steering rules

Define your own coaching behaviour instead of forking the plugin. A topic is a
trigger (which prompts it fires on) and what it injects (guidance text and
requirement IDs from your catalog):

```yaml
security_coach:
  enabled_by_default: true
  baseline: "Follow Acme secure defaults on every change."   # optional, replaces the built-in
  topics:
    payments:
      triggers: [payment, payout, refund]
      guidance: Post to the ledger idempotently; refunds need dual approval.
      requirements: [SEC-PAY-IDEMPOTENT, SEC-PAY-DUAL-APPROVAL]
```

Your topics are added to the built-in ones (auth, injection, crypto, …); an org
topic with the same name replaces the built-in. Set `inherit_default_topics: false`
to use only your own. Guidance is injected as advice — like the packaged context,
it never overrides tool behaviour, gates, or severity.

## Status output

`/appsec-advisor:status` adds an *Org Profile* section when a profile is active or merely configured:

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

Before the first run resolves the profile, the status is `configured (not yet resolved)`.

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

## Abuse cases

The plugin loads cases in this order:

1. **Plugin standard library** — `data/abuse-cases/default-library.yaml` (the
   `AC-T-NNN` mandatory set), unless an org profile sets
   `abuse_cases.inherit_defaults: false`.
2. **Org profile** — `abuse_cases.add` is a glob (relative to the org-profile
   directory) of extra case files; `abuse_cases.disable` removes ids. Use the
   `ORG-AC-NNN` ID prefix.
3. **Repository** — any `*.yaml` under
   `<repo>/.appsec/abuse-cases/` in the target repository is loaded
   automatically. Use the `REPO-AC-NNN` ID prefix. IDs must be unique.
4. **One scan** — `--abuse-case-file <repo-relative-path>` adds a YAML file
   below the target repository. Repeat `--only-abuse-case <ID>` to run selected
   cases only.

Example repo-local case (`<repo>/.appsec/abuse-cases/payments.yaml`):

```yaml
schema_version: 1
abuse_cases:
  - id: REPO-AC-001
    title: Refund replay via idempotency-key reuse
    source: mandatory
    attacker:
      actor_id: authenticated-user
      initial_access: authenticated_low_priv
    goal: Issue duplicate refunds to an attacker-controlled balance.
    chain:
      - step: 1
        label: Reuse a prior idempotency key
        grants: replayed-request
        finding:
          title: Refund endpoint accepts a reused idempotency key
          cwe: CWE-841
          stride: Tampering
          severity: High
          mitigation_title: Enforce one-time idempotency keys per payment intent
          remediation: Bind each key to one payment intent and reject reuse after a successful refund.
        probe:
          sink_patterns: ["idempotenc(y|e)[-_ ]?key"]
```

Use `scope_qualifier.required_signals` and `path_patterns` to limit a case to
relevant repositories. `probe.sink_patterns` match existing findings first; a
direct source match is checked by the verifier before it is reported.

Add `finding` when a direct source match should become a normal finding after
verification. It supplies the classification and mitigation and links the
resulting finding to the abuse-case step. Without it, the case remains a
scenario check and no finding is created.

Add `release_gate` to fail CI for selected final verdicts:

```yaml
release_gate:
  fail_on: [fully_viable]
  applies_to_presets: [release-review]
```

## Hooks

An org can bundle its own Claude Code hooks in the packaged plugin — one central
artifact carrying its own event handlers. Declare them and put the scripts under
`org-profile/hooks/`:

```yaml
hooks:
  block-risky-bash:
    event: PreToolUse
    matcher: Bash                                   # PreToolUse / PostToolUse only
    command: python3 ${CLAUDE_PLUGIN_ROOT}/org-profile/hooks/guard.py
```

Each hook is recorded in `package-surface.json` (org-owned, separate from the
upstream hooks) so the artifact surface stays auditable; `plugin_surface.hooks`
can exclude one by id. Hooks run at Claude Code's event layer — they can add
context or block a tool call, but never reach the analysis pipeline; findings,
severity, and schemas stay core-owned. The full mechanism and rules live in the
[packaging runbook](internal-plugin-packaging.md).

## MCP servers

The `mcp` block lets an org wire its own MCP servers — e.g. an internal SAST or
SCA service — into the packaged plugin. At build time the packager emits the
declared servers into the plugin's `.mcp.json`, so Claude Code loads them
whenever the internal plugin is active. Which servers are emitted can be narrowed
by the [package policy](internal-plugin-packaging.md) allowlist
(`plugin_surface.mcp_servers`); by default every declared server is included.

```yaml
mcp:
  servers:
    acme-sast:                       # http/sse transport
      type: http
      url: ${ACME_SAST_MCP_URL}
      headers:
        Authorization: Bearer ${ACME_SAST_TOKEN}
    acme-sca:                        # stdio transport
      command: ${CLAUDE_PLUGIN_ROOT}/bin/sca
      args: ["--json"]
```

Rules:

- Each server sets **either** `url` (http/sse) **or** `command` (stdio).
- **Secrets never go in the profile.** Reference tokens and internal URLs as
  `${ENV_VAR}`; Claude Code expands them at load time, and `${CLAUDE_PLUGIN_ROOT}`
  resolves to the installed plugin directory. A credential embedded directly in a
  server `url` (`user:pass@host`) is rejected at validation time.
- **MCP tool output is untrusted reference data.** Like markdown context, it can
  inform findings but never changes severity rules, QA gates, schemas,
  permissions, or tool behavior. Only wire in endpoints you trust.
