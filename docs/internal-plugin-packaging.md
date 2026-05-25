# Internal Plugin Packaging

This guide describes how an AppSec or Platform team can build a company-branded Claude Code plugin from `appsec-advisor`.

The goal is a developer experience like this:

```text
/acme-appsec:create-threat-model
```

The command is not the upstream `/appsec-advisor:create-threat-model`. It is your internal plugin namespace, backed by the upstream analysis pipeline and packaged with your company defaults.

Use this when you want to:

- load your AppSec requirements catalog by default
- add company context such as business-critical flows, identity architecture, platform boundaries, or incident impact
- provide approved presets for CI scans, release reviews, and AppSec verification
- enforce guardrails such as cost caps, wall-clock limits, required SARIF output, or disabled publishing paths
- distribute one approved package through an internal marketplace, artifact registry, bootstrap script, or managed developer image

## Packaging Model

Treat `appsec-advisor` as upstream source. Do not edit the upstream checkout in place. Build a separate internal plugin artifact from it.

Your internal plugin owns:

- the plugin name and command namespace, for example `acme-appsec`
- `config.json` defaults
- the bundled `org-profile/`
- internal release and distribution

Upstream still owns:

- analysis behavior
- schemas
- rendering
- QA checks
- deterministic export scripts

## Step 1 - Create An Internal Packaging Repository

Keep the upstream plugin, your company profile, and the packaging script in one internal repository.

```text
acme-appsec-plugin/
|-- upstream/
|   `-- appsec-advisor/        # upstream source, vendored or a pinned submodule
|-- org-profile/
|   |-- org-profile.yaml       # Acme defaults, presets, requirements source
|   `-- context/
|       `-- organization.md    # short business context, treated as untrusted data
`-- scripts/
    `-- package.sh             # builds the installable internal plugin
```

The package script copies the upstream plugin into a build directory, applies Acme-specific packaging changes there, validates the packaged copy, and publishes that build output.

## Step 2 - Choose The Internal Plugin Name

Pick the Claude Code namespace developers should see. Claude Code uses `.claude-plugin/plugin.json` `name` as the command namespace.

```text
Upstream plugin name:  appsec-advisor
Internal plugin name:  acme-appsec
Developer command:     /acme-appsec:create-threat-model
Release artifact:      acme-appsec-0.9.0-acme.20260517.tgz
```

In the packaged copy, set `.claude-plugin/plugin.json` to that internal name.

```json
{
  "name": "acme-appsec",
  "version": "0.9.0-acme.20260517",
  "analysis_version": 2,
  "compatible_analysis_versions": [1, 2],
  "description": "Acme's internal AppSec threat modeling plugin, based on appsec-advisor."
}
```

Changing only `plugin.json` is not enough. Some skills dispatch agents by namespaced IDs such as `appsec-advisor:appsec-threat-analyst`. During packaging, rewrite `appsec-advisor:` to your internal namespace in the packaged copy.

Do not rewrite schema identifiers such as `appsec-advisor.org-profile/v1`.

## Step 3 - Add The Company Profile

The org profile is the company layer: requirements catalog, default preset, output flags, guardrails, and optional business context. Each preset maps to one upstream mode: `quick`, `standard`, or `thorough`.

```yaml
# org-profile/org-profile.yaml
api_version: appsec-advisor.org-profile/v2

organization: { id: acme, name: Acme Corp, profile_version: 2026.05.1 }
compatibility: { core: ">=0.12 <0.14" }
default_preset: ci-standard

requirements:
  source:
    requirements_yaml_url: "https://security.acme.example/appsec-requirements.yaml"
    fail_mode: cache_fallback

llm_context:
  documents:
    - { id: organization, path: context/organization.md, purpose: company_background, max_bytes: 50000 }

actors:
  inherit_defaults: true
  disable: []
  add: actors/*.yaml

presets:
  ci-standard:
    base_mode: standard
    outputs: { sarif: true }
    guardrails: { max_wall_time: 1h, max_cost_usd: 20 }
  release-review:
    base_mode: thorough
    outputs: { sarif: true, pdf: true, pentest_tasks: true }
    guardrails: { max_wall_time: 3h, max_cost_usd: 80 }
```

Context files should describe the business, critical flows, and impact areas. They inform analysis, but they do not change severity rules, QA gates, schemas, permissions, or tool behavior.

Full profile reference: [org-profiles.md](org-profiles.md). Schema: [../schemas/org-profile.schema.yaml](../schemas/org-profile.schema.yaml).

### Actor distribution

The plugin ships a default actor library (`data/actors/default-library.yaml`) covering nine threat actor classes that activate automatically when signals are present — no configuration required. Two distribution paths exist for extending this:

**Path A — extend the plugin default library** (generic actors, ship with the plugin core)

Add actors to `data/actors/default-library.yaml` in the upstream plugin. This is appropriate for actor classes that apply across many organizations and domains. These actors ship with the plugin artifact and are available to every consumer without org-profile configuration.

**Path B — bundle actors in the org profile** (company- or domain-specific actors)

Place actor definition files under `org-profile/<name>/actors/` alongside `context/`. Reference them from the `actors.add` glob in `org-profile.yaml`. These actors are company-specific and bundled into the internal plugin artifact during packaging.

```text
org-profile/
|-- org-profile.yaml          # actors: { add: actors/*.yaml }
|-- context/
|   `-- organization.md
`-- actors/
    `-- insiders.yaml         # ACT-E-* definitions
```

Each actor file is an array under a top-level `actors:` key:

```yaml
# org-profile/acme/actors/insiders.yaml
actors:
  - id: ACT-E-1
    label: acme-privileged-contractor
    access: [internal-network, ci-cd-secrets, staging-env]
    capabilities:
      sophistication: medium
      dwell_time: weeks
      surface_reach: [local, lateral]
    motivation: financial
    heatmap_slug: repo-read
```

The build step copies `org-profile/actors/` into the packaged artifact alongside `context/`. The packaging validation script checks actor definition files against `schemas/actors.schema.yaml`.

Add actor validation to the CI entrypoint from Step 5:

```bash
python3 "build/${INTERNAL_NAME}/scripts/validate_org_profile.py" \
  "build/${INTERNAL_NAME}/org-profile/org-profile.yaml"
# validate_org_profile.py also validates actor definition files referenced by actors.add
```

## Step 4 - Build The Packaged Plugin

The packaged plugin should be self-contained. Copy the upstream plugin into a build directory, copy `org-profile/` into that plugin root, enable the profile in `config.json`, set the plugin name, then rewrite namespaced command references.

Minimal build sequence:

```bash
INTERNAL_NAME="acme-appsec"
BUILD="build/${INTERNAL_NAME}"

mkdir -p build
rsync -a --delete upstream/appsec-advisor/ "${BUILD}/"
rsync -a --delete org-profile/ "${BUILD}/org-profile/"
```

After that copy step, patch `build/acme-appsec/.claude-plugin/plugin.json` as shown in Step 2.

Set `build/acme-appsec/config.json` to enable the bundled profile:

```json
{ "organization_profile": { "enabled": true, "path": "org-profile/org-profile.yaml" } }
```

Target build output:

```text
build/acme-appsec/
|-- .claude-plugin/plugin.json  # name: acme-appsec
|-- config.json                 # points at org-profile/org-profile.yaml
|-- agents/
|-- skills/
|-- scripts/
|-- schemas/
`-- org-profile/
    |-- org-profile.yaml
    `-- context/organization.md
```

Rewrite namespaced references in the packaged copy:

```bash
find build/acme-appsec -type f \( -name "*.md" -o -name "*.txt" \) \
  -exec sed -i 's/appsec-advisor:/acme-appsec:/g' {} +
```

Then fail the build if old namespaced references remain in skills or agents:

```bash
rg -n "appsec-advisor:" build/acme-appsec/skills build/acme-appsec/agents && exit 1
```

## Step 5 - Validate In CI And Publish The Artifact

Put this step in the CI/CD pipeline for the internal packaging repository. The job builds the packaged copy from Step 4, validates that packaged copy, and publishes the `.tgz` only if validation passes.

This catches:

- broken profile paths
- unknown presets
- unsupported compatibility ranges
- malformed requirements sources
- missed namespace rewrites

Example CI entrypoint:

```bash
#!/usr/bin/env bash
set -euo pipefail

INTERNAL_NAME="acme-appsec"
VERSION="${VERSION:-0.9.0-acme.20260517}"

# Build steps from Step 4 run before validation.

python3 "build/${INTERNAL_NAME}/scripts/validate_config.py" "build/${INTERNAL_NAME}"
python3 "build/${INTERNAL_NAME}/scripts/validate_org_profile.py" \
  "build/${INTERNAL_NAME}/org-profile/org-profile.yaml"

rg -n "appsec-advisor:" "build/${INTERNAL_NAME}/skills" "build/${INTERNAL_NAME}/agents" && exit 1

mkdir -p dist
tar -czf "dist/${INTERNAL_NAME}-${VERSION}.tgz" -C build "${INTERNAL_NAME}"
```

Publish the resulting artifact through the mechanism your organization already trusts:

- internal developer portal or plugin marketplace
- artifact registry
- bootstrap script
- managed workstation image
- devcontainer base image
- internal Git release

## Step 6 - Developers Install And Run The Internal Plugin

Developers should not assemble the plugin themselves. They install the approved internal artifact from the company distribution channel, or receive it through a managed image/bootstrap script.

The only local requirement is that the unpacked plugin lands in a stable path.

```bash
mkdir -p ~/.claude/plugins
tar -xzf acme-appsec-0.9.0-acme.20260517.tgz -C ~/.claude/plugins

cd /path/to/service
claude --plugin-dir ~/.claude/plugins/acme-appsec
```

In Claude Code, developers use the company namespace:

```text
/acme-appsec:create-threat-model
```

That command loads the bundled Acme profile automatically, applies the profile's `default_preset`, fetches the configured requirements catalog, and applies the packaged guardrails. Developers can still select another approved preset, for example `--preset release-review`, when the profile defines it.

## Operational Notes

Keep the internal package close to upstream. Prefer small packaging changes over prompt, schema, renderer, or script forks.

When you update upstream:

1. Update the pinned `upstream/appsec-advisor` source.
2. Rebuild the internal package.
3. Run the packaging validation.
4. Smoke-test `/acme-appsec:create-threat-model --dry-run` against a small internal repository.
5. Publish a new internal artifact.

If you need to change analysis behavior, treat that as a real fork. Patch intentionally, keep a changelog, and rerun the relevant upstream tests.
