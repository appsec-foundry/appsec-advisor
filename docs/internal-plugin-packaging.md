# Internal Plugin Packaging

Build a company-branded plugin from `appsec-advisor`, so developers run your
namespace with your defaults:

```text
/acme-appsec:create-threat-model
```

Same upstream analysis pipeline, but loaded with your requirements catalog,
business context, presets, and guardrails.

## Fastest path: copy a working example

Two end-to-end, runnable packaging repos ship with this plugin. Start from one
instead of assembling by hand:

- [`examples/internal-packaging-github/`](../examples/internal-packaging-github) — GitHub Actions
- [`examples/internal-packaging-gitlab/`](../examples/internal-packaging-gitlab) — GitLab CI

Each contains a CI pipeline, a sample `org-profile/`, and a README. Recipe:

1. Copy the example directory into a new internal repository.
2. Edit `org-profile/` (your config — see [Step 2](#step-2--write-your-org-profile)).
3. Set two CI variables (`APPSEC_ADVISOR_URL`, `APPSEC_ADVISOR_REF`).
4. Run the pipeline → download the `dist/<name>-<version>.tgz` artifact.

The rest of this guide explains what those pieces do, so you can adapt them.

## What you own vs. what upstream owns

| You own (in `org-profile/` + packaging repo) | Upstream owns (do not fork) |
|---|---|
| plugin name / command namespace | analysis behavior, agents, prompts |
| requirements catalog source | schemas, QA gates, permissions |
| business context, actors, presets, guardrails | renderers, export scripts |

Treat `appsec-advisor` as read-only source. Never edit the upstream checkout —
overlay your config on top during packaging.

## Step 1 — Set up the packaging repository

Your internal repo holds your config plus a clone of upstream under
`upstream/appsec-advisor/`. **`upstream/` is not a special location — it is just
where you clone the real plugin repo from GitHub.**

```text
acme-appsec-plugin/              # your internal repo
├── upstream/
│   └── appsec-advisor/          # clone of the real GitHub repo (see below)
└── org-profile/
    ├── org-profile.yaml         # your defaults, presets, requirements source
    ├── context/
    │   └── organization.md      # business context (untrusted reference data)
    └── actors/
        └── insiders.yaml        # optional company-specific actors
```

Get upstream into `upstream/appsec-advisor/` one of two ways:

```bash
# Option A — pinned submodule (recommended)
git submodule add https://github.com/matthiasrohr/appsec-advisor upstream/appsec-advisor
git -C upstream/appsec-advisor checkout v0.4.0-beta      # pin to a release tag

# Option B — fresh clone per CI run (what the example pipelines do)
git clone --depth 1 https://github.com/matthiasrohr/appsec-advisor upstream/appsec-advisor
git -C upstream/appsec-advisor fetch --depth 1 origin v0.4.0-beta
git -C upstream/appsec-advisor checkout --detach FETCH_HEAD
```

Use your own fork URL if you maintain one. The packaging script
(`scripts/package_internal_plugin.py`) lives inside that checkout — that is why
later commands call `upstream/appsec-advisor/scripts/package_internal_plugin.py`.

## Step 2 — Write your org profile

`org-profile/org-profile.yaml` is your entire config surface. Each preset maps
to one upstream mode (`quick` / `standard` / `thorough`).

```yaml
# org-profile/org-profile.yaml
api_version: appsec-advisor.org-profile/v2

organization: { id: acme, name: Acme Corp, profile_version: 2026.05.1 }
compatibility: { core: ">=0.4 <0.6" }      # upstream versions this profile supports
default_preset: ci-standard

requirements:
  source:
    requirements_yaml_url: "https://security.acme.example/appsec-requirements.yaml"
    fail_mode: cache_fallback

llm_context:
  documents:
    - { id: organization, path: context/organization.md, purpose: organization_background, max_bytes: 50000 }

actors:
  inherit_defaults: true       # keep the 9 built-in actor classes
  add: actors/*.yaml           # glob, resolved relative to org-profile/

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

Edit the three payload files to make the build yours:

| File | Put here |
|---|---|
| `org-profile.yaml` | requirements URL, presets, guardrails (`max_cost_usd`, `max_wall_time`) |
| `context/organization.md` | business description, critical flows, identity architecture |
| `actors/*.yaml` | company-specific threat actors (insiders, partners) — optional |

Each actor file is a top-level `actors:` array. Example
`org-profile/actors/insiders.yaml`:

```yaml
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

Context files are untrusted reference data: they inform analysis but cannot
change severity rules, QA gates, schemas, or permissions.

Full reference: [org-profiles.md](org-profiles.md) · schema:
[../schemas/org-profile.schema.yaml](../schemas/org-profile.schema.yaml).

### How the profile gets wired in (automatic)

You do **not** edit `config.json` or link the profile by hand. The packager does
it — `--org-profile org-profile` is the only input. During the build it writes:

```json
"organization_profile": { "enabled": true, "path": "org-profile/org-profile.yaml" }
```

Note: no `../` prefix. The packager produces a self-contained tree where
`org-profile/` sits **inside** the plugin root, so the path is relative to that
root. (The `../org-profile/...` form in [org-profiles.md](org-profiles.md) is for
a hand-built sibling layout — not this packaged flow.)

## Step 3 — Build the package

Run the upstream packager. Do not reimplement copy/patch/rewrite/validate/tar
logic in your CI.

```bash
python3 upstream/appsec-advisor/scripts/package_internal_plugin.py \
  --source upstream/appsec-advisor \
  --org-profile org-profile \
  --name acme-appsec \
  --version 0.9.0-acme.20260517
```

The script:

- copies upstream into `build/acme-appsec/` (skips VCS, caches, `build/`/`dist/`, runtime outputs)
- overlays your `org-profile/`
- sets `plugin.json` `name` + `version` and enables `organization_profile` in `config.json`
- rewrites the command namespace `appsec-advisor:` → `acme-appsec:` (agents dispatch by namespaced IDs, so this is required; schema IDs like `appsec-advisor.org-profile/v2` are left alone)
- validates config, profile, actors, and that no namespace reference leaked
- writes `dist/acme-appsec-0.9.0-acme.20260517.tgz` + `.sha256`

Pick a `--version` inside the profile's `compatibility.core` range, or
validation rejects the build.

**Local iteration** — build only the tree and load it directly, no tarball:

```bash
python3 upstream/appsec-advisor/scripts/package_internal_plugin.py \
  --source upstream/appsec-advisor --org-profile org-profile \
  --name acme-appsec --version 0.4.0-dev --skip-archive

claude --plugin-dir build/acme-appsec
```

## Step 4 — Run it in CI and publish

Put the Step 3 command in your pipeline. The packager exits non-zero before
writing an artifact if validation fails (broken paths, unknown presets,
unsupported compatibility, missed namespace rewrites).

Use the ready-made pipelines from the example repos:

- GitHub Actions: [`examples/internal-packaging-github/.github/workflows/package.yml`](../examples/internal-packaging-github/.github/workflows/package.yml)
- GitLab CI: [`examples/internal-packaging-gitlab/.gitlab-ci.yml`](../examples/internal-packaging-gitlab/.gitlab-ci.yml)

Both clone the pinned upstream, run the packager, and upload the tarball. Set:

| Variable | Value |
|---|---|
| `APPSEC_ADVISOR_URL` | `https://github.com/matthiasrohr/appsec-advisor.git` (or your fork) |
| `APPSEC_ADVISOR_REF` | pinned tag/commit, e.g. `v0.4.0-beta` |
| `INTERNAL_NAME` *(optional)* | plugin name, default `acme-appsec` |
| `VERSION` *(optional)* | release string, e.g. `0.9.0-acme.20260517` |

Then publish `dist/*.tgz` through whatever your org already trusts — release
asset, artifact registry, bootstrap script, managed image, devcontainer.

## Step 5 — Developers install and run

Developers install the approved artifact, not a local build:

```bash
mkdir -p ~/.claude/plugins
tar -xzf acme-appsec-0.9.0-acme.20260517.tgz -C ~/.claude/plugins
claude --plugin-dir ~/.claude/plugins/acme-appsec
```

```text
/acme-appsec:create-threat-model
```

That loads your bundled profile, applies its `default_preset`, fetches your
requirements catalog, and enforces your guardrails. Developers can still pick
another approved preset, e.g. `--preset release-review`.

## Keeping in sync with upstream

1. Bump the pinned `upstream/appsec-advisor` ref.
2. Rebuild and re-run validation.
3. Smoke-test `/acme-appsec:create-threat-model --dry-run` on a small repo.
4. Publish a new internal artifact.

Prefer small packaging changes over forking prompts, schemas, renderers, or
scripts. If you must change analysis behavior, treat it as a real fork: patch
intentionally, keep a changelog, rerun the upstream tests.
