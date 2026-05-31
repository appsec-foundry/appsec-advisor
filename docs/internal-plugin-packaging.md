# Internal Plugin Packaging

This guide shows how to build a company-branded version of `appsec-advisor`, so developers run your namespace with your defaults:

```text
/acme-appsec:create-threat-model
```

It is the same analysis pipeline as the upstream project ([`matthiasrohr/appsec-advisor`](https://github.com/matthiasrohr/appsec-advisor)), just pre-loaded with your requirements catalog, business context, presets, and guardrails. Throughout this guide, "upstream" means that repo.

This page is the **build runbook**: how to assemble, validate, and ship the branded plugin. For what an org profile actually contains — every field, the schema, CLI flags, and resolution precedence — see the reference, [org-profiles.md](org-profiles.md).

## Contents

- [Quickstart](#quickstart) — minimal local build, no CI
- [What you own vs. what upstream owns](#what-you-own-vs-what-upstream-owns) — the boundary
- [Step 1 — Set up the packaging repository](#step-1--set-up-the-packaging-repository)
- [Step 2 — Write your org profile](#step-2--write-your-org-profile)
  - [How the profile gets wired in (automatic)](#how-the-profile-gets-wired-in-automatic)
- [Step 3 — Build the package](#step-3--build-the-package)
  - [Local build (no tarball)](#local-build-no-tarball)
- [Step 4 — Run it in CI and publish](#step-4--run-it-in-ci-and-publish)
- [Step 5 — Developers install and run](#step-5--developers-install-and-run)
- [Keeping in sync with upstream](#keeping-in-sync-with-upstream)

## Quickstart

Build a branded plugin from a minimal profile and load it locally. No CI, no tarball, no example repo — just upstream plus a short profile:

```bash
# 1. Get upstream
git clone --depth 1 https://github.com/matthiasrohr/appsec-advisor

# 2. Write a minimal org profile (the core range must cover the upstream release).
#    This sets YOUR default — every scan emits SARIF and is cost-capped.
mkdir org-profile
cat > org-profile/org-profile.yaml <<'YAML'
api_version: appsec-advisor.org-profile/v2
organization: { id: myorg, name: My Org, profile_version: "1" }
compatibility: { core: ">=0.4 <0.6" }
default_preset: secure-default
presets:
  secure-default:
    base_mode: standard
    outputs: { sarif: true }            # always produce SARIF for your dashboard
    guardrails: { max_cost_usd: 10 }    # cap spend per scan
YAML

# 3. Build the plugin tree and load it (re-run these two to update)
python3 appsec-advisor/scripts/package_internal_plugin.py \
  --source appsec-advisor --org-profile org-profile \
  --name my-appsec --version 0.4.0-dev --skip-archive
claude --plugin-dir build/my-appsec
```

That gives you a working `/my-appsec:create-threat-model` that already runs with *your* default — standard depth, SARIF always on, $10 cost cap — instead of bare upstream defaults. Shipping defaults like that is the whole point of an org profile. The rest of this guide turns the skeleton into a real setup — your requirements catalog, business context, and actors (Steps 1–3), and, if a team needs prebuilt artifacts, a CI pipeline that publishes an installable tarball (Steps 4–5).

## What you own vs. what upstream owns

| You own (in `org-profile/` + packaging repo) | Upstream owns (do not fork) |
|---|---|
| plugin name / command namespace | analysis behavior, agents, prompts |
| requirements catalog source | schemas, QA gates, permissions |
| business context, actors, presets, guardrails | renderers, export scripts |

Treat the `appsec-advisor` checkout as read-only. Instead of editing it, you overlay your own config on top of it during packaging.

## Step 1 — Set up the packaging repository

Create your internal repo, then check out the upstream repo into it under `upstream/appsec-advisor/`. There is nothing special about the `upstream/` directory; it is just where you put the clone. Pick one of two ways:

```bash
# Option A — pinned submodule (recommended)
git submodule add https://github.com/matthiasrohr/appsec-advisor upstream/appsec-advisor
git -C upstream/appsec-advisor checkout v0.4.0-beta      # pin to a release tag

# Option B — fresh clone per CI run (what the example pipelines do)
git clone --depth 1 https://github.com/matthiasrohr/appsec-advisor upstream/appsec-advisor
git -C upstream/appsec-advisor fetch --depth 1 origin v0.4.0-beta
git -C upstream/appsec-advisor checkout --detach FETCH_HEAD
```

Substitute your own fork URL if you maintain one. Then add your own config next to the checkout, so the repo looks like this:

```text
acme-appsec-plugin/              # your internal repo
├── .gitignore                   # ignore build/, dist/, and the upstream clone
├── upstream/
│   └── appsec-advisor/          # the checkout from above
└── org-profile/
    ├── org-profile.yaml         # your defaults, presets, requirements source
    ├── context/
    │   └── organization.md      # business context (untrusted reference data)
    └── actors/
        └── insiders.yaml        # optional company-specific actors
```

Add a `.gitignore` so build artifacts and the upstream clone don't get committed (the example repos ship one):

```gitignore
build/
dist/
upstream/appsec-advisor/         # drop this line if you vendor upstream as a submodule
```

The packaging script (`scripts/package_internal_plugin.py`) lives inside the checkout, which is why the later commands call `upstream/appsec-advisor/scripts/package_internal_plugin.py`.

## Step 2 — Write your org profile

`org-profile/org-profile.yaml` is your entire config surface. Each preset maps to one upstream mode (`quick`, `standard`, or `thorough`).

```yaml
# org-profile/org-profile.yaml
api_version: appsec-advisor.org-profile/v2

organization: { id: acme, name: Acme Corp, profile_version: "2026.05.1" }
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

These three files hold everything you customize:

| File | Put here |
|---|---|
| `org-profile.yaml` | requirements URL, presets, guardrails (`max_cost_usd`, `max_wall_time`) |
| `context/organization.md` | business description, critical flows, identity architecture |
| `actors/*.yaml` | company-specific threat actors (insiders, partners) — optional |

Each actor file is a top-level `actors:` array. For example, `org-profile/actors/insiders.yaml`:

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

Context files are untrusted reference data. They inform the analysis but cannot change severity rules, QA gates, schemas, or permissions.

For the full reference, see [org-profiles.md](org-profiles.md); the schema lives at [../schemas/org-profile.schema.yaml](../schemas/org-profile.schema.yaml).

### How the profile gets wired in (automatic)

You never edit `config.json` or link the profile by hand. The packager does it for you, and `--org-profile org-profile` is its only input. During the build it writes:

```json
"organization_profile": { "enabled": true, "path": "org-profile/org-profile.yaml" }
```

Note there is no `../` prefix. The packager produces a self-contained tree where `org-profile/` sits inside the plugin root, so the path is relative to that root. (The `../org-profile/...` form shown in [org-profiles.md](org-profiles.md) is for a hand-built sibling layout, not this packaged flow.)

## Step 3 — Build the package

Run the upstream packager. Don't reimplement its copy, patch, rewrite, validate, and tar logic in your CI:

```bash
python3 upstream/appsec-advisor/scripts/package_internal_plugin.py \
  --source upstream/appsec-advisor \
  --org-profile org-profile \
  --name acme-appsec \
  --version 0.4.0-acme.20260517
```

The script:

- copies upstream into `build/acme-appsec/` (skipping VCS, caches, `build/`/`dist/`, and runtime outputs)
- overlays your `org-profile/`
- sets the `name` and `version` in `plugin.json` and enables `organization_profile` in `config.json`
- rewrites the command namespace from `appsec-advisor:` to `acme-appsec:` (agents dispatch by namespaced IDs, so this is required; schema IDs like `appsec-advisor.org-profile/v2` are left alone)
- validates the config, profile, and actors, and checks that no namespace reference leaked
- writes `dist/acme-appsec-0.4.0-acme.20260517.tgz` and its `.sha256`

Pick a `--version` inside the profile's `compatibility.core` range, or validation rejects the build.

### Local build (no tarball)

Add `--skip-archive` and the packager stops after writing the plugin folder — no tarball, no publishing. Load it straight from `build/`:

```bash
python3 upstream/appsec-advisor/scripts/package_internal_plugin.py \
  --source upstream/appsec-advisor --org-profile org-profile \
  --name acme-appsec --version 0.4.0-dev --skip-archive

claude --plugin-dir build/acme-appsec
```

This is the loop while editing your profile: change `org-profile/`, re-run the command, reload. (It is the same build the [Quickstart](#quickstart) uses.)

## Step 4 — Run it in CI and publish

Put the Step 3 command in your pipeline. If validation fails (broken paths, unknown presets, unsupported compatibility, missed namespace rewrites), the packager exits non-zero before writing any artifact.

The example repos give you ready-made pipelines:

- GitHub Actions: [`examples/internal-packaging-github/.github/workflows/package.yml`](../examples/internal-packaging-github/.github/workflows/package.yml)
- GitLab CI: [`examples/internal-packaging-gitlab/.gitlab-ci.yml`](../examples/internal-packaging-gitlab/.gitlab-ci.yml)

Both clone the pinned upstream, run the packager, and upload the tarball. Set these variables:

| Variable | Value |
|---|---|
| `APPSEC_ADVISOR_URL` | `https://github.com/matthiasrohr/appsec-advisor.git` (or your fork) |
| `APPSEC_ADVISOR_REF` | pinned tag/commit, e.g. `v0.4.0-beta` |
| `INTERNAL_NAME` *(optional)* | plugin name, default `acme-appsec` |
| `VERSION` *(optional)* | release string, e.g. `0.4.0-acme.20260517` |

Then publish `dist/*.tgz` through whatever channel your org already trusts: a release asset, artifact registry, bootstrap script, managed image, or devcontainer.

## Step 5 — Developers install and run

Developers install the approved artifact rather than building their own:

```bash
mkdir -p ~/.claude/plugins
tar -xzf acme-appsec-0.4.0-acme.20260517.tgz -C ~/.claude/plugins
claude --plugin-dir ~/.claude/plugins/acme-appsec
```

```text
/acme-appsec:create-threat-model
```

That loads your bundled profile, applies its `default_preset`, fetches your requirements catalog, and enforces your guardrails. Developers can still choose another approved preset, for example with `--preset release-review`.

## Keeping in sync with upstream

1. Bump the pinned `upstream/appsec-advisor` ref.
2. Rebuild and re-run validation.
3. Smoke-test `/acme-appsec:create-threat-model --dry-run` on a small repo.
4. Publish a new internal artifact.

Prefer small packaging changes over forking the prompts, schemas, renderers, or scripts. If you genuinely need to change analysis behavior, treat it as a real fork: patch it deliberately, keep a changelog, and rerun the upstream tests.
