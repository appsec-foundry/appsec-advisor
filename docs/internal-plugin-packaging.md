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
- [Repo layout](#repo-layout) — the target shape
- [Step 1 — Clone upstream (pinned)](#step-1--clone-upstream-pinned)
- [Step 2 — Add a `.gitignore`](#step-2--add-a-gitignore)
- [Step 3 — Write your org profile](#step-3--write-your-org-profile)
- [Step 4 — Add business context](#step-4--add-business-context)
- [Step 5 — Add company-specific actors (optional)](#step-5--add-company-specific-actors-optional)
- [Step 6 — Build the package](#step-6--build-the-package)
- [Step 7 — Smoke-test the build](#step-7--smoke-test-the-build)
- [Step 8 — Automate the build in CI](#step-8--automate-the-build-in-ci)
- [Step 9 — Publish and install](#step-9--publish-and-install)
- [Keeping in sync with upstream](#keeping-in-sync-with-upstream)

## Quickstart

Build a branded plugin from a minimal profile and load it locally. No CI, no tarball, no example repo — just upstream plus a short profile, in four short steps.

**1. Get upstream.** Shallow-clone the pinned release into `appsec-advisor/`:

```bash
git clone --depth 1 --branch v0.4.0-beta https://github.com/matthiasrohr/appsec-advisor
```

**2. Write a minimal org profile.** This is your whole config surface; here it sets one default so every scan emits SARIF and is cost-capped. The `compatibility.core` range must cover the upstream release you cloned:

```bash
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
```

**3. Build the plugin tree.** The packager copies upstream, overlays your profile, and validates — `--skip-archive` stops before the tarball:

```bash
python3 appsec-advisor/scripts/package_internal_plugin.py \
  --source appsec-advisor --org-profile org-profile \
  --name my-appsec --version 0.4.0-dev --skip-archive
```

**4. Load it in Claude Code.** Re-run steps 3–4 to pick up any profile edit:

```bash
claude --plugin-dir build/my-appsec
```

That gives you a working `/my-appsec:create-threat-model` that already runs with *your* default — standard depth, SARIF always on, $10 cost cap — instead of bare upstream defaults. The rest of this guide turns that skeleton into a real setup (a requirements catalog, business context, actors) and, if a team needs prebuilt artifacts, a CI pipeline that publishes an installable tarball.

## What you own vs. what upstream owns

| You own (in `org-profile/` + packaging repo) | Upstream owns (do not fork) |
|---|---|
| plugin name / command namespace | analysis behavior, agents, prompts |
| requirements catalog source | schemas, QA gates, permissions |
| business context, actors, presets, guardrails | renderers, export scripts |

Treat the `appsec-advisor` checkout as read-only. Instead of editing it, you overlay your own config on top of it during packaging.

## Repo layout

By the end of the steps below, your internal repo looks like this. You commit `org-profile/` (and a CI file); build outputs stay out of git, and so does upstream's source — only a submodule pin, if you use one:

```text
acme-appsec-plugin/              # your internal repo
├── .gitignore                   # ignores build/, dist/, (+ upstream/ if fresh-cloned)
├── upstream/
│   └── appsec-advisor/          # pinned in Step 1 (submodule pointer, or ignored clone)
└── org-profile/
    ├── org-profile.yaml         # Step 3 — defaults, presets, requirements source
    ├── context/
    │   └── organization.md      # Step 4 — business context
    └── actors/
        └── insiders.yaml        # Step 5 — company-specific actors (optional)
```

## Step 1 — Clone upstream (pinned)

Check out the pinned upstream release under `upstream/appsec-advisor/` — just a folder to hold the clone. Either way below, upstream's code is **never committed** to your repo; you only pin *which* version to pull. There are two ways to do it.

### Submodule — recommended

Record the exact upstream commit as a pointer in your own git history:

```bash
git submodule add https://github.com/matthiasrohr/appsec-advisor upstream/appsec-advisor
git -C upstream/appsec-advisor checkout v0.4.0-beta
git commit -am "Pin upstream appsec-advisor v0.4.0-beta"
```

Why it's the better default:

- **Reproducible.** The pin is an immutable commit SHA, so every build — yours, a teammate's, CI — uses the exact same upstream. A tag can be re-pointed upstream; a submodule SHA cannot.
- **Auditable.** Bumping the upstream version is a one-line, reviewable diff in your repo's history, not an invisible change in a CI variable.

It still does not vendor upstream's code — your repo commits only the pointer; `git submodule update` (or `git clone --recurse-submodules`) fetches the actual files. The trade-off is the usual submodule ceremony. If you choose this, drop the `upstream/appsec-advisor/` line from the `.gitignore` in Step 2.

### Fresh clone — simplest

One command clones and pins a release tag; nothing is committed:

```bash
git clone --depth 1 --branch v0.4.0-beta \
  https://github.com/matthiasrohr/appsec-advisor upstream/appsec-advisor
```

This is what the example CI pipelines do — they re-clone on every run, so there is no submodule to manage and the pin lives in the `APPSEC_ADVISOR_REF` variable. Good for quick local use too. `--branch` takes a tag or branch; for a bare commit SHA, clone without it, then `git -C upstream/appsec-advisor fetch --depth 1 origin <sha> && git -C upstream/appsec-advisor checkout --detach FETCH_HEAD`.

Substitute your own fork URL in either command if you maintain one.

## Step 2 — Add a `.gitignore`

Keep the build outputs out of git:

```gitignore
build/
dist/
upstream/appsec-advisor/    # omit this line if you pinned upstream as a submodule
```

The last line ignores a fresh-cloned upstream so it is never vendored into your repo. If you used a submodule (Step 1), leave it out — the submodule pointer is meant to be tracked. The packaging script lives inside the checkout, which is why the later commands call `upstream/appsec-advisor/scripts/package_internal_plugin.py`.

## Step 3 — Write your org profile

`org-profile/org-profile.yaml` is your entire config surface. Each preset maps to one upstream mode (`quick`, `standard`, or `thorough`) and layers your outputs and guardrails on top. This is where you point at your requirements catalog and declare the presets your teams may run:

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

What each field controls:

| Field | Controls |
|---|---|
| `default_preset` | the preset a plain `create-threat-model` run uses |
| `requirements.source` | the requirements catalog the analysis maps findings against |
| `llm_context.documents` | the business-context files loaded into the analysis (Step 4) |
| `actors` | which threat actors apply (built-ins + your additions, Step 5) |
| `presets.*.guardrails` | per-run ceilings — `max_cost_usd`, `max_wall_time` |

For the full reference, see [org-profiles.md](org-profiles.md); the schema lives at [../schemas/org-profile.schema.yaml](../schemas/org-profile.schema.yaml).

## Step 4 — Add business context

Create the context file your profile referenced under `llm_context.documents`. It describes your business, critical flows, and identity architecture so the analysis is grounded in how your systems actually work:

```bash
mkdir -p org-profile/context
cat > org-profile/context/organization.md <<'MD'
# Acme Corp — security context

Acme runs a B2B payments platform. Critical flows: merchant onboarding,
payout settlement, and admin refunds. Identity: Okta SSO for staff,
per-tenant API keys for merchants.
MD
```

Context files are **untrusted reference data**. They inform the analysis but cannot change severity rules, QA gates, schemas, or permissions.

## Step 5 — Add company-specific actors (optional)

Your profile's `actors.add: actors/*.yaml` glob picks up any actor files you drop here, on top of the 9 built-in actor classes. Add one only if you have threat actors specific to your org (insiders, partners). Each file is a top-level `actors:` array:

```yaml
# org-profile/actors/insiders.yaml
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

If you have no custom actors, skip this step — the glob simply matches nothing.

## Step 6 — Build the package

Run the upstream packager. Don't reimplement its copy, patch, rewrite, validate, and tar logic in your CI — `--org-profile` is its only config input:

```bash
python3 upstream/appsec-advisor/scripts/package_internal_plugin.py \
  --source upstream/appsec-advisor \
  --org-profile org-profile \
  --name acme-appsec \
  --version 0.4.0-acme.20260517
```

In one pass the script copies upstream into `build/acme-appsec/` (skipping VCS, caches, and runtime outputs), overlays your `org-profile/`, sets `name`/`version` in `plugin.json`, enables your profile in `config.json`, rewrites the command namespace `appsec-advisor:` → `acme-appsec:`, validates everything, and writes `dist/acme-appsec-0.4.0-acme.20260517.tgz` plus its `.sha256`. Pick a `--version` inside the profile's `compatibility.core` range, or validation rejects the build.

You never edit `config.json` by hand — the packager wires the profile in for you, writing a path relative to the self-contained plugin root:

```json
"organization_profile": { "enabled": true, "path": "org-profile/org-profile.yaml" }
```

To iterate locally without a tarball, add `--skip-archive` and load the folder directly with `claude --plugin-dir build/acme-appsec` (this is the [Quickstart](#quickstart) loop).

## Step 7 — Smoke-test the build

The build validates as it goes, but you can independently assert the finished artifact's contract — plugin name, org-profile wiring, a fully rewritten namespace, and a discoverable entry command — with a fast, no-API check:

```bash
python3 upstream/appsec-advisor/scripts/smoke_test_package.py \
  build/acme-appsec --name acme-appsec
```

It exits non-zero on the first broken assertion, so it works as the last step of a CI job (both example pipelines run it) or against an extracted tarball on a developer machine.

## Step 8 — Automate the build in CI

Put Steps 1, 6, and 7 in a pipeline. If validation fails (broken paths, unknown presets, unsupported compatibility, missed namespace rewrites), the packager exits non-zero before writing any artifact. Copy a ready-made example instead of writing one from scratch:

- GitHub Actions: [`examples/internal-packaging-github/.github/workflows/package.yml`](../examples/internal-packaging-github/.github/workflows/package.yml)
- GitLab CI: [`examples/internal-packaging-gitlab/.gitlab-ci.yml`](../examples/internal-packaging-gitlab/.gitlab-ci.yml)

Both clone the pinned upstream, run the packager, smoke-test the build, and upload the tarball. Set these variables:

| Variable | Value |
|---|---|
| `APPSEC_ADVISOR_URL` | `https://github.com/matthiasrohr/appsec-advisor.git` (or your fork) |
| `APPSEC_ADVISOR_REF` | pinned tag or branch, e.g. `v0.4.0-beta` |
| `INTERNAL_NAME` *(optional)* | plugin name, default `acme-appsec` |
| `VERSION` *(optional)* | release string, e.g. `0.4.0-acme.20260517` |

## Step 9 — Publish and install

Publish `dist/*.tgz` through whatever channel your org already trusts — a release asset, artifact registry, bootstrap script, managed image, or devcontainer. Developers then install the approved artifact rather than building their own:

```bash
mkdir -p ~/.claude/plugins
tar -xzf acme-appsec-0.4.0-acme.20260517.tgz -C ~/.claude/plugins
claude --plugin-dir ~/.claude/plugins/acme-appsec
```

That loads your bundled profile, applies its `default_preset`, fetches your requirements catalog, and enforces your guardrails:

```text
/acme-appsec:create-threat-model
```

Developers can still choose another approved preset, for example `--preset release-review`.

## Keeping in sync with upstream

When a new upstream release lands:

1. Bump the pinned `upstream/appsec-advisor` ref (Step 1).
2. Rebuild and re-run validation (Step 6) and the smoke test (Step 7).
3. End-to-end check: run `/acme-appsec:create-threat-model --dry-run` on a small repo — it exercises the real pipeline with your bundled profile and writes to a temp directory instead of a report in your repo.
4. Publish a new internal artifact (Step 9).

Prefer small packaging changes over forking the prompts, schemas, renderers, or scripts. If you genuinely need to change analysis behavior, treat it as a real fork: patch it deliberately, keep a changelog, and rerun the upstream tests.
