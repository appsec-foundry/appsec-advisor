# Internal Plugin Packaging

Build a company-branded Claude Code plugin so developers run your namespace with your defaults:

```text
/acme-appsec:create-threat-model
```

The packaged plugin still runs the upstream `appsec-advisor` analysis pipeline. Packaging only adds your plugin name, your bundled `org-profile/`, and your default preset. Use [org-profiles.md](org-profiles.md) for the full profile reference.

## Quick start

This is the shortest local loop. Run it in an empty working directory. No CI, no tarball.

**1. Set the versions used below.**

```console
$ APPSEC_ADVISOR_REF=v0.4.0-beta
$ INTERNAL_VERSION=0.4.0-local
```

Use a pinned tag or branch for `APPSEC_ADVISOR_REF`. Avoid `latest` for internal packaging because it makes builds harder to reproduce.

**2. Create a minimal org profile.**

```console
$ mkdir -p org-profile
$ cat > org-profile/org-profile.yaml <<'YAML'
api_version: appsec-advisor.org-profile/v2
organization: { id: myorg, name: My Org, profile_version: "1" }
compatibility: { core: ">=0.4 <0.6" }
default_preset: local-default
presets:
  local-default:
    base_mode: standard
    outputs: { sarif: true }
    guardrails: { max_cost_usd: 10 }
YAML
```

This profile is still tiny, but it changes behavior: a plain `/my-appsec:create-threat-model` uses standard depth, emits SARIF, and caps spend at `$10`. `compatibility` is required by the org-profile schema; it prevents packaging a profile with an unsupported upstream plugin version.

**3. Clone the upstream release.**

```console
$ git clone --depth 1 --branch "$APPSEC_ADVISOR_REF" https://github.com/matthiasrohr/appsec-advisor upstream/appsec-advisor
```

**4. Build a local branded plugin directory.**

```console
$ python3 upstream/appsec-advisor/scripts/package_internal_plugin.py --source upstream/appsec-advisor --org-profile org-profile --name my-appsec --version "$INTERNAL_VERSION" --skip-archive
```

**5. Load it in Claude Code.**

```console
$ claude --plugin-dir build/my-appsec
```

**6. Run the branded command in Claude Code.**

```text
/my-appsec:create-threat-model
```

That is enough for a local branded plugin. The following steps turn the same setup into a team-ready package with requirements, business context, optional actors, and CI artifacts.

## Step 1 - Create the packaging repo

Create one small internal repo. It owns your profile and, later in Step 4, one CI pipeline file. It should not contain a copied upstream checkout.

First choose how the repo gets upstream:

| Option | Use when | How upstream appears | Trade-off |
|---|---|---|---|
| **Option 1 - CI clones upstream** | you want the simplest repo; this is what the examples use | local builds and CI clone `APPSEC_ADVISOR_REF` into ignored `upstream/appsec-advisor/` | pin lives in docs/CI variables, not in git history |
| **Option 2 - Git submodule** | you want the upstream pin visible and reviewable in your repo history | git tracks `upstream/appsec-advisor/` as a submodule pointer | more submodule ceremony for clone/update workflows |

The `.gitignore` difference follows from that choice: Option 1 ignores `upstream/`; Option 2 must not ignore `upstream/` because the submodule pointer is tracked.

Run exactly one of the following setup blocks.

### Option 1 - CI clones upstream

Use this unless you explicitly want a Git submodule. The packaging repo commits only your profile and CI file; `upstream/appsec-advisor/` is created later by the local build command or CI pipeline and stays ignored.

```console
# Create the packaging repo skeleton.
$ mkdir acme-appsec-plugin
$ cd acme-appsec-plugin
$ git init
$ mkdir -p org-profile/context org-profile/actors
$ printf 'build/\ndist/\nupstream/\n' > .gitignore
```

After Step 2, the repo has this shape:

```text
acme-appsec-plugin/
├── .gitignore
├── org-profile/
│   ├── org-profile.yaml
│   ├── context/
│   │   └── organization.md
│   └── actors/
│       └── insiders.yaml
```

Step 4 adds either `.github/workflows/package.yml` or `.gitlab-ci.yml`.

### Option 2 - Git submodule

Use this when the upstream plugin version should be pinned in your packaging repo history. Here `upstream/appsec-advisor/` is tracked as a submodule pointer, so do not ignore `upstream/`.

```console
# Create the packaging repo skeleton with a tracked upstream submodule.
$ mkdir acme-appsec-plugin
$ cd acme-appsec-plugin
$ git init
$ mkdir -p org-profile/context org-profile/actors
$ printf 'build/\ndist/\n' > .gitignore
$ APPSEC_ADVISOR_REF=v0.4.0-beta
$ git submodule add https://github.com/matthiasrohr/appsec-advisor upstream/appsec-advisor
$ git -C upstream/appsec-advisor checkout "$APPSEC_ADVISOR_REF"
$ git add .gitignore .gitmodules upstream/appsec-advisor
$ git commit -m "Pin upstream appsec-advisor"
```

Step 4 still adds either `.github/workflows/package.yml` or `.gitlab-ci.yml`.

The example repos already use Option 1:

- [GitHub Actions example](../examples/internal-packaging-github)
- [GitLab CI example](../examples/internal-packaging-gitlab)

## Step 2 - Write the org profile

`org-profile/org-profile.yaml` is the only company-owned configuration surface. Start with two presets: one default CI-style scan and one deeper release review.

```yaml
api_version: appsec-advisor.org-profile/v2

organization:
  id: acme
  name: Acme Corp
  profile_version: "2026.05.1"

compatibility:
  core: ">=0.4 <0.6"

default_preset: ci-standard

requirements:
  source:
    requirements_yaml_url: "https://security.acme.example/appsec-requirements.yaml"
    label: "Acme AppSec Requirements"
    cache: true
    fail_mode: cache_fallback
  create_threat_model:
    default_active: true
    quick_default_active: false

llm_context:
  documents:
    - id: organization
      path: context/organization.md
      purpose: organization_background
      max_bytes: 50000

actors:
  inherit_defaults: true
  add: actors/*.yaml

presets:
  ci-standard:
    base_mode: standard
    outputs:
      sarif: true
    requirements:
      enabled: true
    guardrails:
      max_wall_time: 1h
      max_cost_usd: 20

  release-review:
    base_mode: thorough
    outputs:
      sarif: true
      pdf: true
      pentest_tasks: true
    requirements:
      enabled: true
    guardrails:
      max_wall_time: 3h
      max_cost_usd: 80
```

Add the referenced context file:

```markdown
# Acme Corp - security context

Acme runs a B2B payments platform. Critical flows: merchant onboarding, payout settlement, and admin refunds. Staff use Okta SSO; merchants use tenant-scoped API keys.
```

Context files are untrusted reference data. They inform the analysis, but they cannot change severity rules, QA gates, schemas, permissions, or tool behavior.

Custom actors are optional. If you keep `actors.add: actors/*.yaml`, actor files must contain a top-level `actors:` array:

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

## Step 3 - Build and validate

Make sure `upstream/appsec-advisor/` exists. With Option 1 from Step 1, clone it locally:

```console
# Option 1 only: create the ignored upstream checkout.
$ APPSEC_ADVISOR_REF=v0.4.0-beta
$ git clone --depth 1 --branch "$APPSEC_ADVISOR_REF" https://github.com/matthiasrohr/appsec-advisor upstream/appsec-advisor
```

With Option 2, the directory is the submodule checkout. Initialize it if this is a fresh clone of your packaging repo:

```console
# Option 2 only: fetch the tracked submodule checkout.
$ git submodule update --init --recursive
```

Build the packaged plugin:

```console
$ INTERNAL_VERSION=0.4.0-acme.20260517
$ python3 upstream/appsec-advisor/scripts/package_internal_plugin.py \
  --source upstream/appsec-advisor \
  --org-profile org-profile \
  --name acme-appsec \
  --version "$INTERNAL_VERSION"
```

The packager copies upstream into `build/acme-appsec/`, overlays `org-profile/`, rewrites `appsec-advisor:` command references to `acme-appsec:`, enables the bundled profile in `config.json`, validates the result, and writes `dist/acme-appsec-${INTERNAL_VERSION}.tgz` plus its `.sha256`.

Run the smoke test after every build:

```console
$ python3 upstream/appsec-advisor/scripts/smoke_test_package.py build/acme-appsec --name acme-appsec
```

Use `--skip-archive` while editing locally:

```console
$ INTERNAL_VERSION=0.4.0-dev
$ python3 upstream/appsec-advisor/scripts/package_internal_plugin.py --source upstream/appsec-advisor --org-profile org-profile --name acme-appsec --version "$INTERNAL_VERSION" --skip-archive
$ claude --plugin-dir build/acme-appsec
```

The `--version` must satisfy `compatibility.core` in the org profile.

## Step 4 - Add CI

Step 4 adds one pipeline file to the packaging repo:

- GitHub Actions: `.github/workflows/package.yml`
- GitLab CI: `.gitlab-ci.yml`

The embedded examples below use Option 1 from Step 1, where CI clones upstream during the job. They do the same three operations as the local build:

1. clone a pinned upstream ref into `upstream/appsec-advisor`
2. run `scripts/package_internal_plugin.py`
3. run `scripts/smoke_test_package.py`

For Option 1, set these CI variables:

| Variable | Required | Meaning |
|---|---:|---|
| `APPSEC_ADVISOR_URL` | yes | upstream or fork URL, for example `https://github.com/matthiasrohr/appsec-advisor.git` |
| `APPSEC_ADVISOR_REF` | yes | pinned tag or branch, for example `v0.4.0-beta` |
| `INTERNAL_NAME` | no | plugin namespace, default `acme-appsec` |
| `VERSION` | no | package version; defaults to a CI snapshot version |

The example clone command uses `git clone --depth 1 --branch "$APPSEC_ADVISOR_REF"`, which is correct for tags and branches. To pin an arbitrary commit SHA, replace that line with a clone plus `git fetch --depth 1 origin <sha>` and checkout.

For Option 2, remove the clone step from the example and configure your CI checkout to initialize submodules. Then run the same package and smoke-test commands against `upstream/appsec-advisor/`.

<details>
<summary>GitHub Actions pipeline</summary>

```yaml
name: package-internal-plugin

on:
  workflow_dispatch:
  push:
    tags:
      - "v*"

permissions:
  contents: read

env:
  INTERNAL_NAME: ${{ vars.INTERNAL_NAME || 'acme-appsec' }}
  PYTHONDONTWRITEBYTECODE: "1"
  PIP_DISABLE_PIP_VERSION_CHECK: "1"

jobs:
  package:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout packaging repo
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install build dependencies
        run: pip install --quiet pyyaml jsonschema packaging

      - name: Resolve version
        id: ver
        env:
          VERSION: ${{ vars.VERSION }}
        run: |
          if [ -n "${VERSION}" ]; then
            echo "version=${VERSION}" >> "$GITHUB_OUTPUT"
          elif [ "${GITHUB_REF_TYPE}" = "tag" ]; then
            echo "version=${GITHUB_REF_NAME#v}" >> "$GITHUB_OUTPUT"
          else
            echo "version=0.4.0-internal.${GITHUB_SHA::8}" >> "$GITHUB_OUTPUT"
          fi

      - name: Clone pinned upstream
        env:
          APPSEC_ADVISOR_URL: ${{ vars.APPSEC_ADVISOR_URL }}
          APPSEC_ADVISOR_REF: ${{ vars.APPSEC_ADVISOR_REF }}
        run: |
          test -n "${APPSEC_ADVISOR_URL}" || { echo "APPSEC_ADVISOR_URL not set"; exit 2; }
          test -n "${APPSEC_ADVISOR_REF}" || { echo "APPSEC_ADVISOR_REF not set"; exit 2; }
          git clone --depth 1 --branch "${APPSEC_ADVISOR_REF}" "${APPSEC_ADVISOR_URL}" upstream/appsec-advisor

      - name: Package plugin
        run: |
          python3 upstream/appsec-advisor/scripts/package_internal_plugin.py \
            --source upstream/appsec-advisor \
            --org-profile org-profile \
            --name "${INTERNAL_NAME}" \
            --version "${{ steps.ver.outputs.version }}"

      - name: Smoke-test package
        run: |
          python3 upstream/appsec-advisor/scripts/smoke_test_package.py \
            "build/${INTERNAL_NAME}" --name "${INTERNAL_NAME}"

      - name: Upload package
        uses: actions/upload-artifact@v4
        with:
          name: ${{ env.INTERNAL_NAME }}-${{ steps.ver.outputs.version }}
          path: |
            dist/${{ env.INTERNAL_NAME }}-${{ steps.ver.outputs.version }}.tgz
            dist/${{ env.INTERNAL_NAME }}-${{ steps.ver.outputs.version }}.tgz.sha256
          retention-days: 30
```

Runnable copy: [examples/internal-packaging-github/.github/workflows/package.yml](../examples/internal-packaging-github/.github/workflows/package.yml)

</details>

<details>
<summary>GitLab CI pipeline</summary>

```yaml
stages:
  - package

variables:
  INTERNAL_NAME: "acme-appsec"
  VERSION: "0.4.0-internal.${CI_COMMIT_SHORT_SHA}"
  PYTHONDONTWRITEBYTECODE: "1"
  PIP_DISABLE_PIP_VERSION_CHECK: "1"

default:
  image: python:3.11-slim
  before_script:
    - apt-get update -qq && apt-get install -y -qq --no-install-recommends git
    - pip install --quiet pyyaml jsonschema packaging

package:
  stage: package
  script:
    - test -n "$APPSEC_ADVISOR_URL" || { echo "APPSEC_ADVISOR_URL not set"; exit 2; }
    - test -n "$APPSEC_ADVISOR_REF" || { echo "APPSEC_ADVISOR_REF not set"; exit 2; }
    - git clone --depth 1 --branch "$APPSEC_ADVISOR_REF" "$APPSEC_ADVISOR_URL" upstream/appsec-advisor
    - >
      python3 upstream/appsec-advisor/scripts/package_internal_plugin.py
      --source upstream/appsec-advisor
      --org-profile org-profile
      --name "$INTERNAL_NAME"
      --version "$VERSION"
    - python3 upstream/appsec-advisor/scripts/smoke_test_package.py "build/${INTERNAL_NAME}" --name "${INTERNAL_NAME}"
  artifacts:
    name: "${INTERNAL_NAME}-${VERSION}"
    paths:
      - "dist/${INTERNAL_NAME}-${VERSION}.tgz"
      - "dist/${INTERNAL_NAME}-${VERSION}.tgz.sha256"
    expire_in: 30 days
```

Runnable copy: [examples/internal-packaging-gitlab/.gitlab-ci.yml](../examples/internal-packaging-gitlab/.gitlab-ci.yml)

</details>

## Step 5 - Publish and install

Publish `dist/*.tgz` through your normal internal channel: CI artifact, release asset, package registry, Artifactory, Nexus, S3, developer portal, devcontainer image, or workstation bootstrap.

Developers install the approved artifact:

```console
$ INTERNAL_VERSION=0.4.0-acme.20260517
$ mkdir -p ~/.claude/plugins
$ tar -xzf "acme-appsec-${INTERNAL_VERSION}.tgz" -C ~/.claude/plugins
$ claude --plugin-dir ~/.claude/plugins/acme-appsec
```

Then they run:

```text
/acme-appsec:create-threat-model
```

To use another bundled preset:

```text
/acme-appsec:create-threat-model --preset release-review
```

## Step 6 - Update upstream

When upstream releases a new version:

1. update `APPSEC_ADVISOR_REF` or your local clone/submodule pin
2. make sure `compatibility.core` covers the new package version
3. rebuild the package
4. run the smoke test
5. run one small dry run with the packaged plugin
6. publish a new internal artifact

Keep packaging changes small. If you need to change analysis behavior, treat it as a real fork and test it as one.
