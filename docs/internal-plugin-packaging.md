# Internal plugin packaging

Build the new composition from a pinned Analyzer wheel, dependency wheels, selected skills and an Advisor host artifact, then apply organization branding with the existing packager. The packager also retains its upstream-checkout path. The [composition contract](internal/contracts/plugin-composition.md) defines artifact integrity, provenance and runtime boundaries. The [implementation evidence](internal/analysis/plan-appsec-advisor-clean-composition-2026-10-18.md#committed-implementation-and-installed-evidence) records the current Linux offline replay; staging is not a replacement release.

Build a company-branded Claude Code plugin so developers run your namespace with your defaults:

```text
/acme-appsec:appsec-analyzer
```

The selected skills determine the available commands. In the current two-entry composition, the primary assessment instructions come from the Analyzer wheel and `security-score` comes from the separate skills collection. Branding changes the host namespace and configuration while retaining the selected engine and skill payloads. The broader [org profile reference](org-profiles.md) also covers checkout packages; composed packages admit only the subset described below.

## Assemble the component artifacts

[`data/plugin-package.json`](../data/plugin-package.json) pins the full commits of [appsec-analyzer](https://github.com/appsec-foundry/appsec-analyzer) and [appsec-skills](https://github.com/appsec-foundry/appsec-skills), the selected files, licenses, engine capabilities, runtime targets and the dependency wheels with their SHA-256 digests. Two targets use it:

```bash
make plugin-package   # build build/appsec-advisor-<version>-staging/
make plugin-update    # move the Analyzer and skills pins to the current main; review and commit the diff
```

`plugin-package` needs network access only on its first run or after a pin changes. It fetches each pinned commit once into `build/appsec-advisor-sources/` and downloads missing dependency wheels into `build/appsec-advisor-wheels/` with `pip --require-hashes`; a wheel with another digest fails. Later builds use these caches offline. The runtime setup later installs the bundled wheels offline, so the package has to contain them.

`plugin-update` reads the `main` heads, rewrites only the two commit pins and prints a GitHub comparison link for each change. Build only after the reviewed pin change is committed, so pushes to `main` never enter a package unreviewed.

`plugin-package` reads only committed files: the Advisor host files at `HOST_REV` (default `HEAD`), the pinned skill files and a clean export of the pinned Analyzer commit. It builds the engine wheel from that export with the locally installed `build`, `setuptools` and `wheel`, without package-index access. Working-tree changes never enter an artifact, and two builds of the same commits produce identical bytes. A dependency wheel that differs from its pin stops the build. `ANALYZER_SRC`/`SKILLS_SRC` select local checkouts and `ANALYZER_REV`/`SKILLS_REV` other revisions for trial builds; `WHEELHOUSE` selects another wheel directory.

The output is `build/appsec-advisor-<version>-staging/` unless `OUT` names another new directory. It contains `artifacts/`, `components.lock.json` and `assembly/` with the staging ZIP, checksums, notices and component inventory. An existing directory is refused, and a failed build leaves no output. The target does not install the engine, invoke models or set up a runtime.

Other selection changes, such as a dependency version or an added skill file, are reviewed edits of `data/plugin-package.json`. Verify new dependency pins against the published files and known vulnerabilities before committing them.

To assemble artifacts prepared another way, record exact revisions, versions, licenses, SHA-256 digests, required capabilities and source-to-target resource mappings in a lock conforming to [the component lock schema](../schemas/components-lock.schema.json) and run the assembler directly as shown below.

For the primary entry, select `appsec-analyzer` in `skill_bindings`, the engine-owned `SKILL.md`, `claude-code.md` and `business-context.md`, and the host bootstrap and progress renderer. Assembly retains the engine entry as `WORKFLOW.md` and generates the Claude invocation separately. Selecting `security-score` or `repo-profile` additionally requires its portable workflow resources and dependency declaration. The [composition contract](internal/contracts/plugin-composition.md#primary-entry-source-checkpoint) gives the ownership and capability checks.

To run the assembler directly, start it from the Advisor checkout with its existing Python dependencies. The output directory must not exist; its parent must exist. Replace the paths with the reviewed selection and artifact directory:

```bash
python3 scripts/compose_plugin.py --lock /packaging/components.lock.json --artifacts /packaging/artifacts --output /packaging/assembly
```

Assembly verifies the inputs and emits a staging ZIP, checksums, notices and component inventory. It does not install the engine, invoke models or fetch dependencies. Verify and extract the ZIP into a separate staging input directory, then apply the organization package step below. Do not pass the assembler's output directory containing the ZIP directly as `--staging`; that option requires the extracted plugin tree.

## Package an assembled staging tree

Verify and extract the reviewed assembler ZIP into a dedicated input directory. Run the packager from the Advisor checkout with its existing dependencies; no component checkout or network access is needed. Replace the paths, name and version in this example:

```bash
python3 scripts/package_internal_plugin.py --staging /staging/extracted-plugin --org-profile /packaging/org-profile --name team-appsec --version 1.0.0-internal --build-dir /packaging/build --dist-dir /packaging/dist
```

`--staging` replaces `--source`. The build and archive directories must be separate from both inputs, and the archive directory must be outside the build. Branding, description and information-URL overrides apply to host outputs. Package-policy skill selection works on the assembled surface, including a score-only package without the legacy primary skill. Organization-added skills, hooks and MCP declarations use the existing profile mechanisms and surface inventory. Disabled skills are removed from staging packages, with their reasons retained in configuration. The generated README lists the selected commands and explicit runtime setup; `--readme` is unavailable on this path.

Staging profiles separate Advisor host settings from the engine-only projection. The selected host and Analyzer must be reassembled with the public `organization_config` version-1 interface; packaging refuses older pins instead of patching them. The projection accepts base-mode presets and `policy.disable_opus` / `policy.url_allowlist`. Engines declaring `assess` in `organization_config.commands` and `profile_source_validation: true` dispatch these settings to full assessments as well as score. Presets seed assessment depth; explicit CLI depth wins. The primary binding retains its documented depth budgets, explicit budget precedence and mandatory policy. Score has no model calls or assessment depth. A nonempty URL allowlist restricts remote Git targets before retrieval. Missing presets, incompatible core versions, malformed policy and unsupported fields remain build errors even with `--skip-validation`. Requirements, data/approval restrictions, context, report branding, baseline enforcement, actors, abuse cases, analyst/coach settings and additional preset fields still require the existing `--source` path. External runtime profiles use the same supported fields and [selection procedure](internal/runbooks/composed-score-staging.md#select-an-external-score-profile); broader profile fields still fail explicitly.

A selected host `config.json` keeps its display pricing, host logging and compatible default-preset choice; these values do not configure engine spending or logs. Unmapped global settings, including external context, baseline and source-config skill toggles, fail explicitly. Profile-based skill toggles retain physical exclusion. See the [dispatch contract](internal/contracts/plugin-composition.md#organization-configuration-dispatch) for the exact ownership and selection rules.

The output contains a normalized branded tarball and checksum. `organization-source/` retains the original lock and component inventory; the delivered inventory hashes the final surface. Engine wheels, retained engine resources, portable skill resources and the bootstrap remain unchanged. The [composition contract](internal/contracts/plugin-composition.md#organization-packaging-boundary) explains delivery ownership and the removal of bindings for excluded skills.

Extract the branded archive and use the [staging setup procedure](internal/runbooks/composed-score-staging.md#prepare-the-runtime), substituting the organization package directory. Session-only loading uses the branded namespace, such as `/team-appsec:appsec-analyzer` and `/team-appsec:security-score` when selected. Explicit setup installs the bundled engine offline; the primary entry then uses public preparation, lifecycle, query and export operations. Packaging itself does not install an engine, invoke a model or start an MCP server. Installation and deterministic replay do not establish complete assessment or native-platform qualification.

## Quick start

The remaining quick start and numbered rollout steps describe the existing `--source` checkout package, including its broader profile fields and retained commands. They do not assemble the Analyzer wheel or portable skill artifacts. For the new composition, use the assembly and `--staging` steps above, followed by the staging runbook. Run this checkout-only local loop in an empty working directory; it needs no CI or tarball.

**1. Set the versions used below.**

```console
$ APPSEC_ADVISOR_REF=v0.6.0-beta.1
$ INTERNAL_VERSION=0.6.0-local
```

Use a pinned tag or branch for `APPSEC_ADVISOR_REF`. Avoid `latest` for internal packaging because it makes builds harder to reproduce.

**2. Create a minimal org profile.**

```console
$ mkdir -p org-profile
$ cat > org-profile/org-profile.yaml <<'YAML'
api_version: appsec-advisor.org-profile/v2
organization: { id: myorg, name: My Org, profile_version: "1" }
compatibility: { core: ">=0.6 <0.7" }
default_preset: local-default
presets:
  local-default:
    base_mode: standard
    outputs: { sarif: true }
    guardrails: { soft_budget_usd: 10 }
YAML
```

With this profile, a plain `/my-appsec:appsec-analyzer` uses standard depth, emits SARIF, and caps spend at `$10`. `compatibility` is required by the org-profile schema; it prevents packaging a profile with an unsupported upstream plugin version.

**3. Clone the upstream release.**

```console
$ git clone --depth 1 --branch "$APPSEC_ADVISOR_REF" https://github.com/appsec-foundry/appsec-advisor upstream/appsec-advisor
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
/my-appsec:appsec-analyzer
```

Continue with the steps below to build and publish the package for a team.

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
$ APPSEC_ADVISOR_REF=v0.6.0-beta.1
$ git submodule add https://github.com/appsec-foundry/appsec-advisor upstream/appsec-advisor
$ git -C upstream/appsec-advisor checkout "$APPSEC_ADVISOR_REF"
$ git add .gitignore .gitmodules upstream/appsec-advisor
$ git commit -m "Pin upstream appsec-advisor"
```

Step 4 still adds either `.github/workflows/package.yml` or `.gitlab-ci.yml`.

The [organization packaging template](https://github.com/appsec-foundry/appsec-advisor-packaging-template) is a ready-made Option 1 repository. It ships an org profile, a package policy, GitHub and GitLab pipelines, and build scripts, and it tracks upstream releases. Use it instead of assembling the repository by hand unless you need a shape it does not cover.

## Step 2 - Write the org profile

`org-profile/org-profile.yaml` is the company-owned runtime configuration surface. Start with two presets: one default CI-style scan and one deeper release review. Build-time package restrictions live next to it in `org-profile/package-policy.yaml`; they are covered after the profile example.

```yaml
api_version: appsec-advisor.org-profile/v2

organization:
  id: acme
  name: Acme Corp
  profile_version: "2026.05.1"

compatibility:
  core: ">=0.6 <0.7"

default_preset: ci-standard

policy:
  url_allowlist: [appsec.int.example.com]   # restrict remote fetches to your hosts

requirements:
  source:
    requirements_yaml_url: "https://appsec.int.example.com/appsec-requirements.yaml"
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
      gate:                     # package the CI gate policy so devs don't pass flags
        mode: enforce           # gate by default (like --gate); advisory otherwise
        gate_on: fail
        priority_floor: MUST
    guardrails:
      max_wall_time: 1h
      soft_budget_usd: 20
      fail_on: high             # headless run exits non-zero on new High+ threats

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
      soft_budget_usd: 80
```

The `requirements.gate` block makes `verify-requirements` and
`audit-security-requirements` gate by your default, so developers don't pass
`--gate` themselves. See [CI gates](org-profiles.md#ci-gates).

Add the referenced context file:

```markdown
# Acme Corp - security context

Acme runs a B2B payments platform. Critical flows: merchant onboarding, payout settlement, and admin refunds. Staff use Okta SSO; merchants use tenant-scoped API keys.
```

Context files are untrusted reference data. They inform the analysis, but they cannot change severity rules, QA gates, schemas, permissions, or tool behavior.

Custom actors are optional. If you keep `actors.add: actors/*.yaml`, actor files must contain a top-level `actors:` array:

```yaml
actors:
  - id: ACT-E-01
    label: acme-privileged-contractor
    access: [internal-network, ci-cd-secrets, staging-env]
    capabilities:
      sophistication: medium
      dwell_time: weeks
      surface_reach: [local, lateral]
    motivation: financial
    heatmap_slug: repo-read
```

### Optional - Restrict the packaged surface

Use `org-profile/package-policy.yaml` when the internal plugin must not expose every upstream skill or hook. The packager auto-detects this file. You can also pass `--package-policy <path>` explicitly.

Package policy removes skills and hooks from the built artifact. Org-profile `skill_toggles` only block skills at runtime.

Prefer allowlists for enterprise packages so newly added upstream skills do not appear until your team reviews them:

```yaml
plugin_surface:
  skills:
    include:
      - appsec-analyzer       # required
      - status
      - check-permissions
      - clean-run-state
      - fix-run-issues
      - security-assessment-health
  hooks:
    include:
      - agent-logger
```

Use denylists when you want to keep the upstream surface except for a small number of functions:

```yaml
plugin_surface:
  skills:
    exclude:
      - authnz-review
      - export-security-assessment
  hooks:
    exclude:
      - security-coach
```

Supported hook IDs today:

| Hook ID | Registered script | Effect when removed |
|---|---|---|
| `security-coach` | `scripts/analyzers/security_steering.py` | Removes prompt-time security coaching; `hooks/steering_keywords.json` is also omitted. |
| `agent-logger` | `scripts/runtime/agent_logger.py` | Removes Claude hook event logging for tool/use/stop events. Run summaries may have less timing and token context. |

`appsec-analyzer` and its internal `internal-threat-analysis-kernel` dependency are required and cannot be removed by package policy. The kernel is preloaded only by focused core agents and is not advertised as a user command. Unknown names fail the build so typos do not silently produce the wrong internal artifact.

If the org profile declares an [`mcp` block](org-profiles.md#mcp-servers), a third surface, `mcp_servers`, narrows which of those servers are emitted into the packaged `.mcp.json`. Every declared server is included by default; use an allowlist to restrict them:

```yaml
plugin_surface:
  mcp_servers:
    include:
      - acme-sast
```

The included/removed servers are recorded in `package-surface.json` alongside skills and hooks, and the smoke test verifies them against the packaged `.mcp.json`.

### Optional - Bundle your own hooks

An org can ship its own Claude Code hooks in the plugin, so one central artifact carries everything. Declare them in the org profile and drop the scripts under `org-profile/hooks/`:

```yaml
# org-profile/org-profile.yaml
hooks:
  block-risky-bash:
    event: PreToolUse
    matcher: Bash                                   # PreToolUse / PostToolUse only
    command: python3 ${CLAUDE_PLUGIN_ROOT}/org-profile/hooks/guard.py
```

The packager merges each declared hook into the built `hooks/hooks.json` and records it in `package-surface.json` under `hooks.org` (separate from the upstream `security-coach` / `agent-logger`), so the artifact stays auditable. The smoke test then checks that every listed org hook is present in `hooks.json` and its script is packaged. `plugin_surface.hooks` can exclude an org hook by id, the same as an upstream one.

Rules:

- The `command` must reference a script under the profile directory via `${CLAUDE_PLUGIN_ROOT}/org-profile/...`; the script must exist and its id must not reuse `security-coach` or `agent-logger`.
- Org hooks run at Claude Code's event layer. They can add context or block tool calls, but cannot change the analysis pipeline's findings, severity rules, or schemas.
- The hook code is yours: it ships in your artifact and runs on your developers' machines, like a bundled MCP stdio server. Only bundle scripts you trust.

## Step 3 - Build and validate

Make sure `upstream/appsec-advisor/` exists. With Option 1 from Step 1, clone it locally:

```console
# Option 1 only: create the ignored upstream checkout.
$ APPSEC_ADVISOR_REF=v0.6.0-beta.1
$ git clone --depth 1 --branch "$APPSEC_ADVISOR_REF" https://github.com/appsec-foundry/appsec-advisor upstream/appsec-advisor
```

With Option 2, the directory is the submodule checkout. Initialize it if this is a fresh clone of your packaging repo:

```console
# Option 2 only: fetch the tracked submodule checkout.
$ git submodule update --init --recursive
```

Build the packaged plugin:

```console
$ INTERNAL_VERSION=0.6.0-acme.20260903
$ python3 upstream/appsec-advisor/scripts/package_internal_plugin.py \
  --source upstream/appsec-advisor \
  --org-profile org-profile \
  --name acme-appsec \
  --version "$INTERNAL_VERSION"
```

The build writes the plugin to `build/acme-appsec/` and creates `dist/acme-appsec-${INTERNAL_VERSION}.tgz` with a `.sha256` checksum. It also validates the profile, package policy, and renamed command namespace.

Every build writes `.claude-plugin/package-surface.json` into the packaged tree. It records the included and removed skills, hooks, and MCP servers so CI and reviewers can verify the artifact surface without reverse-engineering the copied files.

`/<namespace>:status` shows the upstream version, revision, commit date, packaging date, and whether the source checkout was modified. These values are stored in `.claude-plugin/plugin.json` because the package has no `.git` directory. Pass `--upstream-url` to record the source repository explicitly; otherwise, the packager uses the checkout's `origin` remote.

Run the smoke test after every build. It checks the plugin identity, org-profile wiring, namespace rewrite, and the package-surface manifest when present:

```console
$ python3 upstream/appsec-advisor/scripts/smoke_test_package.py build/acme-appsec --name acme-appsec
```

The packager excludes dependency trees, caches, run logs, generated report
state, and other ignored local artifacts at any directory depth. The smoke test
independently rejects those paths and personal home-directory paths, so package
from a clean checkout and treat either finding as a build failure.

Use `--skip-archive` while editing locally:

```console
$ INTERNAL_VERSION=0.6.0-dev
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
| `APPSEC_ADVISOR_URL` | yes | upstream or fork URL, for example `https://github.com/appsec-foundry/appsec-advisor.git` |
| `APPSEC_ADVISOR_REF` | yes | pinned tag or branch, for example `v0.6.0-beta.1` |
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
            echo "version=0.6.0-internal.${GITHUB_SHA::8}" >> "$GITHUB_OUTPUT"
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

The packaging template ships a maintained version of this pipeline in [`ci-templates/github/workflows/package.yml`](https://github.com/appsec-foundry/appsec-advisor-packaging-template/blob/main/ci-templates/github/workflows/package.yml). It adds lint, upstream drift, and release stages, and it pins the runner image and the Python dependencies.

</details>

<details>
<summary>GitLab CI pipeline</summary>

```yaml
stages:
  - package

variables:
  INTERNAL_NAME: "acme-appsec"
  VERSION: "0.6.0-internal.${CI_COMMIT_SHORT_SHA}"
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

The packaging template ships a maintained version of this pipeline in [`ci-templates/gitlab-ci.yml`](https://github.com/appsec-foundry/appsec-advisor-packaging-template/blob/main/ci-templates/gitlab-ci.yml). It adds lint, upstream drift, and release stages, and it pins the runner image and the Python dependencies.

</details>

## Step 5 - Publish and install

Publish `dist/*.tgz` through your normal internal artifact or software-distribution channel.

Developers install the approved artifact:

```console
$ INTERNAL_VERSION=0.6.0-acme.20260903
$ mkdir -p ~/.claude/plugins
$ tar -xzf "acme-appsec-${INTERNAL_VERSION}.tgz" -C ~/.claude/plugins
$ claude --plugin-dir ~/.claude/plugins/acme-appsec
```

Then they run:

```text
/acme-appsec:appsec-analyzer
```

To use another bundled preset:

```text
/acme-appsec:appsec-analyzer --preset release-review
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
