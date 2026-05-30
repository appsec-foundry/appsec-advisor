# Internal Packaging — GitHub Actions example

Runnable GitHub Actions workflow that builds a **company-branded** Claude Code
plugin from upstream [`appsec-advisor`](../../) with a custom org profile and
config, then publishes it as a tarball for internal distribution.

Uses the upstream packager described in
[`docs/internal-plugin-packaging.md`](../../docs/internal-plugin-packaging.md).
Copy this directory into a new GitHub repository, set the two required
repository variables, and the workflow runs end-to-end. This is the GitHub
counterpart of [`../internal-packaging-gitlab`](../internal-packaging-gitlab).

## What it does

```
package
  ├─ clone upstream@$APPSEC_ADVISOR_REF → upstream/appsec-advisor
  └─ python3 upstream/appsec-advisor/scripts/package_internal_plugin.py
       - copies upstream into build/$INTERNAL_NAME/ without VCS/cache/runtime outputs
       - overlays org-profile/
       - patches plugin.json + config.json
       - rewrites appsec-advisor: → $INTERNAL_NAME:
       - validates config + org profile + namespace rewrite
       - writes dist/$INTERNAL_NAME-$VERSION.tgz + .sha256
```

## Repository layout

```
.github/workflows/package.yml   ← workflow definition
org-profile/
  org-profile.yaml              ← presets, requirements source, guardrails
  context/organization.md       ← business context (untrusted data)
  actors/insiders.yaml          ← optional company-specific actors
```

The package job clones upstream into `upstream/appsec-advisor/`.
`APPSEC_ADVISOR_REF` may be a branch, tag, or commit SHA; the job fetches that
ref and checks out `FETCH_HEAD`. If you prefer a pinned submodule instead of a
fresh clone per run, replace the clone, fetch, and checkout lines with
`git submodule update`.

## Setup

1. Push this directory to a new GitHub repository.
2. Configure the upstream source in
   **Settings → Secrets and variables → Actions → Variables**:
   - `APPSEC_ADVISOR_URL` — e.g. `https://github.com/your-fork/appsec-advisor.git`
   - `APPSEC_ADVISOR_REF` — pinned tag or commit, e.g. `v0.4.0-beta`
3. (Optional) Add an `INTERNAL_NAME` variable if you don't want the
   `acme-appsec` default. Add a `VERSION` variable for releases, e.g.
   `0.4.0-acme.20260527`. With no override, a tag build uses the tag name
   (minus the `v` prefix) and any other run uses the CI snapshot default
   `0.4.0-internal.${GITHUB_SHA::8}`.
4. Run the workflow from the **Actions** tab (`Run workflow`) or push a `v*`
   tag, then download the `${INTERNAL_NAME}-${VERSION}` artifact from the run.

## Customizing the config

Everything that makes the build "yours" lives under `org-profile/`:

| File | Change to… |
|---|---|
| `org-profile.yaml` | swap the requirements URL, add/remove presets, tune guardrails (`max_cost_usd`, `max_wall_time`) |
| `context/organization.md` | describe your business, critical flows, identity architecture |
| `actors/*.yaml` | add company-specific threat actors (insiders, partners, etc.) |

The upstream packager validates the packaged config against
`schemas/org-profile.schema.yaml`, so schema errors surface in CI rather than
at runtime.

## Publishing the tarball

The example writes the tarball to a workflow artifact (`dist/*.tgz`, 30-day
retention). For real distribution, uncomment the `Publish to GitHub Release`
step in `package.yml` — it attaches the tarball to the release for a `v*` tag
build. Swap it for a push to GitHub Packages, Artifactory, Nexus, S3, or
whatever your org already trusts.

## Local build (no tarball)

To iterate on the org profile without CI, build just the plugin directory and
load it directly — pass `--skip-archive` so no tarball is written:

```bash
python3 upstream/appsec-advisor/scripts/package_internal_plugin.py \
  --source upstream/appsec-advisor \
  --org-profile org-profile \
  --name acme-appsec --version 0.4.0-dev --skip-archive

claude --plugin-dir build/acme-appsec
```

Validation still runs, so profile and namespace errors surface exactly as they
would in CI. Use a `--version` inside the profile's `compatibility.core` range
(here `>=0.4 <0.6`), otherwise validation rejects the build.

## Installing the built artifact

On a developer machine:

```bash
tar -xzf acme-appsec-<version>.tgz -C ~/.claude/plugins/
claude --plugin-dir ~/.claude/plugins/acme-appsec
```

Then in Claude Code:

```text
/acme-appsec:create-threat-model
```
