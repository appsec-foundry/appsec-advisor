# Internal Packaging — GitLab CI example

Runnable GitLab CI/CD pipeline that builds a **company-branded** Claude Code
plugin from upstream [`appsec-advisor`](../../) with a custom org profile and
config, then publishes it as a tarball for internal distribution.

Uses the upstream packager described in
[`docs/internal-plugin-packaging.md`](../../docs/internal-plugin-packaging.md).
Copy this directory into a new GitLab project, fill in the two required CI
variables, and the pipeline runs end-to-end.

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
  └─ smoke_test_package.py build/$INTERNAL_NAME --name $INTERNAL_NAME
       - asserts the built artifact's contract (no API): plugin name,
         org-profile wiring, namespace rewrite, entry command present
```

## Repository layout

```
.gitlab-ci.yml                  ← pipeline definition
org-profile/
  org-profile.yaml              ← presets, requirements source, guardrails
  context/organization.md       ← business context (untrusted data)
  actors/insiders.yaml          ← optional company-specific actors
```

The package job pins upstream into `upstream/appsec-advisor/` with a single
`git clone --depth 1 --branch $APPSEC_ADVISOR_REF`, so `APPSEC_ADVISOR_REF` is a
tag or branch. To pin an arbitrary commit SHA instead, drop `--branch` and
fetch + check out that SHA.

## Setup

1. Push this directory to a new GitLab project.
2. Configure the upstream source in **Settings → CI/CD → Variables**:
   - `APPSEC_ADVISOR_URL` — e.g. `https://github.com/your-fork/appsec-advisor.git`
   - `APPSEC_ADVISOR_REF` — pinned tag or commit, e.g. `v0.4.0-beta`
3. (Optional) Override `INTERNAL_NAME` if you don't want the `acme-appsec` default.
   Override `VERSION` for releases, e.g. `0.4.0-acme.20260527`; the built-in
   CI snapshot default is `0.4.0-internal.${CI_COMMIT_SHORT_SHA}`.
4. Run a pipeline and download the `dist/${INTERNAL_NAME}-${VERSION}.tgz`
   artifact from the `package` job.

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

The example writes the tarball to a job artifact (`dist/*.tgz`, 30-day expiry).
For real distribution, uncomment the `curl --upload-file` block in the
`package` job — it pushes to the GitLab Generic Packages registry of the same
project using `$CI_JOB_TOKEN`. Swap the URL for Artifactory, Nexus, S3, or
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
