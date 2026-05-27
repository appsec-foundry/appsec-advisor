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
```

## Repository layout

```
.gitlab-ci.yml                  ← pipeline definition
org-profile/
  org-profile.yaml              ← presets, requirements source, guardrails
  context/organization.md       ← business context (untrusted data)
  actors/insiders.yaml          ← optional company-specific actors
```

The package job clones upstream into `upstream/appsec-advisor/`.
`APPSEC_ADVISOR_REF` may be a branch, tag, or commit SHA; the CI job fetches
that ref and checks out `FETCH_HEAD`. If you prefer a pinned submodule instead
of a fresh clone per run, replace the clone, fetch, and checkout lines with
`git submodule update`.

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
