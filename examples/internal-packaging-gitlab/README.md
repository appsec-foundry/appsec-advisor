# Internal Packaging — GitLab CI example

Runnable GitLab CI/CD pipeline that builds a **company-branded** Claude Code
plugin from upstream [`appsec-advisor`](../../) with a custom org profile and
config, then publishes it as a tarball for internal distribution.

Mirrors the workflow in [`docs/internal-plugin-packaging.md`](../../docs/internal-plugin-packaging.md)
(steps 4 and 5). Copy this directory into a new GitLab project, fill in the
two required CI variables, and the pipeline runs end-to-end.

## What it does

```
prepare ──▶ validate ──▶ publish
   │            │            │
   │            │            └─ tar build/acme-appsec → dist/acme-appsec-<ver>.tgz
   │            │              + sha256 + GitLab Generic Packages upload (commented)
   │            │
   │            └─ python3 validate_config.py     (config.json schema)
   │              python3 validate_org_profile.py (org-profile.yaml schema + semantics)
   │              rg -n "appsec-advisor:"         (fails build if upstream namespace leaks)
   │
   └─ clone upstream@$APPSEC_ADVISOR_REF → upstream/appsec-advisor
     ./scripts/package.sh
        - rsync upstream/ → build/$INTERNAL_NAME/
        - rsync org-profile/ → build/$INTERNAL_NAME/org-profile/
        - patch plugin.json: name + version + description
        - patch config.json: organization_profile.enabled = true
        - sed: rewrite "appsec-advisor:" → "$INTERNAL_NAME:" in skills/agents/docs
```

## Repository layout

```
.gitlab-ci.yml                  ← pipeline definition
scripts/package.sh              ← vendor + overlay + patch (called by the pipeline)
org-profile/
  org-profile.yaml              ← presets, requirements source, guardrails
  context/organization.md       ← business context (untrusted data)
  actors/insiders.yaml          ← optional company-specific actors
```

The pipeline expects upstream to be cloned into `upstream/appsec-advisor/` at
prepare time (it does this for you). If you prefer a pinned submodule instead
of a fresh clone per run, swap the `git clone` line for `git submodule update`.

## Setup

1. Push this directory to a new GitLab project.
2. Configure the upstream source in **Settings → CI/CD → Variables**:
   - `APPSEC_ADVISOR_URL` — e.g. `https://github.com/your-fork/appsec-advisor.git`
   - `APPSEC_ADVISOR_REF` — pinned tag or commit, e.g. `v0.4.0-beta`
3. (Optional) Override `INTERNAL_NAME` if you don't want the `acme-appsec` default.
4. Run a pipeline on the default branch (or push a tag) and download the
   `dist/${INTERNAL_NAME}-${VERSION}.tgz` artifact from the `publish` job.

## Customizing the config

Everything that makes the build "yours" lives under `org-profile/`:

| File | Change to… |
|---|---|
| `org-profile.yaml` | swap the requirements URL, add/remove presets, tune guardrails (`max_cost_usd`, `max_wall_time`) |
| `context/organization.md` | describe your business, critical flows, identity architecture |
| `actors/*.yaml` | add company-specific threat actors (insiders, partners, etc.) |

The packaged config is validated against `schemas/org-profile.schema.yaml` in
the `validate` stage, so schema errors surface in CI rather than at runtime.

## Publishing the tarball

The example writes the tarball to a job artifact (`dist/*.tgz`, 30-day expiry).
For real distribution, uncomment the `curl --upload-file` block in the
`publish` job — it pushes to the GitLab Generic Packages registry of the same
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
