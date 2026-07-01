# Internal Packaging: GitHub Actions

Use this workflow to build a company-branded `appsec-advisor` plugin with GitHub Actions.

Copy this directory into a new GitHub repository, then set these repository
variables under **Settings -> Secrets and variables -> Actions -> Variables**:

| Variable | Required | Example |
|---|---:|---|
| `APPSEC_ADVISOR_URL` | yes | `https://github.com/matthiasrohr/appsec-advisor.git` |
| `APPSEC_ADVISOR_REF` | yes | `v0.4.0-beta` |
| `INTERNAL_NAME` | no | `acme-appsec` |
| `VERSION` | no | `0.4.0-acme.20260517` |

The workflow clones the pinned upstream ref, runs
`scripts/package_internal_plugin.py`, smoke-tests the packaged plugin, and
uploads `dist/*.tgz` plus its SHA-256 file as a workflow artifact.

Main runbook: [docs/internal-plugin-packaging.md](../../docs/internal-plugin-packaging.md)
