# Internal Packaging: GitLab CI

Use this pipeline to build a company-branded `appsec-advisor` plugin with GitLab CI.

Copy this directory into a new GitLab project, then set these CI/CD variables
under **Settings -> CI/CD -> Variables**:

| Variable | Required | Example |
|---|---:|---|
| `APPSEC_ADVISOR_URL` | yes | `https://github.com/matthiasrohr/appsec-advisor.git` |
| `APPSEC_ADVISOR_REF` | yes | `v0.4.0-beta` |
| `INTERNAL_NAME` | no | `acme-appsec` |
| `VERSION` | no | `0.4.0-acme.20260517` |

The pipeline clones the pinned upstream ref, runs
`scripts/package_internal_plugin.py`, smoke-tests the packaged plugin, and keeps
`dist/*.tgz` plus its SHA-256 file as job artifacts.

Main runbook: [docs/internal-plugin-packaging.md](../../docs/internal-plugin-packaging.md)
