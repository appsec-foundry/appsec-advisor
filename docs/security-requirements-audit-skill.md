# Requirements Audit

Grades a repository against an `SEC-*` requirements catalog. Faster than a full threat model — fits PR gates, compliance dashboards, and audit preparation.

## Contents

- [What it does](#what-it-does)
- [Prerequisites](#prerequisites)
- [Run](#run)
- [Three paths to a catalog](#three-paths-to-a-catalog)
- [Flags](#flags)
- [Shared source with the threat model](#shared-source-with-the-threat-model)

## What it does

Walks every requirement in the loaded catalog and assigns one of:

| Status | Meaning |
|--------|---------|
| **PASS** | Evidence found in the codebase satisfies the requirement |
| **PARTIAL** | Evidence found, but gaps exist — listed explicitly with file/line |
| **FAIL** | No evidence found, or evidence contradicts the requirement |

Every result links back to the file and line that grounded the decision. `FAIL` and `PARTIAL` items include a before/after fix snippet and land in a prioritised remediation list.

## Prerequisites

A requirements catalog must be reachable before the skill can grade the repository. Point the config at a URL:

```json
// plugin/skills/check-appsec-requirements/config.json
{
  "requirements_source": {
    "requirements_yaml_url": "https://your-org.example.com/appsec-requirements.yaml"
  }
}
```

Once a URL is configured (or a cache exists from a prior run), the skill fetches the latest YAML on each invocation and falls back to the local cache when the remote is unreachable.

## Run

```
/appsec-plugin:check-appsec-requirements
```

## Three paths to a catalog

1. **Adapt the reference baseline.** Copy `plugin/data/appsec-requirements-fallback.yaml` (53 requirements across 10 categories) and rewrite the IDs and text to match your organisation. Serve it over HTTP (dev: `python3 scripts/mock-context-server.py`) or commit it to a Git-hosted raw URL.
2. **Harvest from internal pages.** Use `scripts/harvest-requirements.py` to crawl existing requirements and blueprint documents, then schedule it to stay in sync. Recommended when an internal wiki or intranet catalog already exists. Setup and CI scheduling: [`docs/harvester.md`](harvester.md).
3. **Pass a URL at invocation.** `--requirements <url>` loads from that URL for a single run without touching the config file. Useful for ad-hoc evaluation or switching between catalogs.

## Flags

All flags accepted by `/appsec-plugin:check-appsec-requirements`. Each one changes either where the catalog comes from or which part of the audit is saved.

| Flag | Effect |
|------|--------|
| `--requirements <url>` | Override the configured URL for this run (no cache fallback) |
| `--category <SEC-prefix>` | Limit the audit to one category, e.g. `SEC-AUTH` |
| `--md` | Save a Markdown report |
| `--json` | Save a JSON report |
| `--save` | Save both formats |

## Shared source with the threat model

Phase 8b of `/appsec-plugin:create-threat-model` uses the same catalog. When enabled, the threat model's Threat Register carries `Violated:` tags that link back to the `SEC-*` requirement IDs, and the Mitigation Register emits `Fulfills:` references. The two skills can run independently or together — configure the catalog once and both pick it up.
