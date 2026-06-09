# Requirements Audit

Grades a repository against an `SEC-*` requirements catalog. Faster than a full threat model — fits PR gates, compliance dashboards, and audit preparation.

→ [Back to README](../README.md)

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
| **UNVERIFIABLE** | Static analysis cannot prove the requirement either way |

The console output lists only open requirements: `FAIL` and `PARTIAL`. Passed and unverifiable requirements are counted in the summary but not expanded. Open requirements include the grounded file/line evidence, a concrete risk statement, effort, and a code-aware fix. Saved Markdown reports add short before/after snippets where the repository contains meaningful code evidence.

## Prerequisites

A requirements catalog must be reachable before the skill can grade the repository. Point the config at a URL:

```json
// skills/audit-security-requirements/config.json
{
  "requirements_source": {
    "requirements_yaml_url": "https://your-org.example.com/appsec-requirements.yaml"
  }
}
```

Once a URL is configured (or a cache exists from a prior run), the skill fetches the latest YAML on each invocation and falls back to the local cache when the remote is unreachable.

## Run

```text
# Run with the configured catalog
/appsec-advisor:audit-security-requirements

# Run standalone with a URL
/appsec-advisor:audit-security-requirements --requirements https://URL/appsec-requirements.yaml

# Use the bundled mock server to test locally before connecting a real catalog
python3 scripts/mock-server.py
/appsec-advisor:audit-security-requirements --requirements http://127.0.0.1:4444/requirements.yaml
```

## Three paths to a catalog

1. **Adapt the reference baseline.** Copy `data/appsec-requirements-fallback.yaml` (currently 63 requirements across 38 categories, plus 9 blueprint entries) and rewrite the IDs and text to match your organisation. Serve it over HTTP (dev: `python3 scripts/mock-server.py`) or commit it to a Git-hosted raw URL.
2. **Harvest from internal pages.** Use `scripts/harvest-requirements.py` to crawl existing requirements and blueprint documents, then schedule it to stay in sync. Recommended when an internal wiki or intranet catalog already exists. Setup and CI scheduling: [`docs/harvester.md`](harvester.md).
3. **Pass a URL at invocation.** `--requirements <url>` loads from that URL for a single run without touching the config file. Useful for ad-hoc evaluation or switching between catalogs.

## Flags

All flags accepted by `/appsec-advisor:audit-security-requirements`. Each one changes either where the catalog comes from or which part of the audit is saved.

| Flag | Effect |
|------|--------|
| `--requirements <url>` | Override the configured URL for this run (no cache fallback) |
| `--category <prefix>` | Limit the audit to one category from your catalog (e.g. `SEC-AUTH`, `AUTH`, or whatever prefix your YAML defines) |
| `--md` | Save a Markdown report |
| `--json` | Save a JSON report |
| `--save` | Save both formats |

## Shared source with the threat model

Phase 8b of `/appsec-advisor:create-threat-model` uses the same catalog. When enabled, the threat model's Threat Register carries `Violated:` tags that link back to the requirement IDs in your YAML, and the Mitigation Register emits `Fulfills:` references. The two skills can run independently or together — configure the catalog once and both pick it up.
