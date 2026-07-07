# Requirements Audit

`/appsec-advisor:audit-security-requirements` grades a repository against a security requirements catalog. It is narrower than a full threat model and can be used for pull-request gates or audit preparation.

→ [Back to README](../README.md)

## Contents

- [What it does](#what-it-does)
- [Example](#example)
- [Quick start](#quick-start)
- [Where the catalog comes from](#where-the-catalog-comes-from)
- [Source lifecycle: remember, refresh, inspect](#source-lifecycle-remember-refresh-inspect)
- [Flags](#flags)
- [Structured verdict & CI gate](#structured-verdict--ci-gate)
- [Shared source with the threat model](#shared-source-with-the-threat-model)

## What it does

Each requirement receives one of these statuses:

| Status | Meaning |
|--------|---------|
| **PASS** | Evidence found in the codebase satisfies the requirement |
| **PARTIAL** | Some evidence exists, but the requirement is not fully met |
| **FAIL** | No evidence found, or evidence contradicts the requirement |
| **UNVERIFIABLE** | Static analysis cannot prove the requirement either way |
| **NOT_APPLICABLE** | The requirement does not apply to this repository and never gates |

The console lists `FAIL` and `PARTIAL` results with evidence, risk, effort, and a suggested fix. Other statuses appear in the summary count. Saved Markdown includes short code examples where evidence is available.

## Example

Excerpt from a `--demo` run against [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/):

```text
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 AppSec Requirements Audit
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Requirements Source
  Catalog  : OWASP baseline  ⚠ DEMO — not your organization's requirements
  Loaded   : packaged example examples/appsec-requirements-example.yaml
  Count    : 64 requirements

Results · OWASP Juice Shop · 64 requirements

  🔴 FAIL          28
  🟡 PARTIAL        8
  🟢 PASS           5
  ⚪ UNVERIFIABLE  10
  ➖ NOT_APPLICABLE 13

Open Requirements
🔴 failed · 🟡 partial — worst-first (FAIL before PARTIAL, MUST before SHOULD)

🔴 MUST · AC-001 — No Mutual API Authentication
> All API-to-API calls MUST use mutual authentication (OAuth 2.0 client credentials, mTLS).
Finding : self-signed RS256 JWT signed with a key hardcoded in lib/insecurity.ts:23
Risk    : anyone with the embedded key mints valid tokens for any service call
Evidence: lib/insecurity.ts:23, lib/insecurity.ts:56
Fix     : use OAuth2 client-credentials or mTLS; stop signing with an in-source key.
Effort  : L
Links   : https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html

🟡 MUST · AC-003 — Rate Limiting Incomplete
> Apply rate limiting to all externally reachable API endpoints.
Finding : rateLimit covers a few endpoints (server.ts:343) but not /rest/user/login (server.ts:594)
Risk    : credential brute-force and scraping on unthrottled routes
Evidence: server.ts:594, server.ts:343
Fix     : extend express-rate-limit to all externally reachable endpoints, including login.
Effort  : S
Links   : https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html

… additional open requirements …
```

→ [Full example report](../examples/requirements-auditor/appsec-requirements-report.md) ([JSON](../examples/requirements-auditor/appsec-requirements-report.json), [PDF](../examples/requirements-auditor/appsec-requirements-report.pdf)).

## Quick start

The audit needs a requirements catalog in YAML format.

**1. Provide a catalog** (pick one):

| Where | How |
|-------|-----|
| Internal pages (Confluence, Antora, HTML) | Convert them with `scripts/harvest_requirements.py`; see the [harvester guide](harvester.md) |
| Reference baseline | Adapt `data/appsec-requirements-fallback.yaml` and publish it over HTTP or a raw Git URL |
| Local repo file | Drop `docs/security/requirements.yaml` into the repo |
| Packaged org profile | Included in your organization's plugin and selected automatically |
| URL | `--requirements <url>` per run, or (legacy/fallback) a `requirements_yaml_url` in `skills/audit-security-requirements/config.json` |
| None yet | `--demo` grades against the bundled example catalog |

**2. Run the audit** from the repo you want to grade:

```text
/appsec-advisor:audit-security-requirements           # resolved catalog
/appsec-advisor:audit-security-requirements --demo    # bundled example, no setup
/appsec-advisor:audit-security-requirements --status  # show the catalog that would be used, then exit
```

## Where the catalog comes from

The startup banner shows the selected catalog, source, fetch date, requirement count, and freshness. Sources are selected in this order:

| # | Source | Notes |
|---|--------|-------|
| 1 | `--requirements <src>` | Explicit http(s) URL or local path, this run only. Fail-closed (no cache fallback). |
| 2 | `--demo` | Packaged `examples/appsec-requirements-example.yaml`. Report is stamped **DEMO**. |
| 3 | `docs/security/requirements.yaml` | A developer-authored **local repo catalog**. Overrides the org profile, surfaced in the banner. A maintained input catalog, not a generated dotfile. |
| 4 | Active org profile | The org profile's `requirements.source`, honoring `standalone_audit.enabled`. |
| 5 | Legacy config | `skills/audit-security-requirements/config.json` when it carries a URL. |
| 6 | Remembered source | The URL the catalog was last fetched from, served from the plugin cache. |

If an org profile sets `standalone_audit.enabled: false`, the audit is blocked even when the repository contains `docs/security/requirements.yaml`. An explicit `--requirements` or `--demo` still overrides this setting.

### Catalog format & validation

Both the audit and threat modeler use the format in [`schemas/requirements-catalog.schema.yaml`](../schemas/requirements-catalog.schema.yaml).

Minimum contract: a YAML mapping with a `categories[]` array, each category and each requirement carrying an `id`. Recommended per requirement: `text` (the grading basis), `priority` (`MUST` / `SHOULD` / `MAY`), and `url`. Requirement IDs use your own naming scheme (`AC-*`, `SEC-*`, `SCG-*`, anything) and need not be tagged in the analyzed code.

Invalid structure, such as a downloaded 404 page or truncated file, stops the run. Missing recommended fields and duplicate IDs produce warnings. Validate a catalog with:

```text
python3 scripts/requirements_state.py --validate path/to/catalog.yaml [--strict]
```

The harvester validates its output the same way.

## Source lifecycle: remember, refresh, inspect

After a successful fetch, the catalog is cached:

| Cache age | Behavior |
|-----------|-----------|
| < 30 days | Use the cached copy without a network request |
| ≥ 30 days | Re-fetch attempted; if the source is unreachable, falls back to the cached copy and says so |

Use `--update`, `--cache-only`, `--status`, or `--clear-requirements` to control the cache. See [Flags](#flags).

## Flags

The command accepts these flags:

| Flag | Effect |
|------|--------|
| `--requirements <src>` | Use this http(s) URL or local path for this run (fail-closed, no cache fallback) |
| `--update` | Force a fresh re-fetch from the remembered/configured source and refresh the cache |
| `--cache-only` | Use the plugin cache only; never touch the network |
| `--demo` | Audit against the packaged example catalog; report is stamped **DEMO** |
| `--status` | Show which requirements would be used (source, date, count, freshness), then exit |
| `--clear-requirements` | Forget the remembered source and delete the cached catalog, then exit |
| `<CATEGORY_FILTER>` | Grade only requirements whose ID/category matches (e.g. `SEC-AUTH`, `AUTH`) — narrows scope; an unfiltered run grades the whole catalog |
| `--org-profile <path>` / `--preset <name>` / `--no-org-profile` | Control org-profile source resolution |
| `--md` / `--pdf` / `--json` | Save the report as Markdown / PDF / JSON (`--pdf` also writes the Markdown it is converted from; needs pandoc + weasyprint) |
| `--save` | Save all formats (`--md`, `--pdf`, `--json`) |
| `--quiet` | Suppress the banner + findings; print only a one-line status and the saved file path(s) |
| `--gate` | Enforce a CI gate: exit non-zero when a gating requirement fails (advisory otherwise) |
| `--gate-on <fail\|partial>` | What gates: `fail` (default) or `fail`+`partial` |
| `--priority-floor <MUST\|SHOULD\|MAY>` | Lowest priority eligible to gate (default `MUST`) |

## Structured verdict & CI gate

A console-only run writes no report. `--md` and `--pdf` create human-readable reports. `--json`, `--save`, and `--gate` also write `docs/security/.requirements-audit.json`. The JSON contains the status, priority, scope, evidence, finding, and fix for each requirement.

The audit is advisory by default. `--gate` exits non-zero when an in-scope requirement at or above the priority floor is `FAIL`. Add `--gate-on partial` to block on `PARTIAL` results as well:

```bash
/appsec-advisor:audit-security-requirements --gate            # block on a failing MUST
/appsec-advisor:audit-security-requirements --gate --gate-on partial --priority-floor SHOULD
```

## Shared source with the threat model

`/appsec-advisor:create-threat-model` uses the same catalog. Its findings link violations and mitigations to the matching requirement IDs. Configure the catalog once for both commands.
