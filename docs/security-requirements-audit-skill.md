# Requirements Audit

Grades a repository against a security requirements catalog, reporting PASS / FAIL / PARTIAL per requirement with file/line evidence. Faster than a full threat model — fits PR gates, compliance dashboards, and audit preparation.

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

Walks every requirement in the loaded catalog and assigns one of:

| Status | Meaning |
|--------|---------|
| **PASS** | Evidence found in the codebase satisfies the requirement |
| **PARTIAL** | Evidence found, but gaps exist — listed explicitly with file/line |
| **FAIL** | No evidence found, or evidence contradicts the requirement |
| **UNVERIFIABLE** | Static analysis cannot prove the requirement either way |
| **NOT_APPLICABLE** | The requirement does not apply to this repo (e.g. XML hardening with no XML parsing); never gates |

The console lists only open requirements (`FAIL`, `PARTIAL`) with file/line evidence, risk, effort, and a catalog-anchored fix; the other statuses are counted only. Saved Markdown adds short before/after snippets where there is code evidence.

## Example

Console output of a `--demo` run against [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) — a startup banner, the status tally, then one block per open requirement (trimmed here):

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

… 34 more open requirements …
```

→ [Full example report](../examples/requirements-auditor/appsec-requirements-report.md) ([JSON](../examples/requirements-auditor/appsec-requirements-report.json), [PDF](../examples/requirements-auditor/appsec-requirements-report.pdf)).

## Quick start

The audit grades the repo against a **requirements catalog** — your AppSec standard, expressed as YAML. Provide one, then run.

**1. Provide a catalog** (pick one):

| Where | How |
|-------|-----|
| Internal pages (Confluence, Antora, HTML) | Harvest to YAML with `scripts/harvest_requirements.py` → [docs/harvester.md](harvester.md) |
| Reference baseline | Adapt `data/appsec-requirements-fallback.yaml` (63 OWASP-based requirements), serve over HTTP or a raw Git URL |
| Local repo file | Drop `docs/security/requirements.yaml` into the repo |
| Packaged org profile | Shipped with your org's plugin — picked up automatically, no flag |
| URL | `requirements_yaml_url` in `skills/audit-security-requirements/config.json`, or `--requirements <url>` per run |
| None yet | `--demo` grades against the bundled example catalog |

**2. Run the audit** from the repo you want to grade:

```text
/appsec-advisor:audit-security-requirements           # resolved catalog
/appsec-advisor:audit-security-requirements --demo    # bundled example, no setup
/appsec-advisor:audit-security-requirements --status  # show the catalog that would be used, then exit
```

## Where the catalog comes from

Every run opens with a **startup banner** naming the catalog in effect, its source, fetch date, count, and freshness. Sources resolve in priority order (highest first):

| # | Source | Notes |
|---|--------|-------|
| 1 | `--requirements <src>` | Explicit http(s) URL or local path, this run only. Fail-closed (no cache fallback). |
| 2 | `--demo` | Packaged `examples/appsec-requirements-example.yaml`. Report is stamped **DEMO**. |
| 3 | `docs/security/requirements.yaml` | A developer-authored **local repo catalog**. Overrides the org profile, surfaced in the banner. Non-dot name — distinct from the generated `.requirements.yaml`. |
| 4 | Active org profile | The org profile's `requirements.source`, honouring `standalone_audit.enabled`. |
| 5 | Legacy config | `skills/audit-security-requirements/config.json` when it carries a URL. |
| 6 | Remembered source | The URL the catalog was last fetched from, served from the plugin cache (`.cache/requirements.yaml` + `.cache/requirements.source.json`). |

**Governance override:** if the org profile configures a source but sets `standalone_audit.enabled: false`, the audit is blocked even when a local `docs/security/requirements.yaml` exists — a committed file must not silently defeat org policy. Only an explicit `--requirements` or `--demo` overrides it. Otherwise the table applies as-is (local file beats the org source).

### Catalog format & validation

Every catalog uses one shape — the canonical format in [`schemas/requirements-catalog.schema.yaml`](../schemas/requirements-catalog.schema.yaml). Both `audit-security-requirements` and `create-threat-model` load it through the shared fetch gate, so a catalog that validates works for either.

Minimum contract: a YAML mapping with a `categories[]` array, each category and each requirement carrying an `id`. Recommended per requirement: `text` (the grading basis), `priority` (`MUST` / `SHOULD` / `MAY`), and `url`. Requirement IDs use your own naming scheme (`SEC-*`, `SCG-*`, anything) and need not be tagged in the analyzed code.

The fetch gate validates every catalog against this schema: structural breakage (a 404 page, a truncated or wrong-shaped file) fails the run loudly rather than silently grading zero requirements; content-quality issues (missing `text`/`priority`, duplicate IDs) are warnings and the run proceeds. Validate one yourself:

```text
python3 scripts/requirements_state.py --validate path/to/catalog.yaml [--strict]
```

The harvester runs the same validation on its output, so a malformed crawl is caught at harvest time.

## Source lifecycle: remember, refresh, inspect

Once a source loads successfully, the skill remembers its URL (with a fetch timestamp and content hash) in `.cache/requirements.source.json` and caches the catalog. Freshness is then handled automatically:

| Cache age | Behaviour |
|-----------|-----------|
| < 30 days | Served directly, no network round-trip — banner shows `Freshness: 🟢 fresh` |
| ≥ 30 days | Re-fetch attempted; if the source is unreachable, falls back to the cached copy and says so |

Maintenance flags override this: `--update` (force re-fetch), `--cache-only` (never touch the network), `--status` (print the banner and exit), `--clear-requirements` (forget the source and delete the cache). See [Flags](#flags).

## Flags

All flags accepted by `/appsec-advisor:audit-security-requirements`. Each one changes where the catalog comes from, how it is refreshed, or which part of the audit is saved.

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

A plain console run writes nothing. `--md`/`--pdf` add the human report; `--json`/`--save` or `--gate` also write a structured verdict to `docs/security/.requirements-audit.json` ([`schemas/requirements-audit.schema.json`](../schemas/requirements-audit.schema.json)) — one `results[]` entry per requirement (status, priority, `in_scope`, evidence, finding, fix, verbatim text, blueprint and threat-model links). Summary counts are recomputed by `scripts/requirements_report.py` (the model authors the fields, the script owns the tally), so the Result block never drifts from a hand-count. `--json` copies the verdict to `appsec-requirements-report.json`.

The gate is decided by `scripts/requirements_gate.py` — the same deterministic gate `verify-requirements` uses — from the verdict's `results[]`, not the model's advisory flags. A requirement gates when `in_scope AND status==FAIL (or PARTIAL with --gate-on partial) AND priority >= floor`. Advisory by default; `--gate` exits non-zero on a gating failure, so it drops into CI:

```bash
/appsec-advisor:audit-security-requirements --gate            # block on a failing MUST
/appsec-advisor:audit-security-requirements --gate --gate-on partial --priority-floor SHOULD
```

## Shared source with the threat model

Phase 8b of `/appsec-advisor:create-threat-model` uses the same catalog. When enabled, the threat model's Threat Register carries `Violated:` tags that link back to the requirement IDs in your YAML, and the Mitigation Register emits `Fulfills:` references. The two skills can run independently or together — configure the catalog once and both pick it up.
