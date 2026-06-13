# Requirements Audit

Grades a repository against a security requirements catalog. Requirement IDs follow whatever naming scheme your catalog defines (`SEC-*`, `SCG-*`, your own prefixes, or none in particular) — the repo does not need to tag its code with those IDs. Faster than a full threat model — fits PR gates, compliance dashboards, and audit preparation.

→ [Back to README](../README.md)

## Contents

- [What it does](#what-it-does)
- [Prerequisites](#prerequisites)
- [Run](#run)
- [Where the catalog comes from](#where-the-catalog-comes-from)
- [Source lifecycle: remember, refresh, inspect](#source-lifecycle-remember-refresh-inspect)
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

A requirements catalog must be resolvable before the skill can grade the repository. You have several options (see [Where the catalog comes from](#where-the-catalog-comes-from)); the lowest-friction one is to point the config at a URL:

```json
// skills/audit-security-requirements/config.json
{
  "requirements_source": {
    "requirements_yaml_url": "https://your-org.example.com/appsec-requirements.yaml"
  }
}
```

On a fresh machine with **no** configured source and an empty cache, the skill does not fail cryptically: it prints first-run guidance and offers to run against the bundled example catalog with `--demo`.

## Run

```text
# Run with the resolved catalog (banner shows source, date, count, freshness)
/appsec-advisor:audit-security-requirements

# Run standalone with a URL (also remembered for later --update / --status)
/appsec-advisor:audit-security-requirements --requirements https://URL/appsec-requirements.yaml

# Inspect what would be used — no audit, no fetch
/appsec-advisor:audit-security-requirements --status

# Try it immediately against the bundled example catalog (clearly stamped DEMO)
/appsec-advisor:audit-security-requirements --demo

# Use the bundled mock server to test locally before connecting a real catalog
python3 scripts/mock-server.py
/appsec-advisor:audit-security-requirements --requirements http://127.0.0.1:4444/requirements.yaml
```

## Where the catalog comes from

Every run prints a **startup banner** before any findings — which catalog is in effect, where it came from, when it was fetched, how many requirements, and whether it is still fresh. The source is resolved in this order (highest priority first):

| # | Source | Notes |
|---|--------|-------|
| 1 | `--requirements <src>` | Explicit http(s) URL or local path, this run only. Fail-closed (no cache fallback). |
| 2 | `--demo` | Packaged `examples/appsec-requirements-example.yaml`. Report is stamped **DEMO**. |
| 3 | `docs/security/requirements.yaml` | A developer-authored **local repo catalog**. Overrides the org profile and is surfaced in the banner (`Note: using local repo catalog`). Note the non-dot name — distinct from the generated `.requirements.yaml`. |
| 4 | Active org profile | The org profile's `requirements.source`, honouring `standalone_audit.enabled`. |

> **Governance override (org policy wins over a passive local file).** If the
> active org profile configures a requirements source but sets
> `requirements.standalone_audit.enabled: false`, the standalone audit is
> **blocked even when a local `docs/security/requirements.yaml` is present** — a
> file committed to the repo must not silently defeat the org policy. Only an
> explicit per-run override (`--requirements <src>` or `--demo`) runs the audit
> anyway. With the toggle enabled (or no org source at all), the precedence
> table above applies unchanged and the local file wins over the org source.
| 5 | Legacy config | `skills/audit-security-requirements/config.json` when it carries a URL. |
| 6 | Remembered source | The URL the catalog was last fetched from, served from the plugin cache (`.cache/requirements.yaml` + `.cache/requirements.source.json`). |

Three ways to author the catalog itself: adapt the reference baseline (`data/appsec-requirements-fallback.yaml` — 63 requirements across 38 categories plus 9 blueprints) and serve it over HTTP or a raw Git URL; harvest internal pages with `scripts/harvest_requirements.py` ([`docs/harvester.md`](harvester.md)); or drop a `docs/security/requirements.yaml` straight into the repo.

### Catalog format & validation

All three authoring paths produce **one** shape — the canonical interchange
format defined by [`schemas/requirements-catalog.schema.yaml`](../schemas/requirements-catalog.schema.yaml).
Both skills (`audit-security-requirements` and `create-threat-model`) load the
same file through the shared fetch gate and both accept `--requirements`, so a
catalog that validates is consumable by either.

Minimum contract: a YAML mapping with a `categories[]` array; each category has
an `id`; each requirement has an `id`. Recommended per requirement: `text`
(the grading basis), `priority` (`MUST` / `SHOULD` / `MAY`), and `url`.
Requirement IDs use **your own naming scheme** — `SEC-*`, `SCG-*`, `REQ-*`,
anything — and need **not** be tagged in the analyzed code.

The fetch gate validates every loaded catalog against this schema: structural
breakage (a 404 HTML page, a truncated file, a wrong-shaped document) **fails
the run loudly** instead of silently grading as zero requirements, while
content-quality issues (missing `text`/`priority`, zero requirements, duplicate
IDs) are reported as warnings and the run proceeds. Validate a catalog yourself:

```text
python3 scripts/requirements_state.py --validate path/to/catalog.yaml [--strict]
```

The harvester runs the same validation on its output, so a malformed crawl is
caught at harvest time.

## Source lifecycle: remember, refresh, inspect

Once a configured or remembered source loads successfully, the skill **remembers the URL** (with a fetch timestamp and content hash) in `.cache/requirements.source.json` and refreshes the cached catalog. That memory drives the default freshness behaviour and the maintenance flags:

- **Fresh cache is reused without a network round-trip.** A cache younger than **30 days** is served directly (fast, offline-friendly). The banner shows `Freshness: ● fresh`.
- **Stale cache triggers a refresh attempt.** A cache ≥ 30 days old (or `--update`) re-fetches from the remembered/configured source; if that source is unreachable, the run falls back to the cached copy and says so (`source unreachable this run — served the cached copy`).
- **`--update`** forces a fresh re-fetch and cache refresh regardless of freshness.
- **`--cache-only`** never touches the network — uses the cache, or errors if it is empty.
- **`--status`** prints the banner (source, date, count, freshness) and exits without scanning or fetching.
- **`--clear-requirements`** forgets the remembered source and deletes the cached catalog, then exits.

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
| `<CATEGORY_FILTER>` | Limit the audit to matching requirement IDs/categories (e.g. `SEC-AUTH`, `AUTH`); MUST-level requirements are always included |
| `--org-profile <path>` / `--preset <name>` / `--no-org-profile` | Control org-profile source resolution |
| `--md` / `--pdf` / `--json` | Save the report as Markdown / PDF / JSON (`--pdf` also writes the Markdown it is converted from; needs pandoc + weasyprint) |
| `--save` | Save all formats (`--md`, `--pdf`, `--json`) |
| `--gate` | Enforce a CI gate: exit non-zero when a gating requirement fails (advisory otherwise) |
| `--gate-on <fail\|partial>` | What gates: `fail` (default) or `fail`+`partial` |
| `--priority-floor <MUST\|SHOULD\|MAY>` | Lowest priority eligible to gate (default `MUST`) |

## Structured verdict & CI gate

A plain console run stays light — it grades and prints, without writing files.
When you **save an artifact (`--md`/`--pdf`/`--json`/`--save`) or gate
(`--gate`)**, the skill also writes a structured verdict to
`docs/security/.requirements-audit.json` ([`schemas/requirements-audit.schema.json`](../schemas/requirements-audit.schema.json)):
one `results[]` entry per graded requirement (status, priority, `in_scope`,
evidence, finding, fix, the verbatim requirement text, blueprint and threat-model
links). The summary counts are **recomputed deterministically** by
`scripts/requirements_report.py` (the model authors the fields; the script owns
the tally), so the Result block never drifts from a hand-count. `--json` simply
copies this verdict to `appsec-requirements-report.json`.

The pass/fail gate is decided by `scripts/requirements_gate.py` — the **same**
deterministic gate the diff-scoped `verify-requirements` skill uses — reading
the verdict's `results[]`, never the model's advisory flags. A requirement gates
when `in_scope AND status==FAIL (or PARTIAL with --gate-on partial) AND priority
>= floor`. Advisory by default; `--gate` makes the run exit non-zero on a gating
failure, so it drops into CI:

```bash
/appsec-advisor:audit-security-requirements --gate            # block on a failing MUST
/appsec-advisor:audit-security-requirements --gate --gate-on partial --priority-floor SHOULD
```

## Shared source with the threat model

Phase 8b of `/appsec-advisor:create-threat-model` uses the same catalog. When enabled, the threat model's Threat Register carries `Violated:` tags that link back to the requirement IDs in your YAML, and the Mitigation Register emits `Fulfills:` references. The two skills can run independently or together — configure the catalog once and both pick it up.
