# Requirements Harvester

`scripts/harvest-requirements.py` is the bridge between your organisation's existing security-requirements catalog (wiki, Confluence, Antora, or any HTML page) and the plugin's audit capability.

It crawls configured requirement and blueprint pages, extracts structured requirement IDs (`SEC-AUTH-01`, `OWASP-A01`, or whatever shape your org uses), cross-references blueprints against requirements, and writes everything into a single YAML file. That YAML is what `check-appsec-requirements` and the threat assessment's Phase 8b load to grade your repositories.

**Typical workflow:** configure sources → schedule the harvester → publish or commit the YAML → set `requirements_yaml_url` in the plugin config. From that point on, every audit run automatically picks up the latest requirements catalog without manual intervention.

> **First-time setup?** If you don't have an existing requirements catalog yet, skip the harvester for now: copy `data/appsec-requirements-fallback.yaml` (53 baseline requirements), adapt the IDs and text to your organisation, serve it over HTTP, and set `requirements_yaml_url` in the skill config. Come back to the harvester once you have live pages to crawl.

Run it whenever your requirements change, then commit the updated YAML — or let CI do it automatically (see [Scheduling](#scheduling) below).

## Setup

The harvester reads `scripts/harvest-config.json` (gitignored — it typically contains internal URLs and tokens). A template ships as `scripts/harvest-config.example.json`; copy it and edit:

```bash
cp scripts/harvest-config.example.json scripts/harvest-config.json
# Open scripts/harvest-config.json and set your URLs / auth env var
```

Install dependencies once:

```bash
pip install -r scripts/requirements.txt
```

## Usage

The harvester is a single Python script. The snippets below cover the common invocation modes — full run with the configured sources, authenticated crawl of internal pages, dry-run preview, and filtering by source type.

```bash
# Crawl and regenerate with the configured sources
python scripts/harvest-requirements.py

# With authentication token for internal pages
HARVEST_AUTH_TOKEN=<token> python scripts/harvest-requirements.py

# Preview without writing
python scripts/harvest-requirements.py --dry-run --verbose

# Requirements only (skip blueprint sources)
python scripts/harvest-requirements.py --req-only

# Blueprints only (skip requirement sources)
python scripts/harvest-requirements.py --blueprint-only

# Point at a different config file or output path
python scripts/harvest-requirements.py --config /etc/harvest-prod.json --output /tmp/out.yaml

# Pass the bearer token directly instead of via environment
python scripts/harvest-requirements.py --token "$MY_TOKEN"
```

### CLI flags

Every flag accepted by `harvest-requirements.py` and what it changes:

| Flag | Description |
|------|-------------|
| `--config PATH` | Path to the JSON config (default: `scripts/harvest-config.json`) |
| `--output PATH` | Override the output path resolved from the config's `output` field |
| `--token TOKEN` | Bearer token; overrides the env var named in `request.auth_header_env` |
| `--dry-run` | Fetch and parse but do not write the output file |
| `--verbose`, `-v` | Print each parsed requirement / blueprint section |
| `--req-only` | Process only sources of type `requirement` |
| `--blueprint-only` | Process only sources of type `blueprint` |

## Configuration

Configure sources in `scripts/harvest-config.json`. Each source defines a crawl target with its type, indexing mode, and display metadata:

```json
{
  "description": "ACME Corp Application Security Requirements",
  "url": "https://security.example.com",
  "output": "../data/appsec-requirements-fallback.yaml",

  "request": {
    "timeout_seconds": 15,
    "auth_header_env": "HARVEST_AUTH_TOKEN",
    "verify_ssl": true,
    "use_proxy": true,
    "extra_headers": {}
  },
  "defaults": {
    "max_pages": 100,
    "requirements_mode": "structured",
    "blueprints_mode": "full",
    "section_max_chars": 5000
  },
  "sources": [
    {
      "id": "internal-requirements",
      "type": "requirement",
      "mode": "structured",
      "title": "Internal Security Requirements",
      "reference_url": "https://security.example.com/requirements",
      "crawl_url": "https://security.example.com/requirements"
    },
    {
      "id": "owasp-requirements",
      "type": "requirement",
      "mode": "full",
      "title": "OWASP Web Security",
      "reference_url": "https://owasp.org/Top10/",
      "crawl_url": "https://owasp.org/Top10/",
      "max_pages": 50
    },
    {
      "id": "api-blueprints",
      "type": "blueprint",
      "mode": "full",
      "title": "API Security Blueprints",
      "reference_url": "https://security.example.com/blueprints/api",
      "crawl_url": "https://security.example.com/blueprints/api",
      "section_max_chars": 5000
    }
  ]
}
```

### Top-level fields

The config is a single JSON object. The top-level fields cover catalog metadata, HTTP session defaults, per-source defaults, and the list of sources to crawl.

| Field | Required | Description |
|-------|----------|-------------|
| `description` | No | Human-readable catalog description; copied into the output YAML as `description` |
| `url` | No | Base catalog URL; copied into the output YAML as `url` |
| `output` | No | Output path, resolved relative to the config file. Default: `requirements.yaml` next to the config. Overridable with `--output` |
| `request` | No | HTTP session settings — see table below |
| `defaults` | No | Per-source defaults (indexing mode, page caps) — see below |
| `sources` | Yes | List of crawl sources |

### `request` fields

HTTP session settings shared by every source. Leave the block out to accept the defaults.

| Field | Default | Description |
|-------|---------|-------------|
| `timeout_seconds` | 15 | Per-request timeout |
| `auth_header_env` | `HARVEST_AUTH_TOKEN` | Env-var name for the bearer token (sent as `Authorization: Bearer <token>`) |
| `verify_ssl` | `true` | TLS certificate verification; set `false` for self-signed CAs or pass a path to a custom CA bundle |
| `use_proxy` | `true` | When `true`, honours `HTTP(S)_PROXY` env vars; set `false` when the proxy can't resolve internal hostnames |
| `extra_headers` | `{}` | Additional request headers merged into every call |

### `defaults` fields

Per-source defaults that individual source entries can override. Useful to set one indexing mode for all requirement sources and another for blueprints.

| Field | Default | Description |
|-------|---------|-------------|
| `max_pages` | 100 | Max pages to fetch per source (overridable per-source) |
| `requirements_mode` | `structured` | Default indexing mode for requirement sources |
| `blueprints_mode` | `full` | Default indexing mode for blueprint sources |
| `section_max_chars` | 5000 | Default per-section truncation for blueprint content |

### Source fields

Each entry in the `sources` list defines one crawl target. A minimum entry needs `id`, `type`, `crawl_url`, and `title`; the rest fall back to the `defaults` block.

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique identifier for the source |
| `type` | Yes | `requirement` or `blueprint` |
| `crawl_url` | Yes | URL to crawl and index |
| `title` | Yes | Display title shown to users |
| `reference_url` | No | User-facing reference URL (not used for indexing, echoed into `sources_meta`) |
| `mode` | No | Indexing mode (overrides the default for this type — see below) |
| `max_pages` | No | Max pages to crawl (overrides `defaults.max_pages`) |
| `section_max_chars` | No | Blueprints only: max chars per section (overrides default) |

### Indexing modes

Each source type has a default mode and one alternative. The mode controls how much of each page is copied into the output YAML — relevant when you want either compact requirement lists or full blueprint content.

| Type | Mode | What is stored |
|------|------|---------------|
| Requirements | `structured` *(default)* | `id`, `url`, `text`, `priority` per item |
| Requirements | `full` | structured + a category-level `context` field carrying the page's intro paragraph(s) |
| Blueprints | `full` *(default)* | `title`, `summary`, `topics`, all sections with content |
| Blueprints | `summary` | `title`, `summary`, `topics` only — no section content |

### Output metadata

The generated YAML always carries top-level `generated` and `source` fields. If the config defines `description` and/or `url`, those are copied through as well. A `sources_meta` block records per-source indexing metadata:

```yaml
generated: '2026-04-09T12:00:00Z'
source: harvested
description: ACME Corp Application Security Requirements
url: https://security.example.com
sources_meta:
  - id: internal-requirements
    type: requirement
    title: "Internal Security Requirements"
    reference_url: "https://security.example.com/requirements"
    crawl_url: "https://security.example.com/requirements"
    indexed_at: '2026-04-09T12:00:00Z'
    items_count: 42
    mode: structured
```

Each category and blueprint entry includes a `source_id` field that traces it back to its source.

### Backwards compatibility

Legacy configs using `crawl.requirements_base_url`, `crawl.blueprints_base_url`, and `*_overrides` are still supported. The harvester converts them to the `sources` format internally.

### Requirement-ID shape

The harvester accepts any identifier of the form `PREFIX-PART[-PART…]` where `PREFIX` is two or more uppercase characters starting with a letter. Examples: `SEC-AUTH-01`, `SCG-HARDENXML`, `OWASP-A01`, `REQ-123`, `ISO27K-A12`. No specific prefix is hardcoded — whatever shape your organisation uses will be recognised, provided it follows this generic pattern. Unicode non-breaking hyphens (`U+2011`) and the occasional underscore variant (`SCG_HARDENXML`) are normalised to the canonical ASCII-hyphen form.

### HTML parser strategies

Requirement pages are tried in order, with the first match per ID winning:

0. **Antora / AsciiDoc sectionbody** — `<div class="sectionbody">` containing `<span class="badge">PREFIX-…</span>`, with the preceding `<h2>` carrying a `must-label` / `should-label` / `may-label` span for priority
1. **Anchor IDs** — elements whose `id` is a lowercase ID with a trailing numeric suffix, e.g. `id="sec-auth-01"`
2. **Definition lists** — `<dt>[PREFIX-XX-N]</dt><dd>text</dd>`
3. **Free-text references** — any element whose text contains `[PREFIX-XX-N]`
4. **Table rows** — `<td>[PREFIX-XX-N]</td><td>text</td>`

Blueprint indexing extracts `<h2>`/`<h3>` sections with their content, derives `topics` slugs from headings, collapses consecutive duplicate sentences (a common Antora render artefact), and caps each section's content at `section_max_chars` to keep the YAML context-window friendly.

### Category grouping

When a page yields multiple requirements, the harvester groups them:

- IDs of the form `PREFIX-CATEGORY-NUMBER` are grouped under `PREFIX-CATEGORY` (e.g. `SEC-AUTH-01` and `SEC-AUTH-02` share the `SEC-AUTH` category).
- IDs without a trailing number fall back to a category derived from the page's URL slug (uppercased, hyphens to underscores).

Pages that yield exactly one requirement use that requirement's ID as their category — atomic-requirement pages (common in lifecycle or governance catalogs) therefore appear as one-entry categories named after the ID itself.

### Cross-references between requirements and blueprints

After all sources have been harvested, the script scans every blueprint section's content for any uppercase requirement-ID reference that matches the generic shape above. When a reference resolves against the harvested requirements, the blueprint section gains a `references:` list with `{id, url}` entries pointing at the corresponding requirement anchors. Unresolvable IDs (e.g. from other catalogs not crawled in this run) are silently skipped.

```yaml
blueprints:
  - id: BP-API
    sections:
      - title: Authentication
        url: https://.../blueprints/api#authentication
        content: "... implementers MUST follow SEC-API-AUTH and SEC-TLS ..."
        references:
          - id: SEC-API-AUTH
            url: https://.../scg/api-security#sec-api-auth
          - id: SEC-TLS
            url: https://.../scg/api-security#sec-tls
```

## Scheduling

The harvester is a one-shot script — it does not run automatically. Schedule it to keep `appsec-requirements-fallback.yaml` in sync with your requirements source.

The simplest production setup is **Option B or C** below: a scheduled CI job runs the harvester, commits or publishes the YAML, and all plugin runs pick up the latest version without any manual step.

### Option A — cron (local machine or server)

Use a cron entry on a developer machine or a long-running build host. The snippet below runs the harvester nightly and appends to a rotating log.

```bash
# Edit crontab
crontab -e

# Run every day at 02:00, write a log
0 2 * * * cd /path/to/appsec-advisor && \
  HARVEST_AUTH_TOKEN=<token> \
  python3 scripts/harvest-requirements.py >> /var/log/harvest-requirements.log 2>&1
```

After each run, commit and push the updated YAML so the rest of the team picks it up:

```bash
# Wrapper script: harvest-and-commit.sh
#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
python3 scripts/harvest-requirements.py
git diff --quiet data/appsec-requirements-fallback.yaml \
  || git commit -am "chore: update appsec requirements fallback [harvester]" && git push
```

Replace the direct cron entry with the wrapper script so commits happen automatically:

```bash
# Schedule the wrapper instead
0 2 * * * /path/to/appsec-advisor/harvest-and-commit.sh >> /var/log/harvest-requirements.log 2>&1
```

### Option B — CI/CD pipeline (recommended)

Run the harvester as a scheduled pipeline job so the updated YAML is automatically committed back to the repository.

**GitLab CI** (`.gitlab-ci.yml`):

```yaml
harvest-requirements:
  stage: maintenance
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"   # triggered by a scheduled pipeline
  script:
    - pip install -r scripts/requirements.txt
    - python3 scripts/harvest-requirements.py
    - |
      if ! git diff --quiet data/appsec-requirements-fallback.yaml; then
        git config user.email "ci@example.com"
        git config user.name "CI"
        git commit -am "chore: update appsec requirements fallback [harvester]"
        git push "https://oauth2:${CI_JOB_TOKEN}@${CI_SERVER_HOST}/${CI_PROJECT_PATH}.git" HEAD:main
      fi
  variables:
    HARVEST_AUTH_TOKEN: $HARVEST_AUTH_TOKEN   # set as a masked CI variable
```

Configure the schedule under **CI/CD > Schedules** in GitLab (e.g. daily at 02:00).

**GitHub Actions** (`.github/workflows/harvest-requirements.yml`):

```yaml
name: Harvest Security Requirements

on:
  schedule:
    - cron: '0 2 * * *'   # daily at 02:00 UTC
  workflow_dispatch:        # allow manual trigger

permissions:
  contents: write           # needed to commit the updated YAML

jobs:
  harvest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install -r scripts/requirements.txt

      - name: Run harvester
        env:
          HARVEST_AUTH_TOKEN: ${{ secrets.HARVEST_AUTH_TOKEN }}
        run: python3 scripts/harvest-requirements.py

      - name: Commit updated YAML if changed
        run: |
          git config user.email "ci@github.com"
          git config user.name "GitHub Actions"
          if ! git diff --quiet data/appsec-requirements-fallback.yaml; then
            git add data/appsec-requirements-fallback.yaml
            git commit -m "chore: update appsec requirements fallback [harvester]"
            git push
          else
            echo "No changes — requirements are up to date."
          fi
```

Store `HARVEST_AUTH_TOKEN` as a repository secret. Add `workflow_dispatch` allows you to trigger the harvester manually from the Actions tab without waiting for the schedule.

### Option C — publish YAML, skip commits

If committing back to the plugin repo is not practical, publish the generated YAML to a static URL (GitLab raw file, S3, internal CDN) and set `requirements_yaml_url` in `config.json`. The context-resolver then fetches the latest version automatically on each threat model run — no plugin update required.

```json
{
  "requirements_source": {
    "requirements_yaml_url": "https://gitlab.example.com/security/requirements/-/raw/main/appsec-requirements.yaml"
  }
}
```

The harvester still runs on a schedule and pushes the YAML to that URL; the plugin reads it on demand.

## Recommended workflow

1. **Configure sources** — copy `scripts/harvest-config.example.json` to `scripts/harvest-config.json` and add your requirement and blueprint URLs.
2. **Test locally** — run `python3 scripts/harvest-requirements.py --dry-run --verbose` to verify the harvester can reach and parse your pages before committing anything.
3. **Schedule in CI** — add the GitHub Actions or GitLab CI job from Option B above. The job runs daily (or on demand) and commits the updated YAML automatically.
4. **Point the plugin at the YAML** — set `requirements_yaml_url` in `skills/check-appsec-requirements/config.json` to the raw URL of the committed file, or publish it to a static URL (Option C) and use that. Once this is set, every `check-appsec-requirements` run and every `create-threat-model --requirements` run fetches the latest catalog automatically.

```json
// skills/check-appsec-requirements/config.json
{
  "requirements_source": {
    "enabled": true,
    "requirements_yaml_url": "https://raw.githubusercontent.com/your-org/appsec-advisor/main/data/appsec-requirements-fallback.yaml"
  }
}
```

Set `"enabled": true` to include requirements compliance automatically in every threat model run (Phase 8b), without passing `--requirements` each time.
