# Requirements Harvester

`scripts/harvest-requirements.py` crawls your internal requirements and blueprint pages and regenerates `plugin/data/appsec-requirements-fallback.yaml`. Run it whenever your requirements change, then commit the updated YAML.

## Usage

```bash
# Install dependencies (once)
pip install -r scripts/requirements.txt

# Crawl and regenerate
python scripts/harvest-requirements.py

# With authentication token for internal pages
HARVEST_AUTH_TOKEN=<token> python scripts/harvest-requirements.py

# Preview without writing
python scripts/harvest-requirements.py --dry-run --verbose

# Blueprints only
python scripts/harvest-requirements.py --blueprint-only
```

## Configuration

Configure sources in `scripts/harvest-config.json`. Each source defines a crawl target with its type, indexing mode, and display metadata:

```json
{
  "request": {
    "timeout_seconds": 15,
    "auth_header_env": "HARVEST_AUTH_TOKEN",
    "verify_ssl": false
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

### Source fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique identifier for the source |
| `type` | Yes | `requirement` or `blueprint` |
| `crawl_url` | Yes | URL to crawl and index |
| `title` | Yes | Display title shown to users |
| `reference_url` | No | User-facing reference URL (not used for indexing) |
| `mode` | No | Indexing mode (overrides default, see table below) |
| `max_pages` | No | Max pages to crawl (overrides `defaults.max_pages`) |
| `section_max_chars` | No | Blueprints only: max chars per section (overrides default) |

### Indexing modes

| Type | Mode | What is stored |
|------|------|---------------|
| Requirements | `structured` *(default)* | `id`, `url`, `text`, `priority` per item |
| Requirements | `full` | structured + page intro/context paragraph(s) |
| Blueprints | `full` *(default)* | `title`, `summary`, `topics`, all sections with content |
| Blueprints | `summary` | `title`, `summary`, `topics` only — no section content |

### Output metadata

The generated YAML includes a `sources_meta` section that records per-source indexing metadata:

```yaml
generated: '2026-04-09T12:00:00Z'
source: harvested
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

### HTML parser strategies

Tried in order per page:

1. Elements with `id="sec-xx-n"` anchor attributes
2. Definition lists `<dt>[SEC-XX-N]</dt><dd>text</dd>`
3. Any element whose text starts with `[SEC-XX-N]`
4. Table rows `<td>[SEC-XX-N]</td><td>text</td>`

Blueprint indexing extracts `<h2>`/`<h3>` sections with their content, derives `topics` slugs from headings, and caps each section's content at `section_max_chars` to keep the YAML context-window friendly.

## Scheduling

The harvester is a one-shot script — it does not run automatically. Schedule it to keep `appsec-requirements-fallback.yaml` in sync with your requirements source.

### Option A — cron (local machine or server)

```bash
# Edit crontab
crontab -e

# Run every day at 02:00, write a log
0 2 * * * cd /path/to/appsec-plugin && \
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
git diff --quiet plugin/data/appsec-requirements-fallback.yaml \
  || git commit -am "chore: update appsec requirements fallback [harvester]" && git push
```

```bash
# Schedule the wrapper instead
0 2 * * * /path/to/appsec-plugin/harvest-and-commit.sh >> /var/log/harvest-requirements.log 2>&1
```

### Option B — CI/CD pipeline (recommended)

Run the harvester as a scheduled pipeline job so the updated YAML is automatically committed back to the repository:

```yaml
# GitLab CI example (.gitlab-ci.yml)
harvest-requirements:
  stage: maintenance
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"   # triggered by a scheduled pipeline
  script:
    - pip install -r scripts/requirements.txt
    - python3 scripts/harvest-requirements.py
    - |
      if ! git diff --quiet plugin/data/appsec-requirements-fallback.yaml; then
        git config user.email "ci@example.com"
        git config user.name "CI"
        git commit -am "chore: update appsec requirements fallback [harvester]"
        git push "https://oauth2:${CI_JOB_TOKEN}@${CI_SERVER_HOST}/${CI_PROJECT_PATH}.git" HEAD:main
      fi
  variables:
    HARVEST_AUTH_TOKEN: $HARVEST_AUTH_TOKEN   # set as a masked CI variable
```

Configure the schedule under **CI/CD > Schedules** in GitLab (e.g. daily at 02:00).

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

1. Configure `harvest-config.json` with your sources (one or more requirement/blueprint URLs)
2. Schedule the harvester (CI pipeline, cron, or wrapper script)
3. Harvester commits updated `appsec-requirements-fallback.yaml` automatically
4. Optionally publish the YAML to a static URL and set `requirements_yaml_url` in `config.json` — teams always get the latest without pulling the plugin repo
