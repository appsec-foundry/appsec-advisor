# Requirements Harvester

`scripts/harvest-requirements.py` crawls your internal requirements and blueprint pages and regenerates `appsec-requirements-fallback.yaml`. Run it whenever your requirements change, then commit the updated YAML.

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

Configure source URLs in `scripts/harvest-config.json`:

```json
{
  "crawl": {
    "requirements_base_url": "https://security.example.com/requirements",
    "blueprints_base_url":   "https://security.example.com/blueprints",
    "max_pages": 100
  },
  "indexing": {
    "requirements": { "mode": "structured" },
    "blueprints":   { "mode": "full", "section_max_chars": 500 }
  }
}
```

### Indexing modes

| Type | Mode | What is stored |
|------|------|---------------|
| Requirements | `structured` *(default)* | `id`, `url`, `text`, `priority` per item |
| Requirements | `full` | structured + page intro/context paragraph(s) |
| Blueprints | `full` *(default)* | `title`, `summary`, `topics`, all sections with content |
| Blueprints | `summary` | `title`, `summary`, `topics` only — no section content |

The mode can be overridden per individual page via `indexing_mode` in `requirements_overrides` / `blueprints_overrides`.

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
git diff --quiet plugin/skills/check-appsec-requirements/appsec-requirements-fallback.yaml \
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
      if ! git diff --quiet plugin/skills/check-appsec-requirements/appsec-requirements-fallback.yaml; then
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

1. Configure `harvest-config.json` with your internal URLs
2. Schedule the harvester (CI pipeline, cron, or wrapper script)
3. Harvester commits updated `appsec-requirements-fallback.yaml` automatically
4. Optionally publish the YAML to a static URL and set `requirements_yaml_url` in `config.json` — teams always get the latest without pulling the plugin repo
