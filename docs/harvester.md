# Bringing your AppSec requirements into the plugin

Most organisations already have a security-requirements catalog somewhere — a Confluence space, an Antora site, an ISO 27001 spreadsheet that got exported to HTML. The plugin can grade a repository against that catalog, but it needs the requirements as one structured YAML file first. This doc walks through how to get from "we have requirements on some wiki" to "every threat-model run checks compliance automatically".

## The flow

```mermaid
flowchart LR
    A["Your requirements pages<br/>(Confluence, Antora, wiki…)"] --> B["harvest-requirements.py<br/><i>crawls + parses</i>"]
    B --> C[("appsec-requirements.yaml")]
    C --> D{"Where does the plugin<br/>read it from?"}
    D -->|"Committed in the repo"| E["raw.githubusercontent.com/…"]
    D -->|"Hosted separately"| F["S3 / GitLab raw / CDN"]
    D -->|"Local test loop"| G["mock-server.py on<br/>127.0.0.1:4444"]
    E --> H["check-appsec-requirements<br/>create-threat-model --requirements"]
    F --> H
    G --> H
```

Four moving parts, in order of how you'll touch them:

- **The harvester** — `scripts/harvest-requirements.py`, a one-shot Python script that crawls your pages and writes `appsec-requirements.yaml`.
- **The YAML file** — the canonical format the plugin reads. Ships with a 53-requirement example (`data/appsec-requirements-fallback.yaml`) you can use as a template or starting point.
- **A way to expose the YAML** — commit it to the plugin repo, publish it to a static URL, or serve it locally via the mock server while you iterate.
- **Plugin config** — `requirements_yaml_url` in `skills/check-appsec-requirements/config.json`; once set, every `create-threat-model --requirements` and every `/appsec-advisor:check-appsec-requirements` run picks up the catalog without further flags.

## Three ways to get started

Pick whichever matches how much you want to commit today. Each one ends with a working end-to-end flow; later you can move up the ladder.

### 1. Try the full loop locally in 5 minutes

You don't need a real requirements catalog, and you don't need to run the harvester. The repo ships with an example YAML and a mock HTTP server. This verifies that your plugin install, config, and the audit skill all talk to each other before you invest anything.

```bash
# Serve the bundled example requirements YAML on 127.0.0.1:4444
python3 scripts/mock-server.py

# In a second shell: point the plugin at the mock and run the auditor
/appsec-advisor:check-appsec-requirements --requirements http://127.0.0.1:4444/requirements.yaml
```

What you should see: the skill fetches the YAML, grades the current repo against each requirement, and prints a PASS / PARTIAL / FAIL table with file-and-line evidence. If that works, the integration is wired up — everything below is just "swap the URL for something real".

The mock also exposes `POST /` for the optional `external_context.rest_url` endpoint (business context) — useful for testing the second Phase-1 integration at the same time. See [`docs/configuration.md`](configuration.md) for that one.

### 2. Adapt the fallback YAML

If you don't have live pages to crawl yet, start from `data/appsec-requirements-fallback.yaml`. It contains 53 baseline requirements across 10 categories (auth, input handling, crypto, secrets, frontend, IaC, LLM, …) that roughly match OWASP ASVS. Edit the IDs and text to your organisation's vocabulary, commit, and point the plugin at the raw URL:

```json
// skills/check-appsec-requirements/config.json
{
  "requirements_source": {
    "enabled": true,
    "requirements_yaml_url": "https://raw.githubusercontent.com/your-org/appsec-advisor/main/data/appsec-requirements-fallback.yaml"
  }
}
```

No harvester involved. This is the lightest path and often enough for a small team. Come back for the harvester when your requirements start drifting and manual edits turn into a chore.

### 3. Harvest from a live catalog

The full path: point the harvester at your real requirements pages, let it generate the YAML, schedule it on CI so the YAML stays fresh. This is the right answer once your catalog updates more than a couple of times a year.

```bash
# Copy the template config
cp scripts/harvest-config.example.json scripts/harvest-config.json
# Edit it — at minimum, set the URLs of your requirements & blueprint pages
$EDITOR scripts/harvest-config.json

# Install deps once
pip install -r scripts/requirements.txt

# Dry-run first to verify reachability and parsing
python3 scripts/harvest-requirements.py --dry-run --verbose

# Real run
HARVEST_AUTH_TOKEN=<token> python3 scripts/harvest-requirements.py
```

The generated YAML lands at the path in `output` (defaults to `data/appsec-requirements-fallback.yaml`). You can inspect it directly before wiring it up — it's a readable YAML with one section per category, one entry per requirement, plus a `sources_meta` block so you can trace each entry back to the page it came from.

## The harvester, in one config

A single JSON file drives the crawler. This is the minimum useful shape; everything else has sensible defaults.

```jsonc
{
  "description": "ACME Corp AppSec requirements",
  "url": "https://security.example.com",
  "output": "../data/appsec-requirements-fallback.yaml",

  // HTTP session — timeout, TLS, auth. Safe to omit for public pages.
  "request": {
    "timeout_seconds": 15,
    "auth_header_env": "HARVEST_AUTH_TOKEN",
    "verify_ssl": true
  },

  // The list of pages to crawl. Two types: "requirement" (extract IDs)
  // and "blueprint" (extract section content + cross-reference to IDs).
  "sources": [
    {
      "id": "internal-requirements",
      "type": "requirement",
      "mode": "structured",                       // or "full" (keeps page intro)
      "title": "Internal Security Requirements",
      "crawl_url": "https://security.example.com/requirements"
    },
    {
      "id": "api-blueprints",
      "type": "blueprint",
      "mode": "full",                             // or "summary" (titles only)
      "title": "API Security Blueprints",
      "crawl_url": "https://security.example.com/blueprints/api"
    }
  ]
}
```

The harvester recognises requirement IDs of the shape `PREFIX-PART[-PART…]` — `SEC-AUTH-01`, `SCG-HARDENXML`, `OWASP-A01`, `ISO27K-A12`. No prefix is hardcoded; whatever shape your org uses will be picked up. It tries five HTML-parser strategies per page (Antora sectionbody, anchor IDs, definition lists, free-text references, table rows) and keeps the first match per ID.

Blueprint sections get an automatic cross-reference pass: if a blueprint mentions `SEC-API-AUTH` in its prose and that ID exists in the harvested requirements, a `references:` list is attached so the audit can navigate from blueprint to the requirement it depends on.

### Useful flags

| Flag | When you'd use it |
|---|---|
| `--dry-run` `--verbose` | First run against a new source — see what gets parsed without writing anything |
| `--req-only` / `--blueprint-only` | Debug one source type at a time |
| `--config PATH` | Multiple environments (e.g. staging vs. prod requirements) |
| `--output PATH` | Override the config's `output`; useful in CI |
| `--token TOKEN` | Pass the bearer token on the command line instead of via env var |

Full field reference for `harvest-config.json` is in `scripts/harvest-config.example.json` — the template is annotated and shorter than a table would be.

## Keeping the YAML fresh: scheduling

The harvester is a one-shot script; something else has to run it on a schedule. Three common setups, from simplest to most production-ready:

**Local cron.** Fine for a solo user or a shared build host:

```bash
# crontab -e — run nightly, log to file, commit if anything changed
0 2 * * * cd /path/to/appsec-advisor && \
  HARVEST_AUTH_TOKEN=<token> python3 scripts/harvest-requirements.py \
  && git diff --quiet data/appsec-requirements-fallback.yaml \
  || (git commit -am "chore: refresh appsec requirements [harvester]" && git push) \
  >> /var/log/harvest-requirements.log 2>&1
```

**CI-scheduled commit.** The right answer for a team — GitHub Actions example; the GitLab equivalent is near-identical:

```yaml
# .github/workflows/harvest-requirements.yml
name: Harvest Security Requirements
on:
  schedule: [{ cron: '0 2 * * *' }]   # nightly at 02:00 UTC
  workflow_dispatch:                  # manual trigger too

permissions:
  contents: write

jobs:
  harvest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }
      - run: pip install -r scripts/requirements.txt
      - env: { HARVEST_AUTH_TOKEN: "${{ secrets.HARVEST_AUTH_TOKEN }}" }
        run: python3 scripts/harvest-requirements.py
      - name: Commit if changed
        run: |
          if ! git diff --quiet data/appsec-requirements-fallback.yaml; then
            git config user.email ci@github.com
            git config user.name "GitHub Actions"
            git commit -am "chore: refresh appsec requirements [harvester]"
            git push
          fi
```

**Publish to a separate URL.** When you can't commit back to the plugin repo (policy, visibility, frequency), have the CI job push the YAML to S3 / GitLab raw / an internal CDN, and point `requirements_yaml_url` at that URL instead. The plugin fetches on demand — no plugin update needed when requirements change.

## Wiring it up

One config field flips the requirements integration from "off" to "on by default". After this, `create-threat-model` runs Phase 8b (compliance) automatically; the standalone `check-appsec-requirements` skill uses the same URL.

```json
// skills/check-appsec-requirements/config.json
{
  "requirements_source": {
    "enabled": true,
    "requirements_yaml_url": "https://raw.githubusercontent.com/your-org/appsec-advisor/main/data/appsec-requirements-fallback.yaml"
  }
}
```

The URL is cached at `$CLAUDE_PLUGIN_ROOT/.cache/requirements.yaml` — an unreachable URL falls back to the cached copy. An explicit `--requirements <url>` on the command line always wins over the config, and `--no-requirements` turns the check off for a single run.

## Troubleshooting

**Parser returns zero requirements.** Run with `--verbose` — the harvester prints every parser attempt per page. If all five strategies miss, either the ID shape doesn't match `PREFIX-PART[-PART…]` (e.g. pure numeric IDs like `REQ_001`) or the HTML is an SPA that needs JavaScript to render content (the harvester fetches static HTML only).

**Auth token works interactively but fails in CI.** `HARVEST_AUTH_TOKEN` must be set as a CI secret *and* passed through in the job's `env:` block — secrets are not auto-exposed on recent GitHub / GitLab runners.

**Mock server returns my old YAML after I ran the harvester.** The mock hardcodes `examples/appsec-requirements-example.yaml` as the `/requirements.yaml` payload. Either re-run the harvester with `--output examples/appsec-requirements-example.yaml`, or `ln -sf` the real output file to that location.

**`--requirements` on the CLI is ignored.** The resolution order is: explicit `--requirements <url>` > config `requirements_yaml_url` (when `enabled: true`) > cache. If you passed `--no-requirements` earlier, it wins regardless.
