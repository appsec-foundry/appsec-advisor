# Flag Reference

> Back to [README](../README.md)

Complete reference for all flags available in interactive mode and via the headless script (`scripts/run-headless.sh`).

## Threat Model Flags

These flags work in both interactive (`/appsec-plugin:create-threat-model`) and headless mode.

| Flag | Description |
|------|-------------|
| `--repo <path>` | Path to the repository to analyze (default: current working directory) |
| `--output <path>` | Output directory for all generated files (default: `<repo>/docs/security`). Created automatically in headless mode. |
| `--yaml` | Also write `threat-model.yaml` (machine-readable export) |
| `--sarif` | Also write `threat-model.sarif.json` (SARIF v2.1.0 for CI/CD) |
| `--requirements` | Include requirements compliance check (Phase 8b) |
| `--no-requirements` | Skip requirements check even when enabled in config |
| `--with-sca` | Run SCA dependency vulnerability scan (`npm audit`, `pip-audit`, etc.) |
| `--stride-model <model>` | Override STRIDE analyzer model (e.g. `opus` for higher quality, ~5x cost) |
| `--assessment-depth <level>` | `quick` (~15 min, 3 components), `standard` (default, ~25 min, 5 components), or `thorough` (~40 min, 8 components) |
| `--dry-run` | Preview what would be analyzed without running the full pipeline |
| `--incremental` | Force delta analysis based on git diff (default when prior output exists) |
| `--full` | Force full scan even when a prior threat model exists |
| `--resume` | Continue from the last checkpoint after a failed assessment |

## Requirements Check Flags

These flags apply to the standalone requirements skill (`/appsec-plugin:check-appsec-requirements`) or headless `--check-requirements`.

| Flag | Description |
|------|-------------|
| `--check-requirements` | *(headless only)* Run the `check-appsec-requirements` skill instead of threat model |
| `--category <filter>` | *(headless only)* Filter to a requirement category (e.g. `SEC-AUTH`) |
| `--save-report` | *(headless only)* Save report as Markdown + JSON to the output directory |

In interactive mode, pass the filter as an argument: `/appsec-plugin:check-appsec-requirements AUTH`

## Headless Execution Control

These flags are only available in headless mode (`scripts/run-headless.sh`).

| Flag | Description |
|------|-------------|
| `--max-budget <usd>` | Cap API spend at this dollar amount. **Recommended for API billing mode** — the script warns if unset. When budget is exhausted, Claude stops gracefully; use `--resume` to continue. |
| `--model <model>` | Override the Claude model. In API mode, defaults to `claude-sonnet-4-5` if not specified. In subscription mode, uses the CLI default. |
| `--requirements [<url>]` | *(headless extended form)* Without a URL, uses the configured `requirements_yaml_url` with cache fallback. With a URL, fetches from that URL directly (no cache fallback — aborts if unreachable). |
| `--no-requirements` | Skip requirements check even when enabled in config. Overrides `--requirements`. Resolution order: `--no-requirements` > `--requirements` > config `enabled` value. |
| `--json` | Return structured JSON output instead of text |
| `--verbose` | Stream real-time progress to stderr. Tails `$OUTPUT_DIR/.hook-events.log` and `$OUTPUT_DIR/.agent-run.log` in background, and sets `APPSEC_VERBOSE=1` so hook events are mirrored to stderr with `[appsec]` prefix. |

## Deprecated Flags

These flags still work but print a deprecation warning:

| Deprecated | Use instead |
|-----------|-------------|
| `--with-requirements` | `--requirements` |
| `--ignore-requirements` | `--no-requirements` |
| `--requirements-url <url>` | `--requirements <url>` |
