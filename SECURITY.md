# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.10.x-beta | Yes |
| < 0.10 | No — please upgrade |

The `-beta` suffix means the feature set is stable but has not been battle-tested across a wide range of repositories. Breaking changes to flags, intermediate-file schemas, or YAML output formats may still land in minor-version bumps (`0.10 → 0.11`); see release notes before upgrading.

## Reporting a vulnerability

Do **not** report security vulnerabilities through public GitHub issues.

Instead, open a [GitHub Security Advisory](../../security/advisories/new) in this repository. You will receive a response within 5 business days. If the issue is confirmed, a patch will be released as soon as possible.

When reporting, please include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce (if applicable).
- Any suggested mitigations you have identified.

## Data sent to Anthropic API

This section exists specifically for AppSec reviewers evaluating whether the plugin can run on a given codebase. Read it before approving a run on sensitive repositories.

### What leaves the machine

Every phase of the assessment dispatches one or more prompts to the Anthropic API. The prompts are assembled locally by Claude Code and consist of:

- **Agent system prompt** — plugin-defined instructions from `agents/*.md`. No repository content.
- **Tool-call inputs** — file paths, glob patterns, grep patterns, `Bash` commands. The file paths reference your repository; the patterns are derived from recon heuristics.
- **Tool-call outputs** — the raw contents Claude read back. This is where repository source code enters the conversation. STRIDE analysis requires reading the files under analysis, so source code and configuration files belonging to the scanned components **are** transmitted to the API.
- **Prior tool results within the same session** — once a file has been read, it remains in the conversation context until the phase ends. Phase 9's parallel STRIDE analysers each have their own session, so context between components does not cross over.

The plugin does not upload the repository wholesale. It reads files on demand, scoped to what each phase needs. Typical transmission profile on OWASP Juice Shop (thorough, 8 components): a few hundred file reads, dominated by source files under the components being analysed, plus `package.json`/manifests and configuration files.

### What stays local

All intermediate artefacts are written to `$OUTPUT_DIR` (default: `docs/security/`):

| File | Content | Sensitivity |
|------|---------|-------------|
| `threat-model.md` / `.yaml` / `.sarif.json` | The report itself | Describes vulnerabilities in your code — treat as sensitive |
| `.stride-<component-id>.json` | Per-component STRIDE findings | Same sensitivity as the report |
| `.threats-merged.json` | Canonical merged threat list | Same |
| `.recon-summary.md` | Tech stack, security-pattern hits, detected secrets | **May reference hardcoded secrets** when recon flags them |
| `.threat-modeling-context.md` | External context + business context | Whatever your REST endpoint returned |
| `.dep-scan.json` | SCA advisories | Public CVE data + your dependency list |
| `.agent-run.log` | Structured event log (AGENT_START/END, PHASE_START/END, FILE_WRITE) | File paths, tool-call counts, durations |
| `.hook-events.log` | Token / cost accounting per tool call | Token counts, estimated cost; no repository content |

The two log files carry no source code and no prompt content, but they do carry file paths (e.g. `FILE_WRITE /path/to/secrets.ts`). Treat them as sensitive alongside the reports themselves. Logs rotate at 5 MB (`logging.max_log_bytes` in `config.json`).

When the recon scanner detects hardcoded secrets (Category 12 of 26), the match context — including a small snippet around the match — is written into `.recon-summary.md` so the finding can be audited. This file should be treated as secret-handling scope.

### What is logged by Anthropic

Anthropic's API logs the prompts and responses per their [privacy policy](https://www.anthropic.com/privacy). API-key and Claude Pro/Team/Enterprise subscriptions have different data-retention terms; check with your Anthropic account representative for your specific contract.

Prompt caching is used aggressively (see `pricing.cache_*` in `config.json`). Cached segments reside on Anthropic's infrastructure for the cache TTL.

### Air-gapped environments

The plugin **cannot** run fully air-gapped. Claude Code requires a connection to `api.anthropic.com`. There is no offline mode. If your environment prohibits outbound connections to `api.anthropic.com`, the plugin is not usable in that environment.

### Plugin code fetching

The plugin itself runs locally from `--plugin-dir`. Clone it from an internal mirror if direct GitHub access is restricted. It does not fetch code or model weights at runtime.

### Recommended pre-run checklist

Before running the plugin on a codebase that contains production secrets, PII, or regulated data:

1. Confirm your contract with Anthropic covers the data classification of the source files that will be read.
2. Decide where `docs/security/` lives. Committing `.yaml` / `.sarif.json` to the repository is the common pattern; the intermediate files (`.stride-*.json`, `.recon-summary.md`) are `.gitignore`d by default but contain the same content.
3. Review `hooks/steering_keywords.json` if the security coach is enabled — the coach injects prompts on every user-submitted prompt, not just plugin runs.
4. Rotate any secret the recon scanner might plausibly find before running; assume recon findings will be persisted in `.recon-summary.md`.

## Scope

This plugin generates threat model documents by reading local repository source code. It does not transmit source code to any external service other than the Anthropic API.

The mock context server (`scripts/mock-context-server.py`) ships with illustrative data. Do not store real credentials, findings, or sensitive architecture data in it.
