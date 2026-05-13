# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.10.x-beta | Yes |
| < 0.10 | No — please upgrade |

The `-beta` suffix means the feature set is stable but has been validated against a limited set of repository shapes. Breaking changes to flags, intermediate-file schemas, or YAML output formats may still land in minor-version bumps (`0.10 → 0.11`); check the release notes before upgrading.

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

## Known issues — untrusted repositories

The current threat model assumes the scanned repository is **trusted** (your own code, your organisation's code, a vendor repo cleared for analysis). The plugin is **not hardened against actively malicious repository content**. Until a dedicated untrusted-repo mode lands, the following exposures are known and accepted:

| # | Issue | Vector |
|---|-------|--------|
| 1 | Prompt injection via repo content | Source files, comments, markdown read by agents flow into the LLM context. Attacker-controlled instructions there can steer the agent. Combined with the required `Bash(*)` permission this can become arbitrary command execution on the reviewer's machine. |
| 2 | SSRF via `docs/related-repos.yaml` | If the scanned repo contains this file, `scripts/load_related_repos.py` will fetch its URLs. No host allowlist, no RFC1918/metadata blackhole. Auth headers from `RELATED_REPOS_AUTH_HEADER` are sent on every fetch. |
| 3 | Symlink-driven file reads | Symlinks inside the repo (e.g. `./policy.md` → `/home/user/.ssh/id_rsa`) are followed when agents read files. Contents can land in the LLM context and in `.recon-summary.md`. |
| 4 | Repo-owned Claude Code hooks | A `.claude/settings.json` shipped inside the scanned repo is loaded by Claude Code itself, before the plugin runs. The recon-scanner flags this as Cat 28 but only after the hooks have already executed. |
| 5 | Argument injection in subprocess calls | Filenames and refs from the repo flow into `git`, `npm audit`, `pip-audit`, etc. without consistent `--` separators or strict character validation. |
| 6 | Third-party scanner RCEs | `dep_scan.py` invokes external audit tools on attacker-controlled manifests (`package.json`, `setup.py`, `go.mod`). Any RCE in those tools becomes an RCE in the plugin run. |

### Recommended mitigations until the untrusted-repo mode ships

1. Run the assessment inside an ephemeral container or VM, not on the reviewer's main workstation.
2. Block outbound network egress except `api.anthropic.com` during the scan.
3. Before scanning, reject repos that contain `.claude/settings.json`, `.claude/hooks/`, or symlinks pointing outside the repo root.
4. Pass `--related-repos disable` (or remove `docs/related-repos.yaml`) when the repo is not fully trusted.
5. Treat the reviewer's environment as compromised after a scan: no plain-text credentials in env vars, no SSH-agent forwarding, no cached cloud-CLI tokens.

### Planned: untrusted-repo mode

A future release will add a `--untrusted-repo` flag (working title) that flips these defaults:

- Mandatory worktree-into-container isolation, refuses to run otherwise.
- Pre-scan reject on repo-owned hooks, suspicious symlinks, and oversized manifests.
- Disable `load_related_repos.py` and external-context fetch by default.
- Drop the `Bash(*)` requirement in favour of a tighter command allow-list (slower runs, but no shell escape).
- SSRF-hardened HTTP client (host allowlist, RFC1918 + metadata blackhole, disabled redirects).
- Symlink-aware file reads (no traversal outside repo root).

Tracking: open a GitHub issue if you need this sooner than the current roadmap allows — it helps prioritise.

## Scope

This plugin generates threat model documents by reading local repository source code. It does not transmit source code to any external service other than the Anthropic API.

The mock server (`scripts/mock-server.py`) ships with illustrative data. Do not store real credentials, findings, or sensitive architecture data in it.
