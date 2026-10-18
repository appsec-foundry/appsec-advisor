# Security policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.6.x-beta | Yes |
| < 0.6 | No; upgrade required |

During the beta, flags, intermediate-file schemas, and YAML output formats may change in minor-version bumps (`0.6 → 0.7`). Check the release notes before upgrading.

## Reporting a vulnerability

Do **not** report security vulnerabilities through public GitHub issues.

Open a [GitHub Security Advisory](../../security/advisories/new) in this repository instead. You will receive a response within 5 business days. If the issue is confirmed, a patch will be released as soon as possible.

Please include:

- a description of the vulnerability and its impact;
- steps to reproduce, if applicable;
- any mitigations you have identified.

## Data sent to Anthropic API

AppSec reviewers should read this section before approving a run on a sensitive repository.

### What leaves the machine

Each step of the assessment sends one bounded request to the Anthropic API. The assessment models have no file, shell, or network tools; the controller decides what each request contains:

- **Step instructions** from `agents/*.md`. No repository content.
- **Source excerpts**: line ranges of repository files that the step needs, served by the controller from the selected revision. A model may ask for further excerpts within a fixed per-step limit. This is how source code reaches the API: source code and configuration of the analyzed components **are** sent. Secrets matched by the plugin's secret patterns are masked in every excerpt.
- **Earlier step results** the task builds on, such as the component list or the findings to merge. Component analyses run in separate requests and do not see each other's findings.
- **Business context** you supply interactively, with `--context`, or in `docs/security/business-context.md`.

The plugin does not upload the repository as a whole. The optional repository exploration of `/appsec-advisor:analyze-threats` is the only analysis that gives a model file tools; they are read-only and confined to a copy with secrets masked.

The Claude Code session that runs the plugin also sends its own conversation to the API, as any Claude Code session does: your messages, the plugin's progress output, and whatever else you ask it to read in that session.

### What stays local

Results and intermediate files are written to the assessment directory. By default it lies outside the repository, under your user data directory; see [where results are stored](docs/security-assessment.md#where-results-are-stored).

| File | Content | Sensitivity |
|------|---------|-------------|
| `security-assessment.md` / `.yaml` / `.sarif.json` | The report | Describes vulnerabilities in your code; treat as sensitive |
| `.assessment-work/` and `.assessment-state.json` | Accepted step results (components, data flows, findings per component) and run state | Same as the report |
| `.threats-merged.json` | Merged finding list | Same as the report |
| `.agent-run.log` | Event log (agent, phase, and file-write events) | File paths, tool-call counts, durations |
| `.hook-events.log` | Token and cost accounting per tool call | Token counts and estimated cost; no repository content |

The two log files contain no source code or prompts, but they do contain file paths (for example `FILE_WRITE /path/to/secrets.ts`). Treat them like the reports. Logs rotate at 5 MB (`logging.max_log_bytes` in `config.json`).

A finding about a hardcoded secret names its file and line. Masking only covers secrets that match the plugin's patterns, so a secret in an unusual format can still appear in an excerpt sent to the API or in a quoted line of a finding. Treat the report and its step results as secret-handling scope.

### What Anthropic logs

Anthropic logs prompts and responses according to its [privacy policy](https://www.anthropic.com/privacy). API-key and Claude Pro, Team, or Enterprise subscriptions have different retention terms; check your contract.

The plugin uses prompt caching (see `pricing.cache_*` in `config.json`). Cached segments stay on Anthropic's infrastructure for the cache lifetime.

### Air-gapped environments

Claude Code needs a connection to `api.anthropic.com`. The assessment has no offline mode and cannot run where this connection is blocked.

### Plugin code

The plugin runs locally, installed from the marketplace or from a checkout with `--plugin-dir`. If GitHub access is restricted, install it from an internal mirror. It fetches code only when you ask for it, for example with a Git URL as `--repo` or with `install-baseline`. It never downloads model weights.

### Before running on sensitive code

Before you assess a codebase with production secrets, personal data, or regulated data:

1. Confirm that your Anthropic contract covers the data classification of the source files that will be read.
2. Decide who may read the assessment directory. It is private to your user by default; sharing a result takes an explicit export.
3. If the Security Coach is enabled, review `hooks/steering_keywords.json`. It adds guidance to matching prompts throughout the session, also outside plugin runs.
4. Rotate any hardcoded secret in the repository before the run, and assume that one the masking patterns miss can reach the API and the results.

<a id="known-issues--untrusted-repositories"></a>
## Known issues: untrusted repositories

Scanned repositories are **untrusted by default**. Headless runs apply the untrusted preflight before Claude starts; `--trust-mode trusted` is an explicit opt-in for repositories whose committed agent configuration has been reviewed. This reduces the known exposure but is not a complete sandbox against actively malicious content.

| # | Issue | Details |
|---|-------|---------|
| 1 | Prompt injection via repository content | Source excerpts enter the model context, and instructions planted there can steer an analysis step, for example to hide or invent a finding. The assessment models have no tools, and the controller validates every result and excerpt request, so such an injection does not directly execute commands. The hosting Claude Code session is different: the recommended permission rule is `Bash(*)`, so repository content you ask that session to read can lead to command execution on the reviewer's machine. |
| 2 | SSRF via `docs/related-repos.yaml` | *(Hardened 2026-05.)* `scripts/contexts/load_related_repos.py` checks target URLs with `scripts/shared/_url_guard.py`. It rejects private, loopback, link-local (including `169.254.169.254`), multicast, and reserved addresses, and strips `Authorization` and `Cookie` headers on cross-host redirects. For stricter control, set `APPSEC_URL_ALLOWLIST=host1,host2` and pass `--strict-urls` (on by default in untrusted mode). |
| 3 | File reads through symlinks | *(Hardened 2026-05.)* The recon walker (`scripts/analyzers/recon_patterns.py`) does not follow symlinks, and `scripts/shared/_path_guard.py` drops symlinks that point outside the repository. Reads through Claude Code's Read tool are *not* sandboxed. `scripts/validators/preflight_untrusted.py` lists escaping symlinks before the run and refuses to continue in untrusted mode. |
| 4 | Repository-owned Claude Code hooks | An interactive Claude Code session may load `.claude/settings.json`, `.claude/hooks/`, or `.vscode/tasks.json` from its working directory **before** the plugin runs. Run `scripts/validators/preflight_untrusted.py --strict --strict-urls` before starting an interactive session in a third-party repository, or use the headless runner, which runs this check first. The recon scanner also reports these files (Cat 28). |
| 5 | Argument injection in subprocess calls | File names and refs from the repository are passed to `git` (and, if the GitHub CLI is available, to an optional `gh pr list`) without consistent `--` separators or strict validation. *(Reduced 2026-05: package-manager and CVE-database tools are no longer run.)* |
| 6 | ~~Third-party scanner RCEs~~ | **Resolved 2026-05.** The plugin no longer runs external audit tools such as `npm audit`, `pip-audit`, or `govulncheck` on repository manifests. Supply-chain checks (`scripts/model/emit_sca_practice.py`, `emit_known_bad_libs.py`, `emit_dep_update_activity.py`) only read files and `git log`. |

### Recommended mitigations for untrusted repositories

1. Run the assessment in a disposable container or VM, not on your main workstation.
2. During the scan, block outbound traffic except to `api.anthropic.com` and any hosts in `APPSEC_URL_ALLOWLIST`.
3. Before starting an interactive Claude session in the target repository, run `python3 scripts/validators/preflight_untrusted.py --repo-root <path> --strict --strict-urls`. It fails on repository-owned Claude or IDE hooks, symlinks pointing outside the repository, and unchecked URLs in `docs/related-repos.yaml`. The headless runner does this automatically.
4. If the repository is not fully trusted, remove `docs/related-repos.yaml`, or set `APPSEC_URL_ALLOWLIST` and use `--strict-urls`. There is no flag that disables related repositories.
5. Assume the reviewer's environment may be compromised after the scan: no plain-text credentials in environment variables, no SSH agent forwarding, no cached cloud CLI tokens.

### Trust mode

`scripts/run-headless.sh` uses `--trust-mode untrusted` by default. This mode:

- runs `scripts/validators/preflight_untrusted.py --strict --strict-urls` first and stops before any model call if it finds anything;
- sets `APPSEC_RELATED_REPOS_STRICT_URLS=1`, so related repositories require `APPSEC_URL_ALLOWLIST`;
- sets `APPSEC_LOG_REDACT_PATHS=1`, so `.agent-run.log` records `<redacted:<basename>:<sha8>>` instead of absolute paths;
- refuses to run when it finds an escaping symlink, a repository-owned `.claude/` file, or an unchecked related-repository URL.

Not yet covered (open a GitHub issue if you need one of these):

- mandatory isolation in a container (the script relies on the caller for isolation);
- a narrower shell permission than `Bash(*)` for prompt-free interactive runs;
- size or extension limits on individual manifests beyond `scripts/analyzers/scan_excludes.py`.

## Scope

The plugin produces security assessments by reading local repository source code. It sends source code to no external service other than the Anthropic API.

The mock server (`scripts/mock-server.py`) ships with illustrative data. Do not store real credentials, findings, or sensitive architecture data in it.
