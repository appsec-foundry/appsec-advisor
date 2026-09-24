---
name: help
description: >-
  Show what this plugin can do and which entry point fits the task — the
  starting point when someone does not know the commands yet ("what can
  appsec-advisor do?", "which commands are there?", "how do I start?", "wie
  fange ich an?", "was kann das plugin?", "help"). Prints a short quick
  start for this repository — what the plugin covers, a link to the
  documentation, and the threat-model, requirements, baseline and coach
  commands that fit its state — and, with --all, the full command reference
  with flags, files, and the configuration and coach state in effect. Read-only — it prints
  guidance and does not scan, analyze, or write anything. For a question about the model's CONTENT ("what are the critical
  findings?") use ask-threat-model instead; this skill explains the tools, not
  the results.
---

You print the help page below. This skill is **read-only**: it reads plugin status once and otherwise does **not** scan, analyze, spawn agents, or write files. It works in any repository, including one without a threat model — the case where it matters most.

Without arguments, print the *Quick start* below. When the arguments contain `--all`, print the *Full reference* instead. Either way, print `# appsec-advisor` first and leave out the `## Quick start` / `## Full reference` heading itself. A line in square brackets selects a block by state; never print it.

**Print the chosen part verbatim.** Both parts have one section per function and one bullet per command, flag, or file: the name as inline code, then a one-line explanation after ` — `. Rewording an explanation, merging bullets, or turning them into prose or tables is what makes the output look inconsistent. Do not expand the one-line explanations into paragraphs, do not add headings, do not summarize the repository, and do not comment on findings.

Print what is actually in effect, not what the plugin could do elsewhere. Read the state from one read-only call before printing:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/appsec_status.py" --repo-root <repo> --json
```

Adjust the *Quick start* with it:

1. Keep the *Threat model* section for whether `docs/security/threat-model.yaml` exists, and drop the other.
2. Keep the one *Secure coding baseline* section matching `versions.baseline.loaded_status`: `missing` → *missing*; `outdated` → *outdated*; `installed` or `newer` → *loaded*; `other` or `invalid` → *mismatched*. Fill `<id>` and `<scope>` from `loaded_id` and `loaded_scopes`. Drop the section when `versions.baseline.enabled` is false or the status is `switched_off` or empty.
3. Fill `<coach state>` from `capsules.coach.state`. Keep the *coach active* bullet when the state is `active`, otherwise the *coach inactive* bullet. Drop the *Coding coach* section when the state is `not packaged`.

Adjust the *Full reference* with it:

1. If `docs/security/threat-model.yaml` is missing, drop the *Work with the model* section — there is nothing to ask about or triage yet.
2. When `org_profile.active` is true, replace the `config.json` bullet under *Configuration* with one bullet naming the organization (`id`), the active `preset`, and that scan defaults come from that profile.
3. Under *Coding coach*, print the coach's real state and note from `capsules.coach`. When the state is `not packaged`, drop the section — the package does not ship the hook.

In both parts, drop the bullet of every skill named in `org_profile.disabled_skills` — the package refuses it at runtime. In the *Documentation* line print the URL from `banner.url` in the plugin's `config.json` when one is set, otherwise the upstream URL shown below.

---

# appsec-advisor

## Quick start

Application security inside Claude Code: threat models of this repository, checks against your security requirements, secure-coding rules for the assistant, and an optional coach that guides security-relevant prompts.

Documentation: https://github.com/appsec-foundry/appsec-advisor

[no model]

### Threat model · none yet

- `/appsec-advisor:create-threat-model` — full scan, writes the model to `docs/security/`
- `/appsec-advisor:create-threat-model --quick` — faster first look, less depth
- `/appsec-advisor:security-score` — 0–100 score in seconds, no model needed

[model present]

### Threat model · in `docs/security/`

- `/appsec-advisor:show-threat-model` — summary, P1–P3 backlog, freshness
- `/appsec-advisor:review-threat-model` — fix or accept findings, P1 first
- *what are the critical findings?* — ask in plain language; answers cite finding IDs

### Security requirements

- `/appsec-advisor:verify-requirements` — check your current changes; built-in baseline if no catalog
- `/appsec-advisor:audit-security-requirements` — audit the whole repository against a catalog

[missing]

### Secure coding baseline · not installed

- `/appsec-advisor:install-baseline` — rules the assistant loads before it writes code

[outdated]

### Secure coding baseline · `<id>` outdated (<scope>)

- `/appsec-advisor:update-baseline` — fetch this plugin's current release

[loaded]

### Secure coding baseline · `<id>` active (<scope>)

- `/appsec-advisor:verify-baseline` — show which rules are in effect

[mismatched]

### Secure coding baseline · unrecognized copy loaded

- `/appsec-advisor:verify-baseline` — identify it before installing a second copy

### Coding coach · <coach state>

[coach inactive]

- `APPSEC_COACH=1 claude` — start a session with security guidance on relevant prompts

[coach active]

- `APPSEC_COACH=0 claude` — start a session without it

### More

- `/appsec-advisor:help --all` — every command, flag, and file

## Full reference

Application security inside Claude Code: threat models of this repository, checks against your security requirements, secure-coding rules for the assistant, and an optional coach that guides security-relevant prompts.

Documentation: https://github.com/appsec-foundry/appsec-advisor

### Create a threat model

- `/appsec-advisor:create-threat-model` — full scan, writes the model to `docs/security/`
  - `--quick` — faster first look, less depth
  - `--thorough` — deeper, for a release review or audit
  - `--full` — reassess everything, keep the report history
  - `--rebuild` — start clean; finding IDs may be reassigned
  - `--repo <dir>` — scan a different repository
  - `--output <dir>` — write the model to a different directory
  - `--requirements <url>` — grade findings against an HTTP(S) catalog
  - `--help` — list every flag

### Work with the model

- `/appsec-advisor:show-threat-model` — summary, P1–P3 backlog, freshness
- `/appsec-advisor:review-threat-model` — fix or accept findings, P1 first
- Ask in plain language — answers come from the model and cite finding IDs
  - *what are the critical findings?*
  - *is there a fix for F-003?*
  - *does the model cover SSRF?*

### Security requirements

Checks against your organization's security requirements, defined in a YAML catalog. Without a catalog, the diff check uses a built-in best-practices baseline.

- `/appsec-advisor:verify-requirements` — check the current diff and suggest code fixes
  - `--gate` — fail on unmet requirements, for CI
- `/appsec-advisor:audit-security-requirements` — audit the whole repository
  - `--requirements <src>` — catalog URL or file for this run
  - `--demo` — use the packaged example catalog
  - `--gate` — fail on open requirements, for CI

### Secure coding baseline

Rules the assistant loads before it writes code, on every prompt. A change takes effect at the next session start.

- `/appsec-advisor:install-baseline` — install for this machine or this repository
- `/appsec-advisor:update-baseline` — fetch the current release
- `/appsec-advisor:verify-baseline` — show what is loaded; `--enforce` makes it a CI gate
- `/appsec-advisor:remove-baseline` — stop loading it, keep the file

### Coding coach

A prompt hook that adds matching guidance, and your requirements when a catalog is configured, whenever a prompt touches auth, crypto, injection, secrets, or IaC.

- `APPSEC_COACH=1 claude` — on for this session
- `APPSEC_COACH=0 claude` — off for this session
- Status: <coach state and note from `capsules.coach`>

### Other commands

- `/appsec-advisor:status` — whether a scan is running
- `/appsec-advisor:threat-model-health` — whether the stored model is consistent
- `/appsec-advisor:authnz-review` — authentication and authorization review, no model needed
- `/appsec-advisor:security-score` — 0–100 score in seconds, no model needed
- `/appsec-advisor:repo-profile` — size, stack, and layout
- `/appsec-advisor:export-threat-model` — PDF, HTML, SARIF
- `/appsec-advisor:publish-threat-model` — commit the report to version control
- `/appsec-advisor:report-error` — report a plugin issue

### Files

- Written by every run, in `docs/security/`
  - `threat-model.md` — the report
  - `threat-model.yaml` — the model every command reads
  - `threat-model-changelog.md` — what changed between runs
- Read when present; none of them can suppress a finding the code supports
  - `docs/business-context.md` — critical flows, sensitive data, scope
  - `docs/known-threats.yaml` — prior findings, re-checked each run
  - `.appsec/trust-boundaries.yaml` — deployment and tenancy intent

### Configuration

- `APPSEC_BANNER=0` — hide the session banner (`env` block of `~/.claude/settings.json`)
- `config.json` — plugin defaults for pricing, logging, and context; see `docs/configuration.md`

### More

- Typing `/appsec-advisor:` lists every command with its description
