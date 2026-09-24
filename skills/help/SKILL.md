---
name: help
description: >-
  Show what this plugin can do and which entry point fits the task — the
  starting point when someone does not know the commands yet ("what can
  appsec-advisor do?", "which commands are there?", "how do I start?", "wie
  fange ich an?", "was kann das plugin?", "help"). Prints a short quick
  start for this repository — the first threat-model call and the baseline step
  that fits its state — and, with --all, the full command reference with flags,
  files, and the configuration and coach state in effect. Read-only — it prints
  guidance and does not scan, analyze, or write anything. For a question about the model's CONTENT ("what are the critical
  findings?") use ask-threat-model instead; this skill explains the tools, not
  the results.
---

You print the command reference below. This skill is **read-only**: it reads plugin status once and otherwise does **not** scan, analyze, spawn agents, or write files. It works in any repository, including one without a threat model — the case where it matters most.

Without arguments, print the *Quick start* below. When the arguments contain `--all`, print the *Full reference* instead. Either way, print `# appsec-advisor` first and leave out the `## Quick start` / `## Full reference` heading itself. A line in square brackets selects a block by state; never print it.

**Print the chosen part verbatim.** The *Quick start* puts one sentence above each command; the *Full reference* blocks are column-aligned and no line exceeds 72 columns, so nothing wraps in a terminal. Rewording an explanation, re-wrapping a line, or merging blocks is what makes the output look broken. Do not expand the one-line explanations into paragraphs, do not add headings, do not summarize the repository, and do not comment on findings.

Print what is actually in effect, not what the plugin could do elsewhere. Read the state from one read-only call before printing:

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/appsec_status.py" --repo-root <repo> --json
```

Adjust the *Quick start* with it:

1. Under *Threat model*, keep the block for whether `docs/security/threat-model.yaml` exists, and drop the other.
2. Under *Secure coding baseline*, keep the one block matching `versions.baseline.loaded_status`: `missing` → *missing*; `outdated` → *outdated*; `installed` or `newer` → *loaded*; `other` or `invalid` → *mismatched*. Fill `<id>` and `<scope>` from `loaded_id` and `loaded_scopes`. Drop the section when `versions.baseline.enabled` is false or the status is `switched_off` or empty.

Adjust the *Full reference* with it:

1. If `docs/security/threat-model.yaml` is missing, drop the *Once a model exists* section — there is nothing to ask about or triage yet.
2. When `org_profile.active` is true, replace the plugin-defaults sentence under *Files* with one sentence naming the organization (`id`), the active `preset`, and that scan defaults come from that profile.
3. Under *Guidance while you code*, print the coach's real state and note from `capsules.coach`. When the state is `not packaged`, drop the section — the package does not ship the hook.

In both parts, drop the line of every skill named in `org_profile.disabled_skills` — the package refuses it at runtime. On the last line print the URL from `banner.url` in the plugin's `config.json` when one is set, otherwise the upstream URL shown below.

---

# appsec-advisor

## Quick start

### Threat model

[no model]

Scan this repository and write the model to `docs/security/`; it stays local until you publish it. Add `--quick` for a faster first look.

```text
/appsec-advisor:create-threat-model
```

Rate the repository 0–100 in seconds, without agents and without a model.

```text
/appsec-advisor:security-score
```

[model present]

See the summary: findings by severity, the P1–P3 backlog, and whether the model is current.

```text
/appsec-advisor:show-threat-model
```

Work through the findings, P1 first, and fix the code or record an accepted risk.

```text
/appsec-advisor:review-threat-model
```

Or ask in plain language; the answer cites the finding IDs.

```text
what are the critical findings?
```

### Secure coding baseline

[missing]

Install rules the assistant loads before it writes code, for this machine or this repository.

```text
/appsec-advisor:install-baseline
```

[outdated]

Refresh the loaded `<id>` (`<scope>`), which is behind this plugin's release.

```text
/appsec-advisor:update-baseline
```

[loaded]

Confirm that `<id>` is loaded (`<scope>`).

```text
/appsec-advisor:verify-baseline
```

[mismatched]

See which different or broken baseline is loaded; installing would add a second copy.

```text
/appsec-advisor:verify-baseline
```

Every command, flag and file: `/appsec-advisor:help --all`

Documentation: https://github.com/appsec-foundry/appsec-advisor

## Full reference

### Start here

Scans this repository and writes the model to `docs/security/`. Without a flag it runs a full scan.

```text
/appsec-advisor:create-threat-model

  --quick                       faster, less depth; a first look
  --thorough                    for a release review or audit
  --full                        reassess, keep the report history
  --rebuild                     clean slate, F-IDs may be reassigned
  --repo <dir>                  scan a different repository
  --output <dir>                write the model somewhere else
  --requirements <url>          grade findings against your catalog
  --help                        every flag
```

`<dir>` is a path; `<url>` is an HTTP(S) requirements catalog such as `https://appsec.int.example.com/appsec-requirements.yaml`.

### Once a model exists

No command needed — ask in plain language:

```text
what are the critical findings?
is there a fix for F-003?
does the model cover SSRF?
welche kritischen findings gibt es?
```

Answers come from the model in `docs/security/` and cite finding IDs. When the model does not contain the answer, you are told so.

```text
/appsec-advisor:review-threat-model     triage console, P1 first
/appsec-advisor:show-threat-model       the fixed summary block
```

### Secure coding, before the code exists

A threat model finds what is already wrong. The secure-coding baseline is an instruction file the assistant loads before it writes anything, so the rules apply on every prompt, not only the ones that mention security. It takes effect at the next session start, not the one it was installed in.

```text
/appsec-advisor:install-baseline        this machine, or this repo
/appsec-advisor:update-baseline         re-fetch the installed copy
/appsec-advisor:verify-baseline         is it loaded; exits 1 if not
/appsec-advisor:remove-baseline         stop it loading, keep the file
```

### Guidance while you code

The coach is a prompt hook. When a prompt touches auth, crypto, injection, secrets or IaC, it adds the matching guidance — and the team's requirements when a catalog is configured — before the code is written.

```text
APPSEC_COACH=1 claude ...       on for this session
APPSEC_COACH=0 claude ...       off for this session
```

<coach state and note from `capsules.coach`>

### Everything else

```text
/appsec-advisor:status                  is a scan running
/appsec-advisor:threat-model-health     is the stored model consistent
/appsec-advisor:security-score          0-100 score, no model needed
/appsec-advisor:repo-profile            size, stack and layout
/appsec-advisor:export-threat-model     PDF, HTML, SARIF
/appsec-advisor:publish-threat-model    push the report to its target
/appsec-advisor:report-error            review a plugin issue
```

Typing `/appsec-advisor:` lists every skill with its description.

### Files

A run writes the first group and reads the second when it exists. No input file can suppress a finding the code supports.

```text
docs/security/
  threat-model.md               the report
  threat-model.yaml             the model every skill reads
  threat-model-changelog.md     what changed between runs

docs/business-context.md        critical flows, sensitive data, scope
docs/known-threats.yaml         prior findings, re-checked each run
.appsec/trust-boundaries.yaml   deployment and tenancy intent
```

Set `APPSEC_BANNER=0` in the `env` block of `~/.claude/settings.json` to turn the session banner off. Plugin defaults — pricing, logging, external context — live in `config.json` in the plugin directory, documented in `docs/configuration.md`.

Documentation: https://github.com/appsec-foundry/appsec-advisor
