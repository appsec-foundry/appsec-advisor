---
name: help
description: >-
  Show what this plugin can do and which entry point fits the task — the
  starting point when someone does not know the commands yet ("what can
  appsec-advisor do?", "which commands are there?", "how do I start?", "wie
  fange ich an?", "was kann das plugin?", "help"). Prints a short command
  reference with example calls: creating a first threat model, asking questions
  about an existing one, working through the findings, and the flags that
  matter. Read-only — it prints guidance and does not scan, analyze, or write
  anything. For a question about the model's CONTENT ("what are the critical
  findings?") use ask-threat-model instead; this skill explains the tools, not
  the results.
---

You print the command reference below. This skill is **read-only**: it does
**not** scan, analyze, spawn agents, or write files. It works in any repository,
including one without a threat model — the case where it matters most.

**Print it as a reference, not as prose.** Keep the command blocks and the
one-line explanations; do not expand them into paragraphs, do not summarize the
repository, and do not comment on findings. Two adjustments only:

1. If `docs/security/threat-model.yaml` is missing, drop the *Ask about it* and
   *Work through findings* sections — there is nothing to ask about yet.
2. In *More information*, print the URL from `banner.url` in the plugin's
   `config.json` when one is set, otherwise the upstream URL shown below.

---

# appsec-advisor

## First threat model

```text
/appsec-advisor:create-threat-model              full scan, writes docs/security/
/appsec-advisor:create-threat-model --quick      faster, less depth — good first look
/appsec-advisor:create-threat-model --thorough   for a release review or audit
/appsec-advisor:create-threat-model --help       every flag
```

Analyzing another repository:

```text
/appsec-advisor:create-threat-model --repo ../payment-service --output ./models/payment
```

## Ask about it

No command needed — ask in plain language:

```text
what are the critical findings?
is there a fix for F-003?
does the model cover SSRF?
welche kritischen findings gibt es?
```

Answers come from the committed model and cite finding IDs. When the model does
not contain the answer, you are told so.

```text
/appsec-advisor:show-threat-model    the fixed summary block, on request
```

## Work through findings

```text
/appsec-advisor:review-threat-model    triage console, P1 before P2 before P3
```

## Keep it current

```text
/appsec-advisor:update-threat-model                       re-scan changed components, keeps F-IDs
/appsec-advisor:create-threat-model --full --rebuild      clean slate, F-IDs may be reassigned
```

## Secure coding, before the code exists

A threat model finds what is already wrong. The secure-coding baseline is an
instruction file the assistant loads before it writes anything, so the rules
apply on every prompt — not only the ones that mention security.

```text
/appsec-advisor:install-baseline    menu: this machine, or this repository
/appsec-advisor:verify-baseline     is it actually loaded? read-only, exits 1 if not
/appsec-advisor:remove-baseline     stop it loading; keeps the file unless told otherwise
```

It loads at the next session start, not the one it was installed in.

## Everything else

```text
/appsec-advisor:status                 is a scan running
/appsec-advisor:threat-model-health    is the stored model consistent
/appsec-advisor:export-threat-model    PDF, HTML, SARIF
/appsec-advisor:publish-threat-model   push the report to its destination
/appsec-advisor:report-error           anonymized bundle after a failed run
```

Typing `/appsec-advisor:` lists every skill with its description.

## Files

```text
docs/security/threat-model.md               the report
docs/security/threat-model.yaml             the structured model every skill reads
docs/security/threat-model-changelog.md     what changed between runs
```

## Session banner

```text
APPSEC_BANNER=0     in the env block of ~/.claude/settings.json — turns it off
```

## More information

https://github.com/matthiasrohr/appsec-advisor
