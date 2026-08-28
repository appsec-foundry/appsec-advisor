---
name: security-score
description: Deterministic quick Security Score (0-100) for a repository, computed from the scanner layer alone — no agents, no LLM, no threat model, nothing written into the target repository. Reports the score together with how many rules applied, the finding tally, and the weakest control domains. Use for a fast indication or a per-commit trend; it is not a risk rating and does not replace /appsec-advisor:create-threat-model.
---

You are printing a quick Security Score for a repository. This skill is **read-only** — do not analyze the repository yourself, do not write files, do not dispatch sub-agents. Run the script and present its output.

## `--help` — inline help (early exit)

If the user's arguments contain `--help` or `-h`, print this block verbatim and exit.

```
/appsec-advisor:security-score — Deterministic quick score, no LLM involved.

USAGE
  /appsec-advisor:security-score [--repo <path>] [--json]

FLAGS
  --repo <path>   Repository to score (default: current working dir)
  --json          Emit the result as machine-readable JSON

WHAT THE NUMBER IS
  One score per indicator — Output Handling, Frontend Security, Access
  Control, Hardening & Configuration and the rest — from the coverage
  rules routed to that indicator plus its own scanner findings. Rules
  that cannot fire on this repository are excluded; an indicator no rule
  applied to shows its findings but stays unscored.

  The headline is the mean of the weaker half: a repository is attacked
  where it is weakest.

WHAT IT IS NOT
  No asset tier, no exposure, no abuse chain. Severities are catalog
  defaults without the caps and elevations the report applies. Comparable
  across commits of one repository, not between repositories.

EXIT CODES
  0  score computed
  2  undetermined — too few rules applied to this repository
  1  error
```

## Run

Run the script from the plugin root, passing the user's `--repo` and `--json` through unchanged:

```bash
python3 "${CLAUDE_PLUGIN_ROOT}/scripts/security_score.py" [--repo <path>] [--json]
```

Use exactly `Calculating the repository's security score` as the tool call's description. It is the only thing the user sees for the 15 to 30 seconds the scan takes, so it names the work, not the mechanism: not "Running the security score script", not "Executing security_score.py".

Do not announce the run in prose beside it. "Running the security score script now", "Let me calculate the score" and their kin are forbidden even though they are true — the description line already says it. Just run it.

The script writes its scanner sidecars to a temporary directory and removes them, so the target repository is untouched.

## Present the result

Reprint the script's stdout **verbatim**, in a fenced code block, every line of it, and stop. The user does not see the tool output; what you print is the whole report they get. It is already finished: headline, one indicator per line with its detail line under it, the tally, and any note the run produced.

Summarising it is the failure this rule exists for. All of the following are forbidden, even though each is true:

```
Security Score: 2 / 100 — dominated by Access Control (68 findings), Dependencies
(22 findings), and Authentication (21 findings), all near zero.

For findings with severity, exposure, and mitigations, run
/appsec-advisor:create-threat-model.
```

Nothing may be added after the block either: no summary of the number, no repetition of a note it already carries, no verdict such as "secure" or "at risk", no severities or mitigations of your own. None of that is in the data, and prose beside the block undoes the layout it was given.

Two exceptions, both only when the user asks: name the covered languages — JavaScript/TypeScript, Python, Java/Spring, parts of .NET — when the verdict is `undetermined`, and point at `/appsec-advisor:create-threat-model` when they want the findings, severities, or mitigations behind a low score.
