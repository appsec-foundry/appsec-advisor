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
  Control basis    Share of the APPLICABLE architecture-coverage rules that
                   found a control signal. Rules that cannot fire on this
                   repository are excluded from the denominator.
  Finding penalty  Saturating deduction for the hard findings of the
                   config/IaC and source-auth scanners, weighted by their
                   catalog severity.

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

Print the script's output and stop. It is already the finished report: headline, categories, tallies, and any note the run produced.

Add nothing after it. No summary of the number, no repetition of a note the output already carries, no verdict such as "secure" or "at risk", no severities or mitigations of your own — none of that is in the data, and a paragraph restating the block undoes the layout it was given.

If the verdict is `undetermined`, say that the rule catalog did not cover this repository and name the languages it does cover: JavaScript/TypeScript, Python, Java/Spring, and parts of .NET.

If the user asks what to do about a low score, or for the findings behind it, point them at `/appsec-advisor:create-threat-model`, which is where severity, exposure, and mitigations come from.
