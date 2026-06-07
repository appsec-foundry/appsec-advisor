---
name: verify-requirements
description: Help a developer check the code they just changed against their company security requirements — or, if none are configured, against a built-in best-practices baseline. Scopes to the current diff, dispatches the appsec-reviewer subagent to grade only the triggered requirements, and prints concrete, code-aware guidance (what to fix and how). Advisory by default; an opt-in --gate turns it into a CI/merge gate. Complements the full-repo audit-security-requirements skill.
---

You are helping a developer build secure code. This skill checks the change the
developer just made against the security requirements that apply to it and gives
**concrete, code-aware guidance** — what is missing or wrong and how to fix it.

This is a **dev helper, not a compliance police**:
- It scopes to the **diff** (not the whole repo), so it is fast and relevant.
- It works with **zero setup**: if your team has a company requirements catalog
  configured it checks against that; if not, it falls back to a built-in
  best-practices baseline — it never refuses to help. (Requirement IDs are
  opaque, org-defined strings; no fixed prefix is assumed.)
- It is **advisory by default** (always exits 0). Teams that want a hard CI/merge
  gate opt in explicitly with `--gate`.

Follow the steps exactly.

## `--help` — inline help (early exit)

If the user's arguments contain `--help` or `-h`, **do not scan anything**.
Print the block below verbatim and exit with status 0.

```
/appsec-advisor:verify-requirements — Check your change against security requirements.

USAGE
  /appsec-advisor:verify-requirements [FLAGS]

  Checks only the requirements TRIGGERED by your current diff and tells you what
  to fix and how. Uses your company requirements catalog if configured,
  otherwise a built-in best-practices baseline — no setup needed.
  Advisory by default (always exits 0); pass --gate to fail CI on a regression.

FLAGS
  --gate                   Enforce: exit non-zero when an in-scope requirement
                           at/above the priority floor FAILs. Without it the
                           skill always exits 0 (advisory).
  --gate-on <fail|partial> What gates: `fail` (default) or `fail`+`partial`.
  --priority-floor <p>     Lowest priority that may gate: MUST (default),
                           SHOULD, or MAY.
  --base <ref>             Diff against <ref> (git diff <ref>...HEAD).
                           Default: merge-base with the upstream default branch.
  --staged                 Diff staged changes only (git diff --cached) — for
                           pre-commit hooks.
  --requirements <src>     Load the requirements YAML from <src> instead of the
                           configured source; no cache fallback. <src> is an
                           http(s):// URL or a local file path.
  --org-profile <path>     Use this org profile for source resolution.
  --preset <name>          Use a specific preset from the active org profile.
  --no-org-profile         Ignore packaged/env-pointed org profiles.
  --md                     Also save docs/security/appsec-requirements-change-report.md
  --json                   Also save docs/security/appsec-requirements-change-report.json
  --save                   Both --md and --json
  --help, -h               Show this help and exit

EXIT CODES
  0  advisory mode, or --gate with no gating failures
  1  --gate and >=1 gating failure
  2  usage / requirements-load / verdict error

See `/appsec-advisor:audit-security-requirements` for the full-repo audit and
`docs/configuration.md` → "Security Requirements Management" for source rules.
```

After printing, exit. Do not read any files or perform any other action.

## Step 1 — Parse arguments

Parse arguments after the skill name:

- `--gate` — set `gate_mode = true` (default false / advisory)
- `--gate-on <fail|partial>` — set `gate_on` (default `fail`)
- `--priority-floor <MUST|SHOULD|MAY>` — set `priority_floor` (default `MUST`)
- `--base <ref>` — set `base_ref`
- `--staged` — set `staged = true` (mutually exclusive with `--base`; if both given, hard-fail)
- `--requirements <src>` — set `requirements_url_override`
- `--org-profile <path>` — set `org_profile_override`
- `--preset <name>` — set `preset_override`
- `--no-org-profile` — set `no_org_profile = true`
- `--md` / `--json` / `--save` — report-save flags

#### Reject unknown flags (hard fail)

Any token starting with `--` that is not one of the recognized flags above — or
is not the value consumed by `--gate-on` / `--priority-floor` / `--base` /
`--requirements` / `--org-profile` / `--preset` — is a hard error. Do not read
files, fetch, or dispatch. Print to stderr `Error: unknown argument '<TOKEN>'`
followed by `Run /appsec-advisor:verify-requirements --help for details.` and
exit with status `2`. A flag whose required value is missing counts as unknown.

## Step 2 — Resolve plugin root, org profile, and requirements catalog

Resolve the plugin root (same block as the audit skill):

```bash
if [ -z "$CLAUDE_PLUGIN_ROOT" ]; then
  SKILL_MD_PATH=$(find /root /home /opt -maxdepth 6 \
    -path "*/appsec-advisor/skills/verify-requirements/SKILL.md" \
    2>/dev/null | head -1)
  if [ -n "$SKILL_MD_PATH" ]; then
    CLAUDE_PLUGIN_ROOT=$(dirname "$(dirname "$(dirname "$SKILL_MD_PATH")")")
  fi
fi
export CLAUDE_PLUGIN_ROOT
if [ -z "$CLAUDE_PLUGIN_ROOT" ] || [ ! -d "$CLAUDE_PLUGIN_ROOT" ]; then
  echo "Error: CLAUDE_PLUGIN_ROOT could not be resolved — install appsec-advisor or set the variable manually." >&2
  exit 2
fi

OUTPUT_DIR="${PWD}/docs/security"
mkdir -p "$OUTPUT_DIR"
```

Resolve the org profile, then the requirements source, then fetch through the
shared fail-closed gate — identical contract to `audit-security-requirements`
Step 1b (explicit `--requirements` is fail-closed with no cache fallback;
otherwise require a usable org-profile / legacy source or a populated cache):

```bash
ORG_ARGS=()
[ -n "$ORG_PROFILE_OVERRIDE" ] && ORG_ARGS+=(--org-profile "$ORG_PROFILE_OVERRIDE")
[ -n "$PRESET_OVERRIDE" ] && ORG_ARGS+=(--preset "$PRESET_OVERRIDE")
[ "$NO_ORG_PROFILE" = "true" ] && ORG_ARGS+=(--no-org-profile)

python3 "$CLAUDE_PLUGIN_ROOT/scripts/resolve_org_profile.py" \
  --output-dir "$OUTPUT_DIR" --emit-file "${ORG_ARGS[@]}" >/dev/null || exit $?

FETCH_ARGS=(--caller verify-requirements --output-dir "$OUTPUT_DIR" --plugin-root "$CLAUDE_PLUGIN_ROOT" \
  --fallback-baseline "$CLAUDE_PLUGIN_ROOT/data/appsec-bestpractices-baseline.yaml")
if [ -n "$REQUIREMENTS_URL_OVERRIDE" ]; then
  # Explicit company source: fail-closed, no baseline fallback — if you name a
  # source it must load (a typo/down URL should not silently fall back).
  FETCH_ARGS+=(--requirements "$REQUIREMENTS_URL_OVERRIDE")
else
  # Zero-config path: try the org-profile / cached company source; if none is
  # available, degrade to the bundled best-practices baseline instead of
  # aborting. This is what makes the helper "just work" with no setup.
  FETCH_ARGS+=(--require)
fi

python3 "$CLAUDE_PLUGIN_ROOT/scripts/fetch_requirements.py" "${FETCH_ARGS[@]}"
REQ_FETCH_EXIT=$?
if [ "$REQ_FETCH_EXIT" -ne 0 ]; then
  # Only happens when an EXPLICIT --requirements source was named and could not
  # load. The zero-config path never lands here (it has the baseline fallback).
  echo "✗ The requirements source you named could not be loaded (exit $REQ_FETCH_EXIT)." >&2
  exit 2
fi
```

`$OUTPUT_DIR/.requirements.yaml` is now the catalog — either your company
requirements (when configured) or the bundled best-practices baseline. Its
top-level `source:` field records which (the requirement-id scheme is whatever
the catalog defines — no fixed prefix is assumed), so the output can be honest
about what your change was checked against.

## Step 3 — Build the diff sidecar

```bash
DIFF_ARGS=(--repo-root "$PWD" --output-dir "$OUTPUT_DIR")
[ -n "$BASE_REF" ] && DIFF_ARGS+=(--base "$BASE_REF")
[ "$STAGED" = "true" ] && DIFF_ARGS+=(--staged)

CHANGED_COUNT=$(python3 "$CLAUDE_PLUGIN_ROOT/scripts/build_verify_diff.py" "${DIFF_ARGS[@]}")
DIFF_EXIT=$?
if [ "$DIFF_EXIT" -ne 0 ]; then
  echo "✗ Could not compute the diff (exit $DIFF_EXIT)." >&2
  exit 2
fi
```

If `CHANGED_COUNT` is `0`, print `No changes to verify.` and exit `0`. **Do not
dispatch the subagent** — an empty diff costs nothing.

## Step 4 — Dispatch the verifier subagent

Use the Task tool to launch the `appsec-reviewer` subagent. Pass
inputs in Group A → B → C order (stable → scalars → volatile paths):

```
REPO_ROOT=<PWD>
OUTPUT_DIR=<OUTPUT_DIR>
PRIORITY_FLOOR=<priority_floor>
MODEL_ID=sonnet
DIFF_FILE=<OUTPUT_DIR>/.verify-diff.json
REQUIREMENTS_YAML=<OUTPUT_DIR>/.requirements.yaml
STEERING_MAP=<CLAUDE_PLUGIN_ROOT>/hooks/steering_keywords.json
```

`STEERING_MAP` is the shared topic→requirement relevance map (also used by the
security-steering hook) — the verifier's Stage-A reads it instead of inventing
its own keyword table, so guidance and verification stay in lock-step.

The subagent grades the triggered requirements and writes
`$OUTPUT_DIR/.requirements-verification.json`. It prints its own readable
console summary; do not re-print the findings yourself.

## Step 5 — Compute the gate / exit code

```bash
GATE_ARGS=(--verdict "$OUTPUT_DIR/.requirements-verification.json" \
  --priority-floor "$PRIORITY_FLOOR" --gate-on "$GATE_ON")
[ "$GATE_MODE" = "true" ] && GATE_ARGS+=(--gate)

python3 "$CLAUDE_PLUGIN_ROOT/scripts/requirements_gate.py" "${GATE_ARGS[@]}"
GATE_EXIT=$?
```

`requirements_gate.py` prints the verdict line and is the single authority on
the outcome. Propagate its exit code:

- advisory mode (`--gate` absent) → it always exits 0; the skill exits 0 but the
  printed `WARN` line still tells the team what would block.
- gate mode → exit 1 when a gating failure exists; CI fails the job.
- exit 2 → verdict missing/malformed (treat as a hard failure, not a pass).

```bash
exit "$GATE_EXIT"
```

## Step 6 — Save reports (conditional)

If `--md` / `--json` / `--save` was set, render the report under
`docs/security/appsec-requirements-change-report.{md,json}` from
`.requirements-verification.json`, reusing the `audit-security-requirements`
report format (open + gating requirements only). This is presentation only; it
must not change the exit code computed in Step 5.

---

Note: this skill always has something to check against. With a company catalog
configured (explicit `--requirements`, org-profile source, legacy config, or
plugin cache) it uses that; otherwise it falls back to the bundled
best-practices baseline (`data/appsec-bestpractices-baseline.yaml`). It only
aborts (Step 2, exit 2) when you **explicitly** named a `--requirements` source
that could not be loaded — a deliberately-named source must work.
