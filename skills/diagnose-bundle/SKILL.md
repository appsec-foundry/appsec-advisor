---
name: diagnose-bundle
description: Maintainer/dev skill that triages an anonymised diagnostic bundle (appsec-diag-*.tgz, produced by scripts/diagnostic_bundle.py) a user sent after a pipeline failure. Runs the deterministic inspect, then cross-references the plugin source (scripts/, agents/phases/, AGENTS.md) and known-bug history to produce a grounded root-cause hypothesis. Does NOT re-run the pipeline and never needs the user's repo.
---

# diagnose-bundle

A user hit a pipeline error and sent you an **anonymised** diagnostic bundle
(`appsec-diag-<id>.tgz`). It contains only versions, run shape (phases reached,
stage timings, aggregate counts), a metadata-only file inventory, and scrubbed
logs — never their results, findings, or source (see
`scripts/diagnostic_bundle.py`). Your job: turn those facts into a root-cause
hypothesis by binding them to **this** plugin's code and bug history.

The leverage is that you run inside the `appsec-advisor` repo: the bundle gives
the *symptom* (where/what), the repo gives the *mechanism* (which producer, which
contract). Keep the diagnosis anchored to the structured fields — never invent a
cause the bundle does not support.

This is a **maintainer/dev** skill — never auto-triggered, not part of
`create-threat-model`, and it needs no new permissions (read-only triage of a
file the maintainer chose to open).

## Step 1 — Parse arguments

- `BUNDLE` (required) — path to the `appsec-diag-*.tgz` (or an already-unpacked
  bundle dir). If absent, ask the user for it and stop.

## Step 2 — Resolve `CLAUDE_PLUGIN_ROOT`

```bash
if [ -z "$CLAUDE_PLUGIN_ROOT" ]; then
  CLAUDE_PLUGIN_ROOT=$(find /root /home /opt -maxdepth 6 \
    -path "*/appsec-advisor/skills/diagnose-bundle/SKILL.md" \
    2>/dev/null | head -1 | xargs -r dirname | xargs -r dirname | xargs -r dirname)
fi
export CLAUDE_PLUGIN_ROOT
if [ -z "$CLAUDE_PLUGIN_ROOT" ] || [ ! -d "$CLAUDE_PLUGIN_ROOT" ]; then
  echo "Error: CLAUDE_PLUGIN_ROOT could not be resolved." >&2
  exit 2
fi
```

## Step 3 — Deterministic inspect (facts into context)

Read the bundle **in memory** — do NOT `tar -x` it to disk; a hand-crafted
bundle could path-traverse on extraction. `inspect` reads it safely.

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/diagnostic_bundle.py" inspect \
  --bundle "$BUNDLE" --logs 40
INSPECT_EXIT=$?
[ "$INSPECT_EXIT" -ne 0 ] && { echo "diagnose-bundle: inspect failed ($INSPECT_EXIT)"; exit "$INSPECT_EXIT"; }
```

This prints: environment (plugin version / platform / config), **where it
stopped** (last progress, error count, scrubbed `last error`, stage count),
anonymised counts, the file inventory (with byte sizes), and the last 40
scrubbed log lines. These are your only inputs — treat them as the ground truth.

## Step 4 — Cross-reference the plugin source

Bind the symptom to the mechanism. From the inspect output, take the
`last error`, the stopping `phase`/`component`, and any **anomalous inventory
entry** (a finding sidecar that is `0 B`, missing, or implausibly large), then:

1. **Phase/component → producer.** Map the phase to its phase-group file under
   `agents/phases/` and the script that runs there (e.g. Phase 9/merge →
   `scripts/build_threat_model_yaml.py`; compose → `compose_threat_model.py`).
   Use `AGENTS.md` → "Phase and stage map", the phase-group headings, and
   each agent's frontmatter for its role and turn budget.
2. **Error signature → code.** `Grep` the repo for the distinctive tokens of the
   scrubbed `last error` (schema enum names, function names, event names) across
   `scripts/`, `schemas/`, `agents/`. The `<str>`/`<path>` placeholders are
   redactions — match on the unredacted skeleton around them.
3. **Known-bug history.** Check the auto-memory index
   (`MEMORY.md`) for a prior occurrence of this signature
   (e.g. schema-drift FATALs, STRIDE inline-shortcut → empty output, budget-flag
   poisoning). A match is strong evidence and usually carries the fix location.

## Step 5 — Report (print, do not write files)

Emit exactly these fields, each grounded in a bundle fact or a repo `file:line`:

```
WHERE         <phase> / <component> / <producer script:line>
ROOT CAUSE    <hypothesis, tied to the last_error + an inventory/counts anomaly>
EVIDENCE      <the bundle fact(s)> + <repo file:line or memory entry>
CHECK NEXT    <the producer file/function to read to confirm>
REPRO         <smallest way to reproduce — e.g. threat_fixture replay, a crafted sidecar, a unit test>
CONFIDENCE    high | medium | low  (low if the bundle underdetermines the cause)
```

Rules:
- If the bundle underdetermines the cause, say so and state **which additional
  non-sensitive field** would disambiguate (so we can widen `collect`) — do not
  guess past the evidence.
- Never ask the user for their source or results; the bundle is deliberately
  finding-free and the diagnosis must work without them.
