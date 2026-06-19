---
name: report-error
description: User-facing skill for reporting a pipeline error. Builds an anonymised diagnostic bundle (appsec-diag-*.tgz) from the failed run via scripts/diagnostic_bundle.py, shows the user exactly what it contains, and tells them to review it and attach it to a GitHub issue. The bundle carries only tool versions, run shape, and scrubbed logs — never threat-model results, findings, source, or repo paths — and the tool makes no network calls.
---

# report-error

You hit an error in the threat-model pipeline and want to report it. This skill
builds an **anonymised** diagnostic bundle the maintainer can triage, shows you
exactly what is in it, and leaves the decision to share it entirely to you.

What the bundle contains: tool/plugin versions, the run shape (phases reached,
stage timings, aggregate count histograms), a metadata-only file inventory
(name/size — never contents), and the run logs with paths/quoted-strings/secrets
scrubbed. What it **never** contains: the threat-model results, any finding or
evidence, component names, source code, or the scanned-repo path. The tool makes
**no network calls** — it only writes a local file; you choose whether to attach
it. The deterministic anonymisation is enforced in code
(`scripts/diagnostic_bundle.py`) and pinned by a no-leak test, not by an LLM.

## Step 1 — Parse arguments

All optional:

- `--repo <path>` — the scanned repo root. Default: current working directory.
- `--output <path>` — the run's OUTPUT_DIR. Default: `<repo>/docs/security`.
- `--into <path>` — where to write the `.tgz`. Default: current working directory.

## Step 2 — Resolve `CLAUDE_PLUGIN_ROOT`

```bash
if [ -z "$CLAUDE_PLUGIN_ROOT" ]; then
  CLAUDE_PLUGIN_ROOT=$(find /root /home /opt -maxdepth 6 \
    -path "*/appsec-advisor/skills/report-error/SKILL.md" \
    2>/dev/null | head -1 | xargs -r dirname | xargs -r dirname | xargs -r dirname)
fi
export CLAUDE_PLUGIN_ROOT
if [ -z "$CLAUDE_PLUGIN_ROOT" ] || [ ! -d "$CLAUDE_PLUGIN_ROOT" ]; then
  echo "Error: CLAUDE_PLUGIN_ROOT could not be resolved." >&2
  exit 2
fi
```

## Step 3 — Build the bundle (deterministic)

```bash
REPO_ROOT="${REPO_ROOT:-$PWD}"
OUTPUT_DIR="${OUTPUT_DIR:-$REPO_ROOT/docs/security}"
INTO="${INTO:-$PWD}"

if [ ! -d "$OUTPUT_DIR" ]; then
  echo "Error: no run output at $OUTPUT_DIR — pass --output <dir> pointing at the run's OUTPUT_DIR." >&2
  exit 2
fi

BUNDLE=$(python3 "$CLAUDE_PLUGIN_ROOT/scripts/diagnostic_bundle.py" collect \
  --run "$OUTPUT_DIR" --repo-root "$REPO_ROOT" --into "$INTO" \
  | sed -n 's/^✓ wrote anonymised diagnostic bundle → //p')
[ -z "$BUNDLE" ] && { echo "Error: bundle was not produced." >&2; exit 1; }
```

## Step 4 — Show the user what is in it (review gate)

```bash
python3 "$CLAUDE_PLUGIN_ROOT/scripts/diagnostic_bundle.py" inspect --bundle "$BUNDLE" --logs 20
echo
echo "Bundle written to: $BUNDLE"
```

## Step 5 — Tell the user how to proceed

Relay, in plain language:

- The bundle above is **anonymised** — it contains no threat-model results,
  findings, source, or repo paths, and the tool made no network calls.
- They should **review** the printed inspect summary (and may open the `.tgz` —
  it is plain JSON + scrubbed logs) before sharing anything.
- To report: open a GitHub issue with the **Bug report** template and **attach
  the `.tgz`** (drag it onto the issue). Do not paste raw terminal output.
- Echo the bundle path so they can find the file.

Do not upload, post, or transmit the bundle yourself — sharing is the user's
explicit action. This skill only writes the local file.
