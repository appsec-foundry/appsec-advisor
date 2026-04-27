---
name: export-pdf
description: Convert a finished threat-model.md into a self-contained threat-model.pdf. Standalone post-processing — does not analyze the repo, does not run any agent. Requires pandoc and weasyprint to be installed; mmdc (mermaid-cli) is optional and renders Mermaid diagrams as SVG when present.
---

You are exporting an existing threat model to PDF. This skill is **standalone post-processing** — do not analyze the repository, do not dispatch any agent, do not modify the source Markdown. The skill reads `threat-model.md`, writes `threat-model.pdf`, nothing else.

## `--help` — inline help (early exit)

If the user's arguments contain `--help` or `-h`, print this block verbatim and exit.

```
/appsec-advisor:export-pdf — Convert threat-model.md to threat-model.pdf.

USAGE
  /appsec-advisor:export-pdf [FLAGS]

FLAGS
  --repo <path>        Repository to operate on (default: current working dir)
  --output <path>      Output directory containing threat-model.md
                       (default: <repo>/docs/security)
  --input <path>       Path to a specific Markdown file
                       (default: <output>/threat-model.md)
  --output-pdf <path>  Path of the resulting PDF
                       (default: same dir as input, .pdf extension)
  --no-mermaid         Skip Mermaid SVG pre-rendering even if mmdc is available
                       (Mermaid blocks then appear as code in the PDF)
  --require-mermaid    Fail preflight if mmdc is not installed
                       (default: warn and skip)
  --keep-html          Also write the intermediate HTML next to the PDF
                       (for debugging)
  --check-only         Run preflight checks only — do not convert
  --help, -h           Show this help and exit

DEPENDENCIES (installed by the user, not by this plugin)
  pandoc               Required.  apt install pandoc | brew install pandoc
  weasyprint           Required.  pip install weasyprint
                       (also needs Pango/Cairo system libs on Linux)
  mmdc (mermaid-cli)   Optional.  npm install -g @mermaid-js/mermaid-cli
                       Without it, Mermaid diagrams remain as code blocks.

EXAMPLES
  /appsec-advisor:export-pdf
  /appsec-advisor:export-pdf --check-only
  /appsec-advisor:export-pdf --no-mermaid --keep-html
  /appsec-advisor:export-pdf --input ./report.md --output-pdf ./report.pdf

The skill is idempotent and side-effect-free apart from writing the PDF
(and the optional HTML with --keep-html). It never dispatches agents and
never spends LLM tokens.
```

After printing, exit.

## Step 1 — Parse arguments

Recognized flags:

  `--repo <path>`  `--output <path>`  `--input <path>`  `--output-pdf <path>`
  `--no-mermaid`  `--require-mermaid`  `--keep-html`  `--check-only`
  `--help` | `-h`

Parse these and set `REPO_ROOT`, `OUTPUT_DIR`, `INPUT_MD`, `OUTPUT_PDF`,
`NO_MERMAID`, `REQUIRE_MERMAID`, `KEEP_HTML`, `CHECK_ONLY`.

Defaults:
- `REPO_ROOT` → current working directory
- `OUTPUT_DIR` → `$REPO_ROOT/docs/security`
- `INPUT_MD` → `$OUTPUT_DIR/threat-model.md`
- `OUTPUT_PDF` → derived by `export_pdf.py` from `INPUT_MD` (replace `.md` with `.pdf`)

### Reject unknown arguments (hard fail)

If the invocation contains **any** token that is not one of the recognized
flags above — or is not the value consumed by `--repo` / `--output` /
`--input` / `--output-pdf` — DO NOT proceed. Do not invoke the helper.
Print the following block verbatim to stderr, substituting `<TOKEN>` with the
first unknown token, then exit with status `2`:

```
Error: unknown argument '<TOKEN>'

/appsec-advisor:export-pdf accepts only:
  --repo <path>        Repository to operate on (default: current working dir)
  --output <path>      Output directory (default: <repo>/docs/security)
  --input <path>       Markdown file to convert (default: <output>/threat-model.md)
  --output-pdf <path>  Resulting PDF path (default: same dir as input)
  --no-mermaid         Skip Mermaid SVG pre-rendering
  --require-mermaid    Fail preflight if mmdc is not installed
  --keep-html          Keep the intermediate HTML for debugging
  --check-only         Preflight only, do not convert
  --help, -h           Show full help and exit

Run `/appsec-advisor:export-pdf --help` for details.
```

A flag that takes a value (e.g. `--repo`, `--output`, `--input`,
`--output-pdf`) counts as unknown when its value is missing — treat the flag
itself as the offending token in that case. Repeated occurrences of the same
flag are allowed; the last value wins.

## Step 2 — Run the exporter

Delegate to the Python helper. Every behavior — preflight, Mermaid
pre-pass, pandoc, weasyprint, atomic write — lives in the helper, not in
this skill.

```bash
ARGS=""
[ -n "$INPUT_MD" ]    && ARGS="$ARGS --input $INPUT_MD"
[ -n "$OUTPUT_PDF" ]  && ARGS="$ARGS --output $OUTPUT_PDF"
[ "$NO_MERMAID"      = "true" ] && ARGS="$ARGS --no-mermaid"
[ "$REQUIRE_MERMAID" = "true" ] && ARGS="$ARGS --require-mermaid"
[ "$KEEP_HTML"       = "true" ] && ARGS="$ARGS --keep-html"
[ "$CHECK_ONLY"      = "true" ] && ARGS="$ARGS --check-only"

python3 "$CLAUDE_PLUGIN_ROOT/scripts/export_pdf.py" $ARGS
```

If `INPUT_MD` was not explicitly set by the user but `OUTPUT_DIR` was,
default `INPUT_MD` to `$OUTPUT_DIR/threat-model.md` before passing it on.

Capture the helper's exit code and propagate it. Do not add any commentary
to the output — the helper's stderr (preflight table, mermaid stats,
written-bytes line) is the deliverable.

### Exit codes propagated from the helper

  0  PDF written successfully (or `--check-only` and preflight passed)
  1  hard dependency missing or non-functional (pandoc / weasyprint)
  2  input Markdown file not found
  3  conversion error during pandoc or weasyprint

## Step 3 — (No step 3)

The helper's output is the skill's output. Exit.
