---
name: export-threat-model
description: Re-export a finished threat-model.yaml/.md into PDF + HTML + SARIF + pentest-tasks artifacts. Standalone post-processing — does not analyze the repo, does not run any agent. SARIF and pentest-tasks are derived deterministically from threat-model.yaml; PDF and HTML are converted from threat-model.md (requires pandoc; PDF also needs weasyprint plus mmdc+Chrome for Mermaid diagrams, or --no-mermaid).
---

You are exporting an existing threat model into one or more artifact formats. This skill is **standalone post-processing** — do not analyze the repository, do not dispatch any agent, do not modify the source `threat-model.md` or `threat-model.yaml`. The skill reads those two files and writes the requested exports.

## `--help` — inline help (early exit)

If the user's arguments contain `--help` or `-h`, print this block verbatim and exit.

```
/appsec-advisor:export-threat-model — Re-export a threat model into PDF / HTML / SARIF / pentest-tasks.

USAGE
  /appsec-advisor:export-threat-model [FLAGS]

FLAGS
  --repo <path>            Repository to operate on (default: current working dir)
  --output <path>          Threat-model source directory — must contain
                           threat-model.md and/or threat-model.yaml from a
                           prior create-threat-model run
                           (default: <repo>/docs/security)
  --exports-dir <path>     Directory where the NEW export files are written
                           (default: same as --output — exports land next to
                           the source files)
  --input <path>           Markdown input for PDF/HTML export. Overrides
                           <output>/threat-model.md for markup exports.
  --output-pdf <path>      Exact PDF destination. Implies --formats pdf when
                           --formats is not explicitly provided.
  --formats <csv>          Comma-separated subset of: pdf, html, sarif, pentest, all
                           (default: all)
  --pentest-format <name>  Pentest dialect: generic|strix (default: generic)
  --pentest-target <url>   Optional base URL for the pentest target
  --no-mermaid             Skip Mermaid SVG pre-rendering for PDF/HTML
  --require-mermaid        Fail preflight if mmdc is not installed
  --keep-html              Keep intermediate HTML next to the PDF (debug; pdf only)
  --check-only             Run preflight checks only — do not write
  --help, -h               Show this help and exit

DEPENDENCIES (installed by the user, not by this plugin)
  pandoc        Required for PDF + HTML.  apt install pandoc | brew install pandoc
  weasyprint    Required for PDF only.    pip install weasyprint
  mmdc          Required for PDF Mermaid diagrams (optional for HTML).
                Also needs a Chrome/Chromium for Puppeteer.
                npm install -g @mermaid-js/mermaid-cli
                + npx puppeteer browsers install chrome   (or apt install
                chromium and set PUPPETEER_EXECUTABLE_PATH)
                PDF aborts if missing; pass --no-mermaid to skip diagrams.
  pyyaml        Required for SARIF + pentest. apt install python3-yaml | pip install pyyaml

OUTPUTS
  <exports-dir>/threat-model.pdf           (when pdf ∈ formats)
  <exports-dir>/threat-model.html          (when html ∈ formats)
  <exports-dir>/threat-model.sarif.json    (when sarif ∈ formats)
  <exports-dir>/pentest-tasks.yaml         (when pentest ∈ formats)

EXAMPLES
  /appsec-advisor:export-threat-model
  /appsec-advisor:export-threat-model --formats sarif,pentest
  /appsec-advisor:export-threat-model --formats html
  /appsec-advisor:export-threat-model --formats pdf --no-mermaid
  /appsec-advisor:export-threat-model --formats pdf --input ./report.md --output-pdf ./report.pdf
  /appsec-advisor:export-threat-model --pentest-target https://staging.example.com
  /appsec-advisor:export-threat-model --check-only

The skill is idempotent and side-effect-free apart from writing the requested
exports. It never dispatches agents and never spends LLM tokens.

EXIT CODES
  0  All requested exports written (or --check-only succeeded)
  1  Missing dependency (pandoc / weasyprint / mmdc+Chrome / pyyaml)
  2  Input file not found (threat-model.md or .yaml)
  3  threat-model.yaml is schema-invalid
  4  Conversion error from one of the helpers
```

After printing, exit.

## Step 1 — Parse arguments

Recognized flags:

  `--repo <path>`  `--output <path>`  `--exports-dir <path>`
  `--input <path>`  `--output-pdf <path>`  `--formats <csv>`
  `--pentest-format <name>`  `--pentest-target <url>`
  `--no-mermaid`  `--require-mermaid`  `--keep-html`  `--check-only`
  `--help` | `-h`

Parse these and set `REPO_ROOT`, `OUTPUT_DIR`, `EXPORTS_DIR`, `INPUT_MD_OVERRIDE`, `OUTPUT_PDF_OVERRIDE`, `FORMATS`, `FORMATS_EXPLICIT`, `PENTEST_FORMAT`, `PENTEST_TARGET_URL`, `NO_MERMAID`, `REQUIRE_MERMAID`, `KEEP_HTML`, `CHECK_ONLY`.

Defaults:
- `REPO_ROOT` → current working directory
- `OUTPUT_DIR` → `$REPO_ROOT/docs/security`
- `EXPORTS_DIR` → `$OUTPUT_DIR` (same dir)
- `INPUT_MD_OVERRIDE` → unset (use `$OUTPUT_DIR/threat-model.md`)
- `OUTPUT_PDF_OVERRIDE` → unset (use `$EXPORTS_DIR/threat-model.pdf`)
- `FORMATS` → `pdf,html,sarif,pentest` (when `all`, or no `--formats` flag)
- `PENTEST_FORMAT` → `generic`
- `PENTEST_TARGET_URL` → unset

If `--output-pdf` is provided and `--formats` is not provided, set
`FORMATS=pdf` so the single-output PDF workflow remains available through
this skill.

### Reject unknown arguments (hard fail)

If the invocation contains **any** token that is not one of the recognized flags above — or is not the value consumed by a flag that takes a value — DO NOT proceed. Print the help block (see Step `--help`) to stderr and exit with status `2`.

## Step 2 — Resolve and validate formats

Normalize `FORMATS`:
- Split on comma, lowercase, strip whitespace.
- `all` (any element) → `pdf,html,sarif,pentest`.
- Reject any token that is not in `{pdf, html, sarif, pentest, all}` with a clear error and exit `2`.

Set boolean flags `DO_PDF`, `DO_HTML`, `DO_SARIF`, `DO_PENTEST` from the resolved set.

## Step 3 — Preflight

For each requested format, verify the inputs and dependencies exist. Print each line as you check.

```bash
INPUT_MD="$OUTPUT_DIR/threat-model.md"
INPUT_YAML="$OUTPUT_DIR/threat-model.yaml"
[ -n "$INPUT_MD_OVERRIDE" ] && INPUT_MD="$INPUT_MD_OVERRIDE"
mkdir -p "$EXPORTS_DIR"

PREFLIGHT_FAIL=0

# Yaml needed for sarif + pentest
if [ "$DO_SARIF" = "true" ] || [ "$DO_PENTEST" = "true" ]; then
  if [ ! -f "$INPUT_YAML" ]; then
    echo "ERROR: threat-model.yaml not found at $INPUT_YAML" >&2
    PREFLIGHT_FAIL=2
  else
    python3 "$CLAUDE_PLUGIN_ROOT/scripts/validate_intermediate.py" \
      threat_model_output "$INPUT_YAML" >/dev/null 2>&1 || {
        echo "ERROR: threat-model.yaml is schema-invalid (run validate_intermediate.py for details)" >&2
        PREFLIGHT_FAIL=3
      }
  fi
fi

# Markdown needed for pdf and html
if { [ "$DO_PDF" = "true" ] || [ "$DO_HTML" = "true" ]; } && [ ! -f "$INPUT_MD" ]; then
  echo "ERROR: threat-model.md not found at $INPUT_MD" >&2
  PREFLIGHT_FAIL=2
fi

# PDF dependencies — delegate to export_pdf.py --check-only (pandoc + weasyprint)
if [ "$DO_PDF" = "true" ]; then
  PDF_CHECK_ARGS="--check-only --input $INPUT_MD"
  [ "$NO_MERMAID"      = "true" ] && PDF_CHECK_ARGS="$PDF_CHECK_ARGS --no-mermaid"
  [ "$REQUIRE_MERMAID" = "true" ] && PDF_CHECK_ARGS="$PDF_CHECK_ARGS --require-mermaid"
  python3 "$CLAUDE_PLUGIN_ROOT/scripts/export_pdf.py" $PDF_CHECK_ARGS || PREFLIGHT_FAIL=1
fi

# HTML dependencies — delegate to export_html.py --check-only (pandoc only)
if [ "$DO_HTML" = "true" ]; then
  HTML_CHECK_ARGS="--check-only --input $INPUT_MD"
  [ "$NO_MERMAID"      = "true" ] && HTML_CHECK_ARGS="$HTML_CHECK_ARGS --no-mermaid"
  [ "$REQUIRE_MERMAID" = "true" ] && HTML_CHECK_ARGS="$HTML_CHECK_ARGS --require-mermaid"
  python3 "$CLAUDE_PLUGIN_ROOT/scripts/export_html.py" $HTML_CHECK_ARGS || PREFLIGHT_FAIL=1
fi

[ "$PREFLIGHT_FAIL" != "0" ] && exit "$PREFLIGHT_FAIL"
[ "$CHECK_ONLY" = "true" ] && { echo "Preflight passed."; exit 0; }
```

## Step 4 — Run exports

Execute the requested format helpers in order: SARIF → pentest → HTML → PDF (markup outputs last). Each helper's exit code propagates the first non-zero result back to the user.

**Run the HTML/PDF helpers UNSANDBOXED.** Mermaid rendering (used by both `export_html.py` and `export_pdf.py`) shells out to a headless Chrome via mmdc/Puppeteer, whose `process_singleton` calls `socket()` at launch — a syscall the Bash sandbox blocks (`Operation not permitted`, EPERM, path-independent). Sandboxed, `export_pdf.py` aborts with "Mermaid renderer cannot run …" and writes **no** PDF (a diagram-less PDF is a broken deliverable, not a silent fallback). Dispatch this block with the **sandbox disabled** so diagrams render. The abort message means the sandbox — re-run unsandboxed; do **not** reach for `--no-mermaid` (that is only for a deliberately diagram-less export).

```bash
EXIT_CODE=0

if [ "$DO_SARIF" = "true" ]; then
  python3 "$CLAUDE_PLUGIN_ROOT/scripts/export_sarif.py" \
    --threat-model "$INPUT_YAML" \
    --output       "$EXPORTS_DIR/threat-model.sarif.json" \
    || EXIT_CODE=4
fi

if [ "$DO_PENTEST" = "true" ] && [ "$EXIT_CODE" = "0" ]; then
  PENTEST_ARGS="--threat-model $INPUT_YAML \
                --output $EXPORTS_DIR/pentest-tasks.yaml \
                --dialect $PENTEST_FORMAT"
  [ -n "$PENTEST_TARGET_URL" ] && PENTEST_ARGS="$PENTEST_ARGS --target-url $PENTEST_TARGET_URL"
  python3 "$CLAUDE_PLUGIN_ROOT/scripts/render_pentest_tasks.py" $PENTEST_ARGS \
    || EXIT_CODE=4
fi

if [ "$DO_HTML" = "true" ] && [ "$EXIT_CODE" = "0" ]; then
  HTML_ARGS="--input $INPUT_MD \
             --output $EXPORTS_DIR/threat-model.html"
  [ "$NO_MERMAID"      = "true" ] && HTML_ARGS="$HTML_ARGS --no-mermaid"
  [ "$REQUIRE_MERMAID" = "true" ] && HTML_ARGS="$HTML_ARGS --require-mermaid"
  python3 "$CLAUDE_PLUGIN_ROOT/scripts/export_html.py" $HTML_ARGS \
    || EXIT_CODE=4
fi

if [ "$DO_PDF" = "true" ] && [ "$EXIT_CODE" = "0" ]; then
  OUTPUT_PDF="$EXPORTS_DIR/threat-model.pdf"
  [ -n "$OUTPUT_PDF_OVERRIDE" ] && OUTPUT_PDF="$OUTPUT_PDF_OVERRIDE"
  mkdir -p "$(dirname "$OUTPUT_PDF")"
  PDF_ARGS="--input $INPUT_MD \
            --output $OUTPUT_PDF"
  [ "$NO_MERMAID"      = "true" ] && PDF_ARGS="$PDF_ARGS --no-mermaid"
  [ "$REQUIRE_MERMAID" = "true" ] && PDF_ARGS="$PDF_ARGS --require-mermaid"
  [ "$KEEP_HTML"       = "true" ] && PDF_ARGS="$PDF_ARGS --keep-html"
  python3 "$CLAUDE_PLUGIN_ROOT/scripts/export_pdf.py" $PDF_ARGS \
    || EXIT_CODE=4
fi

exit "$EXIT_CODE"
```

## Step 5 — (No step 5)

The helpers' stdout/stderr is the deliverable. Do not add commentary.
