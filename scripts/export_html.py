#!/usr/bin/env python3
"""export_html.py — convert threat-model.md to a standalone HTML file.

Standalone tool. Companion to export_pdf.py — same Mermaid pre-pass and
pandoc invocation, but stops at HTML (no weasyprint step). The output is a
single self-contained HTML5 file with CSS embedded via pandoc's
--embed-resources flag, suitable for direct browser viewing, internal wiki
attachments, or hand-off to a styling pipeline.

Pipeline:
  1. Pre-process Mermaid blocks (same logic as export_pdf.py). When mmdc is
     available, each ```mermaid``` block is rendered to an inline SVG; when
     missing, blocks stay as code.
  2. Pandoc Markdown → standalone HTML5 with print.css embedded.

Hard dependency (preflight aborts if missing):
  - pandoc          (apt install pandoc / brew install pandoc)

Optional dependency:
  - mmdc            (npm install -g @mermaid-js/mermaid-cli)
                    Without it, Mermaid blocks render as <pre><code>.

Exit codes:
  0  success
  1  missing hard dependency (pandoc)
  2  input file not found / bad arguments
  3  conversion error (pandoc or mmdc failure)
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

try:
    from _atomic_io import atomic_write_text
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent))
    from _atomic_io import atomic_write_text  # noqa: E402

# Re-use the helpers from export_pdf.py so the Mermaid handling, vscode://
# rewrite, and pandoc invocation stay byte-identical between PDF and HTML.
try:
    from export_pdf import (  # noqa: E402
        INSTALL_HINTS,
        _inject_table_colgroups,
        check_tool,
        md_to_html,
        probe_mmdc,
        probe_runs,
        render_mermaid_blocks,
        rewrite_vscode_links,
        stage_relative_images,
    )
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent))
    from export_pdf import (  # noqa: E402
        INSTALL_HINTS,
        _inject_table_colgroups,
        check_tool,
        md_to_html,
        probe_mmdc,
        probe_runs,
        render_mermaid_blocks,
        rewrite_vscode_links,
        stage_relative_images,
    )


DEFAULT_INPUT_REL = "docs/security/threat-model.md"


def preflight(require_mermaid: bool) -> tuple[bool, list[str]]:
    """Probe required tools. Returns (ok, messages).

    Differs from `export_pdf.preflight()` by requiring only pandoc — HTML
    output does not depend on weasyprint.
    """
    messages: list[str] = []
    ok = True

    path = check_tool("pandoc")
    if not path:
        ok = False
        messages.append("  [miss] pandoc      not found")
        messages.append(f"           install: {INSTALL_HINTS['pandoc']}")
    else:
        runs, info = probe_runs("pandoc")
        if runs:
            messages.append(f"  [ok]   pandoc      {path}  ({info})")
        else:
            ok = False
            messages.append(f"  [bad]  pandoc      {path}  — found but does not run")
            messages.append(f"           error:   {info}")
            messages.append(f"           install: {INSTALL_HINTS['pandoc']}")

    mmdc_path = check_tool("mmdc")
    if not mmdc_path:
        if require_mermaid:
            ok = False
            messages.append("  [miss] mmdc        not found (required by --require-mermaid)")
            messages.append(f"           install: {INSTALL_HINTS['mmdc']}")
        else:
            messages.append("  [skip] mmdc        not found — Mermaid blocks will stay as code")
    elif require_mermaid:
        # `which mmdc` is insufficient: mmdc shells out to Puppeteer/Chrome,
        # and a missing or blocked browser would leave every diagram as raw
        # code even though the binary exists. Match the PDF exporter's hard
        # preflight when the caller explicitly requires Mermaid graphics.
        can_render, info = probe_mmdc()
        if can_render:
            messages.append(f"  [ok]   mmdc        {mmdc_path}  ({info})")
        else:
            ok = False
            messages.append(f"  [bad]  mmdc        {mmdc_path}  — {info}")
            messages.append(f"           install: {INSTALL_HINTS['mmdc']}")
            messages.append("           or re-run with --no-mermaid to export without diagrams")
    else:
        messages.append(f"  [ok]   mmdc        {mmdc_path}")

    return ok, messages


def export_html(
    input_md: Path,
    output_html: Path,
    *,
    use_mermaid: bool,
    css_path: Path,
) -> int:
    md_text = input_md.read_text(encoding="utf-8")
    md_text = rewrite_vscode_links(md_text)

    with tempfile.TemporaryDirectory(prefix="export-html-") as tmp:
        work = Path(tmp)

        if use_mermaid and check_tool("mmdc"):
            # SVG, not PNG: HTML is rendered by a browser (no WeasyPrint), which
            # handles mermaid SVG faithfully, and the embedded vector asset is a
            # fraction of the 2× PNG's size. The shared PDF renderer defaults to
            # PNG for WeasyPrint's sake — this path opts into SVG explicitly.
            md_text, rendered, failed = render_mermaid_blocks(md_text, work, fmt="svg")
            sys.stderr.write(f"[export_html] mermaid: {rendered} rendered, {failed} failed\n")

        # Stage relative image assets (e.g. the hand-built figure1.svg) from the
        # document's own directory into the work dir, so pandoc — whose
        # --resource-path points at the work dir (the temp pre.md's parent) —
        # can embed them. Without this the standalone HTML export fails with
        # "File threat-model.figure1.svg not found in resource path" (pandoc
        # exit 99). export_pdf.py already does this; the HTML path omitted it.
        staged = stage_relative_images(md_text, input_md.parent, work)
        if staged:
            sys.stderr.write(f"[export_html] staged {staged} relative image asset(s)\n")

        pre_md = work / "pre.md"
        pre_md.write_text(md_text, encoding="utf-8")

        html_tmp = work / "out.html"
        title = input_md.stem.replace("-", " ").title()
        md_to_html(pre_md, html_tmp, css_path, title)

        # Content-aware table column widths. print.css sets `table-layout:
        # fixed`, but pandoc/gfm drops the pipe-table dash hints, so WITHOUT an
        # explicit <colgroup> the browser distributes every column EQUALLY — a
        # 1-char "#" / "Code" column ends up as wide as a prose Description
        # column, wasting horizontal space and cramping the long cells. The PDF
        # export already injects these widths (export_pdf.py); reuse the exact
        # same helper here so the standalone HTML gets the same sensible,
        # content-proportional distribution. Idempotent: the helper skips any
        # <table> that already carries a <colgroup>.
        html_out = _inject_table_colgroups(html_tmp.read_text(encoding="utf-8"))

        # Atomic copy from the work dir to the final destination.
        atomic_write_text(output_html, html_out)

    size = output_html.stat().st_size
    sys.stderr.write(f"[export_html] wrote {output_html} ({size} bytes)\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="export_html.py",
        description="Convert threat-model.md to a standalone threat-model.html",
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help=f"Input Markdown file (default: ./{DEFAULT_INPUT_REL})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output HTML file (default: same dir as input, .html extension)",
    )
    parser.add_argument(
        "--no-mermaid",
        action="store_true",
        help="Skip Mermaid SVG pre-rendering even if mmdc is installed",
    )
    parser.add_argument(
        "--require-mermaid",
        action="store_true",
        help="Fail preflight if mmdc is not installed (default: warn and skip)",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Run preflight only, do not convert",
    )
    args = parser.parse_args(argv)

    ok, messages = preflight(require_mermaid=args.require_mermaid)
    sys.stderr.write("[export_html] preflight:\n")
    for m in messages:
        sys.stderr.write(m + "\n")
    if not ok:
        sys.stderr.write("[export_html] missing hard dependency — aborting.\n")
        return 1
    if args.check_only:
        sys.stderr.write("[export_html] preflight ok (check-only).\n")
        return 0

    input_md = args.input or Path.cwd() / DEFAULT_INPUT_REL
    if not input_md.is_file():
        sys.stderr.write(
            f"[export_html] input file not found: {input_md}\n"
            f"             run /appsec-advisor:create-threat-model first, or pass --input.\n"
        )
        return 2

    output_html = args.output or input_md.with_suffix(".html")
    output_html.parent.mkdir(parents=True, exist_ok=True)

    css_path = Path(__file__).parent / "assets" / "print.css"
    if not css_path.is_file():
        sys.stderr.write(f"[export_html] print.css missing at {css_path}\n")
        return 3

    try:
        return export_html(
            input_md=input_md,
            output_html=output_html,
            use_mermaid=not args.no_mermaid,
            css_path=css_path,
        )
    except RuntimeError as exc:
        sys.stderr.write(f"[export_html] conversion failed: {exc}\n")
        return 3


if __name__ == "__main__":
    sys.exit(main())
