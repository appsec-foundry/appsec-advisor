#!/usr/bin/env python3
"""export_pdf.py — convert threat-model.md to threat-model.pdf.

Standalone tool. Independent of the create-threat-model rendering pipeline:
takes a finished Markdown file as input, produces a PDF as output.

Pipeline:
  1. Pre-process Mermaid blocks: render each ```mermaid``` fenced block to an
     SVG via mmdc (mermaid-cli), replace the block with an <img> reference.
     Skipped when mmdc is not installed or --no-mermaid is passed; diagrams
     then remain as code blocks in the PDF.
  2. Pandoc Markdown → standalone HTML5 with print.css embedded.
  3. WeasyPrint HTML → PDF (atomic write).

Hard dependencies (preflight aborts if missing):
  - pandoc          (apt install pandoc / brew install pandoc)
  - weasyprint      (pip install weasyprint)

Optional dependency:
  - mmdc            (npm install -g @mermaid-js/mermaid-cli)
                    Without it, Mermaid blocks render as <pre><code>.

Exit codes:
  0  success
  1  missing hard dependency (pandoc or weasyprint)
  2  input file not found / bad arguments
  3  conversion error (pandoc, weasyprint, or mmdc failure)
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

try:
    from _atomic_io import atomic_write_text
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent))
    from _atomic_io import atomic_write_text  # noqa: E402


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

INSTALL_HINTS = {
    "pandoc": "apt install pandoc   |   brew install pandoc   |   https://pandoc.org/installing.html",
    "weasyprint": "pip install weasyprint   (also needs Pango/Cairo system libs on Linux)",
    "mmdc": "npm install -g @mermaid-js/mermaid-cli   (optional — without it, Mermaid blocks remain code blocks)",
}


def check_tool(name: str) -> Optional[str]:
    """Return the absolute path of `name` on PATH, or None if missing."""
    return shutil.which(name)


def probe_runs(name: str) -> tuple[bool, str]:
    """Run `<name> --version` and return (ok, short_error_or_version_line).

    Catches the case where the binary is on PATH but its system libraries
    (e.g. WeasyPrint missing libpango/cairo) are not — `which` would still
    say "ok", but every actual conversion would crash.
    """
    try:
        result = subprocess.run([name, "--version"], capture_output=True, text=True, timeout=10)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return False, f"could not invoke: {exc}"
    if result.returncode != 0:
        # Take the last non-empty line from stderr — that's typically the
        # OSError or library-load message.
        err_lines = [ln for ln in (result.stderr or "").splitlines() if ln.strip()]
        return False, err_lines[-1] if err_lines else f"exit {result.returncode}"
    out_lines = [ln for ln in (result.stdout or "").splitlines() if ln.strip()]
    return True, out_lines[0] if out_lines else "ok"


def preflight(require_mermaid: bool) -> tuple[bool, list[str]]:
    """Probe required tools. Returns (ok, messages).

    `ok=False` only when a hard dependency is missing or non-functional.
    Mermaid is soft — a missing mmdc only produces a warning unless
    `require_mermaid=True`.
    """
    messages: list[str] = []
    ok = True

    for hard in ("pandoc", "weasyprint"):
        path = check_tool(hard)
        if not path:
            ok = False
            messages.append(f"  [miss] {hard:<11} not found")
            messages.append(f"           install: {INSTALL_HINTS[hard]}")
            continue
        runs, info = probe_runs(hard)
        if runs:
            messages.append(f"  [ok]   {hard:<11} {path}  ({info})")
        else:
            ok = False
            messages.append(f"  [bad]  {hard:<11} {path}  — found but does not run")
            messages.append(f"           error:   {info}")
            messages.append(f"           install: {INSTALL_HINTS[hard]}")

    mmdc_path = check_tool("mmdc")
    if mmdc_path:
        messages.append(f"  [ok]   mmdc        {mmdc_path}")
    else:
        if require_mermaid:
            ok = False
            messages.append("  [miss] mmdc        not found (required by --require-mermaid)")
            messages.append(f"           install: {INSTALL_HINTS['mmdc']}")
        else:
            messages.append("  [skip] mmdc        not found — Mermaid blocks will stay as code")

    return ok, messages


# ---------------------------------------------------------------------------
# Mermaid pre-pass
# ---------------------------------------------------------------------------

# A fenced ```mermaid block. Group(1) = the diagram source.
MERMAID_FENCE_RE = re.compile(
    r"^```mermaid[ \t]*\r?\n(.*?)^```[ \t]*$",
    re.DOTALL | re.MULTILINE,
)


MMDC_FAIL_FAST_THRESHOLD = 3


def render_mermaid_blocks(md_text: str, work_dir: Path) -> tuple[str, int, int]:
    """Replace each ```mermaid block with an <img> tag pointing at an SVG.

    Returns (rewritten_md, rendered_count, failed_count).

    A block that fails to render is left as-is in the Markdown so the PDF
    still contains the diagram source rather than a missing image.

    Once `MMDC_FAIL_FAST_THRESHOLD` consecutive failures occur (typical case:
    Puppeteer's Chrome binary is missing, every block will fail the same way)
    we stop calling mmdc altogether and let remaining blocks pass through.
    Saves ~1s startup per remaining diagram and 14× the same stack trace in
    the log.
    """
    counter = {"n": 0, "rendered": 0, "failed": 0}
    first_error: list[str] = []
    bail_out = [False]

    def replace(match: re.Match) -> str:
        counter["n"] += 1
        n = counter["n"]
        if bail_out[0]:
            counter["failed"] += 1
            return match.group(0)
        source = match.group(1)
        mmd_path = work_dir / f"diagram-{n}.mmd"
        svg_path = work_dir / f"diagram-{n}.svg"
        mmd_path.write_text(source, encoding="utf-8")
        try:
            subprocess.run(
                [
                    "mmdc",
                    "-i",
                    str(mmd_path),
                    "-o",
                    str(svg_path),
                    "-b",
                    "transparent",
                    "-q",
                ],
                check=True,
                capture_output=True,
                timeout=60,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            counter["failed"] += 1
            if not first_error:
                stderr = getattr(exc, "stderr", b"") or b""
                if isinstance(stderr, bytes):
                    stderr = stderr.decode("utf-8", errors="replace")
                first_error.append(stderr.strip().splitlines()[-1] if stderr.strip() else str(exc))
                sys.stderr.write(f"[export_pdf] mmdc failed on diagram {n}: {first_error[0]}\n")
            if counter["failed"] >= MMDC_FAIL_FAST_THRESHOLD and counter["rendered"] == 0:
                bail_out[0] = True
                sys.stderr.write(
                    f"[export_pdf] mmdc failed on first {MMDC_FAIL_FAST_THRESHOLD} diagrams — "
                    f"giving up, remaining blocks will stay as code\n"
                )
            return match.group(0)
        counter["rendered"] += 1
        return f"\n![Diagram {n}]({svg_path.name})\n"

    rewritten = MERMAID_FENCE_RE.sub(replace, md_text)
    return rewritten, counter["rendered"], counter["failed"]


# ---------------------------------------------------------------------------
# vscode:// link rewriting
# ---------------------------------------------------------------------------

VSCODE_LINK_RE = re.compile(r"vscode://file(/[^\s\)>\"']+)")


def rewrite_vscode_links(md_text: str) -> str:
    """vscode:// links are dead in PDFs (no PDF reader handles that scheme).

    Rewrite them to file:// so they at least encode the absolute path; the
    user can copy-paste from the PDF if they want to open the file.
    """
    return VSCODE_LINK_RE.sub(r"file://\1", md_text)


# ---------------------------------------------------------------------------
# Pandoc + WeasyPrint
# ---------------------------------------------------------------------------

PANDOC_FORMAT = "gfm+pipe_tables+task_lists+autolink_bare_uris"


def pandoc_supports_embed_resources() -> bool:
    """`--embed-resources` was added in pandoc 2.19.0 (Aug 2022).

    Older versions need the deprecated-but-equivalent `--self-contained`.
    Probe once, cache the result implicitly via the caller.
    """
    try:
        result = subprocess.run(["pandoc", "--version"], capture_output=True, text=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    if result.returncode != 0:
        return False
    first_line = result.stdout.strip().splitlines()[0] if result.stdout else ""
    match = re.search(r"pandoc\s+(\d+)\.(\d+)", first_line)
    if not match:
        return False
    major, minor = int(match.group(1)), int(match.group(2))
    return (major, minor) >= (2, 19)


def md_to_html(md_path: Path, html_path: Path, css_path: Path, title: str) -> None:
    embed_flag = "--embed-resources" if pandoc_supports_embed_resources() else "--self-contained"
    cmd = [
        "pandoc",
        str(md_path),
        "-f",
        PANDOC_FORMAT,
        "-t",
        "html5",
        "--standalone",
        embed_flag,
        f"--css={css_path}",
        "--metadata",
        f"title={title}",
        "-o",
        str(html_path),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"pandoc failed (exit {result.returncode}):\n{result.stderr.strip()}")


def html_to_pdf(html_path: Path, pdf_path: Path) -> None:
    """WeasyPrint writes the PDF directly. We rename atomically afterwards."""
    tmp_pdf = pdf_path.with_suffix(pdf_path.suffix + ".tmp")
    cmd = ["weasyprint", str(html_path), str(tmp_pdf)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        if tmp_pdf.exists():
            tmp_pdf.unlink()
        raise RuntimeError(f"weasyprint failed (exit {result.returncode}):\n{result.stderr.strip()}")
    tmp_pdf.replace(pdf_path)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

DEFAULT_INPUT_REL = "docs/security/threat-model.md"


def export_pdf(
    input_md: Path,
    output_pdf: Path,
    *,
    use_mermaid: bool,
    keep_html: bool,
    css_path: Path,
) -> int:
    md_text = input_md.read_text(encoding="utf-8")
    md_text = rewrite_vscode_links(md_text)

    with tempfile.TemporaryDirectory(prefix="export-pdf-") as tmp:
        work = Path(tmp)

        if use_mermaid and check_tool("mmdc"):
            md_text, rendered, failed = render_mermaid_blocks(md_text, work)
            sys.stderr.write(f"[export_pdf] mermaid: {rendered} rendered, {failed} failed\n")

        pre_md = work / "pre.md"
        pre_md.write_text(md_text, encoding="utf-8")

        html_path = work / "out.html"
        title = input_md.stem.replace("-", " ").title()
        md_to_html(pre_md, html_path, css_path, title)

        if keep_html:
            kept_html = output_pdf.with_suffix(".html")
            atomic_write_text(kept_html, html_path.read_text(encoding="utf-8"))
            sys.stderr.write(f"[export_pdf] kept intermediate HTML: {kept_html}\n")

        html_to_pdf(html_path, output_pdf)

    size = output_pdf.stat().st_size
    sys.stderr.write(f"[export_pdf] wrote {output_pdf} ({size} bytes)\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="export_pdf.py",
        description="Convert threat-model.md to threat-model.pdf",
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
        help="Output PDF file (default: same dir as input, .pdf extension)",
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
        "--keep-html",
        action="store_true",
        help="Also write the intermediate HTML next to the PDF (for debugging)",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Run preflight only, do not convert",
    )
    args = parser.parse_args(argv)

    ok, messages = preflight(require_mermaid=args.require_mermaid)
    sys.stderr.write("[export_pdf] preflight:\n")
    for m in messages:
        sys.stderr.write(m + "\n")
    if not ok:
        sys.stderr.write("[export_pdf] missing hard dependency — aborting.\n")
        return 1
    if args.check_only:
        sys.stderr.write("[export_pdf] preflight ok (check-only).\n")
        return 0

    input_md = args.input or Path.cwd() / DEFAULT_INPUT_REL
    if not input_md.is_file():
        sys.stderr.write(
            f"[export_pdf] input file not found: {input_md}\n"
            f"             run /appsec-advisor:create-threat-model first, or pass --input.\n"
        )
        return 2

    output_pdf = args.output or input_md.with_suffix(".pdf")
    output_pdf.parent.mkdir(parents=True, exist_ok=True)

    css_path = Path(__file__).parent / "assets" / "print.css"
    if not css_path.is_file():
        sys.stderr.write(f"[export_pdf] print.css missing at {css_path}\n")
        return 3

    try:
        return export_pdf(
            input_md=input_md,
            output_pdf=output_pdf,
            use_mermaid=not args.no_mermaid,
            keep_html=args.keep_html,
            css_path=css_path,
        )
    except RuntimeError as exc:
        sys.stderr.write(f"[export_pdf] conversion failed: {exc}\n")
        return 3


if __name__ == "__main__":
    sys.exit(main())
