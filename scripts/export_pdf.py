#!/usr/bin/env python3
"""export_pdf.py — convert threat-model.md to threat-model.pdf.

Standalone tool. Independent of the create-threat-model rendering pipeline:
takes a finished Markdown file as input, produces a PDF as output.

Pipeline:
  1. Pre-process Mermaid blocks: render each ```mermaid``` fenced block to a
     PNG via mmdc (mermaid-cli), replace the block with an <img> reference.
     Skipped when mmdc is not installed or --no-mermaid is passed; diagrams
     then remain as code blocks in the PDF.
  2. Pandoc Markdown → standalone HTML5 with print.css embedded.
  3. Post-process the HTML: content-aware table column widths, a dedicated
     cover page (title + metadata), and a page-numbered table of contents
     (WeasyPrint target-counter; broken TOC anchors degrade gracefully).
  4. WeasyPrint HTML → PDF (atomic write).

Hard dependencies (preflight aborts if missing):
  - pandoc          (apt install pandoc / brew install pandoc)
  - weasyprint      (pip install weasyprint)
  - mmdc + Chrome   (npm install -g @mermaid-js/mermaid-cli, plus a Chrome/
                    Chromium for Puppeteer). Required by default so diagrams
                    render as graphics, not raw code. Pass --no-mermaid to
                    export without diagrams when no Chrome/mmdc is available.

Exit codes:
  0  success
  1  missing hard dependency (pandoc, weasyprint, or mmdc/Chrome)
  2  input file not found / bad arguments
  3  conversion error (pandoc, weasyprint, or mmdc failure)
"""

from __future__ import annotations

import argparse
import json
import os
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
    "mmdc": (
        "npm install -g @mermaid-js/mermaid-cli   AND a Chrome/Chromium for Puppeteer "
        "(e.g. `npx puppeteer browsers install chrome`, or apt install chromium and set "
        "PUPPETEER_EXECUTABLE_PATH)"
    ),
}

# Puppeteer (used by mmdc) looks for its own cached Chrome and ignores a
# system browser unless PUPPETEER_EXECUTABLE_PATH points at one. Probe the
# common system binaries so a plain `apt install chromium` / `google-chrome`
# is enough without the user exporting that variable by hand.
CHROME_CANDIDATES = (
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
    "chrome",
)


def find_chrome() -> Optional[str]:
    """Resolve a Chrome/Chromium for Puppeteer, honouring an explicit env var."""
    env = os.environ.get("PUPPETEER_EXECUTABLE_PATH")
    if env and Path(env).exists():
        return env
    for name in CHROME_CANDIDATES:
        path = shutil.which(name)
        if path:
            return path
    return None


def mmdc_env() -> dict:
    """Environment for mmdc subprocesses with PUPPETEER_EXECUTABLE_PATH set.

    If the user already exported the variable we leave it untouched; otherwise
    we point Puppeteer at a system Chrome when one is on PATH.
    """
    env = os.environ.copy()
    if not env.get("PUPPETEER_EXECUTABLE_PATH"):
        chrome = find_chrome()
        if chrome:
            env["PUPPETEER_EXECUTABLE_PATH"] = chrome
    return env


# Headless-Chrome flags that a server / WSL / root / CI environment needs.
# Without `--no-sandbox` Chrome 11x aborts at launch on most non-desktop hosts
# ("Failed to launch the browser process"); the rest avoid GPU + /dev/shm +
# crash-reporter writes that fail under restricted filesystems. Pointing
# Puppeteer at the system Chrome via `executablePath` also fixes the common
# "Could not find Chrome (ver. …)" when no puppeteer-cached browser exists.
_MMDC_CHROME_ARGS = [
    "--no-sandbox",
    "--disable-gpu",
    "--disable-dev-shm-usage",
    "--disable-crash-reporter",
    "--no-first-run",
    "--disable-extensions",
]
# Mermaid render config. Diagrams are rendered to PNG by mmdc (headless Chrome)
# and embedded as raster images — see `render_mermaid_blocks`. This is CRITICAL:
# WeasyPrint cannot faithfully rasterise mermaid's SVG. A flowchart with
# subgraphs emits nodes nested in `<g transform=…>` cluster groups that
# WeasyPrint silently DROPS — the rendered PDF shows the subgraph boxes + titles
# but loses the inner nodes and edges entirely (Figure 1 / Figure 2 "kaputt").
# An earlier workaround forced `htmlLabels:false` to dodge WeasyPrint's missing
# `<foreignObject>` support, but that only fixed label text — the cluster-node
# drop and FontAwesome `fa:` icons / `<i>` italics leaking as literal text
# remained. Rendering to PNG via Chrome sidesteps EVERY WeasyPrint SVG gap at
# once (foreignObject, cluster transforms, ELK layout, icons), so html labels
# stay ON for full fidelity (icons, italics, badge dots all render).
_MMDC_MERMAID_CONFIG = {
    "themeVariables": {"fontFamily": "DejaVu Sans, Arial, sans-serif"},
}
_MMDC_RENDER_ARGS: list[str] = []


def mmdc_render_args() -> list[str]:
    """Return the extra mmdc flags every render needs:

      * ``-p <puppeteer.json>`` — system Chrome + headless-server launch flags
        (``--no-sandbox`` etc.) so Chrome actually starts on WSL / root / CI.
      * ``-c <mermaid.json>`` — theme font family (html labels stay ON; the PDF
        embeds PNGs rendered by Chrome, so WeasyPrint's SVG gaps never apply).

    Both temp configs are written once per process and cached. Returns the
    subset it could write; a temp-file failure degrades to mmdc's defaults
    (prior behaviour) rather than aborting the export.
    """
    if _MMDC_RENDER_ARGS:
        return _MMDC_RENDER_ARGS
    pptr_cfg: dict = {"args": list(_MMDC_CHROME_ARGS)}
    chrome = find_chrome()
    if chrome:
        pptr_cfg["executablePath"] = chrome
    for flag, cfg, prefix in (
        ("-p", pptr_cfg, "mmdc-pptr-"),
        ("-c", _MMDC_MERMAID_CONFIG, "mmdc-mmd-"),
    ):
        try:
            fd, path = tempfile.mkstemp(prefix=prefix, suffix=".json")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(cfg, fh)
        except OSError:
            continue
        _MMDC_RENDER_ARGS.extend([flag, path])
    return _MMDC_RENDER_ARGS


def probe_mmdc() -> tuple[bool, str]:
    """Actually render a trivial diagram to verify mmdc *works*.

    `which mmdc` is not enough: mmdc shells out to a headless Chrome via
    Puppeteer, and a missing or non-functional Chrome makes every real diagram
    fail at runtime (the diagram silently degrades to a raw code block). This
    render probe is the only reliable way to catch that before conversion.

    Returns (ok, info) — info is a short human-readable status or error tail.
    """
    with tempfile.TemporaryDirectory(prefix="export-pdf-mmdc-probe-") as tmp:
        src = Path(tmp) / "probe.mmd"
        out = Path(tmp) / "probe.svg"
        src.write_text("graph TD\n  A --> B\n", encoding="utf-8")
        try:
            result = subprocess.run(
                ["mmdc", "-i", str(src), "-o", str(out), "-q", *mmdc_render_args()],
                capture_output=True,
                text=True,
                timeout=90,
                env=mmdc_env(),
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return False, f"render probe failed: {exc}"
        if result.returncode != 0 or not out.exists() or out.stat().st_size == 0:
            tail = [ln for ln in (result.stderr or "").splitlines() if ln.strip()]
            hint = tail[-1] if tail else f"exit {result.returncode}"
            return False, f"present but cannot render (missing/broken Chrome for Puppeteer): {hint}"
        return True, f"render probe ok via {find_chrome() or 'puppeteer chrome'}"


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
    if not mmdc_path:
        if require_mermaid:
            ok = False
            messages.append("  [miss] mmdc        not found — needed to render Mermaid diagrams")
            messages.append(f"           install: {INSTALL_HINTS['mmdc']}")
            messages.append("           or re-run with --no-mermaid to export without diagrams")
        else:
            messages.append("  [skip] mmdc        --no-mermaid set — diagrams will stay as code")
    elif require_mermaid:
        # `which mmdc` lies: mmdc needs a headless Chrome (via Puppeteer), and a
        # missing Chrome makes every diagram fail at runtime. Probe for real.
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


# ---------------------------------------------------------------------------
# Mermaid pre-pass
# ---------------------------------------------------------------------------

# A fenced ```mermaid block. Group(1) = the diagram source.
MERMAID_FENCE_RE = re.compile(
    r"^```mermaid[ \t]*\r?\n(.*?)^```[ \t]*$",
    re.DOTALL | re.MULTILINE,
)


MMDC_FAIL_FAST_THRESHOLD = 3

# Each mmdc invocation boots Node + Puppeteer + headless Chrome (~2-5 s);
# the rendering itself is milliseconds. A real report carries 20+ diagrams,
# so serial invocation costs minutes of pure Chrome startup. Rendering is
# subprocess-bound, so a small thread pool gives a near-linear speedup.
MMDC_PARALLEL_WORKERS = 4


def _mermaid_scale() -> int:
    """Puppeteer deviceScaleFactor for PNG rendering.

    mmdc parses ``--scale`` with ``parseInt``, so only integers take effect
    (1.5 silently truncates to 1). 2× keeps diagrams crisp when WeasyPrint
    scales them to page width; `_optimize_png` reclaims most of the byte cost
    without touching sharpness. Set ``APPSEC_MERMAID_SCALE=1`` for a smaller
    (softer) PDF.
    """
    try:
        return max(1, int(os.environ.get("APPSEC_MERMAID_SCALE", "2")))
    except ValueError:
        return 2


def _optimize_png(path: Path) -> None:
    """Best-effort shrink of a rendered PNG, in place.

    pngquant (palette quant, ~50-70% smaller, visually near-lossless) if on
    PATH, else oxipng (lossless). Both optional — a missing tool or a failed
    run is non-fatal and leaves the original PNG untouched. Only used on the
    PDF path; the HTML path renders SVG and never reaches here.
    """
    candidates = (
        ["pngquant", "--force", "--skip-if-larger", "--output", str(path), str(path)],
        ["oxipng", "-q", "-o", "2", str(path)],
    )
    for cmd in candidates:
        if shutil.which(cmd[0]):
            try:
                subprocess.run(cmd, check=True, capture_output=True, timeout=30)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass
            return


def _render_one_mermaid(
    n: int, source: str, work_dir: Path, fmt: str = "png"
) -> tuple[bool, str, str]:
    """Render block *n* via mmdc. Returns (ok, replacement_md, error_line).

    ``fmt`` is ``"png"`` (PDF path — WeasyPrint drops subgraph-nested SVG nodes,
    so it needs a bitmap) or ``"svg"`` (HTML path — browsers render mermaid SVG
    faithfully and the vector asset is ~10-20× smaller than the 2× PNG).
    """
    mmd_path = work_dir / f"diagram-{n}.mmd"
    out_path = work_dir / f"diagram-{n}.{fmt}"
    mmd_path.write_text(source, encoding="utf-8")
    cmd = ["mmdc", "-i", str(mmd_path), "-o", str(out_path)]
    if fmt == "png":
        cmd += ["-s", str(_mermaid_scale())]
    cmd += ["-b", "white", "-q", *mmdc_render_args()]
    try:
        subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            timeout=60,
            env=mmdc_env(),
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        stderr = getattr(exc, "stderr", b"") or b""
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        error_line = stderr.strip().splitlines()[-1] if stderr.strip() else str(exc)
        return False, "", error_line
    if fmt == "png":
        _optimize_png(out_path)
    return True, f"\n![Diagram {n}]({out_path.name})\n", ""


def render_mermaid_blocks(
    md_text: str, work_dir: Path, fmt: str = "png"
) -> tuple[str, int, int]:
    """Replace each ```mermaid block with an <img> tag pointing at a diagram.

    ``fmt="png"`` (PDF default): mmdc rasterises via headless Chrome, which
    renders every mermaid construct faithfully; WeasyPrint then just embeds the
    bitmap. Embedding the SVG instead makes WeasyPrint drop subgraph-nested
    nodes and edges (see `_MMDC_MERMAID_CONFIG`). Rendered at `_mermaid_scale()`
    (2×) for print sharpness, then shrunk by `_optimize_png`.

    ``fmt="svg"`` (HTML path): browsers render mermaid SVG faithfully — the
    WeasyPrint limitation does not apply — and the vector asset embeds far
    smaller than the 2× PNG, so the standalone HTML stays a fraction of the size.

    Returns (rewritten_md, rendered_count, failed_count).

    A block that fails to render is left as-is in the Markdown so the PDF
    still contains the diagram source rather than a missing image.

    Probe-then-parallel: blocks render serially until the first success
    proves the mmdc/Chrome environment works, then the remainder fans out
    over `MMDC_PARALLEL_WORKERS` threads (each mmdc call boots its own
    Chrome, so the work is subprocess-bound and threads suffice). If the
    first `MMDC_FAIL_FAST_THRESHOLD` blocks all fail with zero successes
    (typical case: Puppeteer's Chrome binary is missing, every block will
    fail the same way) we stop calling mmdc altogether and let remaining
    blocks pass through — saves ~1s startup per remaining diagram and 14×
    the same stack trace in the log.
    """
    matches = list(MERMAID_FENCE_RE.finditer(md_text))
    if not matches:
        return md_text, 0, 0

    # replacements[i] is None while block i+1 is unrendered / failed.
    replacements: list[Optional[str]] = [None] * len(matches)
    rendered = 0
    failed = 0
    first_error: list[str] = []

    def _note_failure(n: int, error_line: str) -> None:
        if not first_error:
            first_error.append(error_line)
            sys.stderr.write(f"[export_pdf] mmdc failed on diagram {n}: {error_line}\n")

    # Serial probe: until the first success or the fail-fast bail.
    next_idx = 0
    bailed = False
    while next_idx < len(matches):
        ok, repl, error_line = _render_one_mermaid(next_idx + 1, matches[next_idx].group(1), work_dir, fmt)
        if ok:
            replacements[next_idx] = repl
            rendered += 1
            next_idx += 1
            break
        failed += 1
        _note_failure(next_idx + 1, error_line)
        next_idx += 1
        if failed >= MMDC_FAIL_FAST_THRESHOLD:
            bailed = True
            sys.stderr.write(
                f"[export_pdf] mmdc failed on first {MMDC_FAIL_FAST_THRESHOLD} diagrams — "
                f"giving up, remaining blocks will stay as code\n"
            )
            break

    remaining = list(range(next_idx, len(matches)))
    if bailed:
        failed += len(remaining)
    elif remaining:
        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=min(MMDC_PARALLEL_WORKERS, len(remaining))) as pool:
            futures = {i: pool.submit(_render_one_mermaid, i + 1, matches[i].group(1), work_dir, fmt) for i in remaining}
        for i in remaining:
            ok, repl, error_line = futures[i].result()
            if ok:
                replacements[i] = repl
                rendered += 1
            else:
                failed += 1
                _note_failure(i + 1, error_line)

    counter = {"n": 0}

    def replace(match: re.Match) -> str:
        repl = replacements[counter["n"]]
        counter["n"] += 1
        return repl if repl is not None else match.group(0)

    rewritten = MERMAID_FENCE_RE.sub(replace, md_text)
    return rewritten, rendered, failed


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

# Table column-width injection. Pandoc's `gfm` reader (correctly) ignores the
# relative dash widths in a pipe-table separator, so the compose-stage width
# hints have no effect on the HTML/PDF on their own. We therefore compute each
# table's column widths HERE — directly from the rendered HTML cell content —
# and inject an explicit <colgroup>, which WeasyPrint/browsers honour. Widths
# are content-aware, clamped into a per-role band so finding/link columns get
# room and short ID/severity columns stay compact (mirrors compose's
# _TBL_ROLE_BOUNDS — keep the two in sync).
_COLW_ROLE_BOUNDS: dict[str, tuple[int, int]] = {
    "narrow": (3, 8),
    "medium": (7, 14),
    "default": (8, 22),
    "desc": (14, 36),
    "links": (16, 48),
}

# Minimum width any single column may occupy (percent of table width). At ~510px
# of A4 content width, 9% ≈ 46px — enough for a short header word ("Method") and
# two-letter cells ("No") to stay on one line instead of breaking per character.
_MIN_COL_PCT = 9.0


def _colw_role(header: str) -> str:
    h = re.sub(r"[`*_]", "", header or "").strip().lower()
    if not h:
        return "default"
    if h in {"#", "id", "ids", "auth", "effort", "priority", "protocol", "method", "factor", "level", "p", "sev"}:
        return "narrow"
    if h in {"risk", "severity", "cwe", "cwes", "status", "verdict", "classification", "required role", "role"}:
        return "medium"
    if any(
        t in h
        for t in (
            "description",
            "notes",
            "scenario",
            "reason",
            "rationale",
            "details",
            "meaning",
            "impact",
            "assessment",
            "what it asks",
        )
    ):
        return "desc"
    if any(t in h for t in ("finding", "threat", "addresses", "mitigat", "covers", "linked")):
        return "links"
    return "default"


def _colw_cell_text(cell_html: str) -> int:
    """Widest visible line in an HTML table cell (split on <br>, strip tags)."""
    longest = 0
    for seg in re.split(r"<br\s*/?>", cell_html or "", flags=re.IGNORECASE):
        txt = re.sub(r"<[^>]+>", "", seg)
        txt = re.sub(r"&[a-zA-Z#0-9]+;", "x", txt).strip()
        longest = max(longest, len(txt))
    return longest


def _inject_table_colgroups(html: str) -> str:
    """Insert a content-aware <colgroup> into every <table> that lacks one."""
    cell_re = re.compile(r"<t[hd][^>]*>(.*?)</t[hd]>", re.DOTALL | re.IGNORECASE)
    row_re = re.compile(r"<tr[^>]*>(.*?)</tr>", re.DOTALL | re.IGNORECASE)

    def _one(m: re.Match[str]) -> str:
        open_tag, inner = m.group(1), m.group(2)
        if "<colgroup" in inner.lower():
            return m.group(0)
        rows = row_re.findall(inner)
        if not rows:
            return m.group(0)
        header_cells = cell_re.findall(rows[0])
        ncol = len(header_cells)
        if ncol < 2:
            return m.group(0)
        content = [_colw_cell_text(re.sub(r"<[^>]+>", " ", h)) for h in header_cells]
        roles = [_colw_role(re.sub(r"<[^>]+>", "", h)) for h in header_cells]
        for r in rows[1:]:
            cells = cell_re.findall(r)
            for i in range(min(ncol, len(cells))):
                content[i] = max(content[i], _colw_cell_text(cells[i]))
        weights = []
        for i in range(ncol):
            lo, hi = _COLW_ROLE_BOUNDS.get(roles[i], (8, 22))
            weights.append(max(3, min(hi, max(lo, content[i]))))
        total = sum(weights) or 1
        pcts = [100.0 * w / total for w in weights]
        # Floor every column so a wide prose column (e.g. "Notes"/"Description")
        # can't crush a short one (e.g. "Method"/"Auth") below the width of its
        # own header word — which, under table-layout:fixed, makes the text wrap
        # one character per line ("Met"/"hod"). Floor + renormalise to 100%.
        floor = min(_MIN_COL_PCT, 100.0 / ncol)
        pcts = [max(floor, p) for p in pcts]
        scale = 100.0 / (sum(pcts) or 1)
        pcts = [p * scale for p in pcts]
        cols = "".join(f'<col style="width: {round(p)}%" />' for p in pcts)
        return f"{open_tag}\n<colgroup>{cols}</colgroup>{inner}</table>"

    return re.sub(r"(<table[^>]*>)(.*?)</table>", _one, html, flags=re.DOTALL | re.IGNORECASE)


# ---------------------------------------------------------------------------
# Cover page + Table-of-Contents page numbers
# ---------------------------------------------------------------------------

# Pandoc emits a <header id="title-block-header"> with the (filename-derived)
# --metadata title. The report body already carries its own real <h1> + a
# subtitle blockquote + a metadata line, so the pandoc header is a duplicate.
_TITLE_BLOCK_RE = re.compile(
    r"<header[^>]*id=\"title-block-header\"[^>]*>.*?</header>\s*",
    re.DOTALL | re.IGNORECASE,
)

# The cover region: from the first body <h1> up to (but not including) the
# first <h2>. That span is the report's title + generator line + metadata
# blockquote — everything before the first real section (Changelog / TOC).
# Group 1 becomes the cover; group 2 (the <h2>) is re-emitted after it.
_COVER_REGION_RE = re.compile(
    r"(<h1\b.*?)(<h2\b)",
    re.DOTALL | re.IGNORECASE,
)


def _wrap_cover_page(html: str) -> str:
    """Wrap the leading title block into a dedicated full-page cover.

    The cover holds the title, the generator subtitle, and the metadata table
    (everything before the first <h2>). Best-effort: with no body <h1>+<h2> the
    HTML is returned unchanged — including pandoc's own title header, so the
    document still shows a title.
    """
    stripped = _TITLE_BLOCK_RE.sub("", html, count=1)
    m = _COVER_REGION_RE.search(stripped)
    if not m:
        # No body-h1 + h2 cover region — keep the original (pandoc header intact).
        return html
    cover = '<div class="cover-page">\n' + m.group(1).strip() + "\n</div>\n"
    return stripped[: m.start()] + cover + m.group(2) + stripped[m.end() :]


# Locate the Table-of-Contents region as: heading -> everything up to the next
# <h2>. This is nesting-agnostic (the report emits a <ul> plus an <ol> with
# nested <ul> children), unlike a list-matching regex which backtracks across
# the nested lists and swallows the document body.
_TOC_HEADING_RE = re.compile(
    r"<h2[^>]*id=\"table-of-contents\"[^>]*>.*?</h2>",
    re.DOTALL | re.IGNORECASE,
)
_ID_RE = re.compile(r'\bid="([^"]+)"')
_ANCHOR_RE = re.compile(r'<a\s+href="([^"]*)"([^>]*)>(.*?)</a>', re.DOTALL | re.IGNORECASE)


def _wrap_toc(html: str) -> str:
    """Wrap the TOC (heading + its lists) in <nav class="toc"> for page numbers.

    WeasyPrint's `target-counter` is fatal when it points at a missing anchor,
    so any TOC entry whose `#target` does not exist in the document is
    downgraded to a plain <span> (keeps the text, drops the dead link and its
    page number) rather than aborting the whole PDF. Print CSS then appends
    page numbers to the surviving internal links only.

    Best-effort: if no TOC heading is found the HTML is returned unchanged.
    """
    hm = _TOC_HEADING_RE.search(html)
    if not hm:
        return html
    rest = html[hm.end() :]
    nxt = re.search(r"<h2\b", rest, re.IGNORECASE)
    end = hm.end() + (nxt.start() if nxt else len(rest))
    region = html[hm.start() : end]

    ids = set(_ID_RE.findall(html))

    def _heal(m: re.Match[str]) -> str:
        href, _attrs, text = m.group(1), m.group(2), m.group(3)
        if href.startswith("#") and href[1:] not in ids:
            return f"<span>{text}</span>"
        return m.group(0)

    region = _ANCHOR_RE.sub(_heal, region)
    wrapped = f'<nav class="toc">\n{region}\n</nav>\n'
    return html[: hm.start()] + wrapped + html[end:]


# ---------------------------------------------------------------------------
# Emoji fallback (WeasyPrint has no emoji/symbol font — only DejaVu is embedded)
# ---------------------------------------------------------------------------

# Emoji used as status/severity badges that DejaVu lacks → render as tofu boxes
# in the PDF. Map each to a DejaVu-safe glyph wrapped in a colored span so the
# badge still reads as a colored mark. DejaVu coverage verified for the targets
# (● U+25CF, ✓ U+2713, ✗ U+2717, ▲ U+25B2, ★ U+2605).
_EMOJI_FALLBACKS: dict[str, tuple[str, str]] = {
    "\U0001f534": ("●", "#d1242f"),  # 🔴 red circle
    "\U0001f7e0": ("●", "#bc4c00"),  # 🟠 orange circle
    "\U0001f7e1": ("●", "#9a6700"),  # 🟡 yellow/amber circle
    "\U0001f7e2": ("●", "#1a7f37"),  # 🟢 green circle
    "\U0001f535": ("●", "#0969da"),  # 🔵 blue circle
    "✅": ("✓", "#1a7f37"),  # ✅ -> green check
    "❌": ("✗", "#d1242f"),  # ❌ -> red cross
    "⚠": ("▲", "#9a6700"),  # ⚠ -> amber triangle
    "⭐": ("★", "#9a6700"),  # ⭐ -> amber star
}

_SVG_BLOCK_RE = re.compile(r"<svg\b.*?</svg>", re.DOTALL | re.IGNORECASE)


def _replace_unsupported_emoji(html: str) -> str:
    """Swap emoji WeasyPrint can't render for colored DejaVu-safe glyphs.

    PDF-only (not used by the HTML export — browsers have their own emoji
    fonts). Embedded <svg>…</svg> diagram blocks are left untouched so their
    <text> nodes aren't corrupted by injected HTML spans.
    """
    if not any(e in html for e in _EMOJI_FALLBACKS):
        return html

    def sub(segment: str) -> str:
        for emo, (glyph, color) in _EMOJI_FALLBACKS.items():
            if emo in segment:
                segment = segment.replace(emo, f'<span style="color: {color}">{glyph}</span>')
        return segment

    parts: list[str] = []
    last = 0
    for m in _SVG_BLOCK_RE.finditer(html):
        parts.append(sub(html[last : m.start()]))
        parts.append(m.group(0))
        last = m.end()
    parts.append(sub(html[last:]))
    return "".join(parts)


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


_MD_IMAGE_RE = re.compile(r"!\[[^\]]*\]\(\s*<?([^)\s>]+)>?")


def stage_relative_images(md_text: str, src_dir: Path, work: Path) -> int:
    """Copy relative image assets referenced by the Markdown (e.g. the
    hand-built ``figure1.svg``) from the document's own directory into the temp
    work dir, so pandoc — whose ``--resource-path`` points at the work dir —
    can embed them. Mermaid PNGs already live in ``work``; this covers every
    other relative ``![...](path)`` image. External/absolute refs are skipped.
    Returns the number of assets staged.
    """
    staged = 0
    for ref in {m.group(1).strip() for m in _MD_IMAGE_RE.finditer(md_text)}:
        if re.match(r"^[a-z][a-z0-9+.-]*://", ref) or ref.startswith(("/", "data:", "#")):
            continue
        src, dst = src_dir / ref, work / ref
        if src.is_file() and not dst.exists():
            try:
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
                staged += 1
            except OSError:
                pass
    return staged


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
        # Mermaid PNGs are written next to the (temp) Markdown and referenced
        # relatively as `diagram-N.png`. Pandoc resolves image paths against
        # its CWD, not the input file, so without this it fails to embed them
        # ("File diagram-1.png not found in resource path", exit 99). css_path
        # is absolute, so replacing the default search path here is safe.
        f"--resource-path={md_path.parent}",
        f"--css={css_path}",
        "--metadata",
        f"title={title}",
        "-o",
        str(html_path),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"pandoc failed (exit {result.returncode}):\n{result.stderr.strip()}")
    # Post-process the pandoc HTML (best-effort; any failure leaves it as-is):
    #  - inject content-aware <colgroup> widths (gfm drops pipe-table dash hints)
    #  - wrap the title block into a dedicated cover page
    #  - tag the TOC list so print CSS can add target-counter page numbers
    try:
        html_text = html_path.read_text(encoding="utf-8")
        html_text = _inject_table_colgroups(html_text)
        html_text = _wrap_cover_page(html_text)
        html_text = _wrap_toc(html_text)
        html_path.write_text(html_text, encoding="utf-8")
    except OSError:
        pass


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

    with tempfile.TemporaryDirectory(prefix="export-threat-model-pdf-") as tmp:
        work = Path(tmp)

        if use_mermaid and check_tool("mmdc"):
            md_text, rendered, failed = render_mermaid_blocks(md_text, work)
            sys.stderr.write(f"[export_pdf] mermaid: {rendered} rendered, {failed} failed\n")

        # Stage relative image assets (e.g. figure1.svg) next to the work-dir md
        # so pandoc's --resource-path={work} can embed them.
        staged = stage_relative_images(md_text, input_md.parent, work)
        if staged:
            sys.stderr.write(f"[export_pdf] staged {staged} relative image asset(s)\n")

        pre_md = work / "pre.md"
        pre_md.write_text(md_text, encoding="utf-8")

        html_path = work / "out.html"
        title = input_md.stem.replace("-", " ").title()
        md_to_html(pre_md, html_path, css_path, title)

        # PDF-only: swap emoji WeasyPrint can't render for DejaVu-safe glyphs.
        # Best-effort — any failure leaves the pandoc HTML untouched.
        try:
            html_path.write_text(
                _replace_unsupported_emoji(html_path.read_text(encoding="utf-8")),
                encoding="utf-8",
            )
        except OSError:
            pass

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
        help="Export without diagrams (skip Mermaid rendering AND its preflight). "
        "This is the opt-out for environments with no Chrome/mmdc.",
    )
    parser.add_argument(
        "--require-mermaid",
        action="store_true",
        help="Deprecated/redundant: Mermaid rendering is now required by default. Kept for backward compatibility.",
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

    # Mermaid rendering is required by default: a PDF where diagrams silently
    # degrade to raw code is a broken result, so a missing or non-functional
    # mmdc (e.g. no Chrome for Puppeteer) must abort with a clear error.
    # --no-mermaid is the explicit opt-out; --require-mermaid is now redundant.
    require_mermaid = not args.no_mermaid
    ok, messages = preflight(require_mermaid=require_mermaid)
    sys.stderr.write("[export_pdf] preflight:\n")
    for m in messages:
        sys.stderr.write(m + "\n")
    if not ok:
        # "Right or nothing": a PDF whose diagrams silently degrade to raw code
        # is a broken deliverable, so a non-functional Mermaid renderer is a
        # HARD failure — abort rather than quietly shipping a diagram-less PDF.
        # When the ONLY broken dep is mmdc/Chrome (the no-mermaid re-probe
        # passes), emit a targeted hint: under the Bash sandbox Chrome cannot
        # launch — its process_singleton socket() syscall is blocked (EPERM)
        # path-independently — so the export must be re-run with the sandbox
        # disabled. --no-mermaid stays the explicit opt-out for a deliberately
        # diagram-less PDF.
        if require_mermaid:
            ok_no_mermaid, _ = preflight(require_mermaid=False)
            if ok_no_mermaid:
                sys.stderr.write(
                    "[export_pdf] Mermaid renderer cannot run (mmdc missing, or "
                    "Chrome/Puppeteer fails to launch — under a sandbox the "
                    "process_singleton socket() syscall is blocked).\n"
                    "[export_pdf] Refusing to ship a diagram-less PDF. Do one of:\n"
                    "[export_pdf]   - re-run the export with the sandbox disabled "
                    "(diagrams render in full), or\n"
                    "[export_pdf]   - pass --no-mermaid to deliberately export with "
                    "diagrams kept as code blocks.\n"
                )
                return 1
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
