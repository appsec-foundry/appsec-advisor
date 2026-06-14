"""Tests for scripts/export_pdf.py."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import export_pdf as ep

# ---------------------------------------------------------------------------
# preflight()
# ---------------------------------------------------------------------------


class TestPreflight:
    def test_all_tools_available(self):
        """When pandoc + weasyprint + mmdc all run, preflight passes."""
        with (
            patch.object(ep, "check_tool", return_value="/usr/bin/fake"),
            patch.object(ep, "probe_runs", return_value=(True, "fake 1.2.3")),
        ):
            ok, _ = ep.preflight(require_mermaid=False)
        assert ok is True

    def test_missing_pandoc_fails(self):
        def which(name):
            return None if name == "pandoc" else "/usr/bin/" + name

        with (
            patch.object(ep, "check_tool", side_effect=which),
            patch.object(ep, "probe_runs", return_value=(True, "ok")),
        ):
            ok, msgs = ep.preflight(require_mermaid=False)
        assert ok is False
        assert any("pandoc" in m and "not found" in m for m in msgs)
        assert any("install:" in m for m in msgs)

    def test_missing_weasyprint_fails(self):
        def which(name):
            return None if name == "weasyprint" else "/usr/bin/" + name

        with (
            patch.object(ep, "check_tool", side_effect=which),
            patch.object(ep, "probe_runs", return_value=(True, "ok")),
        ):
            ok, msgs = ep.preflight(require_mermaid=False)
        assert ok is False
        assert any("weasyprint" in m and "not found" in m for m in msgs)

    def test_weasyprint_present_but_broken(self):
        """The libpango-missing case: which() finds it, --version crashes."""

        def probe(name):
            if name == "weasyprint":
                return False, "OSError: cannot load library 'libpango-1.0-0'"
            return True, "ok"

        with (
            patch.object(ep, "check_tool", return_value="/usr/local/bin/weasyprint"),
            patch.object(ep, "probe_runs", side_effect=probe),
        ):
            ok, msgs = ep.preflight(require_mermaid=False)
        assert ok is False
        assert any("found but does not run" in m for m in msgs)
        assert any("libpango" in m for m in msgs)

    def test_missing_mmdc_is_soft(self):
        """Missing mmdc just warns by default, doesn't fail."""

        def which(name):
            return None if name == "mmdc" else "/usr/bin/" + name

        with (
            patch.object(ep, "check_tool", side_effect=which),
            patch.object(ep, "probe_runs", return_value=(True, "ok")),
        ):
            ok, msgs = ep.preflight(require_mermaid=False)
        assert ok is True
        assert any("mmdc" in m and "skip" in m.lower() for m in msgs)

    def test_missing_mmdc_hard_with_require_flag(self):
        def which(name):
            return None if name == "mmdc" else "/usr/bin/" + name

        with (
            patch.object(ep, "check_tool", side_effect=which),
            patch.object(ep, "probe_runs", return_value=(True, "ok")),
        ):
            ok, msgs = ep.preflight(require_mermaid=True)
        assert ok is False
        assert any("mmdc" in m and ("not found" in m or "miss" in m) for m in msgs)

    def test_mmdc_present_but_cannot_render_is_hard(self):
        """mmdc on PATH but Chrome missing → render probe fails → hard abort.

        This is the core regression: `which mmdc` succeeds yet every diagram
        would degrade to raw code, so preflight must fail when mermaid is
        required."""
        with (
            patch.object(ep, "check_tool", return_value="/usr/bin/mmdc"),
            patch.object(ep, "probe_runs", return_value=(True, "ok")),
            patch.object(
                ep,
                "probe_mmdc",
                return_value=(False, "present but cannot render (missing/broken Chrome for Puppeteer): err"),
            ),
        ):
            ok, msgs = ep.preflight(require_mermaid=True)
        assert ok is False
        assert any("mmdc" in m and "cannot render" in m for m in msgs)

    def test_mmdc_render_probe_success_passes(self):
        with (
            patch.object(ep, "check_tool", return_value="/usr/bin/mmdc"),
            patch.object(ep, "probe_runs", return_value=(True, "ok")),
            patch.object(ep, "probe_mmdc", return_value=(True, "render probe ok via /usr/bin/google-chrome")),
        ):
            ok, msgs = ep.preflight(require_mermaid=True)
        assert ok is True
        assert any("mmdc" in m and "ok" in m for m in msgs)

    def test_mmdc_not_probed_when_not_required(self):
        """With --no-mermaid (require_mermaid=False) the slow render probe is
        skipped entirely even when mmdc is present."""
        with (
            patch.object(ep, "check_tool", return_value="/usr/bin/mmdc"),
            patch.object(ep, "probe_runs", return_value=(True, "ok")),
            patch.object(ep, "probe_mmdc", side_effect=AssertionError("probe must not run")),
        ):
            ok, _ = ep.preflight(require_mermaid=False)
        assert ok is True


# ---------------------------------------------------------------------------
# render_mermaid_blocks()
# ---------------------------------------------------------------------------


class TestRenderMermaid:
    def _md_with_blocks(self, count: int) -> str:
        blocks = "\n".join(f"```mermaid\ngraph TD\n  A{i} --> B{i}\n```" for i in range(count))
        return f"# Doc\n\nIntro.\n\n{blocks}\n\nOutro.\n"

    def test_replaces_blocks_when_mmdc_succeeds(self, tmp_path):
        md = self._md_with_blocks(2)
        with patch("subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, b"", b"")

            # Side effect: pretend mmdc wrote the SVG file.
            def fake_run(cmd, **kw):
                Path(cmd[cmd.index("-o") + 1]).write_text("<svg/>")
                return subprocess.CompletedProcess(cmd, 0, b"", b"")

            run.side_effect = fake_run
            rewritten, ok, fail = ep.render_mermaid_blocks(md, tmp_path)
        assert ok == 2 and fail == 0
        assert "```mermaid" not in rewritten
        assert rewritten.count("![Diagram") == 2

    def test_leaves_block_in_place_when_mmdc_fails(self, tmp_path):
        md = self._md_with_blocks(1)
        with patch("subprocess.run") as run:
            run.side_effect = subprocess.CalledProcessError(1, ["mmdc"], b"", b"chrome missing")
            rewritten, ok, fail = ep.render_mermaid_blocks(md, tmp_path)
        assert ok == 0 and fail == 1
        assert "```mermaid" in rewritten  # original block preserved

    def test_fail_fast_after_threshold(self, tmp_path):
        """After N consecutive failures with zero successes, stop calling mmdc."""
        md = self._md_with_blocks(10)
        call_count = {"n": 0}

        def fail_run(cmd, **kw):
            call_count["n"] += 1
            raise subprocess.CalledProcessError(1, cmd, b"", b"chrome missing")

        with patch("subprocess.run", side_effect=fail_run):
            rewritten, ok, fail = ep.render_mermaid_blocks(md, tmp_path)
        assert ok == 0
        assert fail == 10  # all blocks marked failed
        # but mmdc was only called THRESHOLD times, the rest short-circuited
        assert call_count["n"] == ep.MMDC_FAIL_FAST_THRESHOLD

    def test_parallel_path_mixed_failure_after_probe_success(self, tmp_path):
        """After the serial probe succeeds, the remaining blocks render via the
        thread pool; an isolated failure leaves only that block as code and
        document order of the replacements is preserved."""
        md = self._md_with_blocks(6)

        def fake_run(cmd, **kw):
            out = Path(cmd[cmd.index("-o") + 1])
            if out.name == "diagram-4.png":
                raise subprocess.CalledProcessError(1, cmd, b"", b"boom")
            out.write_text("<svg/>")
            return subprocess.CompletedProcess(cmd, 0, b"", b"")

        with patch("subprocess.run", side_effect=fake_run):
            rewritten, ok, fail = ep.render_mermaid_blocks(md, tmp_path)
        assert ok == 5 and fail == 1
        assert rewritten.count("![Diagram") == 5
        assert rewritten.count("```mermaid") == 1
        # Replacements stay aligned with their position: Diagram 3 precedes Diagram 5.
        assert rewritten.index("![Diagram 3]") < rewritten.index("![Diagram 5]")


# ---------------------------------------------------------------------------
# rewrite_vscode_links()
# ---------------------------------------------------------------------------


class TestVscodeLinkRewrite:
    def test_rewrites_basic_link(self):
        md = "See [code](vscode://file/abs/path/to/file.py:42) for details."
        out = ep.rewrite_vscode_links(md)
        assert "vscode://" not in out
        assert "file:///abs/path/to/file.py:42" in out

    def test_handles_multiple_links(self):
        md = "[a](vscode://file/x.py) [b](vscode://file/y.py)"
        out = ep.rewrite_vscode_links(md)
        assert out.count("file://") == 2
        assert "vscode://" not in out

    def test_leaves_other_links_untouched(self):
        md = "[home](https://example.com) and [code](vscode://file/x.py)"
        out = ep.rewrite_vscode_links(md)
        assert "https://example.com" in out
        assert "file:///x.py" in out


# ---------------------------------------------------------------------------
# pandoc_supports_embed_resources()
# ---------------------------------------------------------------------------


class TestPandocVersion:
    def _mock_pandoc(self, version_line: str, returncode: int = 0):
        return subprocess.CompletedProcess([], returncode, version_line, "")

    def test_modern_version_supports_embed(self):
        with patch("subprocess.run", return_value=self._mock_pandoc("pandoc 3.1.3\n...")):
            assert ep.pandoc_supports_embed_resources() is True

    def test_old_version_does_not(self):
        with patch("subprocess.run", return_value=self._mock_pandoc("pandoc 2.9.2.1\n...")):
            assert ep.pandoc_supports_embed_resources() is False

    def test_threshold_2_19(self):
        with patch("subprocess.run", return_value=self._mock_pandoc("pandoc 2.19.0\n")):
            assert ep.pandoc_supports_embed_resources() is True
        with patch("subprocess.run", return_value=self._mock_pandoc("pandoc 2.18.5\n")):
            assert ep.pandoc_supports_embed_resources() is False

    def test_garbage_output_returns_false(self):
        with patch("subprocess.run", return_value=self._mock_pandoc("not-pandoc-at-all\n")):
            assert ep.pandoc_supports_embed_resources() is False

    def test_missing_binary_returns_false(self):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            assert ep.pandoc_supports_embed_resources() is False


# ---------------------------------------------------------------------------
# main() integration via mocked subprocesses
# ---------------------------------------------------------------------------


class TestMainCli:
    def test_missing_input_file_exit_2(self, tmp_path):
        with patch.object(ep, "preflight", return_value=(True, [])):
            rc = ep.main(["--input", str(tmp_path / "nope.md")])
        assert rc == 2

    def test_check_only_passes_when_preflight_ok(self):
        with patch.object(ep, "preflight", return_value=(True, [])):
            rc = ep.main(["--check-only"])
        assert rc == 0

    def test_check_only_fails_when_preflight_bad(self):
        with patch.object(ep, "preflight", return_value=(False, ["[miss] pandoc"])):
            rc = ep.main(["--check-only"])
        assert rc == 1

    def test_aborts_when_only_mermaid_broken(self, tmp_path):
        """ "Right or nothing" (2026-06-06): pandoc + weasyprint present but
        mmdc/Chrome broken must ABORT, NOT silently ship a diagram-less PDF.
        First preflight (require_mermaid=True) fails on mmdc; the re-probe
        (require_mermaid=False) passes, signalling only mermaid is broken — the
        export still refuses and emits the sandbox/--no-mermaid hint."""
        md = tmp_path / "threat-model.md"
        md.write_text("# T\n\n```mermaid\ngraph TD; A-->B\n```\n\nBody.\n")
        pdf = tmp_path / "threat-model.pdf"
        seen: list[str] = []
        with (
            patch.object(
                ep,
                "preflight",
                side_effect=[
                    (False, ["  [bad]  mmdc  — present but cannot render"]),
                    (True, []),
                ],
            ),
            patch("subprocess.run", side_effect=self._pipeline_fake_run(seen)),
        ):
            rc = ep.main(["--input", str(md), "--output", str(pdf)])
        assert rc == 1
        # Refused: no PDF written, no conversion pipeline run.
        assert not pdf.exists()
        assert seen == []

    def test_aborts_when_hard_dependency_missing(self, tmp_path):
        """A genuine pandoc/weasyprint failure still aborts — the no-mermaid
        re-probe also fails, so there is no degrade path."""
        md = tmp_path / "threat-model.md"
        md.write_text("# T\n")
        with patch.object(
            ep,
            "preflight",
            side_effect=[
                (False, ["  [miss] pandoc not found"]),
                (False, ["  [miss] pandoc not found"]),
            ],
        ):
            rc = ep.main(["--input", str(md), "--output", str(tmp_path / "o.pdf")])
        assert rc == 1

    @staticmethod
    def _pipeline_fake_run(
        seen_programs: list[str] | None = None,
        pandoc_writes: str = "<html><body>x</body></html>",
        svg_content: str = "<svg/>",
    ):
        """Build a fake subprocess.run that handles the full pipeline.

        Recognises: `mmdc -i ... -o ...`, `pandoc --version`, `pandoc ... -o ...`,
        `weasyprint <input> <output>`. Records each program name in seen_programs
        if provided.
        """

        def fake_run(cmd, **kw):
            program = Path(cmd[0]).name
            if seen_programs is not None:
                seen_programs.append(program)
            if program == "mmdc":
                Path(cmd[cmd.index("-o") + 1]).write_text(svg_content)
                return subprocess.CompletedProcess(cmd, 0, b"", b"")
            if program == "pandoc":
                if "--version" in cmd:
                    return subprocess.CompletedProcess(cmd, 0, "pandoc 3.0.1\n", "")
                out_idx = cmd.index("-o") + 1
                Path(cmd[out_idx]).write_text(pandoc_writes)
                return subprocess.CompletedProcess(cmd, 0, "", "")
            if program == "weasyprint":
                Path(cmd[2]).write_bytes(b"%PDF-1.7\n%fake\n")
                return subprocess.CompletedProcess(cmd, 0, "", "")
            raise AssertionError(f"unexpected subprocess call: {cmd}")

        return fake_run

    def test_full_run_with_mocked_pipeline(self, tmp_path):
        """End-to-end with subprocesses mocked: ensures the orchestration
        wires inputs/outputs correctly and writes the PDF atomically."""
        md = tmp_path / "threat-model.md"
        md.write_text("# Test\n\nHello [link](vscode://file/x.py).\n\n```mermaid\ngraph TD; A-->B\n```\n\nBye.\n")
        pdf = tmp_path / "threat-model.pdf"

        with (
            patch.object(ep, "preflight", return_value=(True, [])),
            patch("subprocess.run", side_effect=self._pipeline_fake_run()),
        ):
            rc = ep.main(["--input", str(md), "--output", str(pdf)])

        assert rc == 0
        assert pdf.exists()
        assert pdf.read_bytes().startswith(b"%PDF-")

    def test_keep_html_writes_intermediate(self, tmp_path):
        md = tmp_path / "in.md"
        md.write_text("# Doc\n\nNo mermaid.\n")
        pdf = tmp_path / "in.pdf"

        with (
            patch.object(ep, "preflight", return_value=(True, [])),
            patch("subprocess.run", side_effect=self._pipeline_fake_run(pandoc_writes="<html>marker-12345</html>")),
        ):
            rc = ep.main(["--input", str(md), "--output", str(pdf), "--keep-html"])

        assert rc == 0
        kept = tmp_path / "in.html"
        assert kept.exists()
        assert "marker-12345" in kept.read_text()

    def test_no_mermaid_flag_skips_mmdc_even_when_installed(self, tmp_path):
        md = tmp_path / "in.md"
        md.write_text("# Doc\n\n```mermaid\ngraph TD; A-->B\n```\n")
        pdf = tmp_path / "in.pdf"
        seen_programs: list[str] = []

        with (
            patch.object(ep, "preflight", return_value=(True, [])),
            patch.object(ep, "check_tool", return_value="/usr/bin/mmdc"),
            patch("subprocess.run", side_effect=self._pipeline_fake_run(seen_programs)),
        ):
            rc = ep.main(["--input", str(md), "--output", str(pdf), "--no-mermaid"])

        assert rc == 0
        assert "mmdc" not in seen_programs

    def test_pandoc_failure_returns_3(self, tmp_path):
        md = tmp_path / "in.md"
        md.write_text("# Doc\n")
        pdf = tmp_path / "in.pdf"

        def fake_run(cmd, **kw):
            program = Path(cmd[0]).name
            if program == "pandoc":
                if "--version" in cmd:
                    return subprocess.CompletedProcess(cmd, 0, "pandoc 3.0\n", "")
                return subprocess.CompletedProcess(cmd, 6, "", "Unknown option --foo")
            raise AssertionError(f"weasyprint should not run after pandoc fails: {cmd}")

        with (
            patch.object(ep, "preflight", return_value=(True, [])),
            patch.object(ep, "check_tool", return_value=None),
            patch("subprocess.run", side_effect=fake_run),
        ):
            rc = ep.main(["--input", str(md), "--output", str(pdf)])

        assert rc == 3
        assert not pdf.exists()


# ---------------------------------------------------------------------------
# Real integration test — only runs when the toolchain is fully functional
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    ep.preflight(require_mermaid=False)[0] is False,
    reason="hard dependencies (pandoc/weasyprint) not fully functional in this environment",
)
def test_real_pdf_generation(tmp_path):
    md = tmp_path / "threat-model.md"
    md.write_text(
        "# Real Test\n\n"
        "## Section 1\n\n"
        "Some text with a [link](https://example.com).\n\n"
        "| col A | col B |\n|-------|-------|\n| 1 | 2 |\n"
    )
    pdf = tmp_path / "threat-model.pdf"
    rc = ep.main(["--input", str(md), "--output", str(pdf), "--no-mermaid"])
    assert rc == 0
    assert pdf.exists()
    assert pdf.stat().st_size > 1000
    assert pdf.read_bytes().startswith(b"%PDF-")


def test_inject_table_colgroups_content_aware():
    """gfm drops pipe-table dash widths, so export injects a content-aware
    <colgroup>: link/finding columns widest, id/severity narrow."""
    html = (
        "<table>\n<thead>\n<tr>\n"
        "<th>Asset</th><th>ID</th><th>Classification</th>"
        "<th>Description</th><th>Linked Threats</th>\n</tr>\n</thead>\n<tbody>\n"
        "<tr><td>User Credentials Database</td><td>A-001</td><td>Restricted</td>"
        "<td>" + ("x" * 180) + "</td>"
        '<td><a href="#f-001">F-001</a> (SQL injection authentication bypass via login route)</td></tr>\n'
        "</tbody>\n</table>"
    )
    out = ep._inject_table_colgroups(html)
    assert out.count("<colgroup>") == 1
    pct = [int(x) for x in re.findall(r"width:\s*(\d+)%", out)]
    assert len(pct) == 5
    asset, idc, classification, desc, linked = pct
    assert idc < classification < asset  # short cols ordered, id narrowest
    assert desc > asset and linked > desc  # description wide, linked widest
    # Idempotent — a second pass does not add another colgroup.
    assert ep._inject_table_colgroups(out) == out


def test_inject_table_colgroups_skips_existing():
    html = '<table>\n<colgroup><col style="width: 50%"/></colgroup>\n<tr><th>A</th><th>B</th></tr>\n</table>'
    assert ep._inject_table_colgroups(html) == html


def test_inject_table_colgroups_floors_narrow_columns():
    """A wide prose column must not crush short columns below the per-column
    floor (which made headers like 'Method' wrap one char per line)."""
    html = (
        "<table>\n<thead><tr>"
        "<th>Method</th><th>Route</th><th>Auth</th><th>Risk</th><th>Notes</th>"
        "</tr></thead>\n<tbody>\n"
        "<tr><td>POST</td><td>/rest/products/search</td><td>No</td><td>Critical</td>"
        "<td>" + ("word " * 50) + "</td></tr>\n</tbody>\n</table>"
    )
    out = ep._inject_table_colgroups(html)
    pct = [int(x) for x in re.findall(r"width:\s*(\d+)%", out)]
    assert len(pct) == 5
    # Every column at or above the floor (rounding may shave 1%).
    assert min(pct) >= int(ep._MIN_COL_PCT) - 1
    assert 95 <= sum(pct) <= 105


# ---------------------------------------------------------------------------
# Emoji fallback (DejaVu has no emoji glyphs → PDF tofu)
# ---------------------------------------------------------------------------


class TestEmojiFallback:
    def test_replaces_tofu_emoji_with_colored_glyph(self):
        html = "<p>Risk \U0001f534 critical, \U0001f7e0 weak, ✅ ok, ❌ missing</p>"
        out = ep._replace_unsupported_emoji(html)
        # No raw emoji left; replaced by colored DejaVu-safe glyphs.
        for emo in ("\U0001f534", "\U0001f7e0", "✅", "❌"):
            assert emo not in out
        assert '<span style="color: #d1242f">●</span>' in out  # red circle
        assert "✓" in out and "✗" in out  # check + cross

    def test_keeps_dejavu_safe_glyphs_untouched(self):
        # ✓ ✗ ● ≥ → are already in DejaVu; must not be rewritten.
        html = "<p>✓ ✗ ● ≥ →</p>"
        assert ep._replace_unsupported_emoji(html) == html

    def test_does_not_touch_emoji_inside_svg(self):
        html = "<p>\U0001f534</p><svg><text>\U0001f534</text></svg>"
        out = ep._replace_unsupported_emoji(html)
        # The <p> emoji is replaced; the one inside <svg> is preserved verbatim.
        assert "<svg><text>\U0001f534</text></svg>" in out
        assert out.index("<span") < out.index("<svg")

    def test_noop_when_no_emoji(self):
        html = "<p>plain ascii only</p>"
        assert ep._replace_unsupported_emoji(html) is html or ep._replace_unsupported_emoji(html) == html


# ---------------------------------------------------------------------------
# Cover page + TOC page numbers
# ---------------------------------------------------------------------------

_REPORT_HTML = (
    "<body>\n"
    '<header id="title-block-header">\n<h1 class="title">From Filename</h1>\n</header>\n'
    '<h1 id="threat-model-x">Threat Model: x</h1>\n'
    "<blockquote>\n<p>Generated by tool.</p>\n</blockquote>\n"
    "<p><strong>Scan date:</strong> 2025-01-01</p>\n"
    "<hr />\n"
    '<h2 id="table-of-contents">Table of Contents</h2>\n\n'
    '<ul>\n<li><a href="#management-summary">Management Summary</a></li>\n</ul>\n'
    '<ol type="1">\n<li><a href="#1-system-overview">System Overview</a>\n'
    '<ul>\n<li><a href="#scope">Scope</a></li>\n</ul></li>\n</ol>\n'
    '<h2 id="management-summary">Management Summary</h2>\n<p>body</p>\n'
    "</body>"
)


class TestCoverPage:
    def test_wraps_title_block_into_cover(self):
        out = ep._wrap_cover_page(_REPORT_HTML)
        assert '<div class="cover-page">' in out
        # Real body title + subtitle + metadata land inside the cover.
        cover = re.search(r'<div class="cover-page">(.*?)</div>', out, re.S).group(1)
        assert "Threat Model: x" in cover
        assert "Generated by tool." in cover
        assert "Scan date:" in cover

    def test_drops_duplicate_pandoc_title_header(self):
        out = ep._wrap_cover_page(_REPORT_HTML)
        assert "title-block-header" not in out
        assert "From Filename" not in out

    def test_consumes_the_hr_separator(self):
        out = ep._wrap_cover_page(_REPORT_HTML)
        # The <hr/> that delimited the cover region is removed, not left dangling
        # right after the cover div.
        assert "</div>\n<hr" not in out

    def test_toc_stays_outside_cover(self):
        out = ep._wrap_cover_page(_REPORT_HTML)
        cover = re.search(r'<div class="cover-page">(.*?)</div>', out, re.S).group(1)
        assert "table-of-contents" not in cover

    def test_no_cover_region_returns_unchanged(self):
        # No <hr> → no cover; pandoc header preserved so a title still shows.
        html = (
            '<body>\n<header id="title-block-header"><h1 class="title">T</h1></header>\n<h1>Doc</h1>\n<p>x</p>\n</body>'
        )
        assert ep._wrap_cover_page(html) == html


class TestTocPageNumbers:
    def test_wraps_toc_region_in_nav(self):
        out = ep._wrap_toc(_REPORT_HTML)
        assert '<nav class="toc">' in out
        nav = re.search(r'<nav class="toc">(.*?)</nav>', out, re.S).group(1)
        # Heading + BOTH sibling lists (ul + ol) end up inside the nav.
        assert "table-of-contents" in nav
        assert "Management Summary" in nav
        assert "System Overview" in nav
        assert "Scope" in nav  # nested child included too

    def test_toc_nav_closes_before_next_section(self):
        out = ep._wrap_toc(_REPORT_HTML)
        nav = re.search(r'<nav class="toc">(.*?)</nav>', out, re.S).group(1)
        # The Management Summary *section heading* (h2) must stay outside the nav.
        assert '<h2 id="management-summary">' not in nav

    def test_does_not_swallow_unrelated_trailing_list(self):
        html = _REPORT_HTML + "\n<ol><li>unrelated</li></ol>"
        out = ep._wrap_toc(html)
        assert "unrelated" not in re.search(r'<nav class="toc">(.*?)</nav>', out, re.S).group(1)

    def test_no_toc_heading_is_noop(self):
        html = '<h2 id="intro">Intro</h2>\n<ol><li>x</li></ol>'
        assert ep._wrap_toc(html) == html

    def test_heals_broken_anchor_to_span(self):
        """A TOC entry pointing at a missing anchor would make WeasyPrint's
        target-counter abort the whole render; it must degrade to a <span>
        (text kept, dead link + page number dropped) while valid entries stay
        as links."""
        html = (
            '<h2 id="table-of-contents">Table of Contents</h2>\n'
            "<ul>\n"
            '<li><a href="#real">Real Section</a></li>\n'
            '<li><a href="#missing">Broken Section</a></li>\n'
            "</ul>\n"
            '<h2 id="real">Real Section</h2>\n'
        )
        out = ep._wrap_toc(html)
        nav = re.search(r'<nav class="toc">(.*?)</nav>', out, re.S).group(1)
        assert '<a href="#real">Real Section</a>' in nav  # valid link preserved
        assert '<a href="#missing">' not in nav  # dead link removed
        assert "<span>Broken Section</span>" in nav  # but text kept

    def test_external_links_untouched(self):
        html = (
            '<h2 id="table-of-contents">Table of Contents</h2>\n'
            '<ul><li><a href="https://example.com">Ext</a></li></ul>\n'
            '<h2 id="x">X</h2>\n'
        )
        out = ep._wrap_toc(html)
        # External links are not internal anchors → left as-is (CSS [href^="#"]
        # already excludes them from page numbering).
        assert '<a href="https://example.com">Ext</a>' in out


# ---------------------------------------------------------------------------
# md_to_html — resource-path so pandoc can embed rendered Mermaid SVGs
# ---------------------------------------------------------------------------


def test_md_to_html_passes_resource_path(tmp_path):
    """Rendered Mermaid SVGs sit next to the (temp) Markdown and are referenced
    relatively; pandoc must get --resource-path=<md dir> or it cannot embed
    them (exit 99). Regression guard for the latent crash."""
    md = tmp_path / "pre.md"
    md.write_text("# Doc\n\n![Diagram 1](diagram-1.svg)\n")
    html = tmp_path / "out.html"
    css = tmp_path / "print.css"
    css.write_text("body{}")
    captured: dict = {}

    def fake_run(cmd, **kw):
        program = Path(cmd[0]).name
        if program == "pandoc" and "--version" in cmd:
            return subprocess.CompletedProcess(cmd, 0, "pandoc 3.0\n", "")
        if program == "pandoc":
            captured["cmd"] = cmd
            Path(cmd[cmd.index("-o") + 1]).write_text("<html></html>")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        raise AssertionError(f"unexpected: {cmd}")

    with patch("subprocess.run", side_effect=fake_run):
        ep.md_to_html(md, html, css, "Title")

    assert any(a == f"--resource-path={md.parent}" for a in captured["cmd"])


# ---------------------------------------------------------------------------
# find_chrome / mmdc_env — point Puppeteer at a system Chrome
# ---------------------------------------------------------------------------


class TestChromeResolution:
    def test_env_var_takes_precedence(self, tmp_path, monkeypatch):
        chrome = tmp_path / "my-chrome"
        chrome.write_text("")
        monkeypatch.setenv("PUPPETEER_EXECUTABLE_PATH", str(chrome))
        assert ep.find_chrome() == str(chrome)

    def test_falls_back_to_path_lookup(self, monkeypatch):
        monkeypatch.delenv("PUPPETEER_EXECUTABLE_PATH", raising=False)
        with patch.object(
            ep.shutil,
            "which",
            side_effect=lambda n: "/usr/bin/google-chrome" if n == "google-chrome" else None,
        ):
            assert ep.find_chrome() == "/usr/bin/google-chrome"

    def test_none_when_no_chrome(self, monkeypatch):
        monkeypatch.delenv("PUPPETEER_EXECUTABLE_PATH", raising=False)
        with patch.object(ep.shutil, "which", return_value=None):
            assert ep.find_chrome() is None

    def test_mmdc_env_sets_executable_path(self, monkeypatch):
        monkeypatch.delenv("PUPPETEER_EXECUTABLE_PATH", raising=False)
        with patch.object(ep, "find_chrome", return_value="/opt/chrome"):
            env = ep.mmdc_env()
        assert env["PUPPETEER_EXECUTABLE_PATH"] == "/opt/chrome"

    def test_mmdc_env_does_not_override_user_value(self, monkeypatch):
        monkeypatch.setenv("PUPPETEER_EXECUTABLE_PATH", "/user/set/chrome")
        with patch.object(ep, "find_chrome", return_value="/opt/chrome"):
            env = ep.mmdc_env()
        assert env["PUPPETEER_EXECUTABLE_PATH"] == "/user/set/chrome"


# ---- stage_relative_images (Figure 1 SVG asset staging) --------------------
def test_stage_relative_images_copies_local_svg(tmp_path: Path) -> None:
    src = tmp_path / "doc"
    src.mkdir()
    (src / "figure1.svg").write_text("<svg/>")
    work = tmp_path / "work"
    work.mkdir()
    md = "intro\n\n![Figure 1](figure1.svg)\n\nmore"
    n = ep.stage_relative_images(md, src, work)
    assert n == 1
    assert (work / "figure1.svg").read_text() == "<svg/>"


def test_stage_relative_images_skips_external_absolute_and_missing(tmp_path: Path) -> None:
    src = tmp_path / "doc"
    src.mkdir()
    work = tmp_path / "work"
    work.mkdir()
    md = (
        "![a](https://example.com/x.png) "
        "![b](/etc/abs.png) "
        "![c](data:image/png;base64,AAAA) "
        "![d](missing.svg)"  # relative but not present on disk
    )
    assert ep.stage_relative_images(md, src, work) == 0
    assert not any(work.iterdir())


def test_stage_relative_images_does_not_overwrite_existing(tmp_path: Path) -> None:
    src = tmp_path / "doc"
    src.mkdir()
    (src / "figure1.svg").write_text("NEW")
    work = tmp_path / "work"
    work.mkdir()
    (work / "figure1.svg").write_text("KEEP")  # e.g. already produced by mermaid stage
    assert ep.stage_relative_images("![x](figure1.svg)", src, work) == 0
    assert (work / "figure1.svg").read_text() == "KEEP"
