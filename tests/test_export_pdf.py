"""Tests for scripts/export_pdf.py."""
from __future__ import annotations

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
        with patch.object(ep, "check_tool", return_value="/usr/bin/fake"), \
             patch.object(ep, "probe_runs", return_value=(True, "fake 1.2.3")):
            ok, _ = ep.preflight(require_mermaid=False)
        assert ok is True

    def test_missing_pandoc_fails(self):
        def which(name):
            return None if name == "pandoc" else "/usr/bin/" + name
        with patch.object(ep, "check_tool", side_effect=which), \
             patch.object(ep, "probe_runs", return_value=(True, "ok")):
            ok, msgs = ep.preflight(require_mermaid=False)
        assert ok is False
        assert any("pandoc" in m and "not found" in m for m in msgs)
        assert any("install:" in m for m in msgs)

    def test_missing_weasyprint_fails(self):
        def which(name):
            return None if name == "weasyprint" else "/usr/bin/" + name
        with patch.object(ep, "check_tool", side_effect=which), \
             patch.object(ep, "probe_runs", return_value=(True, "ok")):
            ok, msgs = ep.preflight(require_mermaid=False)
        assert ok is False
        assert any("weasyprint" in m and "not found" in m for m in msgs)

    def test_weasyprint_present_but_broken(self):
        """The libpango-missing case: which() finds it, --version crashes."""
        def probe(name):
            if name == "weasyprint":
                return False, "OSError: cannot load library 'libpango-1.0-0'"
            return True, "ok"
        with patch.object(ep, "check_tool", return_value="/usr/local/bin/weasyprint"), \
             patch.object(ep, "probe_runs", side_effect=probe):
            ok, msgs = ep.preflight(require_mermaid=False)
        assert ok is False
        assert any("found but does not run" in m for m in msgs)
        assert any("libpango" in m for m in msgs)

    def test_missing_mmdc_is_soft(self):
        """Missing mmdc just warns by default, doesn't fail."""
        def which(name):
            return None if name == "mmdc" else "/usr/bin/" + name
        with patch.object(ep, "check_tool", side_effect=which), \
             patch.object(ep, "probe_runs", return_value=(True, "ok")):
            ok, msgs = ep.preflight(require_mermaid=False)
        assert ok is True
        assert any("mmdc" in m and "skip" in m.lower() for m in msgs)

    def test_missing_mmdc_hard_with_require_flag(self):
        def which(name):
            return None if name == "mmdc" else "/usr/bin/" + name
        with patch.object(ep, "check_tool", side_effect=which), \
             patch.object(ep, "probe_runs", return_value=(True, "ok")):
            ok, msgs = ep.preflight(require_mermaid=True)
        assert ok is False
        assert any("mmdc" in m and ("not found" in m or "miss" in m) for m in msgs)


# ---------------------------------------------------------------------------
# render_mermaid_blocks()
# ---------------------------------------------------------------------------

class TestRenderMermaid:
    def _md_with_blocks(self, count: int) -> str:
        blocks = "\n".join(
            f"```mermaid\ngraph TD\n  A{i} --> B{i}\n```" for i in range(count)
        )
        return f"# Doc\n\nIntro.\n\n{blocks}\n\nOutro.\n"

    def test_replaces_blocks_when_mmdc_succeeds(self, tmp_path):
        md = self._md_with_blocks(2)
        with patch("subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, b"", b"")
            # Side effect: pretend mmdc wrote the SVG file.
            def fake_run(cmd, **kw):
                # cmd[3] is the -i path, cmd[5] is the -o path
                Path(cmd[5]).write_text("<svg/>")
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

    @staticmethod
    def _pipeline_fake_run(seen_programs: list[str] | None = None,
                           pandoc_writes: str = "<html><body>x</body></html>",
                           svg_content: str = "<svg/>"):
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
                Path(cmd[5]).write_text(svg_content)
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
        md.write_text(
            "# Test\n\nHello [link](vscode://file/x.py).\n\n"
            "```mermaid\ngraph TD; A-->B\n```\n\nBye.\n"
        )
        pdf = tmp_path / "threat-model.pdf"

        with patch.object(ep, "preflight", return_value=(True, [])), \
             patch("subprocess.run", side_effect=self._pipeline_fake_run()):
            rc = ep.main(["--input", str(md), "--output", str(pdf)])

        assert rc == 0
        assert pdf.exists()
        assert pdf.read_bytes().startswith(b"%PDF-")

    def test_keep_html_writes_intermediate(self, tmp_path):
        md = tmp_path / "in.md"
        md.write_text("# Doc\n\nNo mermaid.\n")
        pdf = tmp_path / "in.pdf"

        with patch.object(ep, "preflight", return_value=(True, [])), \
             patch("subprocess.run",
                   side_effect=self._pipeline_fake_run(pandoc_writes="<html>marker-12345</html>")):
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

        with patch.object(ep, "preflight", return_value=(True, [])), \
             patch.object(ep, "check_tool", return_value="/usr/bin/mmdc"), \
             patch("subprocess.run", side_effect=self._pipeline_fake_run(seen_programs)):
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

        with patch.object(ep, "preflight", return_value=(True, [])), \
             patch.object(ep, "check_tool", return_value=None), \
             patch("subprocess.run", side_effect=fake_run):
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
