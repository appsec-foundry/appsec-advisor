"""Unit tests for scripts/export_html.py.

Covers preflight (pandoc present/missing/broken, mmdc present/missing/
require-mermaid render-ok/render-bad/skip), export_html (with and without
mermaid), and main() dispatch (check-only, missing input, missing css,
conversion error, success, abort).

The heavy external tools (pandoc, mmdc) are never actually invoked: the
export_pdf helpers (check_tool, probe_runs, probe_mmdc, render_mermaid_blocks,
md_to_html) are monkeypatched on the export_html module namespace.
"""

from __future__ import annotations

import export_html

# --------------------------------------------------------------------------
# preflight()
# --------------------------------------------------------------------------


def test_preflight_pandoc_missing(monkeypatch):
    monkeypatch.setattr(export_html, "check_tool", lambda name: None)
    ok, messages = export_html.preflight(require_mermaid=False)
    assert ok is False
    joined = "\n".join(messages)
    assert "[miss] pandoc" in joined
    assert "install:" in joined


def test_preflight_pandoc_present_but_broken(monkeypatch):
    monkeypatch.setattr(
        export_html, "check_tool",
        lambda name: "/usr/bin/pandoc" if name == "pandoc" else None,
    )
    monkeypatch.setattr(export_html, "probe_runs", lambda name: (False, "boom"))
    ok, messages = export_html.preflight(require_mermaid=False)
    assert ok is False
    joined = "\n".join(messages)
    assert "[bad]  pandoc" in joined
    assert "does not run" in joined
    assert "error:" in joined


def test_preflight_pandoc_ok_mmdc_missing_optional(monkeypatch):
    monkeypatch.setattr(
        export_html, "check_tool",
        lambda name: "/usr/bin/pandoc" if name == "pandoc" else None,
    )
    monkeypatch.setattr(export_html, "probe_runs", lambda name: (True, "2.x"))
    ok, messages = export_html.preflight(require_mermaid=False)
    assert ok is True
    joined = "\n".join(messages)
    assert "[ok]   pandoc" in joined
    assert "[skip] mmdc" in joined


def test_preflight_mmdc_missing_required_fails(monkeypatch):
    monkeypatch.setattr(
        export_html, "check_tool",
        lambda name: "/usr/bin/pandoc" if name == "pandoc" else None,
    )
    monkeypatch.setattr(export_html, "probe_runs", lambda name: (True, "2.x"))
    ok, messages = export_html.preflight(require_mermaid=True)
    assert ok is False
    joined = "\n".join(messages)
    assert "required by --require-mermaid" in joined


def test_preflight_mmdc_present_require_render_ok(monkeypatch):
    monkeypatch.setattr(
        export_html, "check_tool",
        lambda name: "/usr/bin/pandoc" if name == "pandoc" else "/usr/bin/mmdc",
    )
    monkeypatch.setattr(export_html, "probe_runs", lambda name: (True, "2.x"))
    monkeypatch.setattr(export_html, "probe_mmdc", lambda: (True, "chrome ok"))
    ok, messages = export_html.preflight(require_mermaid=True)
    assert ok is True
    joined = "\n".join(messages)
    assert "[ok]   mmdc" in joined
    assert "chrome ok" in joined


def test_preflight_mmdc_present_require_render_bad(monkeypatch):
    monkeypatch.setattr(
        export_html, "check_tool",
        lambda name: "/usr/bin/pandoc" if name == "pandoc" else "/usr/bin/mmdc",
    )
    monkeypatch.setattr(export_html, "probe_runs", lambda name: (True, "2.x"))
    monkeypatch.setattr(export_html, "probe_mmdc", lambda: (False, "no chrome"))
    ok, messages = export_html.preflight(require_mermaid=True)
    assert ok is False
    joined = "\n".join(messages)
    assert "[bad]  mmdc" in joined
    assert "--no-mermaid" in joined


def test_preflight_mmdc_present_not_required(monkeypatch):
    monkeypatch.setattr(
        export_html, "check_tool",
        lambda name: "/usr/bin/pandoc" if name == "pandoc" else "/usr/bin/mmdc",
    )
    monkeypatch.setattr(export_html, "probe_runs", lambda name: (True, "2.x"))
    ok, messages = export_html.preflight(require_mermaid=False)
    assert ok is True
    joined = "\n".join(messages)
    assert "[ok]   mmdc        /usr/bin/mmdc" in joined


# --------------------------------------------------------------------------
# export_html()
# --------------------------------------------------------------------------


def _stub_md_to_html(pre_md, html_tmp, css_path, title):
    html_tmp.write_text("<html><body>ok</body></html>", encoding="utf-8")


def test_export_html_without_mermaid(tmp_path, monkeypatch):
    inp = tmp_path / "threat-model.md"
    inp.write_text("# Title\n\nbody\n", encoding="utf-8")
    out = tmp_path / "threat-model.html"

    # mmdc not available -> render branch skipped
    monkeypatch.setattr(export_html, "check_tool", lambda name: None)
    monkeypatch.setattr(export_html, "md_to_html", _stub_md_to_html)

    rc = export_html.export_html(
        input_md=inp,
        output_html=out,
        use_mermaid=False,
        css_path=tmp_path / "print.css",
    )
    assert rc == 0
    assert out.is_file()
    assert "ok" in out.read_text(encoding="utf-8")


def test_export_html_with_mermaid(tmp_path, monkeypatch, capsys):
    inp = tmp_path / "diagram.md"
    inp.write_text("# Title\n\n```mermaid\ngraph TD\n```\n", encoding="utf-8")
    out = tmp_path / "diagram.html"

    monkeypatch.setattr(export_html, "check_tool", lambda name: "/usr/bin/mmdc")

    def _render(md_text, work):
        return (md_text, 1, 0)

    monkeypatch.setattr(export_html, "render_mermaid_blocks", _render)
    monkeypatch.setattr(export_html, "md_to_html", _stub_md_to_html)

    rc = export_html.export_html(
        input_md=inp,
        output_html=out,
        use_mermaid=True,
        css_path=tmp_path / "print.css",
    )
    assert rc == 0
    assert out.is_file()
    err = capsys.readouterr().err
    assert "1 rendered, 0 failed" in err
    assert "wrote" in err


# --------------------------------------------------------------------------
# main()
# --------------------------------------------------------------------------


def test_main_preflight_abort(monkeypatch):
    monkeypatch.setattr(
        export_html, "preflight", lambda require_mermaid: (False, ["  [miss] pandoc"])
    )
    rc = export_html.main(["--check-only"])
    assert rc == 1


def test_main_check_only_ok(monkeypatch, capsys):
    monkeypatch.setattr(
        export_html, "preflight", lambda require_mermaid: (True, ["  [ok] pandoc"])
    )
    rc = export_html.main(["--check-only"])
    assert rc == 0
    assert "check-only" in capsys.readouterr().err


def test_main_input_not_found(monkeypatch, tmp_path):
    monkeypatch.setattr(
        export_html, "preflight", lambda require_mermaid: (True, [])
    )
    rc = export_html.main(["--input", str(tmp_path / "nope.md")])
    assert rc == 2


def test_main_css_missing(monkeypatch, tmp_path):
    inp = tmp_path / "tm.md"
    inp.write_text("# t\n", encoding="utf-8")
    monkeypatch.setattr(
        export_html, "preflight", lambda require_mermaid: (True, [])
    )
    # Point __file__-derived css lookup at a dir with no assets/print.css
    monkeypatch.setattr(export_html, "__file__", str(tmp_path / "export_html.py"))
    rc = export_html.main(["--input", str(inp), "--output", str(tmp_path / "o.html")])
    assert rc == 3


def test_main_conversion_runtime_error(monkeypatch, tmp_path):
    inp = tmp_path / "tm.md"
    inp.write_text("# t\n", encoding="utf-8")
    out = tmp_path / "o.html"
    monkeypatch.setattr(
        export_html, "preflight", lambda require_mermaid: (True, [])
    )

    def _boom(**kwargs):
        raise RuntimeError("pandoc exploded")

    monkeypatch.setattr(export_html, "export_html", _boom)
    rc = export_html.main(["--input", str(inp), "--output", str(out)])
    assert rc == 3


def test_main_success_end_to_end(monkeypatch, tmp_path, capsys):
    inp = tmp_path / "tm.md"
    inp.write_text("# t\n\nbody\n", encoding="utf-8")
    out = tmp_path / "sub" / "o.html"  # parent dir must be created
    monkeypatch.setattr(
        export_html, "preflight", lambda require_mermaid: (True, [])
    )
    monkeypatch.setattr(export_html, "check_tool", lambda name: None)
    monkeypatch.setattr(export_html, "md_to_html", _stub_md_to_html)

    rc = export_html.main(
        ["--input", str(inp), "--output", str(out), "--no-mermaid"]
    )
    assert rc == 0
    assert out.is_file()
    assert "wrote" in capsys.readouterr().err


def test_main_default_output_derives_from_input(monkeypatch, tmp_path):
    inp = tmp_path / "tm.md"
    inp.write_text("# t\n", encoding="utf-8")
    monkeypatch.setattr(
        export_html, "preflight", lambda require_mermaid: (True, [])
    )
    monkeypatch.setattr(export_html, "check_tool", lambda name: None)
    monkeypatch.setattr(export_html, "md_to_html", _stub_md_to_html)

    rc = export_html.main(["--input", str(inp), "--no-mermaid"])
    assert rc == 0
    assert (tmp_path / "tm.html").is_file()


# --------------------------------------------------------------------------
# __main__ dispatch via subprocess (real CLI, exercises argparse + exit code)
# --------------------------------------------------------------------------


def test_cli_input_not_found_exit_2(run_plugin_script, tmp_path):
    # pandoc present in the CI image is not guaranteed; if preflight fails we
    # accept exit 1, otherwise input-not-found gives exit 2. Either way the
    # __main__ wrapper + argparse path is exercised.
    result = run_plugin_script(
        "export_html.py",
        "--input",
        str(tmp_path / "does-not-exist.md"),
        check=False,
    )
    assert result.returncode in (1, 2)


def test_cli_help_exit_0(run_plugin_script):
    result = run_plugin_script("export_html.py", "--help", check=False)
    assert result.returncode == 0
    assert "export_html.py" in result.stdout
